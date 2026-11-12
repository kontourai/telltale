import { createHash, randomUUID } from "node:crypto";
import { type Clock, SystemClock } from "./clock.js";
import { deepFreeze, SecretRegistry } from "./secrets.js";
import {
  DeliveryError,
  type EmitMeta,
  type OptionSpec,
  type ReceivedRequest,
  type ReceiveResult,
  SourceError,
  type SourceApi,
  type SourcePlan,
  SourceStoppedError,
  type SourceType,
} from "./source-type.js";
import { folderSourceType } from "./sources/folder.js";
import { githubPollSourceType } from "./sources/github-poll.js";
import { webhookSourceType } from "./sources/webhook.js";
import { InMemoryStateStore, type StateStore } from "./store.js";
import { type Logger, type MaybePromise, type Refusal, silentLogger, type TelltaleEvent, type Trust } from "./types.js";
import { parseDuration } from "./util.js";

/** The longest wait between looks of a source whose looks keep failing (or its own interval, if longer). */
export const POLL_BACKOFF_MAX_MS = 15 * 60_000;
/** Reactions chained beyond this are dropped as a probable loop. */
export const DEFAULT_MAX_HOPS = 8;

const SOURCE_ID = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const EVENT_NAME = /^[a-z][a-z0-9_.-]{0,63}$/;
const REASON = /^[a-z][a-z0-9_]{0,63}$/;
const MAX_DEDUP_KEY = 512;
const STATUS_NOTE_MAX = 200;

/** A subscriber: a function for events, or an object that also takes refusals. */
export type Subscriber =
  | ((event: TelltaleEvent) => MaybePromise<void>)
  | {
      event(event: TelltaleEvent): MaybePromise<void>;
      refusal?(refusal: Refusal): MaybePromise<void>;
    };

export interface Subscription {
  /** Stop receiving. The last subscriber leaving stops the source. */
  unsubscribe(): Promise<void>;
}

export interface AddSourceInput<Bindings = Record<string, unknown>> {
  /** Consumer-chosen id: lowercase letters, digits, `_`, `.`, `-`; at most 64. */
  id: string;
  /** A registered source type name. */
  type: string;
  options?: Record<string, unknown>;
  /**
   * The trust every event from this source carries. Defaults to `untrusted`.
   * Say `owner` only for a source nobody but its owner can make speak. A
   * signed webhook is still `untrusted` when its body carries text other
   * people wrote (issue titles, commit messages), whatever the secret.
   */
  trust?: Trust;
  bindings?: Bindings;
}

/** How a source is doing, safe to show anywhere (no outside text, secrets redacted). */
export interface SourceStatus {
  state: "stopped" | "starting" | "running" | "failing";
  startedAt?: string;
  /** Polling sources only. */
  lastLookAt?: string;
  lastOkAt?: string;
  failingSince?: string;
  failures: number;
  /** Why it is failing: a source-authored `SourceError` message, else "unexpected failure". */
  error?: string;
  /** The source type's own line. */
  note?: string;
  emitted: number;
  refused: number;
}

export interface SourceInfo {
  id: string;
  type: string;
  trust: Trust;
  /** Options with every secret value masked. */
  options: Record<string, unknown>;
  subscribers: number;
  status: SourceStatus;
}

export interface TelltaleHostOptions {
  clock?: Clock;
  state?: StateStore;
  logger?: Logger;
  /** Extra source types, by name, beside the built-ins (`webhook`, `github-poll`, `folder`). */
  types?: Record<string, SourceType<any>>;
  /** Jitter source in [0, 1). Default `Math.random`. Tests pass a constant. */
  random?: () => number;
  maxHops?: number;
}

interface Registration {
  id: string;
  typeName: string;
  type: SourceType<any>;
  options: Record<string, unknown>;
  secretKeys: string[];
  trust: Trust;
  bindings: Record<string, unknown>;
  statePrefix: string;
  /** Objects a source keeps across starts (`api.keep`). They go with the registration. */
  kept: Map<string, unknown>;
}

interface Running {
  abort: AbortController;
  stops: Array<() => MaybePromise<void>>;
  receive?: (request: ReceivedRequest) => Promise<ReceiveResult>;
  polling: boolean;
  pollTimer?: unknown;
  inflight?: Promise<void>;
}

interface MutableStatus {
  startedAt?: number;
  lastLookAt?: number;
  lastOkAt?: number;
  failingSince?: number;
  failures: number;
  error?: string;
  note?: string;
  emitted: number;
  refused: number;
  starting: boolean;
}

const iso = (ms: number | undefined) => (ms === undefined ? undefined : new Date(ms).toISOString());

/**
 * Holds typed sources and the subscriptions to them.
 *
 * Being added does nothing. A source starts on its first subscriber and stops
 * when the last one leaves, so an unsubscribed source holds no timer, no
 * watcher and accepts no request. Every event a source emits is stamped here:
 * id, time, topic, the source it entered through and that source's trust.
 * A source type cannot set trust, and nothing in a payload can raise it.
 */
export class TelltaleHost {
  readonly clock: Clock;
  /** Every secret Telltale knows. Consumers may add their own (`secrets.add`). */
  readonly secrets = new SecretRegistry();
  readonly #state: StateStore;
  readonly #logger: Logger;
  readonly #random: () => number;
  readonly #maxHops: number;
  readonly #types = new Map<string, SourceType<any>>();
  readonly #sources = new Map<string, Registration>();
  readonly #subscribers = new Map<string, Set<Subscriber>>();
  readonly #running = new Map<string, Running>();
  readonly #starting = new Map<string, Promise<void>>();
  readonly #status = new Map<string, MutableStatus>();

  constructor(options: TelltaleHostOptions = {}) {
    this.clock = options.clock ?? new SystemClock();
    this.#state = options.state ?? new InMemoryStateStore();
    this.#logger = options.logger ?? silentLogger;
    this.#random = options.random ?? Math.random;
    this.#maxHops = options.maxHops ?? DEFAULT_MAX_HOPS;
    this.registerType("webhook", webhookSourceType);
    this.registerType("github-poll", githubPollSourceType);
    this.registerType("folder", folderSourceType);
    for (const [name, type] of Object.entries(options.types ?? {})) this.registerType(name, type);
  }

  /** Make a source type available under `name`. Refuses a name already taken. */
  registerType(name: string, type: SourceType<any>): void {
    if (!SOURCE_ID.test(name)) throw new Error(`"${name}" is not a usable type name`);
    if (this.#types.has(name)) throw new Error(`a source type named "${name}" is already registered`);
    if (typeof type?.start !== "function") throw new Error(`source type "${name}" has no start function`);
    this.#types.set(name, type);
  }

  /** The registered type names. */
  types(): string[] {
    return [...this.#types.keys()];
  }

  /** What adding a source would do, without adding it. Secret values come back masked. */
  plan(typeName: string, options: Record<string, unknown> = {}): SourcePlan {
    const { type, plan } = this.#plan(typeName, options);
    return { ...plan, options: mask(type.options, plan.options) };
  }

  /** Register a source. It does not start until something subscribes. */
  add<B extends Record<string, unknown>>(input: AddSourceInput<B>): SourceInfo {
    if (typeof input.id !== "string" || !SOURCE_ID.test(input.id)) {
      throw new Error(`"${input.id}" is not a usable source id (lowercase letters, digits, _ . -, at most 64)`);
    }
    if (this.#sources.has(input.id)) throw new Error(`a source with id "${input.id}" exists already`);
    const trust = input.trust ?? "untrusted";
    if (trust !== "owner" && trust !== "untrusted") throw new Error(`trust must be "owner" or "untrusted"`);
    const { type, plan } = this.#plan(input.type, input.options ?? {});
    const secretKeys = Object.keys(type.options).filter((k) => type.options[k]?.secret === true);
    for (const key of secretKeys) {
      const value = plan.options[key];
      if (value !== undefined) this.secrets.add(value as string);
    }
    const publicOptions = Object.fromEntries(Object.entries(plan.options).filter(([k]) => !secretKeys.includes(k)));
    const fingerprint = createHash("sha256")
      .update(JSON.stringify([input.type, canonical(publicOptions)]))
      .digest("hex")
      .slice(0, 16);
    this.#sources.set(input.id, {
      id: input.id,
      typeName: input.type,
      type,
      options: plan.options,
      secretKeys,
      trust,
      bindings: (input.bindings ?? {}) as Record<string, unknown>,
      statePrefix: `${input.id}:${fingerprint}:`,
      kept: new Map(),
    });
    this.#status.set(input.id, { failures: 0, emitted: 0, refused: 0, starting: false });
    return this.info(input.id)!;
  }

  /** Stop and unregister a source. Its subscriptions end. Its state stays, keyed by its configuration. */
  async remove(id: string): Promise<boolean> {
    if (!this.#sources.has(id)) return false;
    this.#subscribers.delete(id);
    await this.#stop(id);
    this.#sources.delete(id);
    this.#status.delete(id);
    return true;
  }

  /**
   * Subscribe to a source's events (and, with an object subscriber, its
   * refusals). The first subscriber starts the source; if it cannot start,
   * this rejects and nothing stays subscribed.
   */
  async subscribe(id: string, subscriber: Subscriber): Promise<Subscription> {
    if (!this.#sources.has(id)) throw new Error(`there is no source "${id}"`);
    let set = this.#subscribers.get(id);
    if (!set) this.#subscribers.set(id, (set = new Set()));
    // A distinct wrapper per call, so the same function subscribed twice is two subscriptions.
    const entry: Subscriber = typeof subscriber === "function" ? (e) => subscriber(e) : { ...subscriber };
    set.add(entry);
    try {
      await this.#ensure(id);
    } catch (error) {
      set.delete(entry);
      throw error;
    }
    let done = false;
    return {
      unsubscribe: async () => {
        if (done) return;
        done = true;
        const current = this.#subscribers.get(id);
        current?.delete(entry);
        if (!current || current.size === 0) await this.#stop(id);
      },
    };
  }

  /**
   * Hand a request to a receiving source (a webhook). The consumer owns the
   * HTTP server; it answers with `status` from the result.
   */
  async receive(id: string, request: ReceivedRequest): Promise<ReceiveResult> {
    if (!this.#sources.has(id)) return { accepted: false, status: 404, reason: "unknown_source", retryable: false };
    const running = this.#running.get(id);
    if (!running?.receive) return { accepted: false, status: 404, reason: "not_listening", retryable: true };
    return running.receive(request);
  }

  info(id: string): SourceInfo | undefined {
    const reg = this.#sources.get(id);
    if (!reg) return undefined;
    return {
      id: reg.id,
      type: reg.typeName,
      trust: reg.trust,
      options: mask(reg.type.options, reg.options),
      subscribers: this.#subscribers.get(id)?.size ?? 0,
      status: this.status(id)!,
    };
  }

  list(): SourceInfo[] {
    return [...this.#sources.keys()].map((id) => this.info(id)!);
  }

  status(id: string): SourceStatus | undefined {
    const s = this.#status.get(id);
    if (!s) return undefined;
    const running = this.#running.has(id);
    return {
      state: s.starting ? "starting" : !running ? "stopped" : s.failures ? "failing" : "running",
      startedAt: running ? iso(s.startedAt) : undefined,
      lastLookAt: iso(s.lastLookAt),
      lastOkAt: iso(s.lastOkAt),
      failingSince: iso(s.failingSince),
      failures: s.failures,
      error: s.error,
      note: s.note,
      emitted: s.emitted,
      refused: s.refused,
    };
  }

  /** Stop every source. Registrations stay. */
  async close(): Promise<void> {
    this.#subscribers.clear();
    await Promise.all([...this.#running.keys()].map((id) => this.#stop(id)));
  }

  #plan(typeName: string, raw: Record<string, unknown>): { type: SourceType<any>; plan: SourcePlan } {
    const type = this.#types.get(typeName);
    if (!type) throw new Error(`there is no source type "${typeName}"`);
    const options = checkOptions(typeName, type.options, raw);
    const plan = type.plan ? type.plan(options) : { options, does: [`start a ${typeName} source`], opens: true };
    // A plan may fill in defaults; it may not invent options the type does not declare.
    checkOptions(typeName, type.options, plan.options);
    return { type, plan: { ...plan, options: { ...plan.options } } };
  }

  async #ensure(id: string): Promise<void> {
    if (this.#running.has(id)) return;
    const pending = this.#starting.get(id);
    if (pending) return pending;
    const job = this.#launch(id).finally(() => this.#starting.delete(id));
    this.#starting.set(id, job);
    return job;
  }

  async #launch(id: string): Promise<void> {
    const reg = this.#sources.get(id)!;
    const status = this.#status.get(id)!;
    const run: Running = { abort: new AbortController(), stops: [], polling: false };
    const api = this.#api(reg, run, status);
    status.starting = true;
    try {
      await reg.type.start(api);
    } catch (error) {
      run.abort.abort();
      for (const fn of run.stops.reverse()) await Promise.resolve().then(fn).catch(() => {});
      status.starting = false;
      status.error = describeFailure(error, this.secrets);
      this.#log(reg.id).warn("source could not start", { error: status.error });
      throw error;
    }
    status.starting = false;
    status.startedAt = this.clock.now();
    this.#running.set(id, run);
    this.#log(reg.id).info("source started");
  }

  async #stop(id: string): Promise<void> {
    const pending = this.#starting.get(id);
    if (pending) await pending.catch(() => {});
    const run = this.#running.get(id);
    if (!run) return;
    // Still wanted by someone who subscribed while we were getting here.
    if ((this.#subscribers.get(id)?.size ?? 0) > 0 && this.#sources.has(id)) return;
    this.#running.delete(id);
    run.abort.abort();
    if (run.pollTimer !== undefined) this.clock.clearTimer(run.pollTimer);
    await run.inflight?.catch(() => {});
    for (const fn of run.stops.reverse()) await Promise.resolve().then(fn).catch(() => {});
    const status = this.#status.get(id);
    if (status) Object.assign(status, { failures: 0, failingSince: undefined, error: undefined });
    this.#log(id).info("source stopped");
  }

  #log(id: string): Logger {
    const secrets = this.secrets;
    const base = this.#logger;
    const wrap = (level: "info" | "warn") => (message: string, meta?: Record<string, unknown>) => {
      try {
        base[level](secrets.text(message), secrets.deep({ source: id, ...(meta ?? {}) }));
      } catch {
        // Diagnostics never change what a source does.
      }
    };
    return { info: wrap("info"), warn: wrap("warn") };
  }

  async #deliver(id: string, kind: "event" | "refusal", value: TelltaleEvent | Refusal): Promise<void> {
    const subscribers = [...(this.#subscribers.get(id) ?? [])];
    let failures = 0;
    for (const sub of subscribers) {
      try {
        if (kind === "event") await (typeof sub === "function" ? sub(value as TelltaleEvent) : sub.event(value as TelltaleEvent));
        else if (typeof sub !== "function" && sub.refusal) await sub.refusal(value as Refusal);
      } catch (error) {
        failures++;
        this.#log(id).warn(`a subscriber failed to take a ${kind}`, { error: error instanceof Error ? error.name : "error" });
      }
    }
    if (failures) throw new DeliveryError(id, failures);
  }

  #api(reg: Registration, run: Running, status: MutableStatus): SourceApi<any> {
    const host = this;
    const clock = this.clock;
    const secrets = this.secrets;
    const log = this.#log(reg.id);
    const stateStore = this.#state;
    const key = (k: string) => `${reg.statePrefix}${k}`;
    const live = () => {
      if (run.abort.signal.aborted) throw new SourceStoppedError(reg.id);
    };

    const state = {
      async get<T>(k: string): Promise<T | undefined> {
        return (await stateStore.get(key(k))) as T | undefined;
      },
      async set(k: string, value: unknown): Promise<void> {
        await stateStore.set(key(k), value);
      },
      async delete(k: string): Promise<void> {
        await stateStore.delete(key(k));
      },
    };

    return {
      id: reg.id,
      type: reg.typeName,
      options: Object.freeze({ ...reg.options }),
      bindings: reg.bindings,
      clock,
      log,
      signal: run.abort.signal,
      state,

      async emit(name: string, payload: unknown, meta: EmitMeta): Promise<TelltaleEvent> {
        live();
        if (typeof name !== "string" || !EVENT_NAME.test(name)) throw new Error(`source ${reg.id}: "${name}" is not a usable event name`);
        if (!meta || typeof meta.dedupKey !== "string" || !meta.dedupKey || meta.dedupKey.length > MAX_DEDUP_KEY) {
          throw new Error(`source ${reg.id}: every event needs a dedupKey of 1-${MAX_DEDUP_KEY} characters`);
        }
        const hops = meta.cause ? meta.cause.hops + 1 : 0;
        if (hops > host.#maxHops) {
          log.warn("event dropped: too many hops (a loop?)", { hops });
          throw new SourceError(`event dropped after ${hops} hops`);
        }
        const now = clock.now();
        // Built field by field: nothing the source passed besides these can reach the envelope.
        const event: TelltaleEvent = {
          schemaVersion: 1,
          id: randomUUID(),
          ts: new Date(now).toISOString(),
          topic: `${reg.id}/${name}`,
          name,
          source: { id: reg.id, type: reg.typeName },
          payload: secrets.deep(payload ?? {}),
          // Stamped from the registration, the place the event entered. Never from the payload or meta.
          trust: reg.trust,
          dedupKey: secrets.text(meta.dedupKey),
          ...(typeof meta.deliveryId === "string" && meta.deliveryId ? { deliveryId: secrets.text(meta.deliveryId) } : {}),
          ...(typeof meta.occurredAt === "number" && Number.isFinite(meta.occurredAt)
            ? { occurredAt: new Date(meta.occurredAt).toISOString() }
            : {}),
          ...(meta.cause ? { cause: meta.cause.id } : {}),
          hops,
        };
        deepFreeze(event);
        status.emitted++;
        await host.#deliver(reg.id, "event", event);
        return event;
      },

      async refuse(reason: string, meta?: { dedupKey?: string }): Promise<void> {
        live();
        if (typeof reason !== "string" || !REASON.test(reason)) throw new Error(`source ${reg.id}: "${reason}" is not a closed reason`);
        const refusal: Refusal = deepFreeze({
          sourceId: reg.id,
          reason,
          ...(meta?.dedupKey ? { dedupKey: secrets.text(String(meta.dedupKey).slice(0, MAX_DEDUP_KEY)) } : {}),
          at: new Date(clock.now()).toISOString(),
        });
        status.refused++;
        await host.#deliver(reg.id, "refusal", refusal);
      },

      poll(every: string | number, look: (signal: AbortSignal) => MaybePromise<void>): void {
        const ms = parseDuration(every);
        if (run.polling) throw new Error(`source ${reg.id}: a source polls one thing`);
        run.polling = true;
        const signal = run.abort.signal;
        const round = () => {
          run.pollTimer = undefined;
          if (signal.aborted) return;
          status.lastLookAt = clock.now();
          run.inflight = (async () => {
            try {
              await look(signal);
              if (signal.aborted) return;
              if (status.failures) log.info(`works again after ${status.failures} failed look(s)`);
              Object.assign(status, { lastOkAt: clock.now(), failures: 0, failingSince: undefined, error: undefined });
            } catch (error) {
              if (signal.aborted || error instanceof SourceStoppedError) return;
              // Said once, not at every round: the status line carries it from here.
              if (!status.failures) log.warn("could not look", { error: describeFailure(error, secrets) });
              status.failures++;
              status.failingSince ??= clock.now();
              status.error = describeFailure(error, secrets);
            }
          })();
          void run.inflight.then(() => {
            run.inflight = undefined;
            if (signal.aborted) return;
            const wait = status.failures
              ? Math.min(ms * 2 ** Math.min(status.failures, 12), Math.max(ms, POLL_BACKOFF_MAX_MS))
              : ms;
            run.pollTimer = clock.setTimer(round, wait * (0.9 + host.#random() * 0.2));
          });
        };
        // Not awaited: a slow first look must not hold up the start of everything else.
        run.pollTimer = clock.setTimer(round, 0);
      },

      async changed<T>(value: T, slot = ""): Promise<{ previous: T } | undefined> {
        const k = `seen:${slot}`;
        const before = (await state.get<{ value: T }>(k)) ?? undefined;
        if (before && JSON.stringify(before.value) === JSON.stringify(value)) return undefined;
        await state.set(k, { value });
        return before ? { previous: before.value } : undefined;
      },

      keep<T>(name: string, create: () => T): T {
        if (!reg.kept.has(name)) reg.kept.set(name, create());
        return reg.kept.get(name) as T;
      },

      secret(value: string | undefined): void {
        if (value) secrets.add(value);
      },

      status(note: string): void {
        status.note = secrets.text(String(note)).slice(0, STATUS_NOTE_MAX);
      },

      onReceive(handler) {
        run.receive = async (request) => {
          if (run.abort.signal.aborted) return { accepted: false, status: 404, reason: "not_listening", retryable: true };
          return handler(request);
        };
      },

      onStop(fn) {
        run.stops.push(fn);
      },
    };
  }
}

/** Status text for a failure: a source-authored message, or nothing that could quote outside content. */
function describeFailure(error: unknown, secrets: SecretRegistry): string {
  if (error instanceof SourceError) return secrets.text(error.message).slice(0, STATUS_NOTE_MAX);
  return "unexpected failure";
}

function mask(spec: Readonly<Record<string, OptionSpec>>, options: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(options).map(([k, v]) => [k, spec[k]?.secret === true && v !== undefined ? "[secret]" : v]),
  );
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value as Record<string, unknown>)
        .sort()
        .map((k) => [k, canonical((value as Record<string, unknown>)[k])]),
    );
  }
  return value;
}

function checkOptions(
  typeName: string,
  spec: Readonly<Record<string, OptionSpec>>,
  raw: Record<string, unknown>,
): Record<string, unknown> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`${typeName}: options must be an object`);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw)) {
    const s = spec[k];
    if (!s) throw new Error(`${typeName}: unknown option "${k}"`);
    if (v === undefined) continue;
    const ok =
      s.type === "string[]"
        ? Array.isArray(v) && v.every((x) => typeof x === "string")
        : s.type === "object"
          ? !!v && typeof v === "object" && !Array.isArray(v)
          : typeof v === s.type && (s.type !== "number" || Number.isFinite(v));
    if (!ok) throw new Error(`${typeName}: option "${k}" must be ${s.type}`);
    if (s.secret && (typeof v !== "string" || v.length < 8)) throw new Error(`${typeName}: secret option "${k}" must be at least 8 characters`);
    out[k] = v;
  }
  for (const [k, s] of Object.entries(spec)) if (s.required && out[k] === undefined) throw new Error(`${typeName}: needs option "${k}"`);
  return out;
}
