import type { Clock } from "./clock.js";
import type { Logger, MaybePromise, TelltaleEvent } from "./types.js";

/**
 * A source type is a description plus a start function. The description is
 * all a consumer's setup surface needs to offer the type: a one-line summary,
 * its options (with secrets marked), and `plan()`, which says what setting a
 * source up would do before anything starts.
 *
 * The shape follows pmndrs/pine's `SourceType` (summary, options schema,
 * `plan()` returning `{options, does, opens}`), without a schema library: an
 * option is described by a small {@link OptionSpec}.
 */
export interface SourceType<Bindings = Record<string, unknown>> {
  /** One line: what a source of this type reports and what it is for. */
  summary: string;
  /** Every option it takes. Unknown options are refused. */
  options: Readonly<Record<string, OptionSpec>>;
  /**
   * Check the options and say what the source would do. Throw for what cannot
   * work. Return the options as they will be used (defaults filled in).
   * Without it, the checked options are used as given and the plan says only
   * that a source of this type will start.
   */
  plan?(options: Readonly<Record<string, unknown>>): SourcePlan;
  /**
   * Start a source. Called on its first subscriber, never before. Register
   * everything that needs stopping with `api.onStop()`; a throw stops it again
   * and the subscribe call fails.
   */
  start(api: SourceApi<Bindings>): MaybePromise<void>;
}

export type OptionKind = "string" | "number" | "boolean" | "string[]" | "object";

export interface OptionSpec {
  type: OptionKind;
  description: string;
  required?: boolean;
  /**
   * A password, token or signing secret. Its value is registered with the
   * host's secret registry the moment the source is added, so it is redacted
   * from events, refusals, status lines and logs, and `list()` / `plan()`
   * show it masked.
   */
  secret?: boolean;
}

/** What setting a source up would mean, worked out before anything starts. */
export interface SourcePlan {
  /** The options as they will be used. */
  options: Record<string, unknown>;
  /** What it will do, in plain words, for the consumer's confirmation surface. */
  does: string[];
  /** It reaches something new (a folder elsewhere, a network service, an inbound route), so a person should confirm it. */
  opens: boolean;
  /** What the person setting it up should pass on (where a caller finds its secret, for example). */
  tell?: string;
}

/** Metadata every emit carries besides its payload. */
export interface EmitMeta {
  /** Semantic identity of the happening. Required: the consumer dedupes on it. */
  dedupKey: string;
  /** Transport identity, when the transport has one. */
  deliveryId?: string;
  /** When the happening occurred (epoch ms), if the source knows. */
  occurredAt?: number;
  /** The event this one reacts to. Sets `cause` and `hops = cause.hops + 1`. */
  cause?: TelltaleEvent;
}

/** A request handed to a source that receives (a webhook). The consumer owns the transport. */
export interface ReceivedRequest {
  /** Header lookup. Either a plain object (any case) or a Fetch `Headers`. */
  headers: Record<string, string | string[] | undefined> | { get(name: string): string | null };
  /**
   * The raw body bytes, or a function that reads them. Prefer the function:
   * a receiving source calls it only after every header-only check passed,
   * so a refused request never costs a body read. Return `null` when the
   * body exceeds your own transport bound.
   */
  body: Uint8Array | string | (() => Promise<Uint8Array | string | null | undefined>);
}

export type ReceiveResult =
  | { accepted: true; status: 202; event: TelltaleEvent }
  | {
      accepted: false;
      /** HTTP status a transport should answer with. */
      status: 400 | 401 | 403 | 404 | 429 | 503;
      /** A closed, snake_case reason. Safe to return to the caller. */
      reason: string;
      /** Whether the same delivery, re-sent, could succeed. */
      retryable: boolean;
      retryAfterSeconds?: number;
    };

/** What a source's `start()` gets. */
export interface SourceApi<Bindings = Record<string, unknown>> {
  readonly id: string;
  readonly type: string;
  /** Checked, planned options, secrets included (the source needs them; nobody else sees them). */
  readonly options: Readonly<Record<string, unknown>>;
  /** Non-serializable collaborators the consumer passed at `add()` (a fetch, a credential store). */
  readonly bindings: Bindings;
  readonly clock: Clock;
  /** Redacting logger. */
  readonly log: Logger;
  /** Aborted when the source stops. */
  readonly signal: AbortSignal;
  /**
   * Report that something happened. The host stamps id, time, topic, source
   * and trust; the source supplies only the name, payload and identity.
   * Resolves once every subscriber has been handed the event; rejects with a
   * `DeliveryError` when one of them threw, and with `SourceStoppedError`
   * once the source has stopped (a late result is dropped, never delivered).
   */
  emit(name: string, payload: unknown, meta: EmitMeta): Promise<TelltaleEvent>;
  /** Report a refused observation with a closed reason. No outside text. */
  refuse(reason: string, meta?: { dedupKey?: string }): Promise<void>;
  /**
   * Look at something again and again. `look` runs once right away, then
   * every `every` ("30s", "5m"), never twice at once, each wait 10% shorter or
   * longer at random so sources set to one interval do not fire together. A
   * look that throws is a failed look: the wait doubles with each one in a
   * row (up to 15 minutes, or the interval if longer), the status shows since
   * when it fails, and the first look that works restores the interval.
   * One poll per source.
   */
  poll(every: string | number, look: (signal: AbortSignal) => MaybePromise<void>): void;
  /**
   * Compare a value with what was there at the last look, and remember it.
   * Returns what it was before when it differs. The first look returns
   * nothing: it is the starting point, not a change. An unchanged value
   * writes nothing. `slot` keeps several values apart.
   */
  changed<T>(value: T, slot?: string): Promise<{ previous: T } | undefined>;
  /** Private state for this source, namespaced by id, type and non-secret options. */
  readonly state: {
    get<T = unknown>(key: string): Promise<T | undefined>;
    set(key: string, value: unknown): Promise<void>;
    delete(key: string): Promise<void>;
  };
  /** Keep this value out of events, refusals, status lines and logs from now on. */
  secret(value: string | undefined): void;
  /**
   * One line on how things stand, for whoever lists sources. It is read
   * without the mark outside content carries: never put outside text in it
   * (use `harmless()` for a found value). It is redacted and clipped.
   */
  status(note: string): void;
  /** Accept requests passed to `host.receive(id, request)`. */
  onReceive(handler: (request: ReceivedRequest) => Promise<ReceiveResult>): void;
  onStop(fn: () => MaybePromise<void>): void;
}

/**
 * An error whose message the source wrote itself, as fixed text. Only these
 * messages reach a status line; any other failure shows as "unexpected
 * failure", because its message may quote outside content.
 */
export class SourceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SourceError";
  }
}

/** Thrown by `emit()` / `refuse()` after the source stopped. */
export class SourceStoppedError extends Error {
  constructor(sourceId: string) {
    super(`source ${sourceId} has stopped; the result was dropped`);
    this.name = "SourceStoppedError";
  }
}

/** Thrown by `emit()` / `refuse()` when at least one subscriber threw. */
export class DeliveryError extends Error {
  constructor(
    sourceId: string,
    readonly failures: number,
  ) {
    super(`source ${sourceId}: ${failures} subscriber(s) failed to take the delivery`);
    this.name = "DeliveryError";
  }
}
