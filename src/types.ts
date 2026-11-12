/**
 * The normalized event envelope and the small vocabulary every Telltale
 * source shares. See `docs/design.md` for why each field exists.
 */

/**
 * Where an event's content may be trusted to come from.
 *
 * - `owner`: the consumer registered this source as speaking for its owner
 *   (a device only the owner controls, a channel only the owner can write to).
 * - `untrusted`: everything else. Data that may try to give instructions.
 *
 * Trust is stamped from the source's registration, the place the event
 * entered. It is never read from the payload, headers or anything else the
 * outside sent.
 */
export type Trust = "owner" | "untrusted";

/** The source an event entered through. */
export interface EventSourceRef {
  /** The consumer-chosen source id. */
  readonly id: string;
  /** The source type, e.g. `webhook`, `github-poll`, `folder`. */
  readonly type: string;
}

/**
 * One normalized event. Every source emits this shape and nothing else.
 *
 * The envelope is deep-frozen and its payload has had every registered
 * secret replaced with `[redacted]` before any subscriber sees it.
 */
export interface TelltaleEvent<P = unknown> {
  readonly schemaVersion: 1;
  /** Unique per emission (a random UUID). Two deliveries of one happening have different ids. */
  readonly id: string;
  /** When Telltale received or observed it, ISO-8601 from the host clock. */
  readonly ts: string;
  /** `<source id>/<event name>`, e.g. `ci-hooks/received`. */
  readonly topic: string;
  /** The event name alone, e.g. `received`, `workflow_run.completed`, `added`. */
  readonly name: string;
  readonly source: EventSourceRef;
  /** What the source reported. Outside content unless `trust` is `owner`. */
  readonly payload: P;
  readonly trust: Trust;
  /**
   * Semantic identity: the same happening yields the same key whichever
   * transport carried it (a GitHub run seen by poll and by push has one key).
   * Telltale delivers at least once; a consumer that must act exactly once
   * dedupes on this key, atomically with its own effects.
   */
  readonly dedupKey: string;
  /** Transport identity when the transport has one (e.g. `X-GitHub-Delivery`). */
  readonly deliveryId?: string;
  /** When the happening itself occurred, if the source knows (ISO-8601). */
  readonly occurredAt?: string;
  /** The id of the event that led to this one, when a source emits in reaction to another event. */
  readonly cause?: string;
  /** How many reactions separate this event from an outside trigger: 0 for one that entered from outside. */
  readonly hops: number;
}

/**
 * A refused observation: something a source saw and would not turn into an
 * event (malformed, for another repository, too old). It carries a closed
 * reason and an optional dedup key, never outside text.
 */
export interface Refusal {
  readonly sourceId: string;
  /** A closed, snake_case reason such as `malformed_request` or `stale_event`. */
  readonly reason: string;
  readonly dedupKey?: string;
  /** ISO-8601 from the host clock. */
  readonly at: string;
}

/** A value or a promise of it: storage seams may be synchronous or not. */
export type MaybePromise<T> = T | Promise<T>;

/** Where Telltale writes its own diagnostics. Everything passed here is redacted first. */
export interface Logger {
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
}

/** A logger that drops everything; the default. */
export const silentLogger: Logger = {
  info() {},
  warn() {},
};
