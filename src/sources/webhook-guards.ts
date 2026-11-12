/**
 * The bounded collaborators a webhook source verifies with: the credential
 * lookup, the replay ledger, the refusal audit, and the two rate limits.
 * Storage is pluggable; each has an in-memory default.
 *
 * The semantics are ported from a production inbound-webhook intake (named
 * HMAC credentials re-read per request, a durable nonce ledger that fails
 * closed, a per-credential attempt limiter and a global unauthenticated
 * budget whose post-trip noise is aggregated). See docs/design.md.
 */

import { randomUUID } from "node:crypto";
import type { Clock } from "../clock.js";
import type { MaybePromise } from "../types.js";
import { digest } from "../util.js";

/** A secret shorter than this is brute-forceable within the cost of the requests it gates. */
export const MIN_WEBHOOK_SECRET_LENGTH = 32;

export const WEBHOOK_REFUSAL_REASONS = [
  "disabled",
  "unknown_token",
  "revoked_token",
  "malformed_request",
  "stale_timestamp",
  "invalid_signature",
  "replay",
  "rate_limited",
  "policy_unavailable",
  "delivery_failed",
] as const;
export type WebhookRefusalReason = (typeof WEBHOOK_REFUSAL_REASONS)[number];

/** One named credential. `secret` never leaves Telltale: it is registered for redaction on first use. */
export interface WebhookCredential {
  id: string;
  secret: string;
  /** Present means revoked: refused with `revoked_token`. */
  revokedAt?: string;
}

/** What a lookup says: the whole intake is off, or (on) the credential, if one has that id. */
export type WebhookLookup = { enabled: false } | { enabled: true; credential?: WebhookCredential };

/**
 * Where credentials live. Called on every request, so revocation and the off
 * switch take effect on the next request with no cache to invalidate. Throw
 * when the store cannot be read: the request is refused `policy_unavailable`.
 */
export interface WebhookCredentials {
  lookup(credentialId: string): MaybePromise<WebhookLookup>;
}

/** What `reserve` answers: the key is now yours (with the token that proves it), or someone has it already. */
export type ReplayReservation = { outcome: "reserved"; token: string } | { outcome: "replayed" };

/**
 * Remembers which authenticated requests were already delivered, as a small
 * state machine per key. `reserve` takes a free key and returns a token, an
 * opaque proof of ownership. `extend` (while delivery runs), `commit` (every
 * subscriber took the event) and `release` (delivery failed, so the same
 * request may be sent again) act only when the token still owns the key, and
 * answer whether they did. A reserved or delivered key refuses another
 * `reserve`, so two copies of one request are never delivered at once.
 *
 * `reserve` is called only after the request authenticated, so an
 * unauthenticated caller can never burn or lock a key. Throw when you cannot
 * decide (a corrupt or full ledger): the request is refused
 * `policy_unavailable`, so replay protection is never silently removed.
 *
 * **Atomicity is the implementer's obligation.** `reserve` must check and
 * take the key in one atomic step (a transaction, a compare-and-set, a unique
 * insert); a read, an await and then a write lets two concurrent copies both
 * reserve. `extend`, `commit` and `release` must compare the token and change
 * the entry in the same atomic step, so an owner whose reservation expired
 * and was taken by a newer request cannot touch the newer one.
 *
 * `expiresAt` is the first instant at which the key is free again. Keep the
 * key while `now < expiresAt`; forget it only when `now >= expiresAt`. A
 * webhook extends its reservation while delivery runs, so a slow subscriber
 * never lets the key lapse under it; a reservation whose holder stopped (a
 * crash) lapses at its last `expiresAt`.
 */
export interface ReplayLedger {
  reserve(key: string, expiresAt: number, now: number): MaybePromise<ReplayReservation>;
  /** Move a live reservation's expiry later. `false`: the token no longer owns a live reservation. */
  extend(key: string, token: string, expiresAt: number, now: number): MaybePromise<boolean>;
  /** Mark the token's reservation delivered. `false`: the token no longer owns the key; nothing changed. */
  commit(key: string, token: string, now: number): MaybePromise<boolean>;
  /** Free the token's reservation. `false`: the token no longer owns a reservation; nothing changed. */
  release(key: string, token: string, now: number): MaybePromise<boolean>;
}

export class ReplayLedgerFullError extends Error {
  constructor(max: number) {
    super(`replay ledger holds ${max} unexpired keys; refusing rather than evicting one`);
    this.name = "ReplayLedgerFullError";
  }
}

/**
 * In-memory replay ledger. At capacity it first drops expired keys; if every
 * key is still live it refuses the reservation instead of evicting one,
 * because evicting a live key would reopen the replay window it exists to
 * close.
 */
export class InMemoryReplayLedger implements ReplayLedger {
  readonly #keys = new Map<string, { expiresAt: number; state: "reserved" | "delivered"; token: string }>();

  constructor(readonly maxEntries = 10_000) {}

  reserve(key: string, expiresAt: number, now: number): ReplayReservation {
    const existing = this.#keys.get(key);
    if (existing !== undefined && now < existing.expiresAt) return { outcome: "replayed" };
    if (existing !== undefined) this.#keys.delete(key);
    if (this.#keys.size >= this.maxEntries) {
      for (const [k, entry] of this.#keys) if (now >= entry.expiresAt) this.#keys.delete(k);
      if (this.#keys.size >= this.maxEntries) throw new ReplayLedgerFullError(this.maxEntries);
    }
    const token = randomUUID();
    this.#keys.set(key, { expiresAt, state: "reserved", token });
    return { outcome: "reserved", token };
  }

  extend(key: string, token: string, expiresAt: number, now: number): boolean {
    const entry = this.#keys.get(key);
    if (entry?.token !== token || entry.state !== "reserved" || now >= entry.expiresAt) return false;
    entry.expiresAt = Math.max(entry.expiresAt, expiresAt);
    return true;
  }

  commit(key: string, token: string): boolean {
    const entry = this.#keys.get(key);
    if (entry?.token !== token) return false;
    entry.state = "delivered";
    return true;
  }

  release(key: string, token: string): boolean {
    const entry = this.#keys.get(key);
    if (entry?.token !== token || entry.state !== "reserved") return false;
    this.#keys.delete(key);
    return true;
  }

  get size(): number {
    return this.#keys.size;
  }

  /** A key's state, for tests and debugging. */
  state(key: string): "reserved" | "delivered" | undefined {
    return this.#keys.get(key)?.state;
  }
}

/** One audit line. It never holds a body, a header value, a nonce or a secret. */
export interface WebhookAuditEntry {
  at: string;
  reason: WebhookRefusalReason | "unauthenticated_flood";
  /** The credential id, only once it is known to exist (an unknown id is attacker-chosen). */
  credentialId?: string;
  /** For `unauthenticated_flood`: how many suppressed refusals this one entry stands for. */
  count?: number;
}

/** Where refusals are recorded. A failure to record never changes the verdict. */
export interface WebhookAudit {
  record(entry: WebhookAuditEntry): MaybePromise<void>;
}

/** Bounded ring of the most recent audit entries. */
export class InMemoryWebhookAudit implements WebhookAudit {
  readonly #entries: WebhookAuditEntry[] = [];

  constructor(readonly maxEntries = 256) {}

  record(entry: WebhookAuditEntry): void {
    this.#entries.push({ ...entry });
    if (this.#entries.length > this.maxEntries) this.#entries.splice(0, this.#entries.length - this.maxEntries);
  }

  entries(): readonly WebhookAuditEntry[] {
    return this.#entries.map((e) => ({ ...e }));
  }
}

/** Per-credential attempt limiter. Keys are digests of the presented id; it never retains the id itself. */
export class AttemptLimiter {
  readonly #entries = new Map<string, { attempts: number; expiresAt: number }>();

  constructor(
    readonly maxAttempts: number,
    readonly windowMs: number,
    readonly maxTracked = 1_024,
  ) {}

  retryAfterSeconds(presented: string | undefined, now: number): number | undefined {
    this.#prune(now);
    const entry = this.#entries.get(this.#key(presented));
    if (!entry || entry.attempts < this.maxAttempts) return undefined;
    return Math.max(1, Math.ceil((entry.expiresAt - now) / 1000));
  }

  record(presented: string | undefined, now: number): void {
    this.#prune(now);
    const key = this.#key(presented);
    const current = this.#entries.get(key);
    if (current) {
      current.attempts += 1;
      // Re-insert: Map order is the eviction order, most recently used last.
      this.#entries.delete(key);
      this.#entries.set(key, current);
      return;
    }
    while (this.#entries.size >= this.maxTracked) {
      const oldest = this.#entries.keys().next().value;
      if (oldest === undefined) break;
      this.#entries.delete(oldest);
    }
    this.#entries.set(key, { attempts: 1, expiresAt: now + this.windowMs });
  }

  #key(presented: string | undefined): string {
    return digest(presented ?? "<missing>");
  }

  #prune(now: number): void {
    for (const [key, entry] of this.#entries) if (entry.expiresAt <= now) this.#entries.delete(key);
  }
}

/**
 * A budget of refused attempts, with admission. Bind one instance to several
 * webhook sources to share it.
 *
 * A webhook asks `admit` before any work on a request that has not
 * authenticated yet, and calls `release` exactly once when that request is
 * done, whatever the outcome. `fail` counts one refusal. Requests still in
 * flight count against the budget, so a burst of concurrent requests cannot
 * all start a credential lookup before the first of them is refused.
 *
 * A consumer that refuses a request Telltale accepted (a malformed payload, a
 * forbidden start) calls `fail` too, so its refusals share the budget.
 */
export interface UnauthenticatedBudget {
  /** Room for one more request? `true` reserves it until `release`. `false`: refuse it without a lookup. */
  admit(now: number): boolean;
  /** Give back a reservation made by `admit`. */
  release(): void;
  /** Count one refused attempt. */
  fail(now: number): void;
}

/**
 * A global budget of refused attempts, independent of the presented
 * credential id: a rotating id gets a fresh per-credential bucket every
 * request, never a fresh budget. Once refusals plus requests in flight reach
 * the limit, every request is refused for the rest of the window without a
 * credential lookup, including a correctly signed one. That availability
 * trade is deliberate: verifying past the trip would bring back the
 * per-request lookup the budget exists to stop.
 */
export class FailureBudget implements UnauthenticatedBudget {
  #count = 0;
  #inflight = 0;
  #windowStart = Number.NEGATIVE_INFINITY;

  constructor(
    readonly maxFailures: number,
    readonly windowMs: number,
  ) {}

  /** Refusals counted in the current window. */
  failures(now: number): number {
    return now < this.#windowStart + this.windowMs ? this.#count : 0;
  }

  /** Requests admitted and not yet released. */
  get inflight(): number {
    return this.#inflight;
  }

  /** Whether the refusals of this window alone have spent the budget. */
  tripped(now: number): boolean {
    return this.failures(now) >= this.maxFailures;
  }

  admit(now: number): boolean {
    if (this.failures(now) + this.#inflight >= this.maxFailures) return false;
    this.#inflight += 1;
    return true;
  }

  release(): void {
    if (this.#inflight > 0) this.#inflight -= 1;
  }

  fail(now: number): void {
    if (now >= this.#windowStart + this.windowMs) {
      this.#windowStart = now;
      this.#count = 0;
    }
    this.#count += 1;
  }
}

/**
 * Batches refusals that arrive after the budget tripped into at most one
 * `unauthenticated_flood` audit entry per interval, so a flood cannot evict
 * earlier, more useful entries from a bounded audit. A timer flushes the
 * residual count on schedule; a stop flushes what is left.
 */
export class NoiseAggregator {
  #count = 0;
  #windowStart: number;
  #timer: unknown;

  constructor(
    private readonly clock: Clock,
    private readonly flush: (count: number) => void,
    readonly intervalMs = 60_000,
  ) {
    this.#windowStart = clock.now();
  }

  note(): void {
    this.#count += 1;
    const now = this.clock.now();
    if (now - this.#windowStart >= this.intervalMs) {
      this.#flushNow(now);
      return;
    }
    if (this.#timer === undefined) {
      this.#timer = this.clock.setTimer(
        () => {
          this.#timer = undefined;
          if (this.#count > 0) this.#flushNow(this.clock.now());
        },
        Math.max(1, this.intervalMs - (now - this.#windowStart)),
      );
    }
  }

  stop(): void {
    if (this.#count > 0) this.#flushNow(this.clock.now());
    if (this.#timer !== undefined) this.clock.clearTimer(this.#timer);
    this.#timer = undefined;
  }

  #flushNow(now: number): void {
    if (this.#timer !== undefined) {
      this.clock.clearTimer(this.#timer);
      this.#timer = undefined;
    }
    if (this.#count === 0) return;
    const count = this.#count;
    this.#count = 0;
    this.#windowStart = now;
    this.flush(count);
  }
}
