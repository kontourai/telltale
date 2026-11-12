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

/**
 * Remembers which signed requests were already accepted. `claim` is called
 * only after a valid signature, so an unauthenticated caller can never burn
 * or lock a key. It must be atomic per key. Throw when it cannot decide (a
 * corrupt or full ledger): the request is refused `policy_unavailable`, so
 * replay protection is never silently removed.
 */
export interface ReplayLedger {
  claim(key: string, expiresAt: number, now: number): MaybePromise<"claimed" | "replayed">;
}

export class ReplayLedgerFullError extends Error {
  constructor(max: number) {
    super(`replay ledger holds ${max} unexpired keys; refusing rather than evicting one`);
    this.name = "ReplayLedgerFullError";
  }
}

/**
 * In-memory replay ledger. At capacity it first drops expired keys; if every
 * key is still live it refuses the claim instead of evicting one, because
 * evicting a live key would reopen the replay window it exists to close.
 */
export class InMemoryReplayLedger implements ReplayLedger {
  readonly #keys = new Map<string, number>();

  constructor(readonly maxEntries = 10_000) {}

  claim(key: string, expiresAt: number, now: number): "claimed" | "replayed" {
    const existing = this.#keys.get(key);
    if (existing !== undefined && existing > now) return "replayed";
    if (existing !== undefined) this.#keys.delete(key);
    if (this.#keys.size >= this.maxEntries) {
      for (const [k, at] of this.#keys) if (at <= now) this.#keys.delete(k);
      if (this.#keys.size >= this.maxEntries) throw new ReplayLedgerFullError(this.maxEntries);
    }
    this.#keys.set(key, expiresAt);
    return "claimed";
  }

  get size(): number {
    return this.#keys.size;
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

/** A budget of refused attempts. Bind one instance to several webhook sources to share it. */
export interface UnauthenticatedBudget {
  tripped(now: number): boolean;
  fail(now: number): void;
}

/**
 * A global budget of refused attempts, independent of the presented
 * credential id: a rotating id gets a fresh per-credential bucket every
 * request, never a fresh budget. Once it trips, every request is refused for
 * the rest of the window without a credential lookup, including a correctly
 * signed one. That availability trade is deliberate: verifying past the trip
 * would bring back the per-request lookup the budget exists to stop.
 */
export class FailureBudget implements UnauthenticatedBudget {
  #count = 0;
  #windowStart = Number.NEGATIVE_INFINITY;

  constructor(
    readonly maxFailures: number,
    readonly windowMs: number,
  ) {}

  tripped(now: number): boolean {
    return this.#count >= this.maxFailures && now < this.#windowStart + this.windowMs;
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
