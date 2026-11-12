import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import type { ReceivedRequest, ReceiveResult, SourceApi, SourceType } from "../source-type.js";
import { DeliveryError, SourceStoppedError } from "../source-type.js";
import type { MaybePromise } from "../types.js";
import { digest, isRecord, timingSafeEqualText } from "../util.js";
import {
  AttemptLimiter,
  FailureBudget,
  InMemoryReplayLedger,
  InMemoryWebhookAudit,
  MIN_WEBHOOK_SECRET_LENGTH,
  NoiseAggregator,
  type ReplayLedger,
  type ReplayReservation,
  type WebhookAudit,
  type WebhookAuditEntry,
  type WebhookCredential,
  type WebhookCredentials,
  type WebhookLookup,
  type UnauthenticatedBudget,
  type WebhookRefusalReason,
} from "./webhook-guards.js";

/**
 * A webhook source: transport-agnostic verification of requests the consumer
 * received on its own HTTP server.
 *
 * The consumer passes the raw request to `host.receive(id, request)` and
 * answers with the returned status. Telltale verifies, in this order, and
 * refuses at the first failure:
 *
 * 1. the global unauthenticated budget (once tripped: no lookup, no per-request audit);
 * 2. the per-credential attempt limit;
 * 3. the credential: lookup (re-read per request), off switch, unknown, revoked, secret floor;
 * 4. header-only checks (timestamp and nonce shape, freshness, bearer token);
 * 5. only now the body, bounded;
 * 6. the HMAC over the raw bytes, compared in constant time after a length check;
 * 7. the replay reservation, only after a valid signature, keyed only on
 *    signed bytes; committed once delivered, released if delivery failed;
 * 8. emit `received` with `{ credentialId, body, headers }`.
 *
 * Schemes:
 * - `signed-timestamp`: HMAC-SHA256 over `<timestamp>\n<nonce>\n<body>`, `sha256=<hex>`,
 *   a freshness window, replay keyed on (credential, timestamp, nonce).
 * - `signed-body`: HMAC-SHA256 over the body (GitHub's `X-Hub-Signature-256`),
 *   replay keyed on a digest of the signed body for a retention period. The
 *   unsigned delivery header is carried as `deliveryId`, never as identity.
 * - `bearer`: `Authorization: Bearer <secret>`. No integrity over the body, and
 *   no replay protection: a captured request carries the credential. A
 *   delivery header, when configured, folds duplicate deliveries.
 */

export type WebhookScheme = "signed-timestamp" | "signed-body" | "bearer";

export interface WebhookBindings {
  /** Named credentials, looked up per request. Required unless the `secret` option is set. */
  credentials?: WebhookCredentials;
  /** Default: an in-memory ledger of 10,000 keys that refuses when full of live keys. */
  replay?: ReplayLedger;
  /** Default: an in-memory ring of 256 entries. */
  audit?: WebhookAudit;
  /**
   * Default: a budget of this source's own (`unauthenticatedPerMinute`). Bind
   * one `FailureBudget` to several webhook sources so a flood against one
   * route trips them all.
   */
  budget?: UnauthenticatedBudget;
  [key: string]: unknown;
}

export interface WebhookHeaderNames {
  token?: string;
  timestamp?: string;
  nonce?: string;
  signature?: string;
  delivery?: string;
}

const DEFAULT_HEADERS: Record<WebhookScheme, WebhookHeaderNames> = {
  "signed-timestamp": {
    timestamp: "x-telltale-timestamp",
    nonce: "x-telltale-nonce",
    signature: "x-telltale-signature",
  },
  "signed-body": { signature: "x-hub-signature-256", delivery: "x-github-delivery" },
  bearer: { signature: "authorization" },
};
/** signed-timestamp with named credentials: where the credential id is read when no token header is named. */
const DEFAULT_TOKEN_HEADER = "x-telltale-token";

/** Headers carried into the event. Credentials, signatures and nonces never are. */
const DEFAULT_KEPT_HEADERS = ["content-type", "user-agent", "x-github-event", "x-github-delivery", "x-request-id"];
const NEVER_KEPT = /^(authorization|proxy-authorization|cookie|set-cookie)$|signature|token|nonce|secret/i;

const DEFAULT_WINDOW_SECONDS = 300;
const DEFAULT_RETENTION_HOURS = 168;
const DEFAULT_MAX_BODY_BYTES = 256 * 1024;
const MAX_MAX_BODY_BYTES = 10 * 1024 * 1024;
const RATE_WINDOW_MS = 60_000;
/** The shortest lease a reservation is extended by while its delivery runs. */
const MIN_LEASE_MS = 60_000;
const DEFAULT_PER_CREDENTIAL_PER_MINUTE = 60;
const DEFAULT_UNAUTHENTICATED_PER_MINUTE = 300;

const CREDENTIAL_ID = /^[A-Za-z0-9_.-]{1,128}$/;
const NONCE = /^[A-Za-z0-9_-]{16,128}$/;
const TIMESTAMP = /^\d{10}$/;
const DELIVERY = /^[A-Za-z0-9_.:-]{1,128}$/;
const HEX_SIGNATURE = /^sha256=([a-f0-9]{64})$/i;
const HEADER_NAME = /^[A-Za-z0-9-]{1,64}$/;

const STATUS: Record<WebhookRefusalReason, 400 | 401 | 403 | 429 | 503> = {
  disabled: 403,
  unknown_token: 401,
  revoked_token: 403,
  malformed_request: 400,
  stale_timestamp: 403,
  invalid_signature: 403,
  replay: 403,
  rate_limited: 429,
  policy_unavailable: 403,
  delivery_failed: 503,
};

interface Planned {
  scheme: WebhookScheme;
  secret?: string;
  headers: WebhookHeaderNames;
  windowSeconds: number;
  retentionHours: number;
  maxBodyBytes: number;
  keepHeaders: string[];
  perCredentialPerMinute: number;
  unauthenticatedPerMinute: number;
}

function planned(o: Readonly<Record<string, unknown>>): Planned {
  const scheme = (o.scheme ?? "signed-timestamp") as WebhookScheme;
  if (!(scheme in DEFAULT_HEADERS)) throw new Error(`webhook: "scheme" must be signed-timestamp, signed-body or bearer`);
  const given = (o.headers ?? {}) as Record<string, unknown>;
  for (const [k, v] of Object.entries(given)) {
    if (!["token", "timestamp", "nonce", "signature", "delivery"].includes(k)) throw new Error(`webhook: unknown header role "${k}"`);
    if (typeof v !== "string" || !HEADER_NAME.test(v)) throw new Error(`webhook: header "${k}" must be a header name`);
  }
  const headers = { ...DEFAULT_HEADERS[scheme], ...(given as WebhookHeaderNames) };
  const int = (key: string, fallback: number, min: number, max: number) => {
    const v = o[key] ?? fallback;
    if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) throw new Error(`webhook: "${key}" must be an integer from ${min} to ${max}`);
    return v;
  };
  if (o.secret !== undefined && (o.secret as string).length < MIN_WEBHOOK_SECRET_LENGTH) {
    throw new Error(`webhook: "secret" must be at least ${MIN_WEBHOOK_SECRET_LENGTH} characters`);
  }
  const keepHeaders = ((o.keepHeaders as string[] | undefined) ?? []).map((h) => h.toLowerCase());
  for (const h of keepHeaders) {
    if (!HEADER_NAME.test(h) || NEVER_KEPT.test(h)) throw new Error(`webhook: header "${h}" cannot be kept: it may carry a credential`);
  }
  return {
    scheme,
    secret: o.secret as string | undefined,
    headers,
    windowSeconds: int("windowSeconds", DEFAULT_WINDOW_SECONDS, 30, 3600),
    retentionHours: int("retentionHours", DEFAULT_RETENTION_HOURS, 1, 24 * 30),
    maxBodyBytes: int("maxBodyBytes", DEFAULT_MAX_BODY_BYTES, 1, MAX_MAX_BODY_BYTES),
    keepHeaders: [...new Set([...DEFAULT_KEPT_HEADERS, ...keepHeaders])],
    perCredentialPerMinute: int("perCredentialPerMinute", DEFAULT_PER_CREDENTIAL_PER_MINUTE, 1, 100_000),
    unauthenticatedPerMinute: int("unauthenticatedPerMinute", DEFAULT_UNAUTHENTICATED_PER_MINUTE, 1, 1_000_000),
  };
}

export const webhookSourceType: SourceType<WebhookBindings> = {
  summary:
    "a web address other services call: verifies HMAC or bearer credentials, replay and rate limits on a request the consumer's own HTTP server received, then reports it",
  options: {
    scheme: { type: "string", description: "signed-timestamp (default), signed-body (GitHub style) or bearer" },
    secret: {
      type: "string",
      secret: true,
      description: `one shared secret of at least ${MIN_WEBHOOK_SECRET_LENGTH} characters, when no named credentials are bound`,
    },
    headers: { type: "object", description: "header names: token, timestamp, nonce, signature, delivery" },
    windowSeconds: { type: "number", description: "signed-timestamp: how far a timestamp may be from now, and how long a nonce is remembered (default 300)" },
    retentionHours: { type: "number", description: "signed-body and bearer: how long a signed body or delivery id is remembered (default 168)" },
    maxBodyBytes: { type: "number", description: "largest body read (default 262144)" },
    keepHeaders: { type: "string[]", description: "extra non-credential headers carried into the event" },
    perCredentialPerMinute: { type: "number", description: "attempts per presented credential per minute (default 60)" },
    unauthenticatedPerMinute: { type: "number", description: "refused attempts per minute before every request is refused for the rest of the minute (default 300)" },
  },
  plan(o) {
    const p = planned(o);
    const replay =
      p.scheme === "signed-timestamp"
        ? `nonces remembered ${p.windowSeconds}s`
        : p.scheme === "signed-body"
          ? `signed bodies remembered ${p.retentionHours}h (a byte-identical body is a replay)`
          : p.headers.delivery
            ? `NO replay protection (bearer); duplicate delivery ids (${p.headers.delivery}) folded for ${p.retentionHours}h`
            : "NO replay protection (bearer, no delivery header)";
    return {
      options: { ...o, scheme: p.scheme },
      does: [
        `verify ${p.scheme} requests the consumer receives${p.secret ? " with one shared secret" : " against named credentials looked up per request"}; ${replay}`,
        `refuse more than ${p.perCredentialPerMinute} attempts a minute per credential, and every request for the rest of a minute with more than ${p.unauthenticatedPerMinute} refusals`,
        ...(p.scheme === "bearer" ? ["accept the body without integrity protection: anyone holding the secret can send any body"] : []),
      ],
      opens: true,
    };
  },
  start(api: SourceApi<WebhookBindings>) {
    const p = planned(api.options);
    const credentials: WebhookCredentials | undefined =
      api.bindings.credentials ?? (p.secret ? staticCredentials(api.id, p.secret) : undefined);
    if (!credentials) throw new Error(`webhook ${api.id}: needs a "secret" option or a "credentials" binding`);
    if (api.bindings.credentials && p.secret) throw new Error(`webhook ${api.id}: give a "secret" option or a "credentials" binding, not both`);
    // Without a token header the credential id is the source id: one secret per source (GitHub cannot send a custom header).
    const tokenHeader =
      p.headers.token ?? (api.bindings.credentials && p.scheme === "signed-timestamp" ? DEFAULT_TOKEN_HEADER : undefined);
    // Kept with the registration, not this start: an unsubscribe and a new
    // subscriber must not hand a replayed request a fresh ledger or reset a limit.
    const replay = api.bindings.replay ?? api.keep("replay", () => new InMemoryReplayLedger());
    const audit = api.bindings.audit ?? api.keep("audit", () => new InMemoryWebhookAudit());
    const limiter = api.keep("limiter", () => new AttemptLimiter(p.perCredentialPerMinute, RATE_WINDOW_MS));
    const budget = api.bindings.budget ?? api.keep("budget", () => new FailureBudget(p.unauthenticatedPerMinute, RATE_WINDOW_MS));
    const record = (reason: WebhookAuditEntry["reason"], credentialId?: string, count?: number) => {
      void Promise.resolve()
        .then(() =>
          audit.record({
            at: new Date(api.clock.now()).toISOString(),
            reason,
            ...(credentialId ? { credentialId } : {}),
            ...(count !== undefined ? { count } : {}),
          }),
        )
        .catch(() => {
          // A failing audit store must not become a second refusal oracle.
        });
    };
    const noise = new NoiseAggregator(api.clock, (count) => record("unauthenticated_flood", undefined, count));
    api.onStop(() => noise.stop());

    // Every wait on something outside Telltale before delivery (the credential
    // store, the body, the ledger) ends when the source stops, so a stop never
    // waits on a reader that does not settle, and its admission is returned.
    const untilStopped = <T>(work: () => MaybePromise<T>): Promise<T> =>
      new Promise<T>((resolve, reject) => {
        if (api.signal.aborted) return reject(new SourceStoppedError(api.id));
        const onAbort = () => reject(new SourceStoppedError(api.id));
        api.signal.addEventListener("abort", onAbort, { once: true });
        Promise.resolve()
          .then(work)
          .then(resolve, reject)
          .finally(() => api.signal.removeEventListener("abort", onAbort));
      });

    const verify = async (request: ReceivedRequest, authenticated: () => void): Promise<ReceiveResult> => {
      const now = api.clock.now();
      const header = headerReader(request.headers);
      const refuse = (reason: WebhookRefusalReason, credentialId?: string, extra: { retryAfterSeconds?: number } = {}) => {
        budget.fail(api.clock.now());
        record(reason, credentialId);
        api.log.warn("webhook request refused", { reason });
        return refusal(reason, extra);
      };

      // 2. Per-credential attempts. Every attempt counts, accepted or not.
      const presented = tokenHeader ? header(tokenHeader) : api.id;
      const retryAfter = limiter.retryAfterSeconds(presented, now);
      if (retryAfter !== undefined) return refuse("rate_limited", undefined, { retryAfterSeconds: retryAfter });
      limiter.record(presented, now);

      // 3. Credential, re-read now: revocation and the off switch apply to this request.
      const credentialId = presented && CREDENTIAL_ID.test(presented) ? presented : undefined;
      let credential: { id: string; secret: unknown; revoked: boolean } | undefined;
      try {
        const lookup: WebhookLookup = await untilStopped(() => credentials.lookup(credentialId ?? ""));
        if (!isRecord(lookup) || lookup.enabled !== true) {
          return lookup?.enabled === false ? refuse("disabled", credentialId) : refuse("policy_unavailable", credentialId);
        }
        // One read of each field, before anything else is awaited: the store's
        // object may change under us (a rotation), and every later check and
        // the signature must use the secret that was registered for redaction.
        const found: WebhookCredential | undefined = credentialId ? lookup.credential : undefined;
        if (isRecord(found)) credential = { id: found.id, secret: found.secret, revoked: found.revokedAt !== undefined };
      } catch (error) {
        if (error instanceof SourceStoppedError) throw error;
        // Never the exception text: a store's message may quote a secret or a path.
        api.log.warn("webhook credentials unavailable", { code: "credential_lookup_failed" });
        return refuse("policy_unavailable", credentialId);
      }
      if (!credential || credential.id !== credentialId) return refuse("unknown_token");
      if (credential.revoked) return refuse("revoked_token", credential.id);
      const secret = credential.secret;
      if (typeof secret !== "string" || secret.length < MIN_WEBHOOK_SECRET_LENGTH) {
        api.log.warn(`webhook credential "${credential.id}" has a secret shorter than ${MIN_WEBHOOK_SECRET_LENGTH} characters; rotate it`);
        return refuse("policy_unavailable", credential.id);
      }
      api.secret(secret);

      // 4. Every check that needs no body.
      let deliveryId: string | undefined;
      let signedPrefix: Buffer | undefined;
      let signedAt = 0;
      let timestamp: string | undefined;
      let nonce: string | undefined;
      const windowMs = p.windowSeconds * 1000;
      // Inclusive, and the replay key below lives exactly as long.
      const fresh = (at: number) => Math.abs(at - signedAt) <= windowMs;
      if (p.scheme === "signed-timestamp") {
        timestamp = header(p.headers.timestamp!);
        nonce = header(p.headers.nonce!);
        if (!timestamp || !TIMESTAMP.test(timestamp) || !nonce || !NONCE.test(nonce)) return refuse("malformed_request", credential.id);
        signedAt = Number(timestamp) * 1000;
        if (!fresh(now)) return refuse("stale_timestamp", credential.id);
        signedPrefix = Buffer.from(`${timestamp}\n${nonce}\n`);
      } else {
        if (p.headers.delivery) {
          // Transport metadata only. It is not signed, so it never identifies a request for replay.
          const delivery = header(p.headers.delivery);
          if (!delivery || !DELIVERY.test(delivery)) return refuse("malformed_request", credential.id);
          deliveryId = delivery;
        }
        if (p.scheme === "bearer") {
          const presentedToken = /^Bearer (.+)$/.exec(header(p.headers.signature!) ?? "")?.[1];
          if (!presentedToken || !timingSafeEqualText(presentedToken, secret)) return refuse("invalid_signature", credential.id);
        }
      }

      // 5. The body, only now, bounded.
      const body = await untilStopped(() => readBody(request.body, p.maxBodyBytes));
      if (!body) return refuse("malformed_request", credential.id);
      const received = api.clock.now();
      // A body that took longer than the window to arrive is stale by now.
      if (p.scheme === "signed-timestamp" && !fresh(received)) return refuse("stale_timestamp", credential.id);

      // 6. The signature over the raw received bytes.
      if (p.scheme !== "bearer") {
        const signed = signedPrefix ? Buffer.concat([signedPrefix, body]) : body;
        if (!signatureMatches(secret, signed, header(p.headers.signature!))) return refuse("invalid_signature", credential.id);
      }
      authenticated();

      // 7. Replay, keyed only on what the credential authenticated, and only now.
      //    signed-timestamp: (timestamp, nonce), both signed; kept until the
      //      first instant the request is stale (freshness is inclusive).
      //    signed-body: the signed body itself; GitHub's redelivery resends the
      //      same bytes, so it is the same key.
      //    bearer: nothing is signed and a captured request carries the
      //      credential, so the delivery header only folds duplicates.
      let replayKey: string | undefined;
      let expiresAt = 0;
      if (p.scheme === "signed-timestamp") {
        replayKey = digest(credential.id, timestamp!, nonce!);
        expiresAt = signedAt + windowMs + 1;
      } else if (p.scheme === "signed-body") {
        replayKey = digest(credential.id, "signed-body", createHash("sha256").update(body).digest("hex"));
        expiresAt = received + p.retentionHours * 3_600_000;
      } else if (deliveryId) {
        replayKey = digest(credential.id, "bearer-delivery", deliveryId);
        expiresAt = received + p.retentionHours * 3_600_000;
      }
      let token: string | undefined;
      if (replayKey !== undefined) {
        const key = replayKey;
        let reservation: ReplayReservation;
        const asked = Promise.resolve().then(() => replay.reserve(key, expiresAt, received));
        try {
          reservation = await untilStopped(() => asked);
        } catch (error) {
          if (error instanceof SourceStoppedError) {
            // Stopped while the ledger was answering: give back a reservation that still arrives.
            void asked
              .then((late) =>
                isRecord(late) && late.outcome === "reserved" && typeof late.token === "string"
                  ? replay.release(key, late.token, api.clock.now())
                  : undefined,
              )
              .catch(() => {});
            throw error;
          }
          api.log.warn("webhook replay ledger unavailable", { code: "replay_reserve_failed" });
          return refuse("policy_unavailable", credential.id);
        }
        if (!isRecord(reservation) || (reservation.outcome === "reserved" ? typeof reservation.token !== "string" : reservation.outcome !== "replayed")) {
          api.log.warn("webhook replay ledger unavailable", { code: "replay_reserve_malformed" });
          return refuse("policy_unavailable", credential.id);
        }
        if (reservation.outcome === "replayed") return refuse("replay", credential.id);
        token = reservation.token;
      }
      const settle = async (outcome: "commit" | "release") => {
        if (replayKey === undefined || token === undefined) return;
        try {
          const owned =
            outcome === "commit"
              ? await replay.commit(replayKey, token, api.clock.now())
              : await replay.release(replayKey, token, api.clock.now());
          // The token no longer owns the key: nothing was changed, and a newer owner is untouched.
          if (owned !== true) api.log.warn("webhook replay reservation was not ours", { code: `replay_${outcome}_not_owned` });
        } catch {
          // A failed commit keeps the reservation (still refusing replays); a failed release only delays a retry.
          api.log.warn("webhook replay ledger unavailable", { code: `replay_${outcome}_failed` });
        }
      };
      // While delivery runs, keep the reservation alive, so a subscriber slower
      // than the key's lifetime never lets an identical request reserve it.
      let delivering = true;
      let renewal: unknown;
      const lifetime = Math.max(expiresAt - received, MIN_LEASE_MS);
      const renewIn = (until: number) => {
        if (!delivering || replayKey === undefined || token === undefined) return;
        renewal = api.clock.setTimer(renew, Math.max(1, (until - api.clock.now()) / 2));
      };
      const renew = () => {
        renewal = undefined;
        const now = api.clock.now();
        const until = now + lifetime;
        void Promise.resolve()
          .then(() => replay.extend(replayKey!, token!, until, now))
          .then(
            (owned) => {
              if (owned === true) renewIn(until);
              else api.log.warn("webhook replay reservation lapsed during delivery", { code: "replay_extend_not_owned" });
            },
            () => api.log.warn("webhook replay ledger unavailable", { code: "replay_extend_failed" }),
          );
      };
      renewIn(expiresAt);
      const stopRenewing = () => {
        delivering = false;
        if (renewal !== undefined) api.clock.clearTimer(renewal);
        renewal = undefined;
      };

      // 8. Report it.
      const payload = {
        credentialId: credential.id,
        body: parseBody(body),
        headers: Object.fromEntries(p.keepHeaders.flatMap((h) => (header(h) === undefined ? [] : [[h, header(h)!]]))),
      };
      const dedupKey =
        replayKey === undefined
          ? `request:${digest(credential.id, randomUUID())}`
          : `${p.scheme === "bearer" ? "delivery" : "request"}:${replayKey}`;
      try {
        const event = await api.emit("received", payload, { dedupKey, ...(deliveryId ? { deliveryId } : {}) });
        stopRenewing();
        await settle("commit");
        return { accepted: true, status: 202, event };
      } catch (error) {
        stopRenewing();
        // Not delivered: free the key, so the same request, sent again, is delivered.
        await settle("release");
        if (error instanceof SourceStoppedError) return { accepted: false, status: 404, reason: "not_listening", retryable: true };
        if (error instanceof DeliveryError) {
          record("delivery_failed", credential.id);
          return refusal("delivery_failed");
        }
        throw error;
      }
    };

    api.onReceive(async (request: ReceivedRequest): Promise<ReceiveResult> => {
      // 1. Global budget, before any lookup or audit write. Requests still
      //    authenticating count against it, so a concurrent burst cannot
      //    start more lookups than the budget allows.
      if (!budget.admit(api.clock.now())) {
        noise.note();
        return refusal("rate_limited");
      }
      let admitted = true;
      const done = () => {
        if (!admitted) return;
        admitted = false;
        budget.release();
      };
      try {
        return await verify(request, done);
      } catch (error) {
        if (error instanceof SourceStoppedError) return { accepted: false, status: 404, reason: "not_listening", retryable: true };
        throw error;
      } finally {
        done();
      }
    });
  },
};

function refusal(reason: WebhookRefusalReason, extra: { retryAfterSeconds?: number } = {}): ReceiveResult {
  return {
    accepted: false,
    status: STATUS[reason],
    reason,
    retryable: reason === "rate_limited" || reason === "delivery_failed",
    ...extra,
  };
}

function staticCredentials(id: string, secret: string): WebhookCredentials {
  return { lookup: (presented) => ({ enabled: true, credential: presented === id ? { id, secret } : undefined }) };
}

/** The one signature comparison: format first, then equal lengths, then Node's constant-time primitive. */
function signatureMatches(secret: string, signed: Buffer, signature: string | undefined): boolean {
  const match = signature ? HEX_SIGNATURE.exec(signature) : null;
  if (!match) return false;
  const expected = createHmac("sha256", secret).update(signed).digest();
  const received = Buffer.from(match[1]!, "hex");
  return received.length === expected.length && timingSafeEqual(received, expected);
}

function headerReader(headers: ReceivedRequest["headers"]): (name: string) => string | undefined {
  if (headers && typeof (headers as { get?: unknown }).get === "function") {
    const h = headers as { get(name: string): string | null };
    return (name) => h.get(name) ?? undefined;
  }
  // A repeated header is ambiguous for a credential: two spellings of one name,
  // or an array of several values, read as absent. Never first-wins or last-wins.
  const lower = new Map<string, string | null>();
  for (const [k, v] of Object.entries((headers ?? {}) as Record<string, string | string[] | undefined>)) {
    if (v === undefined) continue;
    const name = k.toLowerCase();
    const value = Array.isArray(v) ? (v.length === 1 ? v[0]! : null) : v;
    lower.set(name, lower.has(name) ? null : value);
  }
  return (name) => lower.get(name.toLowerCase()) ?? undefined;
}

async function readBody(body: ReceivedRequest["body"], max: number): Promise<Buffer | null> {
  let value: Uint8Array | string | null | undefined;
  try {
    value = typeof body === "function" ? await body() : body;
  } catch {
    return null;
  }
  if (value === null || value === undefined) return null;
  const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  return bytes.length > max ? null : bytes;
}

/** JSON when it is valid UTF-8 JSON, else `{ text }`. Parsed only after the signature held. */
function parseBody(bytes: Buffer): unknown {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return { bytes: bytes.length };
  }
  try {
    return JSON.parse(text);
  } catch {
    return { text };
  }
}
