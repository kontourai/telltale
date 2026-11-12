import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import type { ReceivedRequest, ReceiveResult, SourceApi, SourceType } from "../source-type.js";
import { DeliveryError, SourceStoppedError } from "../source-type.js";
import { digest, isRecord, timingSafeEqualText } from "../util.js";
import {
  AttemptLimiter,
  FailureBudget,
  InMemoryReplayLedger,
  InMemoryWebhookAudit,
  MIN_WEBHOOK_SECRET_LENGTH,
  NoiseAggregator,
  type ReplayLedger,
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
 * 7. the replay claim, only after a valid signature;
 * 8. emit `received` with `{ credentialId, body, headers }`.
 *
 * Schemes:
 * - `signed-timestamp`: HMAC-SHA256 over `<timestamp>\n<nonce>\n<body>`, `sha256=<hex>`,
 *   a freshness window, replay keyed on (credential, timestamp, nonce).
 * - `signed-body`: HMAC-SHA256 over the body (GitHub's `X-Hub-Signature-256`),
 *   replay keyed on the delivery header for a retention period.
 * - `bearer`: `Authorization: Bearer <secret>`. No integrity over the body; replay
 *   protection only when a delivery header is configured.
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
    retentionHours: { type: "number", description: "how long a delivery id is remembered (default 168)" },
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
        : p.headers.delivery
          ? `delivery ids (${p.headers.delivery}) remembered ${p.retentionHours}h`
          : "NO replay protection (no delivery header)";
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
    const replay = api.bindings.replay ?? new InMemoryReplayLedger();
    const audit = api.bindings.audit ?? new InMemoryWebhookAudit();
    const limiter = new AttemptLimiter(p.perCredentialPerMinute, RATE_WINDOW_MS);
    const budget = api.bindings.budget ?? new FailureBudget(p.unauthenticatedPerMinute, RATE_WINDOW_MS);
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

    api.onReceive(async (request: ReceivedRequest): Promise<ReceiveResult> => {
      const now = api.clock.now();
      const header = headerReader(request.headers);
      const refuse = (reason: WebhookRefusalReason, credentialId?: string, extra: { retryAfterSeconds?: number } = {}) => {
        budget.fail(now);
        record(reason, credentialId);
        api.log.warn("webhook request refused", { reason });
        return refusal(reason, extra);
      };

      // 1. Global budget, before any lookup or audit write.
      if (budget.tripped(now)) {
        noise.note();
        return refusal("rate_limited");
      }

      // 2. Per-credential attempts. Every attempt counts, accepted or not.
      const presented = tokenHeader ? header(tokenHeader) : api.id;
      const retryAfter = limiter.retryAfterSeconds(presented, now);
      if (retryAfter !== undefined) return refuse("rate_limited", undefined, { retryAfterSeconds: retryAfter });
      limiter.record(presented, now);

      // 3. Credential, re-read now: revocation and the off switch apply to this request.
      const credentialId = presented && CREDENTIAL_ID.test(presented) ? presented : undefined;
      let lookup: WebhookLookup;
      try {
        lookup = await credentials.lookup(credentialId ?? "");
      } catch (error) {
        api.log.warn("webhook credentials unavailable", { detail: error instanceof Error ? error.message : "error" });
        return refuse("policy_unavailable", credentialId);
      }
      if (!isRecord(lookup) || lookup.enabled !== true) {
        return lookup?.enabled === false ? refuse("disabled", credentialId) : refuse("policy_unavailable", credentialId);
      }
      const credential: WebhookCredential | undefined = credentialId ? lookup.credential : undefined;
      if (!credential || credential.id !== credentialId) return refuse("unknown_token");
      if (credential.revokedAt !== undefined) return refuse("revoked_token", credential.id);
      if (typeof credential.secret !== "string" || credential.secret.length < MIN_WEBHOOK_SECRET_LENGTH) {
        api.log.warn(`webhook credential "${credential.id}" has a secret shorter than ${MIN_WEBHOOK_SECRET_LENGTH} characters; rotate it`);
        return refuse("policy_unavailable", credential.id);
      }
      api.secret(credential.secret);

      // 4. Every check that needs no body.
      let replayKey: string | undefined;
      let replayExpiresAt = 0;
      let deliveryId: string | undefined;
      let signedPrefix: Buffer | undefined;
      if (p.scheme === "signed-timestamp") {
        const timestamp = header(p.headers.timestamp!);
        const nonce = header(p.headers.nonce!);
        if (!timestamp || !TIMESTAMP.test(timestamp) || !nonce || !NONCE.test(nonce)) return refuse("malformed_request", credential.id);
        const signedAt = Number(timestamp) * 1000;
        const windowMs = p.windowSeconds * 1000;
        if (Math.abs(now - signedAt) > windowMs) return refuse("stale_timestamp", credential.id);
        signedPrefix = Buffer.from(`${timestamp}\n${nonce}\n`);
        // Persist only a digest: the nonce is caller input, not audit data.
        replayKey = digest(credential.id, timestamp, nonce);
        // Anchored to the signed time when it is ahead of receipt: a request
        // signed in the future stays fresh until signedAt + window, so the
        // key must live at least that long or a replay fits in the gap.
        replayExpiresAt = Math.max(now, signedAt) + windowMs;
      } else {
        if (p.headers.delivery) {
          const delivery = header(p.headers.delivery);
          if (!delivery || !DELIVERY.test(delivery)) return refuse("malformed_request", credential.id);
          deliveryId = delivery;
          replayKey = digest(credential.id, delivery);
          replayExpiresAt = now + p.retentionHours * 3_600_000;
        }
        if (p.scheme === "bearer") {
          const presentedToken = /^Bearer (.+)$/.exec(header(p.headers.signature!) ?? "")?.[1];
          if (!presentedToken || !timingSafeEqualText(presentedToken, credential.secret)) return refuse("invalid_signature", credential.id);
        }
      }

      // 5. The body, only now, bounded.
      const body = await readBody(request.body, p.maxBodyBytes);
      if (!body) return refuse("malformed_request", credential.id);

      // 6. The signature over the raw received bytes.
      if (p.scheme !== "bearer") {
        const signed = signedPrefix ? Buffer.concat([signedPrefix, body]) : body;
        if (!signatureMatches(credential.secret, signed, header(p.headers.signature!))) return refuse("invalid_signature", credential.id);
      }

      // 7. Replay, only after the caller proved it holds the secret.
      if (replayKey !== undefined) {
        let claim: "claimed" | "replayed";
        try {
          claim = await replay.claim(replayKey, replayExpiresAt, now);
        } catch (error) {
          api.log.warn("webhook replay ledger unavailable", { error: error instanceof Error ? error.name : "error" });
          return refuse("policy_unavailable", credential.id);
        }
        if (claim === "replayed") return refuse("replay", credential.id);
      }

      // 8. Report it.
      const payload = {
        credentialId: credential.id,
        body: parseBody(body),
        headers: Object.fromEntries(p.keepHeaders.flatMap((h) => (header(h) === undefined ? [] : [[h, header(h)!]]))),
      };
      const dedupKey = deliveryId
        ? `delivery:${digest(credential.id, deliveryId)}`
        : `request:${replayKey ?? digest(credential.id, randomUUID())}`;
      try {
        const event = await api.emit("received", payload, { dedupKey, ...(deliveryId ? { deliveryId } : {}) });
        return { accepted: true, status: 202, event };
      } catch (error) {
        if (error instanceof SourceStoppedError) return { accepted: false, status: 404, reason: "not_listening", retryable: true };
        if (error instanceof DeliveryError) {
          record("delivery_failed", credential.id);
          return refusal("delivery_failed");
        }
        throw error;
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
  const lower = new Map<string, string>();
  for (const [k, v] of Object.entries((headers ?? {}) as Record<string, string | string[] | undefined>)) {
    if (v === undefined) continue;
    // A repeated header is ambiguous for a credential; keep only an unambiguous single value.
    if (Array.isArray(v)) {
      if (v.length === 1) lower.set(k.toLowerCase(), v[0]!);
      continue;
    }
    lower.set(k.toLowerCase(), v);
  }
  return (name) => lower.get(name.toLowerCase());
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
