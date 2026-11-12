# Adopting Telltale in Station

Station's Automations intake moves onto Telltale first: the inbound webhook,
then the GitHub poll. Station depends on a published, pinned
`@kontourai/telltale` and uses only its exported API. Station keeps its HTTP
routes, rules, grants, ledger, episodes, actions and receipts; Telltale
verifies and reports.

This guide maps each Station piece to its Telltale counterpart and lists what
changes in behavior. It describes the intended migration; none of it is
implemented in Station yet.

## What stays in Station

| Station piece | Why it stays |
| --- | --- |
| The Hono route and its response bodies | Telltale is transport-agnostic. |
| Managed-policy refusal (`webhookAutomationsAllowedByManagedPolicy`) | Product policy, checked before Telltale is called. |
| `forbidden_start` grant check, turn start, ephemeral session, `webhookTokenId` metadata | Authority and action. |
| The `accepted` audit entry with the conversation id | A receipt of what Station did. |
| `station.webhooks.inbound_requests` metrics | Station's observability, fed from `ReceiveResult.reason`. |
| Automation rules, matching, episodes, the SQLite ledger and its dedupe | Rules, authority and receipts. |

## Inbound webhook

### Setup

One host per Station process; one webhook source for `/inbound`:

```ts
import { TelltaleHost, FailureBudget } from "@kontourai/telltale";

const host = new TelltaleHost({ logger });
// Shared by Telltale (admission and its own refusals) and by the route (refusals after acceptance).
const budget = new FailureBudget(INBOUND_WEBHOOK_UNAUTHENTICATED_BUDGET_MAX_ATTEMPTS, 60_000);
host.add({
  id: "inbound",
  type: "webhook",
  options: {
    scheme: "signed-timestamp",
    // x-station-webhook-{token,timestamp,nonce,signature}, as today.
    headers: Object.fromEntries(
      ["token", "timestamp", "nonce", "signature"].map((role) => [role, `x-station-webhook-${role}`]),
    ),
  },
  // Untrusted: the body is written by an outside caller.
  bindings: {
    credentials: {
      // Re-read per request, as InboundWebhookConfigurationStore.read() is today.
      lookup(id) {
        const config = configurationStore.read(); // throws -> policy_unavailable
        if (config.enabled !== true) return { enabled: false };
        const token = config.tokens?.find((t) => t.id === id);
        return { enabled: true, credential: token && { id: token.id, secret: token.secret, revokedAt: token.revokedAt } };
      },
    },
    // InboundWebhookReplayStore grows a state and an owner token per entry,
    // each method one read-modify-write of the file under its lock:
    // - reserve: today's claim, writing { state: "reserved", token: randomUUID() }
    //   and returning { outcome: "reserved", token } (or { outcome: "replayed" });
    // - extend / commit / release: act only when the entry's token matches,
    //   and return whether they did (extend moves expiresAt later, commit sets
    //   "delivered", release deletes a "reserved" entry).
    // Its `expiresAt > now` liveness already matches the expiresAt Telltale
    // passes (the first instant the key is free again).
    replay: {
      reserve: (key, expiresAt, now) => replayStore.reserve(key, expiresAt, now),
      extend: (key, token, expiresAt, now) => replayStore.extend(key, token, expiresAt, now),
      commit: (key, token) => replayStore.commit(key, token),
      release: (key, token) => replayStore.release(key, token),
    },
    audit: { record: (e) => auditStore.record(e.reason, e.credentialId) /* or recordAggregatedNoise(e.count) */ },
    budget, // shared with a future /api/webhooks/github/:sourceId route
  },
});
// Subscribe once at startup: an unsubscribed source accepts nothing (404 not_listening).
await host.subscribe("inbound", () => {});
```

### The payload validator

Telltale hands over the body already decoded: strict UTF-8, then
`JSON.parse`. Station's `parsePayload(bytes)` decodes and checks the shape in
one function, so it cannot take `event.payload.body`. Split it; the route
uses the shape half:

```ts
// Unchanged callers that still hold bytes keep this.
function parsePayload(bytes: Uint8Array): WebhookPayload | null {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return null;
  }
  return payloadFrom(value);
}

// The shape check, on a decoded value: what the Telltale route calls.
function payloadFrom(value: unknown): WebhookPayload | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const candidate = value as Record<string, unknown>;
  if (
    typeof candidate.agent !== "string" ||
    !candidate.agent.trim() ||
    typeof candidate.message !== "string" ||
    !candidate.message.trim() ||
    candidate.message.length > 200_000 ||
    (candidate.project !== undefined && (typeof candidate.project !== "string" || !candidate.project.trim()))
  ) {
    return null;
  }
  return {
    agent: candidate.agent.trim(),
    message: candidate.message,
    ...(typeof candidate.project === "string" ? { project: candidate.project.trim() } : {}),
  };
}
```

A body that is not JSON reaches Station as `{ text }` (or `{ bytes }` when it
is not UTF-8), which `payloadFrom` refuses like any other wrong shape.

### The route

Telltale charges the budget and writes the audit entry for every refusal it
makes. A refusal Station makes after Telltale accepted (a malformed payload,
an invalid target, a forbidden start) must do the same by hand, exactly as the
route does today, and `accepted` is recorded only once the turn started:

```ts
app.post("/inbound", async (c) => {
  if (!webhookAutomationsAllowedByManagedPolicy()) { /* unchanged */ }
  const result = await host.receive("inbound", {
    headers: c.req.raw.headers,
    body: () => readBoundedBody(c.req.raw), // called only after header checks pass
  });
  if (!result.accepted) {
    // Budget and audit were already charged by Telltale; only the metric is Station's.
    recordOutcome(result.reason);
    if (result.retryAfterSeconds) c.header("Retry-After", String(result.retryAfterSeconds));
    return c.json({ success: false, code: result.reason, retryable: result.retryable }, result.status);
  }
  const { credentialId, body } = result.event.payload;
  // A refusal after acceptance: the same budget, audit and outcome as today.
  const refuse = (reason: "malformed_request" | "forbidden_start", status: 400 | 403, tokenId?: string) => {
    budget.fail(Date.now());
    auditStore.record(reason, tokenId);
    recordOutcome(reason);
    options.logger.warn("Inbound webhook refused", { reason });
    return c.json({ success: false, code: reason, retryable: false }, status);
  };
  const payload = payloadFrom(body);
  // Today's authorization.recordFailure('malformed_request') records no token id; keep that.
  if (!payload) return refuse("malformed_request", 400);
  let target: ExecutionTarget;
  try {
    target = targetFor(payload);
  } catch {
    return refuse("malformed_request", 400);
  }
  if (!grantAllows(tokenGrants(credentialId), payload.agent, payload.project)) {
    return refuse("forbidden_start", 403, credentialId);
  }
  // ... startTurn, then recordSuccess(credentialId, conversationId) and
  // recordOutcome("accepted"), 202; the turn_start_failed and managed-ceiling
  // branches are unchanged.
});
```

`tokenGrants(credentialId)` reads the token's `starts` from the configuration
store, as the authorization service does today.

### Behavior changes to expect

- **A forbidden start consumes its nonce.** Telltale commits the nonce once
  the event is delivered, before Station's grant check. A caller retrying the
  same signed request after fixing the grant must re-sign. Stricter; no
  current Station test retries a forbidden nonce.
- **A turn that fails to start still consumes its nonce,** as today: the turn
  starts in the route, after Telltale delivered. To make `turn_start_failed`
  retryable with the same signed request, start the turn inside the
  subscriber and throw on failure; Telltale then releases the reservation
  and answers `503 delivery_failed`.
- **Malformed JSON with a bad signature is now `invalid_signature`.** Station
  parsed before verifying; Telltale verifies first. A malformed body with a
  valid signature is still Station's `malformed_request`, from `payloadFrom`.
- **A webhook secret quoted in a message is redacted.** The event payload is
  redacted, so a message that contains a token's secret reaches the turn as
  `[redacted]`.
- **The replay store should refuse when full.** `InboundWebhookReplayStore`
  keeps the newest 10,000 keys, dropping live ones. Make `reserve` throw at
  capacity (Telltale answers `policy_unavailable`) instead.
- **The replay store must be atomic per key.** Each method reads, decides and
  writes under one lock; a read, an `await` and a write would let two copies
  of a request both reserve. `extend`, `commit` and `release` compare the
  owner token in that same step, so a holder whose reservation lapsed cannot
  touch a newer one.
- **Every replay store call must settle.** A stop waits for a pending
  `commit` or `release`; give the adapter a timeout. A store shared by several
  Station processes would also need fencing, which Telltale does not provide;
  within one process Telltale never delivers two identical copies at once.
- **Bound the body read.** `readBoundedBody` should also stop after a
  deadline: a request holds room in the shared budget until it authenticates,
  so a sender that never finishes its body would otherwise hold it.
- **One boundary for freshness and replay.** Today a replay at exactly
  `timestamp + 5 min` is fresh while its key has expired. Through Telltale the
  key lives until the first stale instant.
- **Budget construction and admission.** Tests that inject a
  `RuntimeAuthFailureLimiter` into the route inject a Telltale `FailureBudget`
  (or an adapter with `admit(now)`, `release()` and `fail(now)`). Requests
  still authenticating count against the budget, so at most the budget's
  size can be in verification at once; the rest are refused `rate_limited`
  without a configuration read. The H1 pin test keeps asserting Station's
  constant.
- **Noise aggregation moves.** The post-trip `unauthenticated_flood` entry is
  written through the `audit` binding by Telltale's aggregator; Station's
  `InboundWebhookNoiseAggregator` can be removed or kept as the audit-side
  adapter.

### Fault injection to keep

The epic asks that reverting Telltale's signature check fails a Station
webhook test. `records an invalid signature and starts nothing` does that once
the route uses `host.receive`: with the check gone, the zero-filled signature
is accepted and `startSession` is called.

## GitHub poll

Two ways in. Take the first for the migration slice; it keeps every existing
`github-poll.test.ts` assertion.

### 1. The pure layer, under Station's scheduler tick (recommended first)

Station keeps `GitHubPollAutomationPoller`, its preview gating, its
mid-fetch "source changed / preview disabled / stopping" checks, its ledger
poll state and its summary counts. It replaces three internals:

| Station today | Telltale |
| --- | --- |
| `normalizeGitHubWorkflowRun` (`github-workflow-run.ts`) | `normalizeGitHubWorkflowRun(run, { repository, receivedAt, maxEventAgeMs })` |
| `listGitHubWorkflowRuns` (`external-monitor.ts`) | `listGitHubWorkflowRuns({ repository, workflowFile, token, signal, fetch })` |
| the cursor loop in `pollSource` | `githubPollStep({ listings, cursor, repository, observedAt })` |

Mapping a Telltale observation to Station's `AutomationEvent`:

```ts
{
  schemaVersion: 1,
  eventId: randomUUID(),
  sourceId: source.id,
  sourceKind: "github-poll",
  type: "github.workflow_run.completed",
  semanticKey: obs.semanticKey,      // unchanged format
  occurredAt: new Date(obs.updatedAtMs).toISOString(),
  receivedAt: new Date(observedAt).toISOString(),
  fields: obs.fields,                // the same allow-listed keys
}
```

`githubPollStep` returns the overlap re-reads, so Station's transport-duplicate
counts are unchanged. The step does not apply the first-look rule; Station's
current first poll (process the window) is preserved. Station resolves its
credential binding and settles it around `listGitHubWorkflowRuns`, passing the
token string; Telltale never sees the binding.

### 2. The `github-poll` source, later

When Station wants Telltale to own timing as well, add one source per
Automation source with `backfill: true` (Station's first-poll behavior), its
interval and pinned workflow files, and subscribe Station's intake. Then:

- refusals arrive at the subscriber's `refusal` handler with the same reasons
  and semantic keys;
- overlap re-reads are not re-delivered, so assertions on `duplicate` counts
  from re-polling change (the ledger's dedupe still holds for crash replays);
- the interval and backoff are Telltale's, so "not due" is no longer a
  Station outcome;
- Station's mid-fetch revocation check becomes `remove()` / unsubscribe, after
  which a late result is dropped.

## Trust

Both sources are added `untrusted`. Station's automation prompt already frames
event fields as quoted data; nothing changes. Trust remains a property of the
route a request entered by, never of its content.
