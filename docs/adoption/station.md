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
    replay: { claim: (key, expiresAt, now) => replayStore.claim(key, expiresAt, now) },
    audit: { record: (e) => auditStore.record(e.reason, e.credentialId) /* or recordAggregatedNoise(e.count) */ },
    budget, // shared with a future /api/webhooks/github/:sourceId route
  },
});
// Subscribe once at startup: an unsubscribed source accepts nothing (404 not_listening).
await host.subscribe("inbound", () => {});
```

### The route

```ts
app.post("/inbound", async (c) => {
  if (!webhookAutomationsAllowedByManagedPolicy()) { /* unchanged */ }
  const result = await host.receive("inbound", {
    headers: c.req.raw.headers,
    body: () => readBoundedBody(c.req.raw), // called only after header checks pass
  });
  recordOutcome(result.accepted ? "accepted" : result.reason);
  if (!result.accepted) {
    if (result.retryAfterSeconds) c.header("Retry-After", String(result.retryAfterSeconds));
    return c.json({ success: false, code: result.reason, retryable: result.retryable }, result.status);
  }
  const { credentialId, body } = result.event.payload;
  const payload = parsePayload(body);           // Station's {agent, message, project} validation
  if (!payload) return malformed();
  if (!grantAllows(tokenGrants(credentialId), payload.agent, payload.project)) return forbiddenStart(credentialId);
  // ... startTurn, recordSuccess(credentialId, conversationId), 202 — unchanged
});
```

### Behavior changes to expect

- **A forbidden start consumes its nonce.** Telltale claims the nonce after
  the signature holds, before Station's grant check. A caller retrying the
  same signed request after fixing the grant must re-sign. Stricter; no
  current Station test retries a forbidden nonce.
- **Malformed JSON with a bad signature is now `invalid_signature`.** Station
  parsed before verifying; Telltale verifies first. A malformed body with a
  valid signature is still Station's `malformed_request`, from its own
  `parsePayload`.
- **The replay store should refuse when full.** `InboundWebhookReplayStore`
  keeps the newest 10,000 keys, dropping live ones. Make it throw at capacity
  (Telltale answers `policy_unavailable`) instead.
- **Budget construction.** Tests that inject a `RuntimeAuthFailureLimiter`
  into the route inject a Telltale `FailureBudget` (or a two-method adapter
  over the limiter: `tripped(now)` / `fail(now)`). The H1 pin test keeps
  asserting Station's constant.
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
