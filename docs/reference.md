# Reference

Everything below is exported from `@kontourai/telltale` (`src/index.ts`).

## TelltaleHost

`new TelltaleHost({ clock?, state?, logger?, types?, random?, maxHops? })`

| Option | Default | Meaning |
| --- | --- | --- |
| `clock` | `SystemClock` | Time and timers. Tests use `ManualClock`. |
| `state` | `InMemoryStateStore` | Source bookkeeping (cursors, last-seen values). |
| `logger` | silent | `{ info, warn }`; every line is redacted first. |
| `types` | none | Extra source types by name, beside `webhook`, `github-poll`, `folder`. |
| `random` | `Math.random` | Poll jitter source. |
| `maxHops` | 8 | Reaction depth past which an emit is dropped. |

| Method | Does |
| --- | --- |
| `registerType(name, type)` | Adds a source type. A taken name is refused. |
| `types()` | Registered type names. |
| `plan(type, options)` | What adding would do, without adding. Secrets masked. Throws for what cannot work. |
| `add({ id, type, options?, trust?, bindings? })` | Registers a source. `trust` defaults to `untrusted`. Does not start it. |
| `subscribe(id, subscriber)` | Starts the source on the first subscriber. Resolves to `{ unsubscribe() }`. Rejects, subscribing nothing, if it cannot start. |
| `receive(id, request)` | Hands a request to a receiving source. Resolves to a `ReceiveResult`. |
| `remove(id)` | Stops and unregisters. State stays, keyed by configuration. |
| `info(id)`, `list()` | `SourceInfo`: id, type, trust, masked options, subscriber count, status. |
| `status(id)` | `SourceStatus` (below). |
| `close()` | Stops every source. |
| `secrets` | The `SecretRegistry`. `secrets.add(value)` redacts a value of your own. |

A subscriber is a function `(event) => void | Promise<void>` or an object
`{ event(e), refusal?(r) }`.

### SourceStatus

`{ state: "stopped" | "starting" | "running" | "failing", startedAt?, lastLookAt?, lastOkAt?, failingSince?, failures, error?, note?, emitted, refused }`

`error` is a source-authored `SourceError` message or `"unexpected failure"`.

### ReceiveResult

`{ accepted: true, status: 202, event }` or
`{ accepted: false, status, reason, retryable, retryAfterSeconds? }`.

## TelltaleEvent and Refusal

See [design: the event](design.md#the-event). A `Refusal` is
`{ sourceId, reason, dedupKey?, at }`.

## Writing a source type

```ts
const type: SourceType = {
  summary: "one line",
  options: { token: { type: "string", secret: true, description: "..." } },
  plan(o) { return { options: o, does: ["..."], opens: true }; },
  start(api) {
    api.poll("1m", async (signal) => {
      const value = await look(signal);
      const was = await api.changed(value);
      if (was) await api.emit("changed", { value }, { dedupKey: `v:${value}` });
    });
  },
};
host.registerType("my-type", type);
```

`SourceApi`: `id`, `type`, `options`, `bindings`, `clock`, `log`, `signal`,
`state.{get,set,delete}`, `emit(name, payload, { dedupKey, deliveryId?, occurredAt?, cause? })`,
`refuse(reason, { dedupKey? })`, `poll(every, look)`, `changed(value, slot?)`,
`secret(value)`, `status(note)`, `onReceive(handler)`, `onStop(fn)`.

Errors: `SourceError` (fixed text that may reach a status line),
`SourceStoppedError` (emit after stop), `DeliveryError` (a subscriber threw).

Option kinds: `string`, `number`, `boolean`, `string[]`, `object`. Unknown
options are refused; `secret` options must be strings of at least 8
characters.

## webhook

Options: `scheme` (`signed-timestamp` | `signed-body` | `bearer`), `secret`
(at least 32 characters, or bind `credentials`), `headers` (`token`,
`timestamp`, `nonce`, `signature`, `delivery`), `windowSeconds` (300),
`retentionHours` (168), `maxBodyBytes` (262144), `keepHeaders`,
`perCredentialPerMinute` (60), `unauthenticatedPerMinute` (300).

Bindings: `credentials: WebhookCredentials`, `replay: ReplayLedger`,
`audit: WebhookAudit`, `budget: UnauthenticatedBudget`.

Default headers: `signed-timestamp` uses `x-telltale-timestamp`,
`x-telltale-nonce`, `x-telltale-signature`, and `x-telltale-token` for the
credential id when `credentials` is bound; `signed-body` uses
`x-hub-signature-256` and `x-github-delivery`; `bearer` uses `authorization`.
Without a token header the credential id is the source id.

Event `received`: `{ credentialId, body, headers }`. `dedupKey` is
`delivery:<digest>` with a delivery id, else `request:<digest>`.

Reasons (`WEBHOOK_REFUSAL_REASONS`): `disabled` 403, `unknown_token` 401,
`revoked_token` 403, `malformed_request` 400, `stale_timestamp` 403,
`invalid_signature` 403, `replay` 403, `rate_limited` 429,
`policy_unavailable` 403, `delivery_failed` 503; plus host-level
`not_listening` and `unknown_source` 404.

Guards: `InMemoryReplayLedger(maxEntries = 10000)` (throws
`ReplayLedgerFullError` when full of live keys), `InMemoryWebhookAudit(maxEntries = 256)`,
`FailureBudget(maxFailures, windowMs)`, `AttemptLimiter(maxAttempts, windowMs, maxTracked)`,
`MIN_WEBHOOK_SECRET_LENGTH` (32).

## github-poll

Options: `repository` (required, `owner/repo`), `every` (`"1m"`–`"24h"`,
default `"5m"`), `workflowFiles` (at most 4), `token` (secret), `backfill`
(false), `maxEventAgeHours` (72). Binding: `fetch`.

Event `workflow_run.completed`, payload: the `GITHUB_WORKFLOW_RUN_FIELDS`
present on the run, all strings. `dedupKey`:
`workflow_run:<id>:<attempt>:completed`. `occurredAt`: the run's `updated_at`.
Refusals: `malformed_request`, `wrong_repository`, `stale_event`.

Functions: `normalizeGitHubWorkflowRun(run, { repository, receivedAt, maxEventAgeMs? })`,
`listGitHubWorkflowRuns({ repository, workflowFile?, token?, perPage?, signal?, fetch? })`,
`githubPollStep({ listings, cursor, repository, observedAt, maxEventAgeMs? })`,
`workflowRunSemanticKey(id, attempt)`. Constants: `CURSOR_OVERLAP_MS`,
`DEFAULT_MAX_EVENT_AGE_MS`, `MAX_PINNED_WORKFLOW_FILES`, `WORKFLOW_RUN_COMPLETED`.

## folder

Options: `dir` (required, absolute), `mask`, `pattern`, `ignore`,
`recursive` (true), `every` (at least `"1s"`, default `"5s"`), `maxFiles`
(10000). Events `added` and `changed`, payload `{ file, size }`, `file`
relative to `dir` with `/` separators. `maskTest(mask)` is exported.

## Clocks, state, helpers

`Clock` (`now`, `setTimer`, `clearTimer`), `SystemClock`, `ManualClock`
(`advance(ms)`, `set(ms)`, both async; `pendingTimers()`), `settle()`.
`StateStore`, `InMemoryStateStore`. `SecretRegistry`, `REDACTED`,
`MIN_SECRET_LENGTH`. `harmless(value)`, `parseDuration(value)`,
`POLL_BACKOFF_MAX_MS`, `DEFAULT_MAX_HOPS`, `silentLogger`.
