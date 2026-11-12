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
| `plan(type, options)` | What adding would do, without adding. Secret options masked, and a copy of a secret anywhere else in the plan redacted. Throws for what cannot work. |
| `add({ id, type, options?, trust?, bindings? })` | Registers a source. `trust` defaults to `untrusted`. Does not start it. |
| `subscribe(id, subscriber)` | Starts the source on the first subscriber. Resolves to `{ unsubscribe() }`. Rejects, subscribing nothing, if it cannot start, or if `close()` or `remove()` ran while it was starting. `unsubscribe()` called from inside a subscriber of the same source resolves once the stop has begun; the current look finishes after the subscriber returns. |
| `receive(id, request)` | Hands a request to a receiving source. Resolves to a `ReceiveResult`. |
| `remove(id)` | Stops and unregisters. State stays, keyed by configuration. |
| `info(id)`, `list()` | `SourceInfo`: id, type, trust, options (secret options masked, other copies of secrets redacted), subscriber count, status. |
| `status(id)` | `SourceStatus` (below). |
| `close()` | Stops every source, including one still starting (its `api.signal` is aborted; a start that finishes afterwards never runs) and one already stopping. Resolves once every source drained: current looks and requests finished, stop functions ran. Refuses requests while it runs. |
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
`keep(name, create)`, `secret(value)`, `status(note)`, `onReceive(handler)`, `onStop(fn)`.

`changed()` inside a look remembers the new value only when the look succeeds,
so a change whose delivery failed is seen again at the next look. `keep()`
returns an object that lives as long as the registration, across
unsubscribe and resubscribe: the place for guards whose memory must outlast a
subscription.

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

Event `received`: `{ credentialId, body, headers }`. `body` is the parsed JSON
(strict UTF-8), else `{ text }`, else `{ bytes: <length> }`. `deliveryId` is the
delivery header when one is configured: transport metadata, never identity.

Replay identity comes only from what the credential authenticated:

| Scheme | Replay key | Kept | `dedupKey` |
| --- | --- | --- | --- |
| `signed-timestamp` | (credential, timestamp, nonce) | until the request is stale | `request:<digest>` |
| `signed-body` | (credential, digest of the signed body) | `retentionHours` | `request:<digest>` |
| `bearer` | (credential, delivery id) when a delivery header is configured: folds duplicates, no replay protection | `retentionHours` | `delivery:<digest>`, else a random `request:<digest>` |

Reasons (`WEBHOOK_REFUSAL_REASONS`): `disabled` 403, `unknown_token` 401,
`revoked_token` 403, `malformed_request` 400, `stale_timestamp` 403,
`invalid_signature` 403, `replay` 403, `rate_limited` 429,
`policy_unavailable` 403, `delivery_failed` 503; plus host-level
`not_listening` and `unknown_source` 404.

Guards: `InMemoryReplayLedger(maxEntries = 10000)` (throws
`ReplayLedgerFullError` when full of live keys), `InMemoryWebhookAudit(maxEntries = 256)`,
`FailureBudget(maxFailures, windowMs)`, `AttemptLimiter(maxAttempts, windowMs, maxTracked)`,
`MIN_WEBHOOK_SECRET_LENGTH` (32). Unbound, the replay ledger, audit, limiter
and budget are kept with the registration (`api.keep`), so an unsubscribe
resets none of them; `remove()` drops them.

`ReplayLedger`: `reserve(key, expiresAt, now)` → `{ outcome: "reserved", token }`
or `{ outcome: "replayed" }`, atomic per key; `extend(key, token, expiresAt, now)`
while delivery runs; `commit(key, token, now)` once every subscriber took the
event; `release(key, token, now)` when delivery failed, so the same request
can be sent again. `extend`, `commit` and `release` act only when the token
still owns the key, atomically with that check, and return whether they did.
A reserved or delivered key refuses another `reserve`. `expiresAt` is the
first instant the key is free again: keep it while `now < expiresAt`. Throw
when you cannot decide (the request is refused `policy_unavailable`).
Every operation must settle; bound them in your adapter, since a stop waits
for a pending `commit` or `release`. `ReplayReservation` is the type `reserve`
returns. Within one host a second identical request is refused `replay` while
the first is being delivered, whatever the ledger says; hosts sharing a
ledger need one that fences.

`UnauthenticatedBudget`: `admit(now)` before any work on a request (false:
refuse it, no lookup), `release()` once that request authenticated or ended,
`fail(now)` per refusal. Requests in flight count against the budget, until
they authenticate or the source stops; give your body reader a deadline. A
consumer that refuses a request Telltale accepted calls `fail` too.
`FailureBudget` adds `failures(now)`, `inflight` and `tripped(now)`.

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
(10000), `maxDirectories` (1000), `maxDepth` (32), `maxEntries` (100000,
every directory entry read, ignored ones included). A scan over any bound
fails; it never truncates. The folder's device and inode are pinned at
start, and a scan that finds it, or a folder inside it, replaced fails.
Events `added` and `changed`, payload `{ file, size }`, `file` relative to
`dir` with `/` separators. `maskTest(mask)` is exported.

## Clocks, state, helpers

`Clock` (`now`, `setTimer`, `clearTimer`), `SystemClock`, `ManualClock`
(`advance(ms)`, `set(ms)`, both async; `pendingTimers()`), `settle()`.
`StateStore`, `InMemoryStateStore`. `SecretRegistry`, `REDACTED`,
`MIN_SECRET_LENGTH`. `harmless(value)`, `parseDuration(value)`,
`POLL_BACKOFF_MAX_MS`, `DEFAULT_MAX_HOPS`, `silentLogger`.
