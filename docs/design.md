# Design

Telltale is the suite's event actor: typed sources report what happens
elsewhere, each event is stamped with the trust of the place it entered, and a
consumer decides what, if anything, to do. This document is the contract, the
semantics, where each came from, and where Telltale deliberately diverges.

## Where it sits

| Actor | Turns ... into a trigger | Owns | Never |
| --- | --- | --- | --- |
| Ephemeris | time | deadlines, recurring-schedule evaluation | authors trust state |
| Telltale | outside happenings | sources, verification, the event envelope | starts work, grants authority |

Lookout compares snapshots for drift and Forage acquires sources safely; both
are about content. Telltale is about *something happened*: it carries the
smallest normalized fact a consumer can act on and leaves interpretation to
the consumer. A future HTTP-poll source should compose Forage's pinned
acquisition rather than fetch on its own.

## The contract

### The event

```ts
interface TelltaleEvent<P = unknown> {
  schemaVersion: 1;
  id: string;          // random UUID, unique per emission
  ts: string;          // ISO-8601, host clock, when Telltale received or observed it
  topic: string;       // `${source.id}/${name}`
  name: string;        // "received", "workflow_run.completed", "added", ...
  source: { id: string; type: string };
  payload: P;          // redacted; outside content unless trust is "owner"
  trust: "owner" | "untrusted";
  dedupKey: string;    // semantic identity, same across transports
  deliveryId?: string; // transport identity, when there is one
  occurredAt?: string; // when the happening occurred, if known
  cause?: string;      // id of the event this one reacts to
  hops: number;        // 0 for an outside trigger
}
```

The host builds the envelope field by field. A source supplies only `name`,
`payload` and `{ dedupKey, deliveryId?, occurredAt?, cause? }`; nothing else it
passes reaches the envelope. The event is deep-frozen before any subscriber
sees it.

**Why `dedupKey` is required and Telltale does not dedupe on it.** A consumer
that acts exactly once must record "seen" atomically with its own effect (a
ledger row and an episode change in one transaction). If Telltale dropped
duplicates itself, a crash between Telltale's "seen" and the consumer's commit
would lose the event. So Telltale delivers at least once and gives each event
the key; transport-level repetition (a webhook redelivery, a poll re-reading
its overlap) is suppressed only where that is safe: replay refusal for
webhooks, and a "seen" set for polls that is written only after delivery
succeeded.

### Trust

Set by the consumer at `host.add({ trust })`, `untrusted` by default, stamped
by the host. Pine's rule, unchanged: *trust comes from where an event entered,
never from what it says*. A signed webhook is still `untrusted` when its body
carries text other people wrote; a signature proves who sent the request, not
who wrote what is in it. This slice has no source type that vouches for its
sender (pine's `owner` in a plan); that arrives with chat sources, where a
paired account can be the owner.

### Source types

```ts
interface SourceType<Bindings> {
  summary: string;
  options: Record<string, OptionSpec>;   // { type, description, required?, secret? }
  plan?(options): SourcePlan;            // { options, does: string[], opens: boolean, tell? }
  start(api: SourceApi<Bindings>): void | Promise<void>;
}
```

This is pine's `SourceType` (summary, option schema, `plan()`), with two
changes: the option schema is a small `OptionSpec` map instead of a TypeBox
schema, so Telltale has no runtime dependency; and the start function is a
member, not a module default export, because Telltale is a library and types
are registered in code (`host.registerType`). Pine's `read` (sandbox folder
grants) and `talks` / `sends` are not in this slice: nothing here computes
them. A plan rejects anything that cannot work, including bounds: more than
four pinned workflow files is refused, not silently widened.

**Bindings** carry what cannot be configuration: a credential store, a replay
ledger, an audit sink, a `fetch`. Options stay JSON.

### The source API

`emit`, `refuse`, `poll`, `changed`, `state`, `secret`, `status`, `onReceive`,
`onStop`, plus `clock`, `log` (redacting) and `signal` (aborted on stop).

- `emit` resolves after every subscriber took the event and rejects with
  `DeliveryError` if one threw, so a polling source fails the look and retries.
  After stop it rejects with `SourceStoppedError`: a late result is dropped.
- `refuse(reason, { dedupKey })` reports an observation the source would not
  turn into an event, with a closed snake_case reason and no outside text.
  Subscribers with a `refusal` handler receive it.
- `poll(every, look)` and `changed(value, slot)` are pine's, below.

### The host

`add`, `plan`, `subscribe`, `receive`, `remove`, `list`, `info`, `status`,
`close`, `registerType`. A source starts on its first subscriber and stops on
its last; `receive` on a source with no subscriber is `404 not_listening`, so
an unsubscribed webhook accepts nothing.

State is namespaced by source id plus a fingerprint of the type and its
non-secret options: re-adding the same configuration resumes its cursor; a
changed configuration starts fresh.

## Semantics carried over from pine

From `pmndrs/pine` `src/sources.ts`, `src/watching.ts`, `docs/references/sources.md`
and `security.md` §5–§10, AGENTS.md invariants 3, 6 and 7:

- **Start on first subscriber, cost nothing unsubscribed.**
- **`poll`:** the first look runs at once; later looks every interval with ±10%
  jitter, never two at once; a failed look doubles the wait
  (`min(every·2^min(fails,12), max(every, 15m))`) and is logged once, not per
  round; the first good look restores the interval. Stopping aborts the look's
  signal and waits for it.
- **`changed`:** the first value is the starting point and returns nothing; an
  unchanged value returns nothing and writes nothing; a change returns the
  previous value.
- **Status lines never echo outside text.** Pine relies on `harmless()` and
  discipline. Telltale enforces the failure path: a poll error reaches the
  status only if it is a `SourceError` (fixed text the source wrote); any
  other error reads "unexpected failure". `harmless()` is exported for notes.
- **Secrets:** options marked `secret` are registered at `add()`, values are
  redacted (`[redacted]`) from events (values and keys), refusals, status lines
  and logs, and masked as `[secret]` in `list()` and `plan()`. A secret
  shorter than 8 characters is refused, as pine ignores them, because
  redacting a short string mangles ordinary text.
- **A source only emits; a source that sends decides where to.** No source in
  this slice sends.
- **`cause` and `hops`:** a source reacting to another event passes it as
  `cause`; past `maxHops` (default 8) the emit is dropped as a probable loop.

## The webhook, ported from Station's inbound intake

Station's inbound webhook (route, authorization service and store) is the
reference. Telltale keeps every one of its security properties and moves them
behind a transport-agnostic `receive()`: the consumer owns the HTTP server.

Order of checks (each refusal is audited by reason, without body, headers,
nonce or secret; an unknown credential id is not recorded because the caller
chose it):

1. Global unauthenticated budget (default 300 refusals/min, bindable and
   shareable). Once tripped: no credential lookup, no per-request audit;
   refusals are aggregated into one `unauthenticated_flood` entry per minute.
   A valid signed request is refused too: the disclosed availability trade.
2. Per-credential attempts (default 60/min, keyed by a digest of the presented
   id, at most 1,024 tracked), with `retryAfterSeconds`.
3. Credential lookup on every request (revocation and the off switch apply to
   the next request): `policy_unavailable` when the store throws, `disabled`,
   `unknown_token` (401), `revoked_token`, and `policy_unavailable` for a
   secret under 32 characters (logged with the credential id, never the
   secret).
4. Header-only checks: timestamp `^\d{10}$`, nonce `^[A-Za-z0-9_-]{16,128}$`,
   freshness `|now − ts| ≤ window`; a bearer token comparison.
5. The body, read only now (a lazy reader is never called on a header
   refusal), bounded (default 256 KiB).
6. HMAC-SHA256 over the raw received bytes (`ts\nnonce\nbody` for
   `signed-timestamp`, the body for `signed-body`), `sha256=<hex>`, length
   check then `timingSafeEqual`.
7. Replay claim, only after a valid signature, so an unauthenticated caller
   cannot burn a nonce. Key: a digest of (credential, timestamp, nonce), kept
   until `max(now, signedAt) + window` (a future-skewed request cannot be
   replayed into an early-eviction gap); or a digest of (credential, delivery
   id) for the retention period. A ledger that throws, or is full of live
   keys, refuses `policy_unavailable`.
8. Emit `received` `{ credentialId, body, headers }`. The body is parsed as
   JSON (strict UTF-8) or carried as `{ text }`. Only allow-listed headers are
   kept; credential-bearing headers cannot be added to that list.

Refusal statuses match Station's: 400 malformed, 401 unknown, 403 for the
rest, 429 rate limited, plus 404 `not_listening` and 503 `delivery_failed`.

**Divergences from Station's route, on purpose:**

- *Authority stays with the consumer.* Station's `forbidden_start` grant check
  is authority, so it is not in Telltale. It now runs after the nonce is
  claimed: a request that is authentic but asks for a forbidden start consumes
  its nonce. That is stricter, not weaker; no Station test pins the old order.
- *Parse after verify.* Station's inbound route parses the JSON before the
  HMAC; Telltale parses only after the signature holds (as Station's own
  GitHub-push design requires).
- *A full replay ledger refuses.* Station's file ledger keeps the newest
  10,000 keys and drops older live ones; dropping a live key reopens replay.
  Telltale's in-memory ledger refuses at capacity, and the interface tells
  implementers to do the same.

## The GitHub poll, ported from Station's `github-poll`

Three layers so Station can adopt the part it needs:

- `normalizeGitHubWorkflowRun`: allow-listed string fields only (never
  titles, commit messages or actor names), exact `html_url`, strict SHA and
  timestamps, no control characters, closed refusals (`malformed_request`,
  `wrong_repository`, `stale_event`). Semantic key
  `workflow_run:<id>:<attempt>:completed`, identical for poll and push.
- `listGitHubWorkflowRuns`: one page, never paginated, 1 MiB and 10 s bounds,
  redirects refused, 401 / non-rate-limit 403 as `unauthorized`, everything
  else `unavailable`; `partial` when more runs exist.
- `githubPollStep`: pure cursor arithmetic. Skips runs older than
  `cursor − 10 min`, re-returns the overlap, advances the cursor on a complete
  page to `max(newest accepted, observedAt − maxAge)` (so a stale run is
  refused once), keeps it on a partial or failed page, and never lets a
  refused run move it.

The `github-poll` source runs those on the host's poll and applies the
delivery rules: **the first look is the starting point** (unless
`backfill: true`), a run already delivered is not delivered again when the
overlap re-reads it, and a failed listing is a failed look (backoff, status).

**Divergence, on purpose:** Station's poller processes the first page inside
the 72-hour freshness window. Pine's rule is that setting a source up reports
nothing, so a new source cannot wake work for runs that finished before
anyone asked. Telltale defaults to pine's rule; `backfill: true` is Station's
behavior, named and opt-in.

## The folder, and Ephemeris's directory watcher

Ephemeris's `DirectoryWatcherSource` scans existing files at start and then
uses `fs.watch`; that suits it, because arming a deadline is idempotent and an
existing bundle must be armed. Telltale's folder reports *happenings*, so it
takes the existing files as the starting point. It also scans on the host's
poll instead of `fs.watch` (pine's choice): scanning makes the first-look,
unchanged-look and backoff rules apply unchanged, behaves the same on network
shares and every platform, and is deterministic under test. A file counts once
two scans see the same size and modification time; empty files wait; links
are never followed; more than `maxFiles` files fails the scan rather than
truncating it. A watch-triggered early scan can come later without changing
the contract.

## Storage

`StateStore` (source bookkeeping), `ReplayLedger`, `WebhookAudit`,
`WebhookCredentials` and `UnauthenticatedBudget` are interfaces with in-memory
defaults. Methods may be synchronous or return promises. There is no SQLite
dependency: Station already has its own stores and implements the interfaces
over them; a standalone deployment that needs durability can implement them
over a file or database.

## Next slices

- Sources: MQTT, chat bots (with `owner` vouching and sending that decides
  where), FTP, HTTP poll (over Forage's pinned acquisition), command (in the
  consumer's sandbox).
- A GitHub push normalizer for `signed-body` deliveries producing the same
  `workflow_run.completed` event and `dedupKey` as the poll.
- Ephemeris-backed scheduled events through the same intake.
- A durable file `StateStore` and replay ledger for standalone use.
