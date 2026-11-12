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

`emit`, `refuse`, `poll`, `changed`, `state`, `keep`, `secret`, `status`,
`onReceive`, `onStop`, plus `clock`, `log` (redacting) and `signal` (aborted
on stop).

- `emit` resolves after every subscriber took the event and rejects with
  `DeliveryError` if one threw, so a polling source fails the look and retries.
  After stop it rejects with `SourceStoppedError`: a late result is dropped.
- `refuse(reason, { dedupKey })` reports an observation the source would not
  turn into an event, with a closed snake_case reason and no outside text.
  Subscribers with a `refusal` handler receive it.
- `poll(every, look)` and `changed(value, slot)` are pine's, below.
- `keep(name, create)` returns an object that lives as long as the
  registration rather than the start. A guard whose memory must outlast a
  subscription lives there: a webhook's default replay ledger, audit,
  attempt limiter and budget. Otherwise an unsubscribe followed by a new
  subscriber would hand a replayed request a fresh ledger. `remove()` drops
  them; bind durable guards when protection must outlast a registration or a
  process.

### The host

`add`, `plan`, `subscribe`, `receive`, `remove`, `list`, `info`, `status`,
`close`, `registerType`. A source starts on its first subscriber and stops on
its last; `receive` on a source with no subscriber is `404 not_listening`, so
an unsubscribed webhook accepts nothing.

A start in progress is covered too. When `close()`, `remove()` or the last
unsubscribe happens while a source is starting, the start tears itself down
when it finishes, publishes no running instance and leaves no timer; the
`subscribe()` that was waiting rejects. Stopping is split into beginning
(abort, cancel the next look) and draining (wait for the current look, run
the stop functions). A subscriber that unsubscribes from inside a delivery
of the same source gets the first part and returns; the drain finishes after
the delivery, so it never waits for itself.

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
  previous value. Inside a look the new value is staged and written only when
  the whole look, delivery included, succeeded, so a change whose delivery
  failed is seen, and delivered, at the next look.
- **Status lines never echo outside text.** Pine relies on `harmless()` and
  discipline. Telltale enforces the failure path: a poll error reaches the
  status only if it is a `SourceError` (fixed text the source wrote); any
  other error reads "unexpected failure". `harmless()` is exported for notes.
- **Secrets:** options marked `secret` are registered at `add()`, values are
  redacted (`[redacted]`) from events (values and keys), refusals, status lines
  and logs, and masked as `[secret]` in `list()` and `plan()`. A copy of a
  secret elsewhere in a plan or listing (another option, a `does` line) is
  redacted too; `plan()` redacts with the request's own secrets without
  registering them with the host. Redaction defines keys rather than assigning
  them, so a `"__proto__"` key from parsed JSON stays an own data property,
  and the event is frozen through every own property. A secret
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
   shareable), with admission: `admit` reserves room for the request until it
   authenticates or ends, and requests in flight count against the budget,
   so a concurrent burst with rotating credential ids cannot start more
   lookups than the budget allows. Once spent: no credential lookup, no
   per-request audit; refusals are aggregated into one `unauthenticated_flood`
   entry per minute. A valid signed request is refused too: the disclosed
   availability trade. A request holds its admission until it authenticates,
   so the consumer's own body-read deadline bounds how long a slow sender can
   hold one.
2. Per-credential attempts (default 60/min, keyed by a digest of the presented
   id, at most 1,024 tracked), with `retryAfterSeconds`.
3. Credential lookup on every request (revocation and the off switch apply to
   the next request): `policy_unavailable` when the store throws (logged as
   the fixed code `credential_lookup_failed`, never the exception text),
   `disabled`, `unknown_token` (401), `revoked_token`, and
   `policy_unavailable` for a secret under 32 characters (logged with the
   credential id, never the secret). The credential's fields are read once,
   before anything else is awaited; that snapshot's secret is registered for
   redaction and is the only one verified with, so a rotation during the body
   read cannot slip a new, unregistered secret into the check.
4. Header-only checks: timestamp `^\d{10}$`, nonce `^[A-Za-z0-9_-]{16,128}$`,
   freshness `|now − ts| ≤ window`; a bearer token comparison. A header given
   twice (two spellings of one name, or an array) reads as absent.
5. The body, read only now (a lazy reader is never called on a header
   refusal), bounded (default 256 KiB). Freshness is checked again once it has
   arrived.
6. HMAC-SHA256 over the raw received bytes (`ts\nnonce\nbody` for
   `signed-timestamp`, the body for `signed-body`), `sha256=<hex>`, length
   check then `timingSafeEqual`.
7. Replay reservation, only after a valid signature, so an unauthenticated
   caller cannot burn a key. The key is built only from what the credential
   authenticated (below). The ledger reserves it atomically; it is committed
   once every subscriber took the event and released when delivery failed, so
   the identical request sent again is delivered, while a copy arriving during
   delivery is refused `replay`. A ledger that throws, or is full of live
   keys, refuses `policy_unavailable`.
8. Emit `received` `{ credentialId, body, headers }`. The body is parsed as
   JSON (strict UTF-8) or carried as `{ text }`. Only allow-listed headers are
   kept; credential-bearing headers cannot be added to that list.

**Replay identity, per scheme.** A key made from an unsigned header would let
anyone holding one captured request replay it under a new header value.

- `signed-timestamp`: (credential, timestamp, nonce), all signed. Kept until
  `signedAt + window + 1 ms`, the first instant freshness (`|now − signedAt|
  ≤ window`, inclusive) refuses the request. Freshness and replay share one
  boundary, and a future-skewed request cannot be replayed into an
  early-eviction gap.
- `signed-body`: (credential, SHA-256 of the signed body), kept for the
  retention period. `X-GitHub-Delivery` is carried as `deliveryId` and never
  used as identity. **What a consumer should expect from GitHub:** a
  redelivery resends the same bytes (and the same delivery GUID), so it has
  the same key and the same `dedupKey`. If the first copy was delivered, the
  redelivery is refused `replay` (403); if the first copy failed
  (`503 delivery_failed`), its key was released and the redelivery is
  delivered. Two different happenings with byte-identical bodies count as
  one; a sender that can produce them should use `signed-timestamp`.
- `bearer`: nothing is signed, and a captured request carries the
  credential, so there is no replay protection to give. With a delivery
  header configured, (credential, delivery id) folds duplicate deliveries;
  the plan says "NO replay protection".

Refusal statuses match Station's: 400 malformed, 401 unknown, 403 for the
rest, 429 rate limited, plus 404 `not_listening` and 503 `delivery_failed`.

**Divergences from Station's route, on purpose:**

- *Authority stays with the consumer.* Station's `forbidden_start` grant check
  is authority, so it is not in Telltale. It now runs after the nonce is
  committed: a request that is authentic but asks for a forbidden start
  consumes its nonce. That is stricter, not weaker; no Station test pins the
  old order.
- *A failed delivery frees its nonce.* Station claims the nonce before it
  starts the turn, so a `503` retry of the same request is a `replay`.
  Telltale releases the reservation when a subscriber throws, so the
  retryable answer is honest.
- *One boundary for freshness and replay.* Station's ledger keeps a key while
  `expiresAt > now`, with `expiresAt = max(now, signedAt) + window`, and its
  freshness check is inclusive, so a replay at exactly `signedAt + window` is
  fresh and no longer remembered. Telltale passes the first stale instant as
  `expiresAt`.
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
A refusal is remembered apart from delivered runs, by reason and run time: it
is reported once, and it never stops a later valid observation of the same
run (a future-dated run is delivered once time catches up). The freshness
floor is applied at each look rather than stored, and the poll's memory is
written only when it changed, so an unchanged look writes nothing.

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
are never followed. A watch-triggered early scan can come later without
changing the contract.

**Where it reads is pinned.** The folder's device and inode are taken when the
source starts. Every folder entered is checked with `lstat` (a folder, not a
link, the same device and inode) and `realpath` (at the path it was found
by, so no link anywhere above it) before it is read and again after; a
mismatch fails the scan rather than reporting anything from it. **Residual
race:** a folder swapped for another and swapped back between two checks is
not seen. Node has no `openat` or `fdopendir`, so a directory cannot be read
through a pinned handle; closing that gap needs a native helper.

**Every scan is bounded:** `maxFiles` (10,000), `maxDirectories` (1,000),
`maxDepth` (32) and `maxEntries` (100,000 directory entries read, ignored ones
included). Over any bound the scan fails; it never truncates. Directories are
streamed a batch at a time (`opendir`), never read whole, and the scan yields
every 256 entries so a stop lands mid-scan.

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
