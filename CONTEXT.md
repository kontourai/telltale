# Telltale Context

Telltale is the Kontour suite's event actor. Its role is to turn what happens elsewhere into one normalized, trust-stamped event, and to stop there. Ephemeris turns time into a trigger; Telltale turns outside happenings into reports. Consumers (first, Station Automations) subscribe and own everything after the report.

## Layer Model

- **Source types** own the transport: how to verify a webhook, how to list GitHub runs, how to scan a folder, and how to normalize what they find.
- **The host** owns the envelope and the lifecycle: start on first subscriber, stop on last, poll timing and backoff, status, trust stamping, redaction.
- **Consumers** own meaning and authority: which events matter (rules), who may act (grants), what happens (actions), and what is recorded (receipts, dedup ledgers).

## Invariants

- **It reports; it never starts work.** A source can emit events and refuse observations. Nothing in Telltale matches rules, grants authority, starts an agent or task, or sends anything.
- **Trust comes from where an event entered, never from what it says.** Trust is set by the consumer at `add()` and stamped by the host. Source types cannot set it; payloads, headers and fields cannot raise it.
- **A source costs nothing unsubscribed.** No timer, watcher, or accepted request before the first subscriber or after the last.
- **First look is the starting point; unchanged looks do nothing; failed looks back off and show in status.**
- **Status lines never echo outside text.** Only source-authored `SourceError` messages and the source's own notes reach them.
- **Secrets never leave.** Marked options and webhook credentials are redacted everywhere Telltale writes, and masked in listings and plans.
- **At-least-once delivery.** `emit` resolves only after every subscriber took the event; a throwing subscriber makes the look fail and retry. Exactly-once is the consumer's, keyed on `dedupKey`.

## Vocabulary

- **Source:** A registered instance of a source type, with a consumer-chosen id, options, bindings and trust.
- **Source type:** A summary, an option spec (secrets marked), an optional `plan()`, and `start(api)`. Built-ins: `webhook`, `github-poll`, `folder`.
- **Plan:** What adding a source would do, worked out before it starts: checked options, plain-language `does[]`, and whether it `opens` something new.
- **Binding:** A non-serializable collaborator passed at `add()`: a credential store, a replay ledger, a `fetch`.
- **Subscriber:** A function (events) or an object with `event` and optional `refusal` handlers.
- **Event (`TelltaleEvent`):** `{schemaVersion, id, ts, topic, name, source, payload, trust, dedupKey, deliveryId?, occurredAt?, cause?, hops}`. Deep-frozen and redacted.
- **Trust:** `owner` or `untrusted`. Default `untrusted`.
- **dedupKey:** Semantic identity of a happening, the same across transports (`workflow_run:<id>:<attempt>:completed`).
- **deliveryId:** Transport identity when the transport has one (`X-GitHub-Delivery`).
- **cause / hops:** The event this one reacts to, and the reaction depth. Emits past `maxHops` (default 8) are dropped.
- **Refusal:** A refused observation: source id, closed snake_case reason, optional dedup key. No outside text.
- **Look:** One run of a polling source. **Backoff:** the wait doubling after each failed look, capped at 15 minutes (or the interval if longer).
- **Status:** `stopped | starting | running | failing`, last look and last success, failures, a safe error, the source's note, emitted and refused counts.
- **StateStore:** Telltale-private durable bookkeeping (cursors, last-seen values), namespaced per source and configuration. In-memory by default.
- **Replay ledger / Audit / Budget:** The webhook's pluggable guards: accepted-request keys (fail closed), refusal records without bodies or secrets, and the global unauthenticated attempt budget.

## Boundary

Telltale is a reporter, not an orchestrator or authority. It may verify inbound requests, poll outside services through bounded requests, scan folders, keep its own cursors, and hand events to subscribers.

It does **not**:

- own an HTTP server (the consumer does and passes requests in);
- match, filter or route events beyond what a source type normalizes;
- decide who may act on an event, or start, retry or cancel work;
- keep receipts, episodes or the consumer's dedup ledger;
- send messages anywhere (sending sources arrive in a later slice, and such a source decides itself where it may send);
- read trust, identity or authority from event content;
- fire on a clock of its own for scheduling purposes (time-based triggers are Ephemeris's).
