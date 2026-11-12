# Telltale

[![CI](https://github.com/kontourai/telltale/actions/workflows/ci.yml/badge.svg)](https://github.com/kontourai/telltale/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Status: 0.1 (first slice; not yet published to npm). The webhook, GitHub
poll and folder sources are implemented and tested; the contract may still
change before 1.0.

**The Kontour suite's event actor.** Layer: event actor, the sibling of
[Ephemeris](https://github.com/kontourai/ephemeris) (the time actor).

> *Telltale* (n.) — a strip of yarn on a sail that shows the wind; also, a
> thing that reports what happened. It shows; it does not steer.

Telltale holds typed **sources** that report what happens elsewhere: a webhook
call, a GitHub workflow run, a file dropped in a folder. Each source turns
what it sees into one normalized **event**, stamped with the **trust** of the
place it entered — never with anything the event itself says.

**It reports; it never starts work.** A consumer subscribes to sources and owns
everything after that: rules, authority, actions, receipts. Station Automations
is the first consumer.

```js
import { TelltaleHost } from "@kontourai/telltale";

const host = new TelltaleHost();
host.add({ id: "ci", type: "github-poll", options: { repository: "owner/repo" } });

// Nothing runs until someone subscribes. The first look is the starting point.
await host.subscribe("ci", (event) => {
  // event.trust is "untrusted": GitHub data is outside content.
  console.log(event.topic, event.dedupKey, event.payload["run.conclusion"]);
});
```

## The invariants

These are enforced in code and each has a test that fails without it.

- **Trust comes from where an event entered, never from what it says.** The
  consumer sets a source's trust when it adds it (`untrusted` by default). The
  host stamps it on every event. A source type cannot set it, and no payload,
  header or field can raise it.
- **It reports; it never starts work.** A source can only `emit` events and
  `refuse` observations. There is no action, rule or authority API.
- **A source costs nothing unsubscribed.** It starts on its first subscriber
  and stops when the last leaves: no timer, no watcher, no accepted request.
- **Polling sources follow one rule.** The first look is the starting point
  and reports nothing; an unchanged look does nothing (no event, no write); a
  failed look backs off (doubling, capped at 15 minutes) and shows in the
  status.
- **Status lines never echo outside text.** Only a source's own fixed messages
  reach a status line; any other failure reads "unexpected failure".
- **Secrets stay out.** Options marked `secret`, and webhook credentials, are
  redacted from events, refusals, status lines and logs, and masked in
  plans and listings.
- **Webhooks verify before they read.** Header-only checks run before the
  body is read; the HMAC is over the raw bytes, compared in constant time;
  replay is keyed only on signed bytes and reserved only after the signature
  holds; a failed delivery frees its key for a retry; the replay ledger and
  the credential store fail closed.

## Sources in this slice

| Type | Reports | Notes |
| --- | --- | --- |
| `webhook` | `received` `{ credentialId, body, headers }` | Transport-agnostic: your HTTP server passes the raw request to `host.receive()`. Schemes `signed-timestamp`, `signed-body` (GitHub), `bearer`. Replay ledger, per-credential limit, global unauthenticated budget. |
| `github-poll` | `workflow_run.completed` (allow-listed string fields) | One bounded page per poll, a cursor with overlap, freshness bound, refusals with closed reasons. The normalizer and cursor step are exported as pure functions. |
| `folder` | `added`, `changed` `{ file, size }` | Scans on the host's poll; a file counts once two scans agree. Never follows links; pins the folder's identity; bounded by files, folders, depth and entries. |

MQTT, chat bots, FTP, HTTP polling and command sources are later slices.

## What Telltale does not do

It does not match rules, grant authority, start agents or tasks, send
messages, retry actions, or keep receipts. It does not decide that an event is
a duplicate of something the consumer already acted on: it delivers at least
once and gives every event a `dedupKey` so the consumer can act exactly once,
atomically with its own effects.

## Documentation

- [Getting started](docs/getting-started.md)
- [Design](docs/design.md): the contract, the semantics and where they came from
- [Reference](docs/reference.md)
- [Adopting Telltale in Station](docs/adoption/station.md)
- [Domain context and vocabulary](CONTEXT.md)

## Development

```bash
pnpm install --frozen-lockfile
npm test          # build, then node --test
npm run typecheck
npm run example   # a signed webhook, verified, replayed and forged
```

Licensed under Apache-2.0. Some semantics and small helpers are adapted from
[pmndrs/pine](https://github.com/pmndrs/pine) (MIT); see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
