# Getting started

Telltale is published to npm as `@kontourai/telltale`. It is an ES module
package for Node.js 22 or newer with no runtime dependencies.

```sh
npm install @kontourai/telltale
```

## A host, a source, a subscriber

```js
import { TelltaleHost } from "@kontourai/telltale";

const host = new TelltaleHost();

// Adding does nothing yet. Options are checked now; a bad one throws.
host.add({
  id: "drop",
  type: "folder",
  options: { dir: "/srv/scans", mask: "*.pdf", every: "5s" },
});

// The first subscriber starts it. The first scan is the starting point:
// files already there are not reported.
const subscription = await host.subscribe("drop", (event) => {
  console.log(event.name, event.payload.file, event.trust); // "added", "a.pdf", "untrusted"
});

// The last subscriber leaving stops it: no timer, no scan.
await subscription.unsubscribe();
```

Every event has the same envelope: `id`, `ts`, `topic` (`drop/added`), `name`,
`source`, `payload`, `trust`, `dedupKey`, and `hops`, with `deliveryId`,
`occurredAt` and `cause` when they apply. See [design](design.md#the-event).

## Receive a webhook on your own server

Telltale never opens a port. Your server passes the raw request in and answers
with the status Telltale returns.

```js
import http from "node:http";
import { TelltaleHost } from "@kontourai/telltale";

const host = new TelltaleHost();
host.add({ id: "deploys", type: "webhook", options: { secret: process.env.DEPLOY_HOOK_SECRET } });
await host.subscribe("deploys", (event) => queue.push(event)); // your intake

http.createServer(async (req, res) => {
  const result = await host.receive("deploys", {
    headers: req.headers,
    body: () => readAtMost(req, 256 * 1024), // read only if the headers pass
  });
  res.writeHead(result.status, result.retryAfterSeconds ? { "Retry-After": result.retryAfterSeconds } : {});
  res.end(JSON.stringify(result.accepted ? { ok: true } : { code: result.reason }));
}).listen(8080);
```

The default scheme is `signed-timestamp`: the caller sends
`x-telltale-timestamp` (Unix seconds), `x-telltale-nonce` (16–128 URL-safe
characters) and `x-telltale-signature: sha256=<hex>` of
HMAC-SHA256(secret, `timestamp + "\n" + nonce + "\n" + body`). For GitHub, use
`scheme: "signed-body"`; for a device that can only send a token,
`scheme: "bearer"` (no integrity over the body; replay protection only with a
delivery header).

For several named credentials, bind a store instead of `secret`; it is read on
every request, so revoking a credential applies to the next one:

```js
host.add({
  id: "inbound",
  type: "webhook",
  bindings: { credentials: { lookup: (id) => ({ enabled: true, credential: myStore.get(id) }) } },
});
```

## Poll GitHub workflow runs

```js
host.add({
  id: "ci",
  type: "github-poll",
  options: {
    repository: "owner/repo",
    every: "5m",
    workflowFiles: ["main-qualification.yml"],
    token: process.env.GITHUB_TOKEN, // secret: redacted everywhere
  },
});
await host.subscribe("ci", {
  event: (e) => console.log(e.dedupKey, e.payload["run.conclusion"]),
  refusal: (r) => console.log("refused", r.reason, r.dedupKey),
});
```

The first look is the starting point. Pass `backfill: true` to have the first
look report runs completed inside the freshness window (72 hours by default).

## Status

```js
host.status("ci");
// { state: "failing", failures: 2, failingSince: "...", error: "GitHub was unavailable", emitted: 4, refused: 0, ... }
```

Status lines never carry outside text, so they are safe to show to an agent.

## Troubleshooting

- **`not_listening` (404) from `receive`.** Nothing is subscribed to that
  source, so it is not running. Subscribe at startup.
- **`policy_unavailable` from a webhook.** The credential store or replay
  ledger threw, a credential's secret is under 32 characters (the log names
  it), or the replay ledger is full of live keys.
- **A polling source reports nothing on its first look.** That is the rule;
  use `backfill` for GitHub if you want the window.
- **`rate_limited` for a valid request.** The unauthenticated budget tripped
  after many refused requests, or too many requests were still
  authenticating at once; it clears when the minute passes. Give the body
  reader you pass to `receive` a deadline, so a sender that never finishes its
  body cannot hold room in the budget.
- **`replay` for a request you never delivered.** A copy of it is being
  delivered right now, or a `signed-body` sender sent byte-identical bodies
  for two different happenings. A request whose delivery failed (`503
  delivery_failed`) is not a replay: send it again.
