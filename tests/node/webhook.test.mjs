import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { FailureBudget, InMemoryReplayLedger, InMemoryWebhookAudit, settle } from "../../dist/index.js";
import { newHost, collect } from "./helpers.mjs";

// Generated per run: 24 random bytes are 32 base64url characters, the floor.
const SECRET = randomBytes(24).toString("base64url");
const WEAK = "w".repeat(16);
const START = 1_780_000_000_000;
const ts = (ms = START) => String(Math.floor(ms / 1000));
const nonce = () => randomBytes(16).toString("base64url");

const sign = (body, n, at = ts(), secret = SECRET) =>
  `sha256=${createHmac("sha256", secret).update(`${at}\n${n}\n${body}`).digest("hex")}`;

/** Station-style named credentials, re-read per request. `config` is mutable by the test. */
function credentialStore(config) {
  const calls = { lookups: 0 };
  return {
    calls,
    credentials: {
      lookup(id) {
        calls.lookups++;
        if (config.unavailable) throw new Error("config file is corrupt");
        if (config.enabled !== true) return { enabled: false };
        return { enabled: true, credential: config.tokens.find((t) => t.id === id) };
      },
    },
  };
}

async function setup({ config, options = {}, bindings = {} } = {}) {
  const cfg = config ?? { enabled: true, tokens: [{ id: "ci-deploy", secret: SECRET }] };
  const store = credentialStore(cfg);
  const audit = new InMemoryWebhookAudit();
  const replay = new InMemoryReplayLedger();
  const ctx = newHost({ start: START });
  ctx.host.add({
    id: "inbound",
    type: "webhook",
    options,
    bindings: { credentials: store.credentials, audit, replay, ...bindings },
  });
  const sink = await collect(ctx.host, "inbound");
  return { ...ctx, ...sink, cfg, store, audit, replay };
}

function request(body, { token = "ci-deploy", n = nonce(), at = ts(), signature, bodyReader } = {}) {
  return {
    headers: {
      "Content-Type": "application/json",
      "x-telltale-token": token,
      "x-telltale-timestamp": at,
      "x-telltale-nonce": n,
      "x-telltale-signature": signature ?? sign(body, n, at),
    },
    body: bodyReader ?? body,
  };
}

const BODY = JSON.stringify({ agent: "station", message: "CI failed: inspect the deploy receipt." });

test("a correctly signed request is accepted and reported once, untrusted, with the credential id", async () => {
  const { host, events } = await setup();
  const result = await host.receive("inbound", request(BODY));
  assert.equal(result.accepted, true);
  assert.equal(result.status, 202);
  assert.equal(events.length, 1);
  const [event] = events;
  assert.equal(event.topic, "inbound/received");
  assert.equal(event.trust, "untrusted");
  assert.equal(event.payload.credentialId, "ci-deploy");
  assert.deepEqual(event.payload.body, JSON.parse(BODY));
  assert.deepEqual(event.payload.headers, { "content-type": "application/json" });
  assert.match(event.dedupKey, /^request:[0-9a-f]{64}$/);
});

test("a bad signature is rejected, recorded, and reports nothing", async () => {
  const { host, events, audit } = await setup();
  // Valid header shape, wrong digest: this reaches the constant-time comparison.
  const result = await host.receive("inbound", request(BODY, { signature: `sha256=${"0".repeat(64)}` }));
  assert.deepEqual(result, { accepted: false, status: 403, reason: "invalid_signature", retryable: false });
  assert.equal(events.length, 0);
  assert.ok(audit.entries().some((e) => e.reason === "invalid_signature" && e.credentialId === "ci-deploy"));
});

test("a signature made with another secret, or over other bytes, is rejected", async () => {
  const { host, events } = await setup();
  const n = nonce();
  const forged = await host.receive("inbound", request(BODY, { n, signature: sign(BODY, n, ts(), "another-secret-of-at-least-32-chars!!") }));
  assert.equal(forged.reason, "invalid_signature");
  const n2 = nonce();
  const tampered = await host.receive("inbound", { ...request(BODY, { n: n2 }), body: BODY.replace("deploy", "delete") });
  assert.equal(tampered.reason, "invalid_signature");
  assert.equal(events.length, 0);
});

test("the HMAC covers the raw received bytes, not a re-serialization", async () => {
  const { host, events } = await setup();
  const raw = '{ "agent"   : "station",\n  "message" : "deploy finished" }';
  const result = await host.receive("inbound", request(raw));
  assert.equal(result.accepted, true);
  assert.equal(events[0].payload.body.message, "deploy finished");
});

test("a replayed nonce is rejected and reports nothing the second time", async () => {
  const { host, events, audit } = await setup();
  const n = "replay-proof-nonce-0001";
  assert.equal((await host.receive("inbound", request(BODY, { n }))).status, 202);
  const replay = await host.receive("inbound", request(BODY, { n }));
  assert.deepEqual(replay, { accepted: false, status: 403, reason: "replay", retryable: false });
  assert.equal(events.length, 1);
  assert.ok(audit.entries().some((e) => e.reason === "replay"));
});

test("a future-skewed request cannot be replayed after its receipt-anchored expiry would have passed", async () => {
  const { host, clock, events } = await setup();
  const windowMs = 5 * 60_000;
  const skewed = ts(START + windowMs - 1000);
  const n = nonce();
  assert.equal((await host.receive("inbound", request(BODY, { n, at: skewed }))).status, 202);
  // Receipt time + window has passed; the signed timestamp keeps the request fresh.
  await clock.set(START + windowMs + 1000);
  const replay = await host.receive("inbound", request(BODY, { n, at: skewed }));
  assert.equal(replay.reason, "replay");
  assert.equal(events.length, 1);
});

test("an unauthenticated caller cannot burn a nonce: a bad signature claims nothing", async () => {
  const { host, events } = await setup();
  const n = nonce();
  await host.receive("inbound", request(BODY, { n, signature: `sha256=${"1".repeat(64)}` }));
  const real = await host.receive("inbound", request(BODY, { n }));
  assert.equal(real.status, 202);
  assert.equal(events.length, 1);
});

test("a stale timestamp is refused before anything is reported", async () => {
  const { host, events } = await setup();
  const old = ts(START - 5 * 60_000 - 1000);
  const result = await host.receive("inbound", request(BODY, { at: old }));
  assert.equal(result.reason, "stale_timestamp");
  assert.equal(result.status, 403);
  assert.equal(events.length, 0);
});

test("unknown and revoked credentials are told apart, and revocation applies to the next request", async () => {
  const { host, cfg, events, audit } = await setup();
  const unknown = await host.receive("inbound", request(BODY, { token: "missing" }));
  assert.deepEqual([unknown.status, unknown.reason], [401, "unknown_token"]);
  assert.ok(audit.entries().every((e) => e.credentialId !== "missing"), "an attacker-chosen id is not recorded");
  cfg.tokens[0].revokedAt = "2026-08-16T00:00:00.000Z";
  const revoked = await host.receive("inbound", request(BODY));
  assert.deepEqual([revoked.status, revoked.reason], [403, "revoked_token"]);
  assert.equal(events.length, 0);
});

test("the off switch refuses a valid signature", async () => {
  const { host, events } = await setup({ config: { enabled: false, tokens: [{ id: "ci-deploy", secret: SECRET }] } });
  const result = await host.receive("inbound", request(BODY));
  assert.deepEqual([result.status, result.reason], [403, "disabled"]);
  assert.equal(events.length, 0);
});

test("header-only refusals never read the body", async () => {
  for (const [label, config, overrides, reason] of [
    ["off switch", { enabled: false, tokens: [] }, {}, "disabled"],
    ["unknown token", { enabled: true, tokens: [] }, {}, "unknown_token"],
    ["stale timestamp", undefined, { at: ts(START - 3_600_000) }, "stale_timestamp"],
    ["bad nonce", undefined, { n: "short" }, "malformed_request"],
  ]) {
    const { host } = await setup({ config });
    let reads = 0;
    const result = await host.receive(
      "inbound",
      request(BODY, { ...overrides, bodyReader: async () => (reads++, Buffer.from(BODY)) }),
    );
    assert.equal(result.reason, reason, label);
    assert.equal(reads, 0, `${label}: body was read`);
  }
});

test("a body over the bound is refused as malformed", async () => {
  const { host, events } = await setup({ options: { maxBodyBytes: 64 } });
  const big = JSON.stringify({ message: "x".repeat(100) });
  const result = await host.receive("inbound", request(big));
  assert.equal(result.reason, "malformed_request");
  assert.equal(events.length, 0);
});

test("a credential secret under 32 characters fails closed as policy_unavailable", async () => {
  const { host, events, log } = await setup({ config: { enabled: true, tokens: [{ id: "weak", secret: WEAK }] } });
  const result = await host.receive("inbound", request(BODY, { token: "weak" }));
  assert.equal(result.reason, "policy_unavailable");
  assert.equal(events.length, 0);
  assert.ok(log.lines.some((l) => l.includes('"weak"') && l.includes("32")), "the log names the credential and the floor");
  assert.ok(log.lines.every((l) => !l.includes(WEAK)), "but not the secret");
});

test("an unreadable credential store or replay ledger fails closed", async () => {
  const { host, cfg, events } = await setup();
  cfg.unavailable = true;
  assert.equal((await host.receive("inbound", request(BODY))).reason, "policy_unavailable");
  const broken = await setup({
    bindings: {
      replay: {
        reserve() {
          throw new Error("ledger corrupt");
        },
        commit() {},
        release() {},
      },
    },
  });
  assert.equal((await broken.host.receive("inbound", request(BODY))).reason, "policy_unavailable");
  assert.equal(events.length + broken.events.length, 0);
});

test("a replay ledger full of live keys refuses rather than evicting one", async () => {
  const { host, events } = await setup({ bindings: { replay: new InMemoryReplayLedger(2) } });
  assert.equal((await host.receive("inbound", request(BODY))).status, 202);
  assert.equal((await host.receive("inbound", request(BODY))).status, 202);
  assert.equal((await host.receive("inbound", request(BODY))).reason, "policy_unavailable");
  assert.equal(events.length, 2);
});

test("per-credential attempts are limited, with Retry-After", async () => {
  const { host } = await setup({ options: { perCredentialPerMinute: 3 } });
  for (let i = 0; i < 3; i++) assert.equal((await host.receive("inbound", request(BODY))).status, 202);
  const limited = await host.receive("inbound", request(BODY));
  assert.equal(limited.status, 429);
  assert.equal(limited.reason, "rate_limited");
  assert.equal(limited.retryAfterSeconds, 60);
});

test("once the unauthenticated budget trips, rotating ids cost no lookup and a valid request is refused too", async () => {
  const { host, store, audit, events } = await setup({ options: { unauthenticatedPerMinute: 5 } });
  for (let i = 0; i < 5; i++) await host.receive("inbound", request(BODY, { token: `rotating-${i}` }));
  const lookupsAtTrip = store.calls.lookups;
  const entriesAtTrip = audit.entries().length;
  for (let i = 5; i < 50; i++) {
    const r = await host.receive("inbound", request(BODY, { token: `rotating-${i}` }));
    assert.equal(r.status, 429);
  }
  assert.equal(store.calls.lookups, lookupsAtTrip, "no credential lookup after the trip");
  const valid = await host.receive("inbound", request(BODY));
  assert.equal(valid.reason, "rate_limited", "the disclosed availability trade: a valid request is refused too");
  assert.equal(events.length, 0);
  await new Promise((r) => setImmediate(r));
  assert.equal(audit.entries().length, entriesAtTrip, "post-trip noise writes no per-request audit");
});

test("one bound budget is shared: a flood against one webhook source trips another", async () => {
  const budget = new FailureBudget(3, 60_000);
  const ctx = newHost({ start: START });
  for (const id of ["one", "two"]) {
    ctx.host.add({ id, type: "webhook", options: { scheme: "signed-body", secret: SECRET }, bindings: { budget } });
    await collect(ctx.host, id);
  }
  for (let i = 0; i < 3; i++) await ctx.host.receive("one", { headers: {}, body: "{}" });
  const body = "{}";
  const valid = {
    headers: { "x-hub-signature-256": `sha256=${createHmac("sha256", SECRET).update(body).digest("hex")}`, "x-github-delivery": "d-1" },
    body,
  };
  assert.equal((await ctx.host.receive("two", valid)).reason, "rate_limited");
  await ctx.clock.advance(60_000);
  assert.equal((await ctx.host.receive("two", valid)).status, 202, "the window passed");
});

test("post-trip noise is aggregated and cannot evict earlier audit entries", async () => {
  const audit = new InMemoryWebhookAudit(10);
  const { host, clock } = await setup({ options: { unauthenticatedPerMinute: 3 }, bindings: { audit } });
  for (let i = 0; i < 3; i++) await host.receive("inbound", request(BODY, { token: `x${i}` }));
  await new Promise((r) => setImmediate(r));
  const before = audit.entries();
  assert.equal(before.length, 3);
  for (let i = 0; i < 200; i++) await host.receive("inbound", request(BODY, { token: `y${i}` }));
  await clock.advance(60_000);
  const after = audit.entries();
  assert.deepEqual(after.slice(0, 3), before, "earlier entries survive");
  assert.equal(after.length, 4);
  assert.equal(after[3].reason, "unauthenticated_flood");
  assert.equal(after[3].count, 200);
});

test("a credential secret never appears in an emitted event or a log, even when the body echoes it", async () => {
  const { host, events, log, audit } = await setup();
  const body = JSON.stringify({ message: `my secret is ${SECRET}`, [SECRET]: true });
  assert.equal((await host.receive("inbound", request(body))).status, 202);
  await host.receive("inbound", request(body, { signature: `sha256=${"0".repeat(64)}` }));
  const everything = JSON.stringify({ events, log: log.lines, audit: audit.entries(), list: host.list() });
  assert.ok(everything.includes("[redacted]"), "the check reached the echoed secret");
  assert.ok(!everything.includes(SECRET), "the secret leaked");
});

test("headers that carry credentials are never kept, and cannot be asked for", async () => {
  const { host, events } = await setup({ options: { keepHeaders: ["x-request-id"] } });
  const req = request(BODY);
  req.headers.authorization = "Bearer something-long-enough";
  req.headers["x-request-id"] = "req-1";
  await host.receive("inbound", req);
  assert.deepEqual(Object.keys(events[0].payload.headers).sort(), ["content-type", "x-request-id"]);
  assert.throws(() => host.add({ id: "h2", type: "webhook", options: { secret: SECRET, keepHeaders: ["Authorization"] } }), /cannot be kept/);
});

test("trust cannot be raised by payload content or headers", async () => {
  const { host, events } = await setup();
  const body = JSON.stringify({ trust: "owner", source: { id: "owner-console" }, hops: -1 });
  const req = request(body);
  req.headers["x-telltale-trust"] = "owner";
  await host.receive("inbound", req);
  assert.equal(events[0].trust, "untrusted");
  assert.deepEqual(events[0].source, { id: "inbound", type: "webhook" });
  assert.equal(events[0].hops, 0);
});

test("signed-body (GitHub style): verifies X-Hub-Signature-256 over the body and refuses the same signed body again", async () => {
  const ctx = newHost({ start: START });
  ctx.host.add({ id: "gh", type: "webhook", options: { scheme: "signed-body", secret: SECRET } });
  const { events } = await collect(ctx.host, "gh");
  const body = JSON.stringify({ action: "completed", workflow_run: { id: 1 } });
  const sig = `sha256=${createHmac("sha256", SECRET).update(body).digest("hex")}`;
  const req = (delivery, signature = sig) => ({
    headers: { "X-Hub-Signature-256": signature, "X-GitHub-Delivery": delivery, "X-GitHub-Event": "workflow_run" },
    body,
  });
  const ok = await ctx.host.receive("gh", req("72d3162e-cc78-11e3-81ab-4c9367dc0958"));
  assert.equal(ok.status, 202);
  assert.equal(events[0].deliveryId, "72d3162e-cc78-11e3-81ab-4c9367dc0958");
  assert.equal(events[0].payload.headers["x-github-event"], "workflow_run");
  assert.match(events[0].dedupKey, /^request:[0-9a-f]{64}$/);
  assert.equal((await ctx.host.receive("gh", req("72d3162e-cc78-11e3-81ab-4c9367dc0958"))).reason, "replay");
  assert.equal((await ctx.host.receive("gh", req("other-delivery", `sha256=${"a".repeat(64)}`))).reason, "invalid_signature");
  assert.equal((await ctx.host.receive("gh", { headers: { "X-Hub-Signature-256": sig }, body })).reason, "malformed_request");
  assert.equal(events.length, 1);
});

test("bearer: a wrong token is rejected before the body is read", async () => {
  const ctx = newHost({ start: START });
  ctx.host.add({ id: "b", type: "webhook", options: { scheme: "bearer", secret: SECRET } });
  const { events } = await collect(ctx.host, "b");
  let reads = 0;
  const wrong = await ctx.host.receive("b", {
    headers: { authorization: "Bearer not-the-secret-at-all-not-at-all" },
    body: async () => (reads++, "{}"),
  });
  assert.equal(wrong.reason, "invalid_signature");
  assert.equal(reads, 0);
  const right = await ctx.host.receive("b", { headers: { authorization: `Bearer ${SECRET}` }, body: '{"ring":1}' });
  assert.equal(right.status, 202);
  assert.deepEqual(events[0].payload.body, { ring: 1 });
  assert.deepEqual(ctx.host.plan("webhook", { scheme: "bearer", secret: SECRET }).does.some((d) => /without integrity/.test(d)), true);
});

test("a static secret shorter than 32 characters is refused at add", () => {
  const { host } = newHost();
  assert.throws(() => host.add({ id: "w", type: "webhook", options: { secret: "x".repeat(20) } }), /at least 32/);
});

test("a subscriber failure answers 503 delivery_failed", async () => {
  const { host } = await setup();
  await host.subscribe("inbound", () => {
    throw new Error("ledger down");
  });
  const result = await host.receive("inbound", request(BODY));
  assert.deepEqual(result, { accepted: false, status: 503, reason: "delivery_failed", retryable: true });
});

// ---- Fix round 1 -------------------------------------------------------------

const ghSign = (body, secret = SECRET) => `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;

async function githubHook(options = {}, bindings = {}) {
  const ctx = newHost({ start: START });
  ctx.host.add({ id: "gh", type: "webhook", options: { scheme: "signed-body", secret: SECRET, ...options }, bindings });
  return { ...ctx, ...(await collect(ctx.host, "gh")) };
}

test("signed-body: replay identity comes from the signed bytes, not the unsigned delivery header", async () => {
  const { host, events } = await githubHook();
  const body = JSON.stringify({ action: "completed", workflow_run: { id: 7 } });
  const req = (delivery) => ({ headers: { "x-hub-signature-256": ghSign(body), "x-github-delivery": delivery }, body });
  const first = await host.receive("gh", req("captured-delivery"));
  assert.equal(first.status, 202);
  // A captured body and signature with a new delivery id is the same signed request.
  const replayed = await host.receive("gh", req("attacker-replacement"));
  assert.deepEqual([replayed.status, replayed.reason], [403, "replay"]);
  assert.equal(events.length, 1);
  assert.equal(events[0].deliveryId, "captured-delivery", "the delivery id is still carried, as metadata");
});

test("signed-body: GitHub's redelivery (same body, same GUID) is refused once delivered, and delivered when the first try failed", async () => {
  const { host } = await githubHook();
  let fail = true;
  const delivered = [];
  await host.subscribe("gh", (e) => {
    if (fail) throw new Error("consumer store unavailable");
    delivered.push(e);
  });
  const body = JSON.stringify({ action: "completed", workflow_run: { id: 8 } });
  const req = { headers: { "x-hub-signature-256": ghSign(body), "x-github-delivery": "guid-1" }, body };
  const first = await host.receive("gh", req);
  assert.deepEqual([first.status, first.reason, first.retryable], [503, "delivery_failed", true]);
  fail = false;
  const redelivery = await host.receive("gh", req);
  assert.equal(redelivery.status, 202, "a failed delivery left the key free for GitHub's redelivery");
  assert.equal(delivered.length, 1);
  const again = await host.receive("gh", req);
  assert.equal(again.reason, "replay", "after a delivered copy, the redelivery is a replay");
  assert.equal(delivered.length, 1);
});

test("bearer with a delivery header folds duplicate delivery ids, and says it has no replay protection", async () => {
  const ctx = newHost({ start: START });
  ctx.host.add({ id: "b", type: "webhook", options: { scheme: "bearer", secret: SECRET, headers: { delivery: "x-delivery" } } });
  const { events } = await collect(ctx.host, "b");
  const req = (delivery) => ({ headers: { authorization: `Bearer ${SECRET}`, "x-delivery": delivery }, body: "{}" });
  assert.equal((await ctx.host.receive("b", req("d-1"))).status, 202);
  assert.equal((await ctx.host.receive("b", req("d-1"))).reason, "replay");
  // Nothing is signed: whoever captured a request holds the credential and can send anything.
  assert.equal((await ctx.host.receive("b", req("d-2"))).status, 202);
  assert.equal(events.length, 2);
  assert.match(events[0].dedupKey, /^delivery:[0-9a-f]{64}$/);
  const plan = ctx.host.plan("webhook", { scheme: "bearer", secret: SECRET, headers: { delivery: "x-delivery" } });
  assert.ok(plan.does.some((d) => /NO replay protection/.test(d)));
});

test("an unsubscribe and a new subscriber do not reset the replay ledger, the limiter or the budget", async () => {
  const { host, subscription } = await setup({ options: { perCredentialPerMinute: 2, unauthenticatedPerMinute: 1000 } });
  const n = nonce();
  assert.equal((await host.receive("inbound", request(BODY, { n }))).status, 202);
  await subscription.unsubscribe();
  assert.equal(host.status("inbound").state, "stopped");
  const sink = await collect(host, "inbound");
  const replayed = await host.receive("inbound", request(BODY, { n }));
  assert.equal(replayed.reason, "replay", "the identical request is still a replay after resubscribing");
  assert.equal(sink.events.length, 0);
  // Two attempts already counted for this credential this minute.
  assert.equal((await host.receive("inbound", request(BODY))).reason, "rate_limited");
});

test("a credential rotated while the body is read: the request is verified with the secret that was looked up, and the new one never leaks", async () => {
  const token = { id: "ci-deploy", secret: SECRET };
  const ctx = newHost({ start: START });
  ctx.host.add({ id: "inbound", type: "webhook", bindings: { credentials: { lookup: () => ({ enabled: true, credential: token }) } } });
  const { events } = await collect(ctx.host, "inbound");
  const rotated = randomBytes(24).toString("base64url");
  const body = JSON.stringify({ message: `new secret ${rotated}` });
  const n = nonce();
  let release;
  const pending = ctx.host.receive("inbound", {
    ...request(body, { n, signature: sign(body, n, ts(), rotated) }),
    body: () => new Promise((resolve) => (release = resolve)),
  });
  await settle();
  token.secret = rotated;
  release(body);
  const result = await pending;
  assert.equal(result.reason, "invalid_signature");
  assert.equal(events.length, 0);
  assert.ok(!JSON.stringify(ctx.log.lines).includes(rotated));
});

test("a credential lookup failure logs a fixed code, never the store's exception text", async () => {
  const marker = "do-not-log-this-store-detail-0123456789";
  const ctx = newHost({ start: START });
  ctx.host.add({
    id: "inbound",
    type: "webhook",
    bindings: {
      credentials: {
        lookup() {
          throw new Error(`cannot read /etc/station/tokens: ${marker}`);
        },
      },
    },
  });
  await collect(ctx.host, "inbound");
  const result = await ctx.host.receive("inbound", request(BODY));
  assert.equal(result.reason, "policy_unavailable");
  assert.ok(ctx.log.lines.some((l) => l.includes("credential_lookup_failed")), "the failure is logged");
  assert.ok(ctx.log.lines.every((l) => !l.includes(marker)), "but not its text");
});

test("a retryable delivery failure leaves the request retryable; a concurrent copy is still refused", async () => {
  const { host } = await setup();
  let mode = "fail";
  let unblock;
  const delivered = [];
  await host.subscribe("inbound", async (e) => {
    if (mode === "fail") throw new Error("storage unavailable");
    if (mode === "block") await new Promise((resolve) => (unblock = resolve));
    delivered.push(e);
  });
  const n = nonce();
  const req = () => request(BODY, { n });
  const first = await host.receive("inbound", req());
  assert.deepEqual([first.status, first.reason, first.retryable], [503, "delivery_failed", true]);

  mode = "block";
  const retry = host.receive("inbound", req());
  await settle();
  const concurrent = await host.receive("inbound", req());
  assert.equal(concurrent.reason, "replay", "a copy arriving while one is being delivered is refused");
  unblock();
  const retried = await retry;
  assert.equal(retried.status, 202, "the identical retry was delivered");
  assert.equal(delivered.length, 1);

  mode = "ok";
  assert.equal((await host.receive("inbound", req())).reason, "replay", "once delivered, it is a replay");
  assert.equal(delivered.length, 1);
});

test("concurrent requests cannot overshoot the global budget: admission counts requests still in flight", async () => {
  const ctx = newHost({ start: START });
  let lookups = 0;
  ctx.host.add({
    id: "inbound",
    type: "webhook",
    options: { unauthenticatedPerMinute: 3 },
    bindings: {
      credentials: {
        async lookup() {
          lookups++;
          await new Promise((r) => setImmediate(r));
          return { enabled: true };
        },
      },
    },
  });
  await collect(ctx.host, "inbound");
  const results = await Promise.all(
    Array.from({ length: 100 }, (_, i) => ctx.host.receive("inbound", request(BODY, { token: `rotating-${i}` }))),
  );
  assert.ok(lookups <= 3, `${lookups} lookups for a budget of 3`);
  assert.ok(results.filter((r) => r.status === 429).length >= 97);
});

test("an authenticated request gives its admission back: the budget only charges refusals", async () => {
  const budget = new FailureBudget(2, 60_000);
  const { host } = await setup({ bindings: { budget } });
  for (let i = 0; i < 5; i++) assert.equal((await host.receive("inbound", request(BODY))).status, 202);
  assert.equal(budget.inflight, 0);
  assert.equal(budget.failures(START), 0);
});

test("replay and freshness share one boundary: at exactly signedAt + window the request is fresh and its key is live", async () => {
  const { host, clock, events } = await setup();
  const n = nonce();
  assert.equal((await host.receive("inbound", request(BODY, { n }))).status, 202);
  await clock.set(START + 300_000);
  const atBoundary = await host.receive("inbound", request(BODY, { n }));
  assert.equal(atBoundary.reason, "replay", "fresh (inclusive) and still remembered");
  await clock.set(START + 300_001);
  assert.equal((await host.receive("inbound", request(BODY, { n }))).reason, "stale_timestamp");
  assert.equal(events.length, 1);
  // The boundary is inclusive for a first delivery too.
  const fresh = await setup();
  await fresh.clock.set(START + 300_000);
  assert.equal((await fresh.host.receive("inbound", request(BODY))).status, 202);
});

test("a body that arrives after the window closed is stale", async () => {
  const { host, clock, events } = await setup();
  let release;
  const pending = host.receive("inbound", request(BODY, { bodyReader: () => new Promise((r) => (release = r)) }));
  await settle();
  await clock.advance(300_001);
  release(BODY);
  assert.equal((await pending).reason, "stale_timestamp");
  assert.equal(events.length, 0);
});

test("a security header given twice, in two spellings, is refused whichever comes first", async () => {
  for (const order of ["valid-last", "valid-first"]) {
    const { host, events } = await setup();
    const n = nonce();
    const good = sign(BODY, n);
    const bad = `sha256=${"0".repeat(64)}`;
    const base = request(BODY, { n });
    delete base.headers["x-telltale-signature"];
    base.headers = order === "valid-last"
      ? { ...base.headers, "x-telltale-signature": bad, "X-Telltale-Signature": good }
      : { ...base.headers, "X-Telltale-Signature": good, "x-telltale-signature": bad };
    const result = await host.receive("inbound", base);
    assert.equal(result.reason, "invalid_signature", order);
    assert.equal(events.length, 0);
  }
});

test("a __proto__ key in a signed body stays data: one subscriber cannot change what the next one sees", async () => {
  const { host } = await setup();
  const seen = {};
  await host.subscribe("inbound", (e) => {
    try {
      e.payload.body.__proto__.message = "changed by the first subscriber";
    } catch {
      seen.mutationRefused = true;
    }
    try {
      e.payload.body.message = "added by the first subscriber";
    } catch {
      seen.additionRefused = true;
    }
  });
  await host.subscribe("inbound", (e) => {
    seen.inherited = e.payload.body.message;
    seen.own = Object.getOwnPropertyDescriptor(e.payload.body, "__proto__")?.value?.message;
    seen.prototype = Object.getPrototypeOf(e.payload.body);
  });
  const body = '{"__proto__":{"message":"original"}}';
  const result = await host.receive("inbound", request(body));
  assert.equal(result.status, 202);
  assert.equal(seen.inherited, undefined, "nothing is inherited from the body");
  assert.equal(seen.own, "original", "the __proto__ key is an own, unchanged data property");
  assert.equal(seen.prototype, Object.prototype);
  assert.ok(seen.mutationRefused && seen.additionRefused, "the whole payload is frozen");
});

test("plan() and list() redact a copy of a secret wherever it appears, before and after add", async () => {
  const { host } = newHost({ start: START });
  // Hex, so it is also a valid header name: a copy of it outside the option marked secret.
  const secret = randomBytes(20).toString("hex");
  const options = { scheme: "signed-body", secret, headers: { delivery: secret } };
  const plan = host.plan("webhook", options);
  assert.equal(plan.options.secret, "[secret]");
  assert.ok(JSON.stringify(plan).includes("[redacted]"), "the check reached the copy");
  assert.ok(!JSON.stringify(plan).includes(secret), "a copy of the secret leaked from plan()");
  assert.equal(host.secrets.size, 0, "planning registers nothing with the host");
  host.add({ id: "gh", type: "webhook", options });
  assert.ok(!JSON.stringify(host.list()).includes(secret), "a copy of the secret leaked from list()");
});
