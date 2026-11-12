import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, renameSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { maskTest } from "../../dist/index.js";
import { newHost, collect } from "./helpers.mjs";

function folder(t) {
  const dir = mkdtempSync(join(tmpdir(), "telltale-folder-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** Write a file with a fixed mtime so "unchanged between two scans" does not depend on filesystem timing. */
function put(dir, name, content, mtimeS = 1_700_000_000) {
  const file = join(dir, name);
  writeFileSync(file, content);
  utimesSync(file, mtimeS, mtimeS);
}

async function watch(t, options = {}) {
  const dir = folder(t);
  put(dir, "existing.txt", "already here");
  const ctx = newHost();
  ctx.host.add({ id: "drop", type: "folder", options: { dir, every: "1s", ...options } });
  const sink = await collect(ctx.host, "drop");
  await ctx.clock.advance(0);
  return { dir, ...ctx, ...sink, scan: () => ctx.clock.advance(1000) };
}

test("the first scan is the starting point: files already there are not reported", async (t) => {
  const { events, scan } = await watch(t);
  await scan();
  await scan();
  assert.equal(events.length, 0);
});

test("a new file is reported once it is unchanged across two scans; a changed file is reported as changed", async (t) => {
  const { dir, events, scan } = await watch(t);
  put(dir, "scan.pdf", "partial");
  await scan();
  assert.equal(events.length, 0, "seen once: may still be growing");
  put(dir, "scan.pdf", "partial and more", 1_700_000_100);
  await scan();
  assert.equal(events.length, 0, "it changed between scans: still waiting");
  await scan();
  assert.equal(events.length, 1);
  assert.equal(events[0].name, "added");
  assert.deepEqual(events[0].payload, { file: "scan.pdf", size: 16 });
  assert.equal(events[0].trust, "untrusted");
  await scan();
  assert.equal(events.length, 1, "unchanged: reported once");

  put(dir, "existing.txt", "edited content", 1_700_000_200);
  await scan();
  await scan();
  assert.equal(events.length, 2);
  assert.equal(events[1].name, "changed");
  assert.equal(events[1].payload.file, "existing.txt");
});

test("subfolders, masks and the default ignore list apply; links are never followed", async (t) => {
  const { dir, events, scan } = await watch(t, { mask: "*.{csv,pdf}" });
  mkdirSync(join(dir, "nested"));
  mkdirSync(join(dir, "node_modules"));
  put(dir, "nested/report.csv", "a,b");
  put(dir, "node_modules/x.csv", "ignored");
  put(dir, "notes.txt", "not matching the mask");
  const outside = folder(t);
  put(outside, "secret.csv", "outside the folder");
  symlinkSync(join(outside, "secret.csv"), join(dir, "link.csv"));
  await scan();
  await scan();
  assert.deepEqual(events.map((e) => e.payload.file), ["nested/report.csv"]);
});

test("an unchanged scan writes nothing to state", async (t) => {
  const { state, scan } = await watch(t);
  const writes = [];
  const set = state.set.bind(state);
  state.set = (k, v) => (writes.push(k), set(k, v));
  await scan();
  await scan();
  assert.deepEqual(writes, []);
});

test("more files than maxFiles fails the scan instead of truncating, and shows in the status", async (t) => {
  const dir = folder(t);
  for (let i = 0; i < 4; i++) put(dir, `f${i}.txt`, "x");
  const ctx = newHost();
  ctx.host.add({ id: "drop", type: "folder", options: { dir, every: "1s", maxFiles: 3 } });
  await collect(ctx.host, "drop");
  await ctx.clock.advance(0);
  assert.equal(ctx.host.status("drop").state, "failing");
  assert.match(ctx.host.status("drop").error, /more than 3 files/);
});

test("a missing or relative folder is refused at add", () => {
  const { host } = newHost();
  assert.throws(() => host.add({ id: "a", type: "folder", options: { dir: "relative/path" } }), /absolute/);
  assert.throws(() => host.add({ id: "b", type: "folder", options: { dir: "/definitely/not/here" } }), /not a folder/);
});

test("maskTest", () => {
  assert.ok(maskTest("*.pdf").test("A.PDF"));
  assert.ok(maskTest("*.{png,jpg}").test("x.jpg"));
  assert.ok(maskTest("a?.txt, b*.md").test("bee.md"));
  assert.ok(!maskTest("*.pdf").test("x.pdf.exe"));
});

// ---- Fix round 1 -------------------------------------------------------------

test("a folder replaced by a link to another folder after the starting point is not read: the scan fails", async (t) => {
  const { dir, events, host, scan } = await watch(t);
  const outside = folder(t);
  put(outside, "private.txt", "outside data");
  const moved = `${dir}-moved`;
  t.after(() => rmSync(moved, { recursive: true, force: true }));
  renameSync(dir, moved);
  symlinkSync(outside, dir);
  t.after(() => rmSync(dir, { force: true }));
  await scan();
  await scan();
  assert.deepEqual(events, [], "nothing from the other folder was reported");
  assert.equal(host.status("drop").state, "failing");
  assert.match(host.status("drop").error, /replaced/);
});

test("a folder replaced by another real folder at the same path is not read either", async (t) => {
  const { dir, events, host, scan } = await watch(t);
  const moved = `${dir}-moved`;
  t.after(() => rmSync(moved, { recursive: true, force: true }));
  renameSync(dir, moved);
  mkdirSync(dir);
  put(dir, "planted.txt", "a different folder");
  await scan();
  await scan();
  assert.deepEqual(events, []);
  assert.match(host.status("drop").error, /replaced/);
});

async function bounded(t, build, options) {
  const dir = folder(t);
  build(dir);
  const ctx = newHost();
  ctx.host.add({ id: "drop", type: "folder", options: { dir, every: "1s", ...options } });
  await collect(ctx.host, "drop");
  await ctx.clock.advance(0);
  return ctx.host.status("drop");
}

test("traversal is bounded by folders, depth and entries read, not only by files found", async (t) => {
  // The reviewer's case: maxFiles 1 and 1,200 empty folders.
  const many = await bounded(t, (d) => {
    for (let i = 0; i < 1200; i++) mkdirSync(join(d, `d${i}`));
  }, { maxFiles: 1 });
  assert.equal(many.state, "failing");
  assert.match(many.error, /more than 1000 folders/);

  const deep = await bounded(t, (d) => mkdirSync(join(d, "a/b/c/d/e"), { recursive: true }), { maxDepth: 3 });
  assert.match(deep.error, /more than 3 deep/);

  // Entries count even when every one is ignored or filtered out.
  const noisy = await bounded(t, (d) => {
    for (let i = 0; i < 50; i++) put(d, `f${i}.tmp`, "x");
  }, { maxEntries: 20 });
  assert.match(noisy.error, /more than 20 entries/);

  const within = await bounded(t, (d) => {
    for (let i = 0; i < 5; i++) mkdirSync(join(d, `d${i}`));
  }, { maxDirectories: 5, maxEntries: 5 });
  assert.equal(within.state, "running", "at the bound is allowed; max + 1 is refused");
});

test("bounds are checked at plan time", () => {
  const { host } = newHost();
  const dir = tmpdir();
  for (const key of ["maxDirectories", "maxDepth", "maxEntries"]) {
    assert.throws(() => host.plan("folder", { dir, [key]: 0 }), new RegExp(key));
  }
});

test("a folder already replaced by a link when the source starts is refused, not read through the link", async (t) => {
  const dir = folder(t);
  const outside = folder(t);
  put(outside, "private.txt", "outside data");
  const ctx = newHost();
  ctx.host.add({ id: "drop", type: "folder", options: { dir, every: "1s" } });
  // Swapped between add() (which resolved the path) and the first subscriber.
  const moved = `${dir}-moved`;
  t.after(() => rmSync(moved, { recursive: true, force: true }));
  renameSync(dir, moved);
  symlinkSync(outside, dir);
  t.after(() => rmSync(dir, { force: true }));
  const events = [];
  await ctx.host.subscribe("drop", (e) => void events.push(e)).catch(() => {});
  await ctx.clock.advance(0);
  put(outside, "later.txt", "more outside data");
  await ctx.clock.advance(1000);
  await ctx.clock.advance(1000);
  assert.deepEqual(events, []);
  assert.notEqual(ctx.host.status("drop").state, "running");
  assert.match(ctx.host.status("drop").error ?? "", /replaced/);
});
