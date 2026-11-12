import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
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
