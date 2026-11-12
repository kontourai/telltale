// Runs the publish job's release guards, read straight out of
// .github/workflows/publish-npm.yml, against real git refs. They are the last
// thing between a ref and an OIDC-backed `npm publish`, and nothing else
// executes them before a release.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = new URL("../../", import.meta.url);
const workflow = readFileSync(new URL(".github/workflows/publish-npm.yml", root), "utf8");

// The guards, in the order the publish job runs them before the install.
const GUARDS = ["Verify Ref Is A Tag", "Verify Tag Matches Package Version", "Verify Tagged Commit Is On Main"];

function publishJobLines() {
  const lines = workflow.split("\n");
  const start = lines.indexOf("  publish:");
  assert.notEqual(start, -1, "publish-npm.yml has no publish job");
  const end = lines.findIndex((line, i) => i > start && /^ {2}\S/.test(line));
  return lines.slice(start, end === -1 ? undefined : end);
}

// Returns the `run: |` body of the named step, dedented.
function stepScript(name) {
  const lines = publishJobLines();
  const at = lines.indexOf(`      - name: ${name}`);
  assert.notEqual(at, -1, `publish job has no step named "${name}"`);
  const runAt = lines.findIndex((line, i) => i > at && /^ +run: \|$/.test(line));
  const nextStep = lines.findIndex((line, i) => i > at && /^ {6}- /.test(line));
  assert.ok(runAt !== -1 && (nextStep === -1 || runAt < nextStep), `step "${name}" has no run block`);
  const indent = lines[runAt].indexOf("run:");
  const body = [];
  for (const line of lines.slice(runAt + 1)) {
    if (line.trim() !== "" && line.search(/\S/) <= indent) break;
    body.push(line.slice(indent + 2));
  }
  return body.join("\n");
}

function git(cwd, env, ...args) {
  const r = spawnSync("git", args, { cwd, env, encoding: "utf8" });
  assert.equal(r.status, 0, `git ${args.join(" ")} failed: ${r.stderr}`);
  return r.stdout.trim();
}

// origin: main holds `onMain`; a side branch holds `offMain`. The job's checkout
// is a clone of origin, as actions/checkout leaves it.
function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), "telltale-publish-guards-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const env = {
    PATH: process.env.PATH,
    HOME: dir,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_AUTHOR_NAME: "t",
    GIT_AUTHOR_EMAIL: "t@example.invalid",
    GIT_COMMITTER_NAME: "t",
    GIT_COMMITTER_EMAIL: "t@example.invalid",
  };
  const origin = join(dir, "origin");
  spawnSync("git", ["init", "-q", "-b", "main", origin], { env });
  writeFileSync(join(origin, "package.json"), JSON.stringify({ name: "x", version: "0.1.0" }));
  git(origin, env, "add", "package.json");
  git(origin, env, "commit", "-q", "-m", "release 0.1.0");
  const onMain = git(origin, env, "rev-parse", "HEAD");
  git(origin, env, "checkout", "-q", "-b", "side");
  git(origin, env, "commit", "-q", "--allow-empty", "-m", "off main");
  const offMain = git(origin, env, "rev-parse", "HEAD");
  git(origin, env, "checkout", "-q", "main");
  const work = join(dir, "work");
  git(dir, env, "clone", "-q", origin, work);
  return { work, env, onMain, offMain };
}

// Runs the guards in order the way Actions runs `run:` steps (bash -e).
// Returns the name of the first guard that refused, or null when all passed.
function runGuards({ work, env }, { sha, ref }, guards = GUARDS) {
  const [, kind, name] = ref.match(/^refs\/(heads|tags)\/(.+)$/);
  const stepEnv = {
    ...env,
    GITHUB_SHA: sha,
    GITHUB_REF: ref,
    GITHUB_REF_NAME: name,
    GITHUB_REF_TYPE: kind === "tags" ? "tag" : "branch",
  };
  for (const guard of guards) {
    const r = spawnSync("bash", ["--noprofile", "--norc", "-eo", "pipefail", "-c", stepScript(guard)], {
      cwd: work,
      env: stepEnv,
      encoding: "utf8",
    });
    if (r.status !== 0) return guard;
  }
  return null;
}

test("a version tag on main whose version matches package.json passes every guard", (t) => {
  const f = fixture(t);
  assert.equal(runGuards(f, { sha: f.onMain, ref: "refs/tags/v0.1.0" }), null);
});

test("a branch named like the version tag is refused before install", (t) => {
  const f = fixture(t);
  const ref = { sha: f.onMain, ref: "refs/heads/v0.1.0" };
  // The name-based guards cannot tell this branch from the tag on their own...
  assert.equal(runGuards(f, ref, GUARDS.slice(1)), null);
  // ...so the ref-type guard is what refuses it.
  assert.equal(runGuards(f, ref), "Verify Ref Is A Tag");
});

test("a tag whose name does not match package.json is refused", (t) => {
  const f = fixture(t);
  assert.equal(runGuards(f, { sha: f.onMain, ref: "refs/tags/v0.2.0" }), "Verify Tag Matches Package Version");
});

test("a matching tag on a commit that is not on main is refused", (t) => {
  const f = fixture(t);
  assert.equal(runGuards(f, { sha: f.offMain, ref: "refs/tags/v0.1.0" }), "Verify Tagged Commit Is On Main");
});

test("the guards run before anything installs or publishes", () => {
  const steps = publishJobLines()
    .filter((line) => line.startsWith("      - name: "))
    .map((line) => line.slice("      - name: ".length));
  const install = steps.indexOf("Install");
  assert.notEqual(install, -1);
  for (const guard of GUARDS) {
    const at = steps.indexOf(guard);
    assert.ok(at !== -1 && at < install, `"${guard}" must run before Install`);
  }
});
