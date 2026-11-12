import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const root = new URL("../../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");

// The README's status line states the published version. release-please
// rewrites it in every release PR (README.md is in `extra-files`; the marker
// tells its generic updater which line to bump), so it must always equal
// package.json's version and must keep the marker that keeps it so.
test("README status line states package.json's version and is release-please managed", () => {
  const { version } = JSON.parse(read("package.json"));
  const statusLines = read("README.md")
    .split("\n")
    .filter((line) => /^Status:/i.test(line));
  assert.equal(statusLines.length, 1, "README has exactly one Status line");
  const [line] = statusLines;
  const claimed = line.match(/^Status:\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/i)?.[1];
  assert.ok(claimed, `README Status line must state a full version: ${line}`);
  assert.equal(claimed, version, `README claims ${claimed}, package is ${version}`);
  assert.match(line, /x-release-please-version/, "Status line lost the release-please version marker");

  const config = JSON.parse(read("release-please-config.json"));
  assert.ok(
    config.packages["."]["extra-files"]?.includes("README.md"),
    "release-please-config.json must list README.md in extra-files",
  );
});
