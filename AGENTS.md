# Agent Guide

## Source Of Truth

- Product/domain context: `CONTEXT.md`.
- Contract and semantics, with their origins: `docs/design.md`.
- Public API: `README.md` and `docs/reference.md`.
- Broad verification: `npm test`.
- Published docs: built with Corpus. `corpus.json` lists the published docs and MCP topics, and `npm run docs:check` is the gate. When you change code that a document `covers`, update that document.

## Match Checks To Change Type

- Docs/interface-only changes: inspect the Markdown diff and run `npm test` before merge readiness.
- TypeScript/API changes: run `npm run typecheck` plus the focused test file that covers the touched code (`npm run build && node --test tests/node/<file>.test.mjs`).
- Package or behavior changes: run `npm test`; it builds first, then runs deterministic `node --test` tests.
- Generated output: do not edit `dist/` or other generated files by hand.
- Releases use release-please with conventional commits; the version lives in
  `.release-please-manifest.json` and `package.json`. Merging the release PR
  tags the release and dispatches `publish-npm.yml`, which publishes through npm
  trusted publishing. Do not bump versions, push tags or run `npm publish` by hand.

## Useful Commands

- `npm test` - broad repo verification (`npm run build` plus `node --test tests/node/*.test.mjs`).
- `npm run typecheck` - TypeScript check without emitting build output.
- `npm run build` - compile TypeScript into `dist/`.
- `npm run test:node` - run the node test suite against an existing build.
- `npm run example` - build and run the signed-webhook demo.

## Repo Boundaries

- Telltale is the suite's event actor. It reports; it never starts work. Do not add rules, authority, actions, receipts or a consumer's dedup ledger here.
- Trust is stamped by the host from the source's registration. Never let a source type, payload, header or option raise it.
- A source only emits and refuses. A future source that sends decides itself where it may send; do not move that check to a consumer, prompt or router.
- A polling source uses `api.poll` and `api.changed`, never timers of its own. Status lines carry only source-authored text (`SourceError`) or `harmless()` values.
- Anything secret is an option marked `secret: true` or passed to `api.secret()`.
- Every security property has a test that fails when the code providing it is reverted. Add one with each new property, and prove it with fault injection (commit, clean tree, inject, red, restore, green).
- Keep runtime dependencies at zero unless a design note justifies one.

## Source-qualified documentation review

The Corpus gate selects the canonical documents mapped in `corpus.json` when
implementation inputs change. Review those claims against the actual code.
Update inaccurate prose in the same PR. Do not add filler text or refresh hashes
without inspecting the change. A passing check does not certify semantic
correctness, runtime or publication.

<!-- veritas:governance-block:start -->
This repo uses Veritas for AI governance. Read `.veritas/GOVERNANCE.md` before making changes.
After changes, run `npx --no @kontourai/veritas readiness` and address any FAIL lines before finishing.
If npx says the package is missing, install this repo's dependencies, adding `@kontourai/veritas` as a development dependency if it is not one, and run it again.
<!-- veritas:governance-block:end -->
