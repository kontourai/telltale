import { SourceError, type SourceApi, type SourceType } from "../source-type.js";
import { isRecord, parseDuration } from "../util.js";

/**
 * GitHub workflow runs, polled. Needs no inbound route.
 *
 * Three layers, so a consumer with its own scheduler and ledger can take only
 * what it needs:
 *
 * - {@link normalizeGitHubWorkflowRun}: one REST `workflow_run` to allow-listed
 *   string fields, or a closed refusal. Free text written by whoever triggered
 *   the run (titles, commit messages, actor names) is never read.
 * - {@link listGitHubWorkflowRuns} and {@link githubPollStep}: one bounded
 *   listing, and the pure cursor arithmetic over it (overlap, partial pages,
 *   freshness).
 * - {@link githubPollSourceType}: the source, which runs both on the host's
 *   poll and applies the delivery rules (first look is the starting point,
 *   an unchanged look does nothing, a failed look backs off).
 */

export const WORKFLOW_RUN_COMPLETED = "workflow_run.completed";

/** Fields a normalized run may carry. Matchers and episode keys can name only these. */
export const GITHUB_WORKFLOW_RUN_FIELDS = [
  "repository",
  "workflow.path",
  "run.id",
  "run.run_attempt",
  "run.event",
  "run.conclusion",
  "run.head_branch",
  "run.head_repository",
  "run.head_sha",
  "run.html_url",
] as const;

export type GitHubRunRefusalReason = "malformed_request" | "wrong_repository" | "stale_event";

/** Listing lag tolerated behind the cursor before a run counts as seen. */
export const CURSOR_OVERLAP_MS = 10 * 60 * 1000;
/** Runs older than this are refused as `stale_event`. */
export const DEFAULT_MAX_EVENT_AGE_MS = 72 * 60 * 60 * 1000;
export const GITHUB_RUNS_PER_PAGE = 20;
export const MAX_PINNED_WORKFLOW_FILES = 4;
const MAX_FIELD_LENGTH = 256;
const MAX_LISTING_BYTES = 1024 * 1024;
const MAX_PER_PAGE = 30;
const REQUEST_DEADLINE_MS = 10_000;
const MIN_INTERVAL_MS = 60_000;
const MAX_INTERVAL_MS = 86_400_000;
/** Bound on remembered run keys; refused at max+1 rather than silently forgetting. */
const MAX_SEEN = 50_000;

const HEAD_SHA = /^[0-9a-f]{40}$/;
const POSITIVE_INTEGER = /^[1-9][0-9]{0,15}$/;
// biome-ignore lint/suspicious/noControlCharactersInRegex: the class names the refused characters.
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
/** GitHub REST timestamps: second-precision UTC. */
const GITHUB_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const NAME = /^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?$/;
const WORKFLOW_FILE = /^[A-Za-z0-9_.-]{1,100}\.ya?ml$/;

export type GitHubRunNormalization =
  | Readonly<{ kind: "event"; semanticKey: string; fields: Readonly<Record<string, string>>; updatedAtMs: number }>
  | Readonly<{ kind: "refused"; reason: GitHubRunRefusalReason; semanticKey: string; updatedAtMs?: number }>;

const boundedText = (value: unknown): string | undefined =>
  typeof value === "string" && value.length > 0 && value.length <= MAX_FIELD_LENGTH && !CONTROL.test(value) ? value : undefined;

const decimalId = (value: unknown): string | undefined => {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) return undefined;
  const text = String(value);
  return POSITIVE_INTEGER.test(text) ? text : undefined;
};

const parseTimestamp = (value: unknown): number | undefined => {
  if (typeof value !== "string" || !GITHUB_TIMESTAMP.test(value)) return undefined;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : undefined;
};

/** Source-independent identity: a run seen by poll or by push is one key. */
export const workflowRunSemanticKey = (id: string, attempt: string) => `workflow_run:${id}:${attempt}:completed`;

/**
 * One REST `workflow_run` to allow-listed fields, or a refusal. Refusals:
 * `malformed_request` for a missing or invalid id, attempt, status,
 * conclusion, path, event, SHA, URL, branch or timestamp, or a timestamp in
 * the future; `wrong_repository` when `repository.full_name` is not
 * `repository`; `stale_event` when `updated_at` is older than `maxEventAgeMs`.
 * Numbers are carried as canonical decimal strings.
 */
export function normalizeGitHubWorkflowRun(
  run: unknown,
  context: { repository: string; receivedAt: number; maxEventAgeMs?: number },
): GitHubRunNormalization {
  const value = isRecord(run) ? run : undefined;
  const id = decimalId(value?.id);
  const attempt = decimalId(value?.run_attempt);
  const semanticKey = workflowRunSemanticKey(id ?? "invalid", attempt ?? "invalid");
  const updatedAtMs = parseTimestamp(value?.updated_at);
  const refuse = (reason: GitHubRunRefusalReason): GitHubRunNormalization => ({
    kind: "refused",
    reason,
    semanticKey,
    ...(updatedAtMs === undefined ? {} : { updatedAtMs }),
  });
  if (!value || !id || !attempt || updatedAtMs === undefined) return refuse("malformed_request");
  if (value.status !== "completed") return refuse("malformed_request");
  const repository = boundedText(isRecord(value.repository) ? value.repository.full_name : undefined);
  if (!repository) return refuse("malformed_request");
  if (repository !== context.repository) return refuse("wrong_repository");
  const conclusion = boundedText(value.conclusion);
  const event = boundedText(value.event);
  const workflowPath = boundedText(value.path);
  const headSha = typeof value.head_sha === "string" && HEAD_SHA.test(value.head_sha) ? value.head_sha : undefined;
  // Exact, never a prefix or a parse: a consumer may hand this URL on, so it
  // must point at this run in this repository and nowhere else.
  const htmlUrl = value.html_url === `https://github.com/${repository}/actions/runs/${id}` ? value.html_url : undefined;
  if (!conclusion || !event || !workflowPath || !headSha || !htmlUrl) return refuse("malformed_request");
  // A branch-less run or a deleted fork carries null: absent is honest.
  const headBranch = value.head_branch === null ? undefined : boundedText(value.head_branch);
  if (value.head_branch !== null && headBranch === undefined) return refuse("malformed_request");
  const headRepositoryValue = value.head_repository;
  const headRepository =
    headRepositoryValue === null ? undefined : boundedText(isRecord(headRepositoryValue) ? headRepositoryValue.full_name : undefined);
  if (headRepositoryValue !== null && headRepository === undefined) return refuse("malformed_request");
  const maxAge = context.maxEventAgeMs ?? DEFAULT_MAX_EVENT_AGE_MS;
  if (updatedAtMs < context.receivedAt - maxAge) return refuse("stale_event");
  if (updatedAtMs > context.receivedAt) return refuse("malformed_request");
  const fields: Record<string, string> = {
    repository,
    "workflow.path": workflowPath,
    "run.id": id,
    "run.run_attempt": attempt,
    "run.event": event,
    "run.conclusion": conclusion,
    "run.head_sha": headSha,
    "run.html_url": htmlUrl,
  };
  if (headBranch !== undefined) fields["run.head_branch"] = headBranch;
  if (headRepository !== undefined) fields["run.head_repository"] = headRepository;
  return { kind: "event", semanticKey, fields, updatedAtMs };
}

export type GitHubWorkflowRunListing =
  | Readonly<{ kind: "runs"; runs: readonly unknown[]; partial: boolean }>
  | Readonly<{ kind: "failed"; outcome: "unauthorized" | "unavailable"; detail: string }>;

export type GitHubFetch = (input: string, init: RequestInit) => Promise<Response>;

/**
 * One page of completed workflow runs, bounded in size and time. Never
 * paginates: a response that advertises more runs is `partial`. A redirect,
 * an oversized or malformed response, or a timeout is `unavailable`; 401, and
 * a 403 that is not a rate limit, are `unauthorized`. The token is sent only
 * to api.github.com and never appears in the result.
 */
export async function listGitHubWorkflowRuns(input: {
  repository: string;
  workflowFile?: string;
  token?: string;
  perPage?: number;
  signal?: AbortSignal;
  fetch?: GitHubFetch;
}): Promise<GitHubWorkflowRunListing> {
  const [owner, repo, extra] = input.repository.split("/");
  if (!owner || !repo || extra !== undefined || !NAME.test(owner) || !NAME.test(repo)) throw new Error("repository must be owner/repo");
  if (input.workflowFile !== undefined && !WORKFLOW_FILE.test(input.workflowFile)) throw new Error("workflow file must be a .yml or .yaml file name");
  const perPage = input.perPage ?? GITHUB_RUNS_PER_PAGE;
  if (!Number.isInteger(perPage) || perPage < 1 || perPage > MAX_PER_PAGE) throw new RangeError("perPage out of range");
  const fetcher = input.fetch ?? (globalThis.fetch as GitHubFetch);
  const signal = AbortSignal.any([AbortSignal.timeout(REQUEST_DEADLINE_MS), ...(input.signal ? [input.signal] : [])]);
  const base = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/actions`;
  const path = input.workflowFile ? `${base}/workflows/${encodeURIComponent(input.workflowFile)}/runs` : `${base}/runs`;
  const failed = (outcome: "unauthorized" | "unavailable", detail: string): GitHubWorkflowRunListing => ({ kind: "failed", outcome, detail });
  try {
    const response = await fetcher(`${path}?status=completed&per_page=${perPage}`, {
      method: "GET",
      redirect: "error",
      signal,
      headers: {
        Accept: "application/vnd.github+json",
        "User-Agent": "telltale",
        ...(input.token ? { Authorization: `Bearer ${input.token}` } : {}),
      },
    });
    if (response.redirected || response.type === "opaqueredirect") return failed("unavailable", "GitHub answered with a redirect");
    if (response.status === 401) return failed("unauthorized", "GitHub did not accept the credential");
    if (response.status === 403) {
      const limited = response.headers.get("x-ratelimit-remaining") === "0" || response.headers.has("retry-after");
      return limited ? failed("unavailable", "GitHub rate limit") : failed("unauthorized", "GitHub did not accept the credential");
    }
    if (response.status === 404 || response.status === 410) return failed("unavailable", "the repository or workflow is unavailable");
    if (!response.ok) return failed("unavailable", `GitHub answered HTTP ${response.status}`);
    const declared = Number(response.headers.get("content-length") ?? "0");
    if (!Number.isFinite(declared) || declared > MAX_LISTING_BYTES) return failed("unavailable", "GitHub response too large");
    const reader = response.body?.getReader();
    if (!reader) return failed("unavailable", "GitHub response had no body");
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > MAX_LISTING_BYTES) {
        await reader.cancel().catch(() => {});
        return failed("unavailable", "GitHub response too large");
      }
      chunks.push(next.value);
    }
    let value: unknown;
    try {
      value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      return failed("unavailable", "GitHub response was not JSON");
    }
    const runs = isRecord(value) ? value.workflow_runs : undefined;
    const total = isRecord(value) ? value.total_count : undefined;
    if (!Array.isArray(runs) || runs.length > perPage || !Number.isSafeInteger(total) || (total as number) < runs.length) {
      return failed("unavailable", "GitHub workflow run response was incomplete");
    }
    return { kind: "runs", runs, partial: (total as number) > runs.length || /rel="next"/.test(response.headers.get("link") ?? "") };
  } catch (error) {
    return failed("unavailable", error instanceof Error && error.name === "TimeoutError" ? "GitHub request timed out" : "GitHub request failed");
  }
}

/** Cursor state of one polled repository. */
export interface GitHubPollCursor {
  /** Newest accepted `updated_at` a complete poll processed (epoch ms). */
  cursorMs?: number;
}

export type GitHubPollObservation = GitHubRunNormalization;

export interface GitHubPollStep {
  outcome: "ok" | "partial" | "unauthorized" | "unavailable";
  /** Runs inside the window, oldest first. Includes re-reads inside the overlap. */
  observations: GitHubPollObservation[];
  /** The cursor to keep. Unchanged on a failed or partial poll. */
  cursor: GitHubPollCursor;
}

/**
 * The pure part of one poll: given the listings and the previous cursor,
 * which runs are in the window and where the cursor goes next.
 *
 * Runs older than `cursor - CURSOR_OVERLAP_MS` are skipped; runs inside the
 * overlap are returned again (the consumer dedupes on their key). A complete
 * response advances the cursor to the newest accepted run, and never trails
 * the freshness bound, so a run already too old is refused once, not on every
 * poll. A partial or failed response keeps the cursor.
 */
export function githubPollStep(input: {
  listings: readonly GitHubWorkflowRunListing[];
  cursor: GitHubPollCursor | undefined;
  repository: string;
  /** When the response was observed; runs are checked against this time. */
  observedAt: number;
  maxEventAgeMs?: number;
}): GitHubPollStep {
  const previous = input.cursor ?? {};
  const failed = input.listings.find((l) => l.kind === "failed");
  if (failed?.kind === "failed") return { outcome: failed.outcome, observations: [], cursor: previous };
  const maxEventAgeMs = input.maxEventAgeMs ?? DEFAULT_MAX_EVENT_AGE_MS;
  const updatedAtOf = (run: unknown) => {
    const ms = isRecord(run) && typeof run.updated_at === "string" ? Date.parse(run.updated_at) : Number.NaN;
    return Number.isFinite(ms) ? ms : Number.POSITIVE_INFINITY;
  };
  // Oldest first, so a consumer opening an episode opens it on the first failing run.
  const runs = input.listings.flatMap((l) => (l.kind === "runs" ? l.runs : [])).sort((a, b) => updatedAtOf(a) - updatedAtOf(b));
  const cutoff = previous.cursorMs === undefined ? Number.NEGATIVE_INFINITY : previous.cursorMs - CURSOR_OVERLAP_MS;
  const observations: GitHubPollObservation[] = [];
  let newest = Number.NEGATIVE_INFINITY;
  for (const run of runs) {
    const n = normalizeGitHubWorkflowRun(run, { repository: input.repository, receivedAt: input.observedAt, maxEventAgeMs });
    if (n.updatedAtMs !== undefined && n.updatedAtMs < cutoff) continue;
    observations.push(n);
    // A refused (e.g. future-dated) run never moves the cursor.
    if (n.kind === "event") newest = Math.max(newest, n.updatedAtMs);
  }
  const partial = input.listings.some((l) => l.kind === "runs" && l.partial);
  return {
    outcome: partial ? "partial" : "ok",
    observations,
    cursor: partial ? previous : { cursorMs: Math.max(newest, input.observedAt - maxEventAgeMs) },
  };
}

export interface GitHubPollBindings {
  /** Replaces the global `fetch` (tests, proxies). */
  fetch?: GitHubFetch;
  [key: string]: unknown;
}

interface PollMemory {
  cursor?: GitHubPollCursor;
  /** Keys already delivered (or taken as the starting point), with their run time, so the overlap re-read stays quiet. */
  seen: Record<string, number>;
}

export const githubPollSourceType: SourceType<GitHubPollBindings> = {
  summary: "completed GitHub Actions workflow runs of one repository, polled: reports each run once, with allow-listed fields only",
  options: {
    repository: { type: "string", required: true, description: "owner/repo" },
    every: { type: "string", description: 'how often to look, "1m" to "24h" (default "5m")' },
    workflowFiles: {
      type: "string[]",
      description: `up to ${MAX_PINNED_WORKFLOW_FILES} workflow file names under .github/workflows/ to list separately (keeps a long run on the first page); omit to list the whole repository`,
    },
    token: { type: "string", secret: true, description: "a GitHub token with actions:read; omit for a public repository" },
    backfill: {
      type: "boolean",
      description:
        "false (default): the first look is the starting point and reports nothing. true: the first look reports completed runs inside the freshness window",
    },
    maxEventAgeHours: { type: "number", description: "runs older than this are refused as stale_event (default 72)" },
  },
  plan(o) {
    const repository = String(o.repository);
    const [owner, repo, extra] = repository.split("/");
    if (!owner || !repo || extra !== undefined || !NAME.test(owner) || !NAME.test(repo)) throw new Error(`github-poll: "repository" must be owner/repo`);
    const every = (o.every as string | undefined) ?? "5m";
    const ms = parseDuration(every);
    if (ms < MIN_INTERVAL_MS || ms > MAX_INTERVAL_MS) throw new Error(`github-poll: "every" must be from "1m" to "24h"`);
    const files = (o.workflowFiles as string[] | undefined) ?? [];
    if (files.length > MAX_PINNED_WORKFLOW_FILES) {
      throw new Error(`github-poll: at most ${MAX_PINNED_WORKFLOW_FILES} workflowFiles; omit them to list the whole repository`);
    }
    for (const f of files) if (!WORKFLOW_FILE.test(f)) throw new Error(`github-poll: "${f}" is not a workflow file name`);
    const hours = (o.maxEventAgeHours as number | undefined) ?? 72;
    if (!Number.isInteger(hours) || hours < 1 || hours > 24 * 30) throw new Error(`github-poll: "maxEventAgeHours" must be an integer from 1 to 720`);
    return {
      options: { ...o, every, maxEventAgeHours: hours, backfill: o.backfill === true },
      does: [
        `ask api.github.com every ${every} for completed workflow runs of ${repository}${files.length ? ` (${files.join(", ")})` : ""}${o.token ? ", sending the token only there" : ""}`,
        o.backfill === true
          ? `report runs completed in the last ${hours}h on the first look, then each new run once`
          : "take the first look as the starting point, then report each new run once",
      ],
      opens: true,
    };
  },
  start(api: SourceApi<GitHubPollBindings>) {
    const o = api.options as { repository: string; every: string; workflowFiles?: string[]; token?: string; backfill: boolean; maxEventAgeHours: number };
    const maxEventAgeMs = o.maxEventAgeHours * 3_600_000;
    const files = o.workflowFiles?.length ? [...o.workflowFiles].sort() : [undefined];
    api.secret(o.token);
    api.poll(o.every, async (signal) => {
      const listings: GitHubWorkflowRunListing[] = [];
      for (const workflowFile of files) {
        listings.push(
          await listGitHubWorkflowRuns({
            repository: o.repository,
            ...(workflowFile ? { workflowFile } : {}),
            ...(o.token ? { token: o.token } : {}),
            signal,
            ...(api.bindings.fetch ? { fetch: api.bindings.fetch } : {}),
          }),
        );
        if (signal.aborted) return;
      }
      const observedAt = api.clock.now();
      const memory: PollMemory = (await api.state.get<PollMemory>("poll")) ?? { seen: {} };
      const step = githubPollStep({ listings, cursor: memory.cursor, repository: o.repository, observedAt, maxEventAgeMs });
      if (step.outcome === "unauthorized" || step.outcome === "unavailable") {
        throw new SourceError(step.outcome === "unauthorized" ? "GitHub did not accept the credential" : "GitHub was unavailable");
      }
      const baseline = memory.cursor === undefined && !o.backfill;
      try {
        for (const obs of step.observations) {
          if (memory.seen[obs.semanticKey] !== undefined) continue;
          if (!baseline) {
            if (obs.kind === "refused") await api.refuse(obs.reason, { dedupKey: obs.semanticKey });
            else {
              await api.emit(WORKFLOW_RUN_COMPLETED, obs.fields, {
                dedupKey: obs.semanticKey,
                occurredAt: obs.updatedAtMs,
              });
            }
          }
          memory.seen[obs.semanticKey] = obs.updatedAtMs ?? observedAt;
        }
        // Only a poll whose every observation was taken moves the cursor.
        memory.cursor = step.cursor;
      } finally {
        // Forget what the cursor has passed, and anything older than the freshness window:
        // such a run is refused as stale, and a page of newest runs does not bring it back.
        const floor = Math.max(
          (memory.cursor?.cursorMs ?? Number.NEGATIVE_INFINITY) - CURSOR_OVERLAP_MS,
          observedAt - maxEventAgeMs - CURSOR_OVERLAP_MS,
        );
        for (const [k, at] of Object.entries(memory.seen)) if (at < floor) delete memory.seen[k];
        await api.state.set("poll", memory);
      }
      if (Object.keys(memory.seen).length > MAX_SEEN) {
        throw new SourceError(`more than ${MAX_SEEN} runs remembered inside the freshness window; pin workflowFiles`);
      }
      api.status(step.outcome === "partial" ? "last look saw a partial page" : "");
    });
  },
};
