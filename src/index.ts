/**
 * Telltale: the Kontour suite's event actor.
 *
 * Typed sources report what happens elsewhere. Trust is stamped from where an
 * event entered, never from what it says. It reports; it never starts work.
 * See README.md and docs/design.md.
 */

// Host
export { TelltaleHost, POLL_BACKOFF_MAX_MS, DEFAULT_MAX_HOPS } from "./host.js";
export type { AddSourceInput, SourceInfo, SourceStatus, Subscriber, Subscription, TelltaleHostOptions } from "./host.js";

// Envelope and vocabulary
export type { EventSourceRef, Logger, MaybePromise, Refusal, TelltaleEvent, Trust } from "./types.js";
export { silentLogger } from "./types.js";

// Source-type contract
export type {
  EmitMeta,
  OptionKind,
  OptionSpec,
  ReceivedRequest,
  ReceiveResult,
  SourceApi,
  SourcePlan,
  SourceType,
} from "./source-type.js";
export { DeliveryError, SourceError, SourceStoppedError } from "./source-type.js";

// Clock, state, secrets
export type { Clock } from "./clock.js";
export { ManualClock, SystemClock, settle } from "./clock.js";
export type { StateStore } from "./store.js";
export { InMemoryStateStore } from "./store.js";
export { MIN_SECRET_LENGTH, REDACTED, SecretRegistry } from "./secrets.js";
export { harmless, parseDuration } from "./util.js";

// webhook
export { webhookSourceType } from "./sources/webhook.js";
export type { WebhookBindings, WebhookHeaderNames, WebhookScheme } from "./sources/webhook.js";
export {
  AttemptLimiter,
  FailureBudget,
  InMemoryReplayLedger,
  InMemoryWebhookAudit,
  MIN_WEBHOOK_SECRET_LENGTH,
  ReplayLedgerFullError,
  WEBHOOK_REFUSAL_REASONS,
} from "./sources/webhook-guards.js";
export type {
  ReplayLedger,
  UnauthenticatedBudget,
  WebhookAudit,
  WebhookAuditEntry,
  WebhookCredential,
  WebhookCredentials,
  WebhookLookup,
  WebhookRefusalReason,
} from "./sources/webhook-guards.js";

// github-poll
export {
  CURSOR_OVERLAP_MS,
  DEFAULT_MAX_EVENT_AGE_MS,
  GITHUB_WORKFLOW_RUN_FIELDS,
  MAX_PINNED_WORKFLOW_FILES,
  WORKFLOW_RUN_COMPLETED,
  githubPollSourceType,
  githubPollStep,
  listGitHubWorkflowRuns,
  normalizeGitHubWorkflowRun,
  workflowRunSemanticKey,
} from "./sources/github-poll.js";
export type {
  GitHubFetch,
  GitHubPollBindings,
  GitHubPollCursor,
  GitHubPollObservation,
  GitHubPollStep,
  GitHubRunNormalization,
  GitHubRunRefusalReason,
  GitHubWorkflowRunListing,
} from "./sources/github-poll.js";

// folder
export { folderSourceType, maskTest } from "./sources/folder.js";
