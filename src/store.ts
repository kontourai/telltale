import type { MaybePromise } from "./types.js";

/**
 * Private, durable bookkeeping for sources: what a poll last saw, a cursor,
 * which files were already reported. It is Telltale's own state, never
 * authoritative product state, and holds no secrets or outside text beyond
 * what a source needs to recognise "the same as last time".
 *
 * The host namespaces keys per source, so a source cannot read another's.
 * Implement it over any storage; methods may return promises.
 */
export interface StateStore {
  get(key: string): MaybePromise<unknown>;
  set(key: string, value: unknown): MaybePromise<void>;
  delete(key: string): MaybePromise<void>;
}

/** The default store. Values are deep-copied in and out so callers cannot alias them. */
export class InMemoryStateStore implements StateStore {
  readonly #values = new Map<string, unknown>();

  get(key: string): unknown {
    return this.#values.has(key) ? structuredClone(this.#values.get(key)) : undefined;
  }

  set(key: string, value: unknown): void {
    this.#values.set(key, structuredClone(value));
  }

  delete(key: string): void {
    this.#values.delete(key);
  }

  /** Keys currently stored, for tests and debugging. */
  keys(): string[] {
    return [...this.#values.keys()];
  }
}
