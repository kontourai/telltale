/**
 * Secret registry and redaction.
 *
 * Every value Telltale learns is a secret (an option marked `secret: true`, a
 * webhook credential resolved for a request, anything a source passes to
 * `api.secret()`) is registered here. Events, refusals, status lines and log
 * lines pass through `redact()` before anyone sees them, so a secret that
 * leaks into outside content (a body that echoes it, an error message that
 * quotes a URL) comes out as `[redacted]`.
 */

export const REDACTED = "[redacted]";

/**
 * Shorter secrets are refused rather than registered: redacting every
 * occurrence of a 3-character string would mangle ordinary text, and a value
 * that short is not a secret worth the name.
 */
export const MIN_SECRET_LENGTH = 8;

export class SecretRegistry {
  #secrets: string[] = [];

  /** Register a secret. Throws for one shorter than {@link MIN_SECRET_LENGTH}. */
  add(value: string): void {
    if (typeof value !== "string" || value.length < MIN_SECRET_LENGTH) {
      throw new Error(`a secret must be a string of at least ${MIN_SECRET_LENGTH} characters`);
    }
    if (this.#secrets.includes(value)) return;
    this.#secrets.push(value);
    // Longest first, so a secret that contains another is replaced whole.
    this.#secrets.sort((a, b) => b.length - a.length);
  }

  get size(): number {
    return this.#secrets.length;
  }

  /** A new registry with these secrets and every secret of this one, for redacting one request without keeping its values. */
  with(values: Iterable<string>): SecretRegistry {
    const copy = new SecretRegistry();
    for (const secret of this.#secrets) copy.add(secret);
    for (const value of values) copy.add(value);
    return copy;
  }

  /** Replace every registered secret in a string. */
  text(s: string): string {
    for (const secret of this.#secrets) if (s.includes(secret)) s = s.split(secret).join(REDACTED);
    return s;
  }

  /** Redact strings anywhere in a JSON-like value, keys included. Returns a new value. */
  deep<T>(value: T): T {
    return this.#deep(value, 0) as T;
  }

  #deep(value: unknown, depth: number): unknown {
    if (depth > 64) throw new Error("value is nested too deeply to redact");
    if (typeof value === "string") return this.text(value);
    if (Array.isArray(value)) return value.map((v) => this.#deep(v, depth + 1));
    if (value && typeof value === "object") {
      if (value instanceof Uint8Array) return this.text(Buffer.from(value).toString("utf8"));
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) {
        // Defined, not assigned: a "__proto__" key from parsed JSON stays an own
        // data property instead of becoming the result's (mutable) prototype.
        Object.defineProperty(out, this.text(k), { value: this.#deep(v, depth + 1), enumerable: true, writable: true, configurable: true });
      }
      return out;
    }
    return value;
  }
}

/** Freeze a value and everything inside it: every own property, whatever its key, even under an object frozen already. */
export function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (!value || (typeof value !== "object" && typeof value !== "function") || seen.has(value as object)) return value;
  // A typed array cannot be frozen; payloads never hold one (redaction turns bytes into text).
  if (ArrayBuffer.isView(value)) return value;
  seen.add(value as object);
  Object.freeze(value);
  for (const key of Reflect.ownKeys(value as object)) {
    const descriptor = Object.getOwnPropertyDescriptor(value as object, key);
    if (descriptor && "value" in descriptor) deepFreeze(descriptor.value, seen);
  }
  return value;
}
