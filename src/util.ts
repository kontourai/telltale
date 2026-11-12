import { createHash, timingSafeEqual as nodeTimingSafeEqual } from "node:crypto";

/** "30s", "5m", "1h", "1d", "250ms", or a number of milliseconds. Throws for anything else. */
export function parseDuration(value: string | number): number {
  if (typeof value === "number") {
    if (!Number.isFinite(value) || value <= 0) throw new Error(`"${value}" is not a positive duration`);
    return value;
  }
  const m = /^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)$/.exec(String(value).trim());
  if (!m) throw new Error(`"${value}" is not a duration such as "30s", "5m" or "1h"`);
  const n = Number(m[1]);
  const unit = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2] as "ms" | "s" | "m" | "h" | "d"];
  const ms = n * unit;
  if (!(ms > 0)) throw new Error(`"${value}" is not a positive duration`);
  return ms;
}

/**
 * A value as a status line may repeat it. Status lines are read without the
 * mark that outside content carries, so they repeat only what cannot carry a
 * sentence: a number, an amount, one word. Anything else is only counted.
 *
 * Adapted from pmndrs/pine `harmless()` (MIT); see THIRD_PARTY_NOTICES.md.
 */
export function harmless(value: unknown): string {
  if (value === null || value === undefined) return "nothing";
  const s = typeof value === "string" ? value : JSON.stringify(value) ?? "";
  return /^[\d.,:%+\- ]{1,24}$/.test(s) || /^[\w.-]{1,32}$/.test(s) ? s : `a value of ${s.length} characters`;
}

/** Constant-time string comparison that does not leak length: both sides are hashed first. */
export function timingSafeEqualText(a: string, b: string): boolean {
  const ha = createHash("sha256").update(a).digest();
  const hb = createHash("sha256").update(b).digest();
  return nodeTimingSafeEqual(ha, hb);
}

/** sha256 over NUL-separated parts, hex. NUL cannot appear in the header values we digest. */
export function digest(...parts: string[]): string {
  const h = createHash("sha256");
  parts.forEach((p, i) => {
    if (i) h.update("\0");
    h.update(p);
  });
  return h.digest("hex");
}

export const isRecord = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
