/**
 * Injectable clock. All timing in Telltale (event timestamps, poll intervals,
 * backoff, replay windows, rate-limit windows) flows through this interface,
 * so tests drive time with `ManualClock` and never wait on the wall clock.
 *
 * It extends Ephemeris's `Clock` (`now()`) with timers, because a polling
 * source has to be woken, not only asked the time.
 */
export interface Clock {
  /** Current time in epoch milliseconds. */
  now(): number;
  /** Run `fn` once after `ms` milliseconds. The handle is opaque. */
  setTimer(fn: () => void, ms: number): unknown;
  /** Cancel a timer from `setTimer`. Unknown or fired handles are ignored. */
  clearTimer(handle: unknown): void;
}

/** Production clock: `Date.now()` and unref'd Node timers, so a pending poll never holds the process open. */
export class SystemClock implements Clock {
  now(): number {
    return Date.now();
  }

  setTimer(fn: () => void, ms: number): unknown {
    const timer = setTimeout(fn, Math.max(0, ms));
    timer.unref?.();
    return timer;
  }

  clearTimer(handle: unknown): void {
    clearTimeout(handle as ReturnType<typeof setTimeout>);
  }
}

interface ManualTimer {
  at: number;
  seq: number;
  fn: () => void;
}

/**
 * Deterministic test clock. Time moves only on `advance()` / `set()`, which
 * run every timer that has come due, in order, and let the async work those
 * timers started settle before returning.
 */
export class ManualClock implements Clock {
  #current: number;
  #seq = 0;
  readonly #timers = new Map<number, ManualTimer>();

  constructor(start = 0) {
    this.#current = start;
  }

  now(): number {
    return this.#current;
  }

  setTimer(fn: () => void, ms: number): unknown {
    const seq = ++this.#seq;
    this.#timers.set(seq, { at: this.#current + Math.max(0, ms), seq, fn });
    return seq;
  }

  clearTimer(handle: unknown): void {
    this.#timers.delete(handle as number);
  }

  /** How many timers are waiting. */
  pendingTimers(): number {
    return this.#timers.size;
  }

  /** Move time forward by `ms`, firing due timers in order. */
  async advance(ms: number): Promise<void> {
    if (ms < 0) throw new Error("ManualClock.advance: ms must be >= 0");
    await this.set(this.#current + ms);
  }

  /** Set absolute time (never backwards), firing due timers in order. */
  async set(target: number): Promise<void> {
    if (target < this.#current) throw new Error("ManualClock.set: time must not move backwards");
    await settle();
    for (;;) {
      const next = [...this.#timers.values()]
        .filter((t) => t.at <= target)
        .sort((a, b) => a.at - b.at || a.seq - b.seq)[0];
      if (!next) break;
      this.#timers.delete(next.seq);
      this.#current = Math.max(this.#current, next.at);
      next.fn();
      await settle();
    }
    this.#current = target;
    await settle();
  }
}

/** Let queued promise work (including I/O-free async chains) run to completion. */
export async function settle(rounds = 20): Promise<void> {
  for (let i = 0; i < rounds; i++) await new Promise<void>((resolve) => setImmediate(resolve));
}
