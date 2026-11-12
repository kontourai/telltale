import { TelltaleHost, ManualClock, InMemoryStateStore } from "../../dist/index.js";

/** A logger that keeps every line it was given, as text, for "never appears in a log" checks. */
export function captureLogger() {
  const lines = [];
  const at = (level) => (message, meta) => lines.push(`${level} ${message} ${JSON.stringify(meta ?? {})}`);
  return { lines, logger: { info: at("info"), warn: at("warn") } };
}

export function newHost(extra = {}) {
  const clock = new ManualClock(extra.start ?? 1_780_000_000_000);
  const state = new InMemoryStateStore();
  const log = captureLogger();
  const host = new TelltaleHost({ clock, state, logger: log.logger, random: () => 0.5, ...extra.options });
  return { host, clock, state, log };
}

/** Subscribe and collect events and refusals. */
export async function collect(host, id) {
  const events = [];
  const refusals = [];
  const subscription = await host.subscribe(id, {
    event: (e) => void events.push(e),
    refusal: (r) => void refusals.push(r),
  });
  return { events, refusals, subscription };
}
