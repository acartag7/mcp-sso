// Caller/infrastructure-provided clock. Core use-cases never call ambient
// wall-clock APIs directly: tests need deterministic time, and audit/token
// provenance must be controlled (contracts §6.1).

export interface ClockPort {
  nowMs(): number;
}

const MIN_CANONICAL_MS = -62_167_219_200_000; // 0000-01-01T00:00:00.000Z
const MAX_CANONICAL_MS = 253_402_300_799_999; // 9999-12-31T23:59:59.999Z

/** Read the caller-owned port once and erase any port-authored failure shape. */
export function integerClockSnapshot(clock: ClockPort): number {
  // ClockPort is caller-supplied, so a throwing nowMs() is untrusted input on the
  // error channel. Every operation reads the clock BEFORE the use-case try, so an
  // OAuthError raised here would reach asOAuth and select the public response.
  // Re-cast to the same RangeError an out-of-range value produces: one failure
  // shape for "the clock is unusable", whatever the port did (§6.1, §13).
  let nowMs: number;
  try {
    nowMs = clock.nowMs();
  } catch {
    throw new RangeError("ClockPort.nowMs() must fit the canonical UTC timestamp range");
  }
  if (!Number.isSafeInteger(nowMs)) {
    throw new RangeError("ClockPort.nowMs() must be a safe-integer millisecond timestamp");
  }
  return nowMs;
}

/** Read once; require canonical store/audit time plus any operation-owned future offset. */
export function finiteClockSnapshot(clock: ClockPort, futureOffsetMs = 0): number {
  const nowMs = integerClockSnapshot(clock);
  if (!Number.isSafeInteger(futureOffsetMs)
    || futureOffsetMs < 0 || nowMs < MIN_CANONICAL_MS
    || nowMs > MAX_CANONICAL_MS - futureOffsetMs) {
    throw new RangeError("ClockPort.nowMs() must fit the canonical UTC timestamp range");
  }
  return nowMs;
}

/** Invalid CIMD cache timing is a fail-toward-refetch observation. */
export function cacheClockObservation(clock: ClockPort): number {
  try { return finiteClockSnapshot(clock); }
  catch { return Number.NaN; }
}

/** Expose one already-validated value without reading the underlying port. */
export function fixedClockSnapshot(nowMs: number): ClockPort {
  return { nowMs: () => nowMs };
}

export class SystemClock implements ClockPort {
  nowMs(): number {
    return Date.now();
  }
}
