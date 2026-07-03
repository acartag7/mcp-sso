// Caller/infrastructure-provided clock. Core use-cases never call ambient
// wall-clock APIs directly: tests need deterministic time, and audit/token
// provenance must be controlled (contracts §6.1).

export interface ClockPort {
  nowMs(): number;
}

export class SystemClock implements ClockPort {
  nowMs(): number {
    return Date.now();
  }
}
