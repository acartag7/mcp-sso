import { finiteClockSnapshot, type ClockPort } from "../ports/clock.ts";

export const STORE_EXPIRY_SWEEP_INTERVAL_MS = 300_000;

interface ExpirySweepTarget {
  sweepExpired(nowIso: string): Promise<void>;
}

export class StoreExpiryScheduler {
  private readonly target: ExpirySweepTarget;
  private readonly clock: ClockPort;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private active: Promise<void> = Promise.resolve();
  private stopped = false;

  constructor(target: ExpirySweepTarget, clock: ClockPort) {
    this.target = target;
    this.clock = clock;
    this.schedule();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer !== undefined) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
    await this.active;
  }

  private schedule(): void {
    const timer = setTimeout(() => {
      this.timer = undefined;
      if (!this.stopped) this.active = this.run();
    }, STORE_EXPIRY_SWEEP_INTERVAL_MS);
    timer.unref?.();
    this.timer = timer;
  }

  private async run(): Promise<void> {
    try {
      const nowMs = finiteClockSnapshot(this.clock);
      await this.target.sweepExpired(new Date(nowMs).toISOString());
    } catch {
      reportSweepFailure();
    } finally {
      if (!this.stopped) this.schedule();
    }
  }
}

function reportSweepFailure(): void {
  try { console.error("[mcp-sso] store expiry sweep failed"); } catch { /* contained */ }
}
