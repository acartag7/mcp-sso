import { finiteClockSnapshot, type ClockPort } from "../ports/clock.ts";
import { StoreExpiryScheduler } from "./expiry-scheduler.ts";

interface ExpirySweepTarget {
  sweepExpired(nowIso: string): Promise<void>;
}

export class StoreExpiryLifecycle {
  private readonly target: ExpirySweepTarget;
  private ready: boolean;
  private stopped = false;
  private readonly clocks: ClockPort[] = [];
  private readonly aggregateClock: ClockPort = { nowMs: () => this.earliestNowMs() };
  private scheduler: StoreExpiryScheduler | undefined;
  private readonly collectionLagMs: number;

  constructor(target: ExpirySweepTarget, ready = false, collectionLagMs = 0) {
    if (!Number.isSafeInteger(collectionLagMs) || collectionLagMs < 0) {
      throw new RangeError("Expiry collection lag must be a non-negative safe integer");
    }
    this.target = target;
    this.ready = ready;
    this.collectionLagMs = collectionLagMs;
  }

  markReady(): void {
    this.ready = true;
  }

  start(clock: ClockPort): void {
    if (this.stopped) throw new Error("Store expiry collection is stopped");
    if (!this.ready) throw new Error("Store schema is not ready for expiry collection");
    if (typeof clock !== "object" || clock === null || typeof clock.nowMs !== "function") {
      throw new TypeError("Expiry collection requires a ClockPort");
    }
    if (this.clocks.includes(clock)) return;
    this.clocks.push(clock);
    try { this.scheduler ??= new StoreExpiryScheduler(this.target, this.aggregateClock); }
    catch (error) { this.clocks.pop(); throw error; }
  }

  async stop(): Promise<void> {
    this.stopped = true;
    await this.scheduler?.stop();
  }

  private earliestNowMs(): number {
    if (this.clocks.length === 0) throw new Error("Store expiry collection has no configured clock");
    let earliest = finiteClockSnapshot(this.clocks[0]!);
    for (let index = 1; index < this.clocks.length; index++) {
      earliest = Math.min(earliest, finiteClockSnapshot(this.clocks[index]!));
    }
    return earliest - this.collectionLagMs;
  }
}
