import type { RateLimitPort } from "../../src/ports/rate-limit.ts";
import { OrderedFixtureScript } from "./fixture-script.ts";
import type { RateLimitCheck } from "./types.ts";

export class ScriptedRateLimit implements RateLimitPort {
  readonly #script: OrderedFixtureScript<RateLimitCheck, string>;

  constructor(checks: readonly RateLimitCheck[]) {
    this.#script = new OrderedFixtureScript(checks, matchesKey);
  }

  async check(key: string): Promise<boolean> {
    const check = this.#script.consume(key);
    if (check.outcome === "allow") return true;
    if (check.outcome === "deny") return false;
    throw new Error(check.outcome.throws);
  }

  assertConsumed(): void {
    this.#script.assertConsumed();
  }
}

function matchesKey(actual: string, expected: Readonly<RateLimitCheck>): boolean {
  return actual === expected.key;
}
