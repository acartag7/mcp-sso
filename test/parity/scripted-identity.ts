import { isDeepStrictEqual } from "node:util";
import { OAuthError } from "../../src/errors.ts";
import type { IdentityPort, IdentityResult } from "../../src/ports/identity.ts";
import { FixtureRunnerError } from "./error.ts";
import { OrderedFixtureScript } from "./fixture-script.ts";
import type { BodyValue, IdentityCheck } from "./types.ts";

const GENERIC_FAILURE = "scripted generic identity failure";
const MISSING_OUTCOME = "identity check has no result or throw";

export class ScriptedIdentity implements IdentityPort {
  readonly #script: OrderedFixtureScript<IdentityCheck, unknown>;

  constructor(checks: readonly IdentityCheck[]) {
    this.#script = new OrderedFixtureScript(checks, matchesInput);
  }

  async verify(input: unknown): Promise<IdentityResult> {
    const check = this.#script.consume(input);
    if (check.throw?.kind === "oauth") {
      throw new OAuthError(check.throw.code, check.throw.description, check.throw.status);
    }
    if (check.throw?.kind === "generic") throw new Error(GENERIC_FAILURE);
    if (check.result === undefined) throw new FixtureRunnerError(MISSING_OUTCOME);
    return check.result;
  }

  assertConsumed(): void {
    this.#script.assertConsumed();
  }
}

function matchesInput(actual: unknown, expected: Readonly<IdentityCheck>): boolean {
  const body = expected.input;
  return "absent" in body ? actual === undefined : isDeepStrictEqual(actual, body.value);
}
