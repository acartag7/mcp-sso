import { isDeepStrictEqual } from "node:util";
import { OAuthError } from "../../src/errors.ts";
import type { IdentityPort, IdentityResult } from "../../src/ports/identity.ts";
import type { BodyValue, IdentityCheck } from "./types.ts";
import { FixtureRunnerError } from "./error.ts";

const UNMATCHED_CALL = "unmatched IdentityPort.verify call";
const INPUT_MISMATCH = "identity check input mismatch";
const UNCONSUMED_CHECKS = "all identity checks must be consumed";

export class ScriptedIdentity implements IdentityPort {
  readonly #checks: IdentityCheck[];
  #index = 0;

  constructor(checks: IdentityCheck[]) {
    this.#checks = structuredClone(checks);
  }

  async verify(input: unknown): Promise<IdentityResult> {
    const check = this.#checks[this.#index];
    if (check === undefined) throw new FixtureRunnerError(UNMATCHED_CALL);
    assertBodyValue(input, check.input);
    this.#index += 1;

    if (check.throw?.kind === "oauth") {
      throw new OAuthError(check.throw.code, check.throw.description, check.throw.status);
    }
    if (check.throw?.kind === "generic") throw new Error("scripted generic identity failure");
    if (!check.result) throw new FixtureRunnerError("identity check has no result or throw");
    return structuredClone(check.result);
  }

  assertConsumed(): void {
    if (this.#index !== this.#checks.length) {
      throw new FixtureRunnerError(UNCONSUMED_CHECKS);
    }
  }
}

function assertBodyValue(actual: unknown, expected: BodyValue): void {
  const matches = "absent" in expected
    ? actual === undefined
    : isDeepStrictEqual(actual, expected.value);
  if (!matches) throw new FixtureRunnerError(INPUT_MISMATCH);
}
