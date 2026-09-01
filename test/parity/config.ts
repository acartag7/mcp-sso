import { FIXTURES_ROOT } from "./corpus.ts";
import { FixtureRunnerError } from "./error.ts";
import { privateJwk, publicKey } from "./keys.ts";

export interface FixtureKeys {
  signingPrivate?: string;
  signingPublic?: string;
}

export async function materializeConfigInput(
  literal: unknown,
  keys: FixtureKeys,
  fixturesRoot = FIXTURES_ROOT,
): Promise<unknown> {
  const input = structuredClone(literal);
  if (keys.signingPublic !== undefined) await publicKey(keys.signingPublic, fixturesRoot);
  if (keys.signingPrivate !== undefined) {
    if (!isRecord(input)) throw new FixtureRunnerError("a signingPrivate key requires an object config");
    if (Object.hasOwn(input, "signingPrivateJwk")) {
      throw new FixtureRunnerError("config and given.keys both supply signingPrivateJwk");
    }
    input.signingPrivateJwk = await privateJwk(keys.signingPrivate, fixturesRoot);
  }
  return input;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
