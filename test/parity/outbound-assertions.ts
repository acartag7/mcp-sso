import { FixtureRunnerError } from "./error.ts";
import type { HttpExchangeRegistry } from "./http-exchange-registry.ts";
import { matcherMatches } from "./matchers.ts";
import { bodyObservation, headerObservation, type Observation } from "./observations.ts";
import type { Matcher, OutboundCall } from "./types.ts";

const COUNT_MISMATCH = "outbound call count did not match fixture",
  METHOD_MISMATCH = "outbound call method did not match fixture",
  URL_MISMATCH = "outbound call URL did not match fixture",
  HEADER_NAMES_MISMATCH = "outbound header-name set did not match fixture",
  HEADER_VALUE_MISMATCH = "outbound header value did not match fixture",
  BODY_MISMATCH = "outbound body did not match fixture";

export function assertOutbound(
  registry: Pick<HttpExchangeRegistry, "assertAllConsumed" | "observed">, expected: OutboundCall[],
): void {
  registry.assertAllConsumed();
  const observed = registry.observed;
  if (observed.length !== expected.length) throw new FixtureRunnerError(COUNT_MISMATCH);
  for (let index = 0; index < expected.length; index += 1) {
    const actual = observed[index]!, wanted = expected[index]!;
    if (actual.method !== wanted.method) throw new FixtureRunnerError(METHOD_MISMATCH);
    if (actual.url !== wanted.url) throw new FixtureRunnerError(URL_MISMATCH);
    if (!sameHeaderNames(actual.headers, wanted.headers)) {
      throw new FixtureRunnerError(HEADER_NAMES_MISMATCH);
    }
    for (const [name, matcher] of Object.entries(wanted.headers)) {
      assertMatches(headerObservation(actual.headers, name), matcher, HEADER_VALUE_MISMATCH);
    }
    let body: Observation;
    try { body = bodyObservation(actual.body, actual.headers); }
    catch { throw new FixtureRunnerError(BODY_MISMATCH); }
    assertMatches(body, wanted.body, BODY_MISMATCH);
  }
}

function sameHeaderNames(
  observed: Record<string, unknown>, expected: Record<string, unknown>,
): boolean {
  const actualNames = Object.keys(observed).sort(), expectedNames = Object.keys(expected).sort();
  return actualNames.length === expectedNames.length
    && actualNames.every((name, index) => name === expectedNames[index]);
}

function assertMatches(observation: Observation, matcher: Matcher, message: string): void {
  try {
    const matches = typeof matcher === "object" && matcher !== null && "absent" in matcher
      ? !observation.present
      : observation.present && matcherMatches(observation.value, matcher);
    if (!matches) throw new FixtureRunnerError(message);
  } catch {
    throw new FixtureRunnerError(message);
  }
}
