// RedirectIdentityPort provenance boundary for the §17.11 orchestrator. Both
// the method call and every selected returned field stay inside `callPort` so a
// custom getter cannot author an OAuth response after the call returns.

import type { RedirectExchangeResult, RedirectIdentityPort } from "../ports/identity.ts";
import { callPort } from "../port-failure.ts";
import { snapshotRedirectExchangeResult } from "../port-result.ts";

type AuthorizationRequest = Parameters<RedirectIdentityPort["buildAuthorizationUrl"]>[0];
type ExchangeRequest = Parameters<RedirectIdentityPort["exchangeAndVerify"]>[0];

export async function buildUpstreamAuthorizationUrl(
  identity: RedirectIdentityPort,
  request: AuthorizationRequest,
): Promise<string> {
  return await callPort("RedirectIdentityPort", "buildAuthorizationUrl", async () => {
    const built = identity.buildAuthorizationUrl(request);
    if (typeof built !== "string" || built.length === 0) {
      throw new TypeError("RedirectIdentityPort.buildAuthorizationUrl must return a non-empty string");
    }
    return built;
  });
}

export async function exchangeUpstreamIdentity(
  identity: RedirectIdentityPort,
  request: ExchangeRequest,
  includeClaims = false,
): Promise<RedirectExchangeResult> {
  return await callPort("RedirectIdentityPort", "exchangeAndVerify", async () =>
    snapshotRedirectExchangeResult(await identity.exchangeAndVerify(request), includeClaims));
}
