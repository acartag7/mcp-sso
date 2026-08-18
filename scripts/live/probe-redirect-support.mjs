// Shared DCR-callback preflight for the live provider probes.
import { redirectAllowlistPolicyFromEnv } from "../../examples/fastify-sqlite/app.ts";
import { assertAllowedRedirectUri, assertRegistrationRedirectPolicy } from "../../src/redirect.ts";

// The production composition root parses its allowlist with an empty default
// (examples/fastify-sqlite/app.ts, configFromEnv); the localhost default belongs
// to the quickstart branch, which a provider-configured probe never takes.
const PRODUCTION_DEFAULT_ENTRIES = "";

/** Reject a probe callback the deployment could never accept, BEFORE any
 *  provider I/O or side effect.
 *
 *  Checking the syntax alone is not enough. A syntactically valid https URL that
 *  is absent from the effective allowlist — the common case under
 *  `OAUTH_REDIRECT_ALLOWLIST_MODE=replace` — passes a scheme check, so the probe
 *  boots the example, performs discovery and JWKS reads, and only then has
 *  `/oauth/register` reject it as `invalid_redirect_uri`. That spends provider
 *  I/O on a configuration guaranteed to abort, and reports the failure at the
 *  wrong layer. Apply the same policy the example will install, up front.
 */
export function assertProbeClientRedirect(rawRedirect, env = process.env) {
  const { redirectAllowlist, redirectAllowlistMode } = redirectAllowlistPolicyFromEnv(
    env, PRODUCTION_DEFAULT_ENTRIES,
  );
  const entry = assertRegistrationRedirectPolicy(rawRedirect, "web");
  return assertAllowedRedirectUri(entry, redirectAllowlist, redirectAllowlistMode);
}
