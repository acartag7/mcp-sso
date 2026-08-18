import { GOOGLE_ISSUER } from "../../src/identity/google.ts";
import { resolveEndpoints } from "../../src/identity/generic-oidc-discovery.ts";

export const resolveFetchedGoogleDiscovery = async (response) => resolveEndpoints({
  issuer: GOOGLE_ISSUER,
  endpoints: "discover",
  clientSecret: "live-probe-present-secret",
}, {
  async get(url) {
    if (url !== `${GOOGLE_ISSUER}/.well-known/openid-configuration`) {
      throw new Error("Google discovery validator requested an unexpected URL");
    }
    return response;
  },
});
