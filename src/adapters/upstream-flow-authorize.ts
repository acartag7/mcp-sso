import type { Bridge } from "./bridge.ts";
import type { RedirectIdentityPort } from "../ports/identity.ts";
import type { ClockPort } from "../ports/clock.ts";
import type { RateLimitPort } from "../ports/rate-limit.ts";
import type { CimdTransport, DnsResolver } from "../cimd/transport.ts";
import { OAuthError } from "../errors.ts";
import { pkceChallenge } from "../crypto.ts";
import { queryString, noStoreHeaders, type NormRequest, type NormResponse } from "./http.ts";
import { resolveUpstreamAuthorizeClient } from "./upstream-flow-cimd.ts";
import { buildUpstreamAuthorizationUrl } from "./upstream-flow-port.ts";
import {
  OAUTH_SINGLETON_PARAM_KEYS, directErrorResponse, findDuplicatedKeys, flowCookieOversized,
  gatherOAuthParams, randomFlowToken, setCookieValue, signFlowToken, type CookieProfile,
} from "./upstream-flow-internals.ts";

export function createUpstreamAuthorizeHandler(args: {
  bridge: Bridge; identity: RedirectIdentityPort; clock: ClockPort; rateLimit: RateLimitPort;
  callbackPath: string; flowTtlSeconds: number; complete: "bridge" | "identity";
  cookieProfile: CookieProfile; guard(req: NormRequest, prefix: string): Promise<void>;
  cimdTransport?: CimdTransport; cimdResolver?: DnsResolver;
}): (req: NormRequest) => Promise<NormResponse> {
  const { bridge, identity, clock, rateLimit, callbackPath, flowTtlSeconds, complete, cookieProfile, guard } = args;
  const secret = bridge.config.consentSigningSecret;
  const issuer = bridge.config.issuer;
  const cimd = bridge.cimd;
  const cimdSeams = args.cimdTransport !== undefined || args.cimdResolver !== undefined
    ? { transport: args.cimdTransport, resolver: args.cimdResolver } : undefined;
  return async (req) => {
    try {
      await guard(req, complete === "bridge" ? "upstream" : "website-login");
      const state = randomFlowToken(), nonce = randomFlowToken(), codeVerifier = randomFlowToken();
      const jti = `upf_${randomFlowToken()}`;
      if (complete === "identity") {
        const flowJwt = await signFlowToken({ secret, issuer, clock, callbackPath, complete, jti, state, nonce, codeVerifier, ttlSeconds: flowTtlSeconds });
        if (flowCookieOversized(cookieProfile, flowJwt, flowTtlSeconds)) return directErrorResponse("invalid_request", "request parameters too large");
        return redirectToIdentity(await buildLocation(identity, state, nonce, codeVerifier), cookieProfile, flowJwt, flowTtlSeconds);
      }
      if (findDuplicatedKeys(req.query, OAUTH_SINGLETON_PARAM_KEYS).length > 0) return directErrorResponse("invalid_request", "duplicate request parameters");
      const clientId = queryString(req.query, "client_id");
      if (!clientId) return directErrorResponse("invalid_request", "client_id is required");
      const resolved = await resolveUpstreamAuthorizeClient({
        config: bridge.config, cimd, seams: cimdSeams, rateLimit, clientId,
        redirectUri: queryString(req.query, "redirect_uri") ?? "", ip: req.ip,
      });
      const flowJwt = await signFlowToken({
        secret, issuer, clock, callbackPath, complete, jti, state, nonce, codeVerifier,
        params: gatherOAuthParams(req), ttlSeconds: flowTtlSeconds,
        ...(resolved.registration === undefined ? {} : { cimd: resolved.registration }),
      });
      if (flowCookieOversized(cookieProfile, flowJwt, flowTtlSeconds)) {
        if (resolved.registration !== undefined) throw await cimd.rejectAfterResolve("oversize", clientId, req.ip);
        return directErrorResponse("invalid_request", "request parameters too large");
      }
      await resolved.emitSuccess();
      return redirectToIdentity(await buildLocation(identity, state, nonce, codeVerifier), cookieProfile, flowJwt, flowTtlSeconds);
    } catch (error) {
      const mapped = error instanceof OAuthError ? error : new OAuthError("internal_error", "OAuth request failed", 500);
      return directErrorResponse(mapped.code, mapped.message, mapped.status);
    }
  };
}

async function buildLocation(identity: RedirectIdentityPort, state: string, nonce: string, codeVerifier: string): Promise<string> {
  return buildUpstreamAuthorizationUrl(identity, { state, nonce, codeChallenge: pkceChallenge(codeVerifier), codeChallengeMethod: "S256" });
}

function redirectToIdentity(location: string, cookie: CookieProfile, token: string, ttl: number): NormResponse {
  return { status: 302, headers: noStoreHeaders({ location, "set-cookie": setCookieValue(cookie, token, ttl) }), redirect: location };
}
