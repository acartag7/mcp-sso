import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import type { JWK } from "jose";
import { Bridge } from "../../src/adapters/bridge.ts";
import type { NormRequest, NormResponse } from "../../src/adapters/http.ts";
import { createUpstreamRedirectFlow, type UpstreamRedirectFlow } from "../../src/adapters/upstream-flow.ts";
import { createBridgeConfig, type BridgeConfig } from "../../src/config.ts";
import { pkceChallenge } from "../../src/crypto.ts";
import type { AuditPort, AuthAuditEvent } from "../../src/ports/audit.ts";
import type { RedirectIdentityPort } from "../../src/ports/identity.ts";
import { MemoryStore } from "../../src/store/memory.ts";

const NOW_MS = Date.parse("2026-08-12T12:00:00.000Z");
const ISSUER = "https://auth.test";
const RESOURCE = "https://api.test/mcp";
export const CALLBACK = "/oauth/callback";
const CLIENT_REDIRECT = "https://client.test/callback";
const AUDIT_ERROR_MESSAGE = "audit sink failed";

export type FailureMode = "sync" | "async";

export function failingAudit(mode: FailureMode, event?: AuthAuditEvent["event"]): AuditPort {
  return {
    writeAuthEvent(candidate): Promise<void> {
      if (event !== undefined && candidate.event !== event) return Promise.resolve();
      if (mode === "sync") throw new Error(AUDIT_ERROR_MESSAGE);
      return Promise.reject(new Error(AUDIT_ERROR_MESSAGE));
    },
  };
}

function config(): BridgeConfig {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const signingPrivateJwk = { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK;
  return createBridgeConfig({
    issuer: ISSUER, resource: RESOURCE,
    consentSigningSecret: randomBytes(32).toString("base64url"),
    signingPrivateJwk, signingKeyId: "k",
    redirectAllowlist: [CLIENT_REDIRECT], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: [ISSUER], dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

export function harness(audit: AuditPort, identityAccepted = false): { bridge: Bridge; flow: UpstreamRedirectFlow } {
  const c = config();
  const store = new MemoryStore();
  const clock = { nowMs: () => NOW_MS };
  const identity: RedirectIdentityPort = {
    redirectUri: `${ISSUER}${CALLBACK}`,
    buildAuthorizationUrl({ state }) { return `https://idp.test/authorize?state=${encodeURIComponent(state)}`; },
    async exchangeAndVerify() {
      if (identityAccepted) return { ok: true, identity: { subject: "user-1" } };
      return { ok: false, kind: "identity_rejected", reason: "policy_denied" };
    },
  };
  const bridge = new Bridge({ config: c, store, clock, audit });
  const flow = createUpstreamRedirectFlow({ bridge, identity, store, clock, audit, callbackPath: CALLBACK });
  return { bridge, flow };
}

export function request(query: NormRequest["query"], headers: NormRequest["headers"] = {}): NormRequest {
  return { query, headers, body: undefined, ip: "203.0.113.8" };
}

export function authorizeQuery(): Record<string, string> {
  return {
    response_type: "code", client_id: "client-1", redirect_uri: CLIENT_REDIRECT,
    code_challenge: pkceChallenge("v".repeat(43)), code_challenge_method: "S256",
    scope: "mcp:read", state: "client-state",
  };
}

export function readableCookieHeader(): string {
  return `__Host-mcp-sso-upstream=${randomBytes(24).toString("base64url")}`;
}

export function assertClear(res: NormResponse, label: string): void {
  assert.match(res.headers["set-cookie"] ?? "", /Max-Age=0/, `${label}: flow cookie cleared`);
  assert.equal(res.headers["cache-control"], "no-store", `${label}: clear is not cacheable`);
}
