import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { test } from "node:test";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig } from "../src/config.ts";
import { signAccessToken } from "../src/crypto.ts";
import { noopAudit } from "../src/ports/audit.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { RequestAuthorizer } from "../src/verifier.ts";
import { http, mountStack, sdkPing } from "./lib/release-http-stack.ts";

const clock = { nowMs: () => Date.parse("2026-08-26T12:00:00.000Z") };
const issuer = "https://auth.example.com";
const scopes = ["mcp:read", "mcp:write"];
const initialize = { jsonrpc: "2.0", id: 1, method: "initialize", params: {
  protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "mount-check", version: "1" },
} };

for (const kind of ["fastify", "express", "hono"] as const) {
  test(`${kind}: single-resource mounts serve discovery and reject the other resource's token`, async (t) => {
    // Sharing issuer and signing material makes resource binding decisive.
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const signingPrivateJwk = privateKey.export({ format: "jwk" });
    const publicFields = publicKey.export({ format: "jwk" });
    const mounts = [];
    for (const name of ["first", "second"]) {
      const origin = `https://${name}.example.com`;
      const config = createBridgeConfig({
        issuer, resource: `${origin}/mcp`, signingPrivateJwk, signingKeyId: "test-key",
        consentSigningSecret: randomBytes(32).toString("hex"),
        redirectAllowlist: ["https://client.example.com/callback"], redirectAllowlistMode: "replace",
        scopeCatalog: scopes, defaultScopes: ["mcp:read"], allowedOrigins: [issuer], dcr: { mode: "stateless" },
        accessTokenTtlSeconds: 300, refreshTokenTtlSeconds: 3600,
        consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
      });
      const store = new MemoryStore();
      t.after(() => store.close());
      const bridge = new Bridge({ config, store, clock, audit: noopAudit });
      const authorizer = new RequestAuthorizer({ config, clock, audit: noopAudit });
      const stack = await mountStack(kind, bridge, authorizer, config, {
        identity: { async verify() { throw new Error("identity is not used for discovery or bearer verification"); } },
      });
      t.after(() => stack.close());
      const token = await signAccessToken({ subject: name, clientId: "test-client", scopes: ["mcp:read"] }, config, clock);
      mounts.push({ origin, stack, token, name });
    }

    for (const current of mounts) {
      const { stack, origin, token, name } = current;
      await sdkPing(stack.base, token, `pong: ${name}`);
      const other = mounts.find(mount => mount !== current)!;
      const denied = await http.postJson(stack.base, "/mcp", initialize, { authorization: `Bearer ${other.token}` });
      assert.equal(denied.status, 401);
      const metadataUrl = `${origin}/.well-known/oauth-protected-resource`;
      assert.equal(denied.headers["www-authenticate"], `Bearer resource_metadata="${metadataUrl}", scope="mcp:read mcp:write", error="invalid_token", error_description="Bearer token is invalid"`);

      // Logical public URLs map to this mount's loopback socket. This does not
      // exercise DNS, TLS termination, reverse proxies, or same-origin routing.
      const root = await http.get(stack.base, new URL(metadataUrl).pathname);
      const inserted = await http.get(stack.base, "/.well-known/oauth-protected-resource/mcp");
      const expectedPrm = { resource: `${origin}/mcp`, authorization_servers: [issuer], scopes_supported: scopes };
      for (const response of [root, inserted]) {
        assert.equal(response.status, 200);
        assert.deepEqual(JSON.parse(response.body), expectedPrm);
      }
      const as = await http.get(stack.base, "/.well-known/oauth-authorization-server");
      assert.equal(as.status, 200);
      const asMetadata = JSON.parse(as.body);
      assert.deepEqual(asMetadata, {
        issuer, authorization_endpoint: `${issuer}/oauth/authorize`, token_endpoint: `${issuer}/oauth/token`,
        jwks_uri: `${issuer}/oauth/jwks`, registration_endpoint: `${issuer}/oauth/register`,
        revocation_endpoint: `${issuer}/oauth/revoke`, response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"], code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"], scopes_supported: scopes,
        authorization_response_iss_parameter_supported: true,
      });
      const keys = await http.get(stack.base, new URL(asMetadata.jwks_uri).pathname);
      assert.equal(keys.status, 200);
      assert.equal(keys.headers["cache-control"], "public, max-age=60");
      assert.deepEqual(JSON.parse(keys.body), { keys: [{ ...publicFields, alg: "ES256", use: "sig", kid: "test-key" }] });
    }
  });
}
