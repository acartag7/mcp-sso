import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";
import { test } from "node:test";
import type { JWK } from "jose";
import { createBridgeConfig } from "../src/config.ts";
import { signAccessToken } from "../src/crypto.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { buildGateway } from "../examples/api-key-gateway/app.ts";

const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "release" } as JWK;
}

releaseTest("RM.9 gateway relays documented backend authorization failures without leaking its credential", async () => {
  const credential = "release-backend-credential";
  const received: string[] = [];
  const backend = createServer((request, response) => {
    received.push(request.headers.authorization ?? "");
    const status = new URL(request.url ?? "/", "http://backend.test").searchParams.get("status") === "403" ? 403 : 401;
    response.writeHead(status, { "content-type": "application/json", "x-backend-secret": credential });
    response.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "backend authorization failed" }, id: null }));
  });
  await new Promise<void>((resolve) => backend.listen(0, "127.0.0.1", resolve));
  const backendPort = (backend.address() as { port: number }).port;
  const config = createBridgeConfig({ issuer: "http://localhost", resource: "http://localhost/mcp",
    consentSigningSecret: "g".repeat(40), signingPrivateJwk: jwk(), signingKeyId: "release",
    redirectAllowlist: ["http://localhost:4321/callback"], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["http://localhost"], dcr: { mode: "stateless" }, dev: { allowInsecureLocalhost: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300 });
  const gateway = await buildGateway({ config, backendUrl: `http://127.0.0.1:${backendPort}/mcp`, getBackendCredential: () => credential,
    identity: { async verify() { return { ok: false as const, reason: "unused" }; } } });
  const accessToken = await signAccessToken({ subject: "release-user", clientId: "release-client", scopes: ["mcp:read"] }, config, new SystemClock());
  const base = await gateway.app.listen({ host: "127.0.0.1", port: 0 });
  try {
    for (const status of [401, 403]) {
      const response = await fetch(`${base}/mcp?status=${status}`, { method: "POST", headers: {
        authorization: `Bearer ${accessToken}`, "content-type": "application/json",
      }, body: JSON.stringify({ jsonrpc: "2.0", method: "tools/call", id: 1 }) });
      assert.equal(response.status, status);
      assert.equal(response.headers.get("x-backend-secret"), null, "non-allowlisted backend headers are not relayed");
      assert.equal((await response.text()).includes(credential), false, "backend credential is not client-visible");
    }
    assert.deepEqual(received, [`Bearer ${credential}`, `Bearer ${credential}`]);
  } finally {
    await gateway.app.close(); await gateway.store.close();
    await new Promise<void>((resolve) => backend.close(() => resolve()));
  }
});
