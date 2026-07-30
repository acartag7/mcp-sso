// The shipped two-resource example must actually boot and isolate. An example
// that only typechecks is not a demo — a live-verification checklist that points
// at it would fail at the operator's terminal, not here.

import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { buildApp, buildConfig, RESOURCE_PATHS } from "../examples/fastify-multi-resource/app.ts";
import type { IdentityPort } from "../src/ports/identity.ts";
import { signAccessToken } from "../src/access-token.ts";
import { SystemClock } from "../src/ports/clock.ts";

const ORIGIN = "https://mcp.example";
const [PATH_A, PATH_B] = RESOURCE_PATHS;

function env(): NodeJS.ProcessEnv {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" };
  return {
    OAUTH_ISSUER: ORIGIN,
    OAUTH_CONSENT_SIGNING_SECRET: "s".repeat(40),
    OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(jwk),
    OAUTH_SIGNING_KEY_ID: "k",
    OAUTH_REDIRECT_ALLOWLIST: "https://client.example/cb",
  } as NodeJS.ProcessEnv;
}

const stubIdentity: IdentityPort = {
  async verify() {
    return { ok: true, subject: "user@example", claims: {} } as never;
  },
};

test("example: buildConfig produces two isolated resources", () => {
  const config = buildConfig(env());
  const resources = config.resources.map((r) => r.resource);
  assert.deepEqual(resources, [`${ORIGIN}${PATH_A}`, `${ORIGIN}${PATH_B}`]);
  // The shared scope is the point: isolation must not depend on scope names.
  assert.ok(config.resources[0]!.scopeCatalog.includes("mcp:read"));
  assert.ok(config.resources[1]!.scopeCatalog.includes("mcp:read"));
  assert.ok(!config.resources[1]!.scopeCatalog.includes("grafana:admin"));
});

test("example: blank config fails closed, it does not default", () => {
  for (const key of ["OAUTH_ISSUER", "OAUTH_CONSENT_SIGNING_SECRET", "OAUTH_SIGNING_KEY_ID"]) {
    const broken = { ...env(), [key]: "" };
    assert.throws(() => buildConfig(broken), new RegExp(key), `${key}="" must be rejected`);
  }
});

test("example: each resource serves its own PRM document", async () => {
  const config = buildConfig(env());
  const app = await buildApp({ config, identity: stubIdentity });
  try {
    for (const path of RESOURCE_PATHS) {
      const res = await app.inject({ method: "GET", url: `/.well-known/oauth-protected-resource${path}` });
      assert.equal(res.statusCode, 200, `PRM for ${path} must be served`);
      const doc = res.json() as { resource: string };
      assert.equal(doc.resource, `${ORIGIN}${path}`);
      const other = path === PATH_A ? PATH_B : PATH_A;
      assert.ok(!JSON.stringify(doc).includes(`${ORIGIN}${other}`), `${path} PRM must not mention ${other}`);
    }
  } finally {
    await app.close();
  }
});

test("example: an unauthenticated call is challenged for THAT endpoint's resource", async () => {
  const config = buildConfig(env());
  const app = await buildApp({ config, identity: stubIdentity });
  try {
    for (const path of RESOURCE_PATHS) {
      const res = await app.inject({
        method: "POST", url: path,
        headers: { "content-type": "application/json" },
        payload: JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1 }),
      });
      assert.equal(res.statusCode, 401, `${path} must reject an unauthenticated call`);
      const challenge = res.headers["www-authenticate"] as string;
      // RFC 9728: the challenge carries the per-resource PRM *metadata* URL,
      // which is where the client goes to discover this resource's issuer.
      assert.ok(
        challenge.includes(`${ORIGIN}/.well-known/oauth-protected-resource${path}`),
        `challenge must point at ${path}'s own PRM document, got: ${challenge}`,
      );
      const other = path === PATH_A ? PATH_B : PATH_A;
      assert.ok(!challenge.includes(other), `challenge must not name ${other}`);
    }
  } finally {
    await app.close();
  }
});

test("example: a token minted for one resource is refused at the other", async () => {
  const config = buildConfig(env());
  const clock = new SystemClock();
  const app = await buildApp({ config, identity: stubIdentity });
  try {
    const call = (path: string, token: string) => app.inject({
      method: "POST", url: path,
      headers: {
        "content-type": "application/json",
        // The streamable-HTTP transport requires both media types in Accept.
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${token}`,
      },
      payload: JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1 }),
    });

    for (const path of RESOURCE_PATHS) {
      const other = path === PATH_A ? PATH_B : PATH_A;
      const token = await signAccessToken(
        { clientId: "c1", subject: "user@example", scopes: ["mcp:read"], resource: `${ORIGIN}${path}` },
        config, clock,
      );
      // Its own endpoint accepts it...
      assert.equal((await call(path, token)).statusCode, 200, `${path}'s own token must work at ${path}`);
      // ...and the sibling endpoint must refuse it. This is the whole feature:
      // both resources publish "mcp:read", so only the audience pin separates them.
      assert.equal((await call(other, token)).statusCode, 401, `${path}'s token must be refused at ${other}`);
    }
  } finally {
    await app.close();
  }
});
