import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createRemoteJWKSet, customFetch, exportJWK, generateKeyPair, jwtVerify, SignJWT,
} from "jose";
import { createValidatedRemoteJWKSet } from "../src/identity/remote-jwks.ts";

test("validated remote JWKS requires key selectors to be own data", async () => {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(publicKey);
  const token = await new SignJWT({ sub: "subject" })
    .setProtectedHeader({ alg: "RS256", kid: "selected-key" })
    .setExpirationTime("5m")
    .sign(privateKey);
  const response = () => new Response(JSON.stringify({ keys: [publicJwk] }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
  const options = { [customFetch]: async () => response() };

  let reads = 0;
  Object.defineProperty(Object.prototype, "kid", {
    configurable: true,
    enumerable: false,
    get() { reads += 1; return "selected-key"; },
  });
  try {
    const baseline = createRemoteJWKSet(new URL("https://issuer.test/baseline-jwks"), options);
    await assert.doesNotReject(jwtVerify(token, baseline, { algorithms: ["RS256"] }));
    assert.ok(reads > 0, "control did not exercise inherited selector lookup");

    reads = 0;
    const guarded = createValidatedRemoteJWKSet(new URL("https://issuer.test/guarded-jwks"), options);
    await assert.rejects(jwtVerify(token, guarded, { algorithms: ["RS256"] }));
    assert.equal(reads, 0, "selector accessor ran before the defensive check");
  } finally {
    delete (Object.prototype as Record<string, unknown>).kid;
  }
});

test("validated remote JWKS rejects response fields from a plain prototype", async () => {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(publicKey);
  const token = await new SignJWT({ sub: "subject" })
    .setProtectedHeader({ alg: "RS256", kid: "selected-key" })
    .setExpirationTime("5m")
    .sign(privateKey);
  let reads = 0;
  const prototype = Object.create(null) as Record<string, unknown>;
  Object.defineProperty(prototype, "status", {
    get() { reads += 1; return 200; },
  });
  const response = Object.assign(Object.create(prototype), {
    async json() { return { keys: [{ ...publicJwk, kid: "selected-key" }] }; },
  });
  const guarded = createValidatedRemoteJWKSet(
    new URL("https://issuer.test/guarded-response"),
    { [customFetch]: async () => response },
  );
  await assert.rejects(jwtVerify(token, guarded, { algorithms: ["RS256"] }));
  assert.equal(reads, 0);
});
