import assert from "node:assert/strict";
import { test } from "node:test";
import { SignJWT, jwtVerify } from "jose";

test("smoke: jose sign+verify under Node 24 native TS + node:test", async () => {
  // jose accepts a Uint8Array as an HS256 key (the consent-token path uses TextEncoder too).
  const key = new TextEncoder().encode("smoke-test-secret-32-bytes-long!");
  const jwt = await new SignJWT({ sub: "alice" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("https://smoke.test")
    .sign(key);
  const { payload } = await jwtVerify(jwt, key, { algorithms: ["HS256"], issuer: "https://smoke.test" });
  assert.equal(payload.sub, "alice");
});
