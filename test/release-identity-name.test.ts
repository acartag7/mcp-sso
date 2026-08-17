// RM.12 — `claims.name` reaches a host through the SHIPPED identity ports.
//
// An earlier version of this row called the pure claim validators directly. That
// proved the gate's logic and nothing about whether it is wired: if
// `createGoogleRedirectIdentity` or `createGenericOidcRedirectIdentity` stopped
// invoking the validator, assembled identity differently, or stripped the claim
// on the way out, the row stayed green. Review caught it, and it is the same
// defect class as the CIMD regression — a test that confirms the rule its author
// just wrote rather than the behaviour a consumer gets.
//
// So this drives each shipped port's real `exchangeAndVerify` path: a signed
// id_token, returned by an injected token transport, verified against an
// injected key. No JWKS fetch, but every layer of the port in between.
import assert from "node:assert/strict";
import { test } from "node:test";
import { SignJWT, generateKeyPair, type CryptoKey } from "jose";
import { createGoogleRedirectIdentity } from "../src/identity/google.ts";
import { createGenericOidcRedirectIdentity } from "../src/identity/generic-oidc-redirect.ts";

const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;

const NOW = 1_800_000_000;
const CLIENT_ID = "release-client";
const REDIRECT = "https://app.test/cb";
const GOOGLE_ISSUER = "https://accounts.google.com";
const GENERIC_ISSUER = "https://idp.test";

async function signIdToken(claims: Record<string, unknown>, key: CryptoKey): Promise<string> {
  return await new SignJWT(claims).setProtectedHeader({ alg: "RS256", typ: "JWT" }).sign(key);
}

/** A token transport that returns one signed id_token, as the real exchange does. */
function transportFor(idToken: string) {
  return { async postForm() { return { status: 200, async text() { return JSON.stringify({ id_token: idToken, access_token: "AT_MUST_NOT_LEAK" }); } }; } };
}

/** Drive the shipped Google port end to end and return the claims it surfaces. */
async function googleClaims(extra: Record<string, unknown>) {
  const rsa = await generateKeyPair("RS256");
  const idToken = await signIdToken(
    { iss: GOOGLE_ISSUER, aud: CLIENT_ID, sub: "104", exp: NOW + 3600, iat: NOW, nonce: "n", ...extra },
    rsa.privateKey,
  );
  const port = await createGoogleRedirectIdentity(
    { clientId: CLIENT_ID, clientSecret: "release-secret", redirectUri: REDIRECT },
    { verifyKey: rsa.publicKey, currentDate: new Date(NOW * 1000), transport: transportFor(idToken) },
  );
  const res = await port.exchangeAndVerify({ code: "c", codeVerifier: "v", nonce: "n" });
  return res;
}

/** Same for the shipped generic OIDC port, in manual-endpoint mode. */
async function genericClaims(extra: Record<string, unknown>) {
  const rsa = await generateKeyPair("RS256");
  const idToken = await signIdToken(
    { iss: GENERIC_ISSUER, aud: CLIENT_ID, sub: "user-1", exp: NOW + 3600, iat: NOW, nonce: "n", ...extra },
    rsa.privateKey,
  );
  const port = await createGenericOidcRedirectIdentity(
    {
      issuer: GENERIC_ISSUER, clientId: CLIENT_ID, clientSecret: "release-secret", redirectUri: REDIRECT,
      endpoints: {
        authorizationEndpoint: `${GENERIC_ISSUER}/auth`,
        tokenEndpoint: `${GENERIC_ISSUER}/token`,
        jwksUri: `${GENERIC_ISSUER}/jwks`,
      },
    },
    { verifyKey: rsa.publicKey, currentDate: new Date(NOW * 1000), transport: transportFor(idToken) },
  );
  return await port.exchangeAndVerify({ code: "c", codeVerifier: "v", nonce: "n" });
}

// Names spelled out literally: the release-matrix integrity check matches
// manifest evidence by exact substring, so interpolated names cannot be gated.
const PORTS = [
  { run: googleClaims, subject: "104",
    verified: "RM.12 [Google preset] the shipped port surfaces a verified display name",
    unverified: "RM.12 [Google preset] the shipped port drops an unverified display name",
    overlong: "RM.12 [Google preset] the shipped port omits an over-long name rather than truncating",
    nonString: "RM.12 [Google preset] the shipped port ignores a non-string name" },
  { run: genericClaims, subject: `${GENERIC_ISSUER}|user-1`,
    verified: "RM.12 [generic OIDC] the shipped port surfaces a verified display name",
    unverified: "RM.12 [generic OIDC] the shipped port drops an unverified display name",
    overlong: "RM.12 [generic OIDC] the shipped port omits an over-long name rather than truncating",
    nonString: "RM.12 [generic OIDC] the shipped port ignores a non-string name" },
] as const;

for (const port of PORTS) {
  releaseTest(port.verified, async () => {
    const res = await port.run({ email: "ada@idp.test", email_verified: true, name: "Ada Lovelace" });
    assert.ok(res.ok, `port must verify a well-formed token: ${JSON.stringify(res)}`);
    assert.equal(res.identity.claims?.name, "Ada Lovelace", "the gate must be WIRED, not merely implemented");
    assert.equal(res.identity.subject, port.subject, "subject shape must be unaffected by the claim");
    assert.ok(
      !JSON.stringify(res.identity).includes("AT_MUST_NOT_LEAK"),
      "the access token must never reach IdentityClaims",
    );
  });

  releaseTest(port.unverified, async () => {
    const res = await port.run({ email: "ada@idp.test", email_verified: false, name: "Ada Lovelace" });
    assert.ok(res.ok, JSON.stringify(res));
    assert.ok(!("name" in (res.identity.claims ?? {})), "an unverified identity must carry no display name");
  });

  releaseTest(port.overlong, async () => {
    const res = await port.run({ email_verified: true, name: "a".repeat(257) });
    assert.ok(res.ok, JSON.stringify(res));
    assert.ok(
      !("name" in (res.identity.claims ?? {})),
      "truncating would publish a string the IdP never issued",
    );
  });

  releaseTest(port.nonString, async () => {
    const res = await port.run({ email_verified: true, name: 7 });
    assert.ok(res.ok, JSON.stringify(res));
    assert.ok(!("name" in (res.identity.claims ?? {})), "a non-string name must be dropped, never coerced");
  });
}
