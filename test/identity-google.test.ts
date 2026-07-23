// GoogleIdentity (contracts §17.6 preset) — pure claim-validation + the preset
// factory + redirect port. Zero-network: jose synthetic keys + a discoveryFetch
// stub (Google uses discovery at https://accounts.google.com). Covers the
// Google-specific gates: strict iss (schemeless variant rejected), hostedDomain
// via the `hd` claim (not the email domain), email surfaced only when
// email_verified === true, and clientSecret-required boot.

import assert from "node:assert/strict";
import { test } from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import {
  validateGoogleIdToken, verifyGoogleIdToken, createGoogleIdentity, createGoogleRedirectIdentity,
  GOOGLE_ISSUER, type GoogleConfig, type GoogleIdTokenPayload,
} from "../src/identity/google.ts";
import type { DiscoveryTransport, GenericOidcTokenTransport } from "../src/identity/generic-oidc-discovery.ts";

const CLIENT_ID = "google-test-client-id";
const SECRET = "google-test-secret";
const REDIRECT_URI = "https://bridge.test/oauth/callback";
const NOW = Math.floor(Date.parse("2026-07-03T12:00:00.000Z") / 1000);
const CONFIG: GoogleConfig = { clientId: CLIENT_ID, clientSecret: SECRET, redirectUri: REDIRECT_URI };

function gp(overrides: Record<string, unknown> = {}): GoogleIdTokenPayload {
  return { iss: GOOGLE_ISSUER, aud: CLIENT_ID, sub: "google-sub-123", exp: NOW + 3600, iat: NOW, ...overrides } as GoogleIdTokenPayload;
}

// --- pure validator ----------------------------------------------------------

test("validateGoogleIdToken: happy path; subject = raw Google sub (no issuer namespace)", () => {
  const r = validateGoogleIdToken(gp(), CONFIG);
  assert.equal(r.ok, true);
  assert.equal(r.ok && r.identity.subject, "google-sub-123");
});

test("validateGoogleIdToken: strict iss — schemeless variant rejected", () => {
  assert.equal(validateGoogleIdToken(gp({ iss: "accounts.google.com" }), CONFIG).ok, false); // schemeless legacy variant
  assert.equal(validateGoogleIdToken(gp({ iss: "https://evil.test" }), CONFIG).ok, false);
});

test("validateGoogleIdToken: hostedDomain via the hd claim (never the email domain)", () => {
  const hd: GoogleConfig = { ...CONFIG, hostedDomain: "example.com" };
  assert.equal(validateGoogleIdToken(gp({ hd: "example.com" }), hd).ok, true); // match
  assert.equal(validateGoogleIdToken(gp({ hd: "evil.com" }), hd).ok, false); // mismatch
  assert.equal(validateGoogleIdToken(gp({}), hd).ok, false); // missing hd
  // hostedDomain unset + hd present ⇒ ignored (accepted)
  assert.equal(validateGoogleIdToken(gp({ hd: "anything" }), CONFIG).ok, true);
});

test("validateGoogleIdToken: hostedDomain comparison is case-insensitive (domains normalize)", () => {
  assert.equal(validateGoogleIdToken(gp({ hd: "example.com" }), { ...CONFIG, hostedDomain: "Example.COM" }).ok, true);
  assert.equal(validateGoogleIdToken(gp({ hd: "EXAMPLE.COM" }), { ...CONFIG, hostedDomain: "example.com" }).ok, true);
});

test("validateGoogleIdToken + createGoogleIdentity: a blank hostedDomain is fail-closed (does NOT silently disable the gate)", () => {
  // a present-but-blank hostedDomain must reject, not skip the Workspace gate
  assert.equal(validateGoogleIdToken(gp({ hd: "example.com" }), { ...CONFIG, hostedDomain: "" }).ok, false);
  assert.equal(validateGoogleIdToken(gp({ hd: "example.com" }), { ...CONFIG, hostedDomain: "  " }).ok, false);
  assert.equal(validateGoogleIdToken(
    gp({ hd: "example.com" }),
    { ...CONFIG, hostedDomain: { trim: () => "example.com" } as unknown as string },
  ).ok, false);
});

test("createGoogleIdentity rejects a non-string hostedDomain before discovery", async () => {
  await assert.rejects(
    createGoogleIdentity({
      ...CONFIG,
      hostedDomain: { trim: () => "example.com" } as unknown as string,
    }),
    /google_bad_config: hostedDomain must be a non-empty string/,
  );
});

test("validateGoogleIdToken: email surfaced only when email_verified === true (strict)", () => {
  const verified = validateGoogleIdToken(gp({ email: "u@example.com", email_verified: true }), CONFIG);
  assert.equal(verified.ok, true);
  assert.equal(verified.ok && verified.identity.claims?.email, "u@example.com"); // surfaced
  const unverified = validateGoogleIdToken(gp({ email: "u@example.com", email_verified: false }), CONFIG);
  assert.equal(unverified.ok, true);
  assert.equal(unverified.ok && (unverified.identity.claims?.email ?? undefined), undefined); // stripped
  const strTrue = validateGoogleIdToken(gp({ email: "u@example.com", email_verified: "true" }), CONFIG);
  assert.equal(strTrue.ok && (strTrue.identity.claims?.email ?? undefined), undefined); // string "true" ⇒ stripped (strict)
});

test("validateGoogleIdToken: hosted-domain and verification selectors use own data only", () => {
  const inheritedHd = Object.assign(Object.create({ hd: "example.com" }), gp()) as GoogleIdTokenPayload;
  const hdResult = validateGoogleIdToken(inheritedHd, { ...CONFIG, hostedDomain: "example.com" });
  assert.equal(hdResult.ok, false);
  if (!hdResult.ok) assert.equal(hdResult.reason, "google_missing_hosted_domain");

  const inheritedVerified = Object.assign(
    Object.create({ email_verified: true }),
    gp({ email: "u@example.com" }),
  ) as GoogleIdTokenPayload;
  const emailResult = validateGoogleIdToken(inheritedVerified, CONFIG);
  assert.equal(emailResult.ok, true);
  assert.equal(emailResult.ok && (emailResult.identity.claims?.email ?? undefined), undefined);

  let reads = 0;
  const accessorPayload = gp();
  Object.defineProperty(accessorPayload, "hd", {
    enumerable: true,
    get() { reads += 1; return "example.com"; },
  });
  assert.equal(validateGoogleIdToken(
    accessorPayload,
    { ...CONFIG, hostedDomain: "example.com" },
  ).ok, false);
  assert.equal(reads, 0);
});

test("validateGoogleIdToken: reuses generic gates (multi-audience, iat, nonce)", () => {
  assert.equal(validateGoogleIdToken(gp({ aud: [CLIENT_ID, "other"] }), CONFIG).ok, false); // multi-aud
  assert.equal(validateGoogleIdToken(gp({ iat: undefined }), CONFIG).ok, false); // iat required
  assert.equal(validateGoogleIdToken(gp({ nonce: "n" }), CONFIG, { expectedNonce: "x" }).ok, false); // nonce mismatch
});

// --- factory + redirect port (discoveryFetch stub, jose synthetic key) -------

const GOOGLE_DOC = {
  issuer: GOOGLE_ISSUER,
  authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
  token_endpoint: "https://oauth2.googleapis.com/token",
  jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
  id_token_signing_alg_values_supported: ["RS256"],
  code_challenge_methods_supported: ["S256"],
};
function googleDiscovery(): DiscoveryTransport {
  return { async get() { return { status: 200, async json() { return GOOGLE_DOC; } }; } };
}

test("createGoogleIdentity: clientSecret required at boot; builds via discovery", async () => {
  await assert.rejects(createGoogleIdentity({ clientId: CLIENT_ID, clientSecret: "", redirectUri: REDIRECT_URI } as GoogleConfig, { discoveryFetch: googleDiscovery() }));
  await assert.rejects(createGoogleIdentity({ clientId: CLIENT_ID, redirectUri: REDIRECT_URI } as unknown as GoogleConfig, { discoveryFetch: googleDiscovery() }));
  const id = await createGoogleIdentity(CONFIG, { discoveryFetch: googleDiscovery() });
  assert.equal(id.redirectUri, REDIRECT_URI);
  assert.match(id.getAuthorizationUrl({ state: "s", nonce: "n", codeChallenge: "c" }), /^https:\/\/accounts\.google\.com\/o\/oauth2\/v2\/auth\?/);
  assert.equal((await id.verify(undefined)).ok, false); // non-string — no JWKS fetch
});

test("createGoogleIdentity requires own required config fields", async () => {
  const inherited = {
    clientId: CLIENT_ID, clientSecret: SECRET, redirectUri: REDIRECT_URI,
  };
  const previous = new Map<string, PropertyDescriptor | undefined>();
  for (const [key, value] of Object.entries(inherited)) {
    previous.set(key, Object.getOwnPropertyDescriptor(Object.prototype, key));
    Object.defineProperty(Object.prototype, key, { configurable: true, value });
  }
  try {
    await assert.rejects(
      createGoogleIdentity({} as GoogleConfig, { discoveryFetch: googleDiscovery() }),
      /google_client_secret_required|generic_oidc_bad_config/,
    );
  } finally {
    for (const key of Object.keys(inherited)) {
      const descriptor = previous.get(key);
      if (descriptor === undefined) delete (Object.prototype as Record<string, unknown>)[key];
      else Object.defineProperty(Object.prototype, key, descriptor);
    }
  }
});

test("verifyGoogleIdToken: RS256 accept + Google hd/email_verified shaping", async () => {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const now = new Date(NOW * 1000);
  const claims = { iss: GOOGLE_ISSUER, aud: CLIENT_ID, sub: "g-1", exp: NOW + 3600, iat: NOW, hd: "example.com", email: "u@example.com", email_verified: true };
  const token = await new SignJWT(claims).setProtectedHeader({ alg: "RS256", typ: "JWT" }).sign(privateKey);
  const r = await verifyGoogleIdToken(token, publicKey, { ...CONFIG, hostedDomain: "example.com" }, { currentDate: now });
  assert.equal(r.ok, true);
  assert.equal(r.ok && r.identity.subject, "g-1");
  assert.equal(r.ok && r.identity.claims?.email, "u@example.com"); // verified ⇒ surfaced
  // hd mismatch ⇒ identity_rejected
  const bad = await verifyGoogleIdToken(token, publicKey, { ...CONFIG, hostedDomain: "other.com" }, { currentDate: now });
  assert.equal(bad.ok, false);
});

test("createGoogleRedirectIdentity: exchangeAndVerify ok + google_bad_hosted_domain identity_rejected", async () => {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const now = new Date(NOW * 1000);
  const baseClaims = { iss: GOOGLE_ISSUER, aud: CLIENT_ID, sub: "g-1", exp: NOW + 3600, iat: NOW, nonce: "n", email: "u@example.com", email_verified: true };
  const transport = (hd: string | undefined): GenericOidcTokenTransport => ({
    async postForm() {
      const token = await new SignJWT({ ...baseClaims, ...(hd !== undefined ? { hd } : {}) }).setProtectedHeader({ alg: "RS256", typ: "JWT" }).sign(privateKey);
      return { status: 200, async text() { return JSON.stringify({ id_token: token, access_token: "SECRET_ATK" }); } };
    },
  });
  // matching hd ⇒ ok
  const okPort = await createGoogleRedirectIdentity({ ...CONFIG, hostedDomain: "example.com" }, { discoveryFetch: googleDiscovery(), verifyKey: publicKey, currentDate: now, transport: transport("example.com") });
  const ok = await okPort.exchangeAndVerify({ code: "c", codeVerifier: "v", nonce: "n" });
  assert.equal(ok.ok, true);
  assert.equal(JSON.stringify(ok.ok ? ok.identity : {}).includes("SECRET_ATK"), false); // no access_token leak
  // mismatched hd ⇒ identity_rejected with the google reason
  const badPort = await createGoogleRedirectIdentity({ ...CONFIG, hostedDomain: "example.com" }, { discoveryFetch: googleDiscovery(), verifyKey: publicKey, currentDate: now, transport: transport("evil.com") });
  const bad = await badPort.exchangeAndVerify({ code: "c", codeVerifier: "v", nonce: "n" });
  assert.ok(!bad.ok && bad.kind === "identity_rejected");
});

test("createGoogleRedirectIdentity: an unusable remote key is exchange_failed", async () => {
  const rsa = await generateKeyPair("RS256", { extractable: true });
  const claims = {
    iss: GOOGLE_ISSUER, aud: CLIENT_ID, sub: "g-1", exp: NOW + 3600, iat: NOW, nonce: "n",
  };
  const idToken = await new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "selected-key" })
    .sign(rsa.privateKey);
  const transport: GenericOidcTokenTransport = {
    async postForm() {
      return {
        status: 200,
        async text() { return JSON.stringify({ id_token: idToken, access_token: "atk" }); },
      };
    },
  };
  const nonPublicJwk = { ...await exportJWK(rsa.privateKey), kid: "selected-key", alg: "RS256" };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(JSON.stringify({ keys: [nonPublicJwk] }), { status: 200 })) as typeof fetch;
  try {
    const port = await createGoogleRedirectIdentity(CONFIG, {
      discoveryFetch: googleDiscovery(), transport, currentDate: new Date(NOW * 1000),
    });
    const result = await port.exchangeAndVerify({ code: "c", codeVerifier: "v", nonce: "n" });
    assert.ok(!result.ok && result.kind === "exchange_failed");
  } finally {
    globalThis.fetch = realFetch;
  }
});
