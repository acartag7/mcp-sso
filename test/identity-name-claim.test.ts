// §17.6 `claims.name` — an OPTIONAL display attribute for hosts that drive a
// RedirectIdentityPort directly and would otherwise have to parse the id_token
// themselves (which the contract forbids).
//
// `name` is attacker-influenced: on most IdPs the end user edits their own
// profile name. So it is display-only — never a subject, never an authorization
// input, never trim-folded for matching — and it is surfaced only alongside a
// verified identity. Google inherits the gate by delegation.
import assert from "node:assert/strict";
import { test } from "node:test";

import { validateGenericOidcIdToken } from "../src/identity/generic-oidc-claims.ts";
import { validateGoogleIdToken } from "../src/identity/google.ts";

const ISSUER = "https://idp.test";
const CLIENT_ID = "client-abc";
const GOOGLE_ISSUER = "https://accounts.google.com";

function generic(overrides: Record<string, unknown> = {}) {
  return validateGenericOidcIdToken(
    { iss: ISSUER, aud: CLIENT_ID, sub: "user-1", exp: 1_800_000_000, iat: 1_700_000_000, ...overrides },
    { issuer: ISSUER, clientId: CLIENT_ID },
  );
}

function google(overrides: Record<string, unknown> = {}) {
  return validateGoogleIdToken(
    { iss: GOOGLE_ISSUER, aud: CLIENT_ID, sub: "104", exp: 1_800_000_000, iat: 1_700_000_000, ...overrides },
    { clientId: CLIENT_ID, clientSecret: "s3cret", redirectUri: "https://app.test/cb" },
  );
}

function claimsOf(result: ReturnType<typeof generic>): Record<string, unknown> {
  assert.ok(result.ok, "expected a valid identity");
  return (result.identity.claims ?? {}) as Record<string, unknown>;
}

// --- the three rows dengon specified, on BOTH validators --------------------

for (const [label, run] of [["generic OIDC", generic], ["Google", google]] as const) {
  test(`${label}: a verified string name is surfaced`, () => {
    const claims = claimsOf(run({ name: "Ada Lovelace", email: "ada@idp.test", email_verified: true }));
    assert.equal(claims.name, "Ada Lovelace");
  });

  test(`${label}: an unverified name is absent`, () => {
    const claims = claimsOf(run({ name: "Ada Lovelace", email: "ada@idp.test", email_verified: false }));
    assert.ok(!("name" in claims), `name must not survive email_verified:false — got ${JSON.stringify(claims)}`);
    // The strict gate: only boolean true qualifies, never the string "true".
    const coerced = claimsOf(run({ name: "Ada Lovelace", email_verified: "true" }));
    assert.ok(!("name" in coerced), "the string \"true\" must not satisfy the verified gate");
    // Absent email_verified is unverified.
    assert.ok(!("name" in claimsOf(run({ name: "Ada Lovelace" }))), "a missing email_verified must not surface name");
  });

  test(`${label}: a non-string name is absent, never coerced`, () => {
    for (const bad of [7, null, {}, [], true]) {
      const claims = claimsOf(run({ name: bad, email_verified: true }));
      assert.ok(!("name" in claims), `name ${JSON.stringify(bad)} must be dropped, not coerced`);
    }
  });
}

// --- bounds and non-folding -------------------------------------------------

test("an over-long name is omitted rather than truncated", () => {
  // Truncating would publish a string the IdP never issued. 256 is the cap.
  const claims = claimsOf(generic({ name: "a".repeat(257), email_verified: true }));
  assert.ok(!("name" in claims), "a 257-char name must be dropped");
  assert.equal(claimsOf(generic({ name: "a".repeat(256), email_verified: true })).name, "a".repeat(256));
});

test("a blank name is absent, but a padded one is surfaced unmodified", () => {
  assert.ok(!("name" in claimsOf(generic({ name: "   ", email_verified: true }))), "whitespace-only is not a name");
  // Presence is decided on trimmed content; the surfaced value stays RAW so no
  // caller can mistake this for a canonical/normalized form.
  assert.equal(claimsOf(generic({ name: "  Ada  ", email_verified: true })).name, "  Ada  ");
});

// --- the invariants this must not disturb -----------------------------------

test("name never becomes the subject", () => {
  const g = generic({ name: "Ada Lovelace", email_verified: true });
  assert.ok(g.ok);
  assert.equal(g.identity.subject, `${ISSUER}|user-1`, "generic subject stays issuer-namespaced sub");

  const gg = google({ name: "Ada Lovelace", email_verified: true });
  assert.ok(gg.ok);
  assert.equal(gg.identity.subject, "104", "Google subject stays the raw sub");
});

test("adding name does not disturb the existing email gating", () => {
  // Google strips an unverified email; the generic port surfaces it with the
  // emailVerified flag. Both behaviors are unchanged by this addition.
  const gg = claimsOf(google({ name: "Ada", email: "ada@gmail.test", email_verified: false }));
  assert.ok(!("email" in gg), "Google must still strip an unverified email");

  const gen = claimsOf(generic({ name: "Ada", email: "ada@idp.test", email_verified: false }));
  assert.equal(gen.email, "ada@idp.test", "generic OIDC still surfaces email with the flag");
  assert.equal(gen.emailVerified, false);
});
