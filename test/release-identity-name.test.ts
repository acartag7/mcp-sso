// RM.12 — `claims.name` reaches a host through the shipped identity ports.
//
// Composition row for the second feature this release introduces. The unit
// tests pin the gate; this pins that the gate is actually WIRED on both shipped
// OIDC ports — Google reaches it only by delegating to the generic validator, so
// a refactor that gave Google its own claim assembly would pass every unit test
// and silently drop the gate on the port most deployments use.
import assert from "node:assert/strict";
import { test } from "node:test";
import { validateGenericOidcIdToken } from "../src/identity/generic-oidc-claims.ts";
import { validateGoogleIdToken } from "../src/identity/google.ts";

const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;

const ISSUER = "https://idp.test";
const CLIENT_ID = "release-client";
const GOOGLE_ISSUER = "https://accounts.google.com";
const BASE = { exp: 1_800_000_000, iat: 1_700_000_000 };

function claimsOf(result: { ok: true; identity: { claims?: Record<string, unknown> } } | { ok: false; reason: string }) {
  assert.ok(result.ok, "expected a valid identity");
  return (result.identity.claims ?? {}) as Record<string, unknown>;
}

const PORTS = [
  {
    label: "generic OIDC",
    run: (o: Record<string, unknown>) => validateGenericOidcIdToken(
      { iss: ISSUER, aud: CLIENT_ID, sub: "user-1", ...BASE, ...o },
      { issuer: ISSUER, clientId: CLIENT_ID },
    ),
    subject: `${ISSUER}|user-1`,
  },
  {
    label: "Google preset",
    run: (o: Record<string, unknown>) => validateGoogleIdToken(
      { iss: GOOGLE_ISSUER, aud: CLIENT_ID, sub: "104", ...BASE, ...o },
      { clientId: CLIENT_ID, clientSecret: "release-secret", redirectUri: "https://app.test/cb" },
    ),
    subject: "104",
  },
] as const;

releaseTest("RM.12 both shipped OIDC ports surface a verified display name and drop an unverified one", () => {
  for (const port of PORTS) {
    const verified = claimsOf(port.run({ name: "Ada Lovelace", email: "ada@idp.test", email_verified: true }));
    assert.equal(verified.name, "Ada Lovelace", `${port.label} must surface a verified name`);

    const unverified = claimsOf(port.run({ name: "Ada Lovelace", email: "ada@idp.test", email_verified: false }));
    assert.ok(!("name" in unverified), `${port.label} must drop the name for an unverified identity`);

    // Attacker-influenced: an over-long value is omitted, never truncated into a
    // string the IdP never issued.
    const overlong = claimsOf(port.run({ name: "a".repeat(257), email_verified: true }));
    assert.ok(!("name" in overlong), `${port.label} must drop an over-long name`);

    // The claim must never become identity. Google keeps its raw sub; the generic
    // port keeps its issuer-namespaced subject.
    const withName = port.run({ name: "Ada Lovelace", email_verified: true });
    assert.ok(withName.ok);
    assert.equal(withName.identity.subject, port.subject, `${port.label} subject must not be affected by name`);
  }
});
