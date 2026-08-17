// Live Cloudflare Access leg + the hardening surface that does not need a
// browser. Boots the SHIPPED example against the real Access application and
// drives negative cases that only mean something against live infrastructure:
// a token we mint ourselves must be refused by verification against
// Cloudflare's REAL published keys.
//
// No secret is printed.
import { buildExample } from "../../examples/fastify-sqlite/app.ts";
const { SignJWT, generateKeyPair } = await import("jose");

const out = [];
const ok = (label, cond, detail = "") => {
  out.push(`${cond ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  return cond;
};

const built = await buildExample(process.env);
const app = built.app;
let failures = 0;
const APP = process.env.PROBE_APP_CALLBACK;

try {
  // --- 1. Real Cloudflare Access infrastructure -----------------------------
  const certsUrl = process.env.CF_ACCESS_CERTS_URL;
  const certs = await fetch(certsUrl);
  const certsJson = await certs.json();
  if (!ok("Cloudflare Access certs endpoint resolves", certs.status === 200, `HTTP ${certs.status}`)) failures++;
  if (!ok("Access publishes real signing keys", (certsJson.keys ?? []).length > 0, `${(certsJson.keys ?? []).length} keys`)) failures++;

  // --- 2. Identity is fail-closed -------------------------------------------
  // Use a real registered client and otherwise-valid authorize request. If the
  // identity gate regresses, this request reaches consent (200) instead of
  // failing later on an unrelated unknown-client or parameter check.
  const identityClient = await app.inject({
    method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
    payload: JSON.stringify({ redirect_uris: [APP], application_type: "web" }),
  });
  const identityClientId = identityClient.statusCode === 201 ? identityClient.json().client_id : undefined;
  if (!ok("identity-negative fixture registers a valid client",
    identityClient.statusCode === 201 && typeof identityClientId === "string", `HTTP ${identityClient.statusCode}`)) failures++;
  const identityQuery = new URLSearchParams({
    response_type: "code", client_id: identityClientId ?? "fixture-registration-failed",
    redirect_uri: APP, code_challenge: "A".repeat(43), code_challenge_method: "S256",
    scope: "mcp:read", state: "identity-negative",
  });
  const noHeader = await app.inject({ method: "GET", url: `/oauth/authorize?${identityQuery}` });
  if (!ok("authorize without an Access assertion is refused by identity verification",
    noHeader.statusCode === 401, `HTTP ${noHeader.statusCode}`)) failures++;

  // A token WE mint, with the right issuer and audience, signed by a key
  // Cloudflare never published. Verification runs against the live JWKS, so
  // this is a real negative against real infrastructure — not a stub.
  const { privateKey } = await generateKeyPair("RS256");
  const forged = await new SignJWT({ email: "attacker@example.test" })
    .setProtectedHeader({ alg: "RS256", kid: "forged-key" })
    .setIssuer(process.env.CF_ACCESS_ISSUER)
    .setAudience(process.env.CF_ACCESS_AUDIENCE)
    .setIssuedAt().setExpirationTime("5m")
    .sign(privateKey);
  const forgedRes = await app.inject({
    method: "GET", url: `/oauth/authorize?${identityQuery}`,
    headers: { "cf-access-jwt-assertion": forged },
  });
  if (!ok("a self-signed Access assertion is refused by the live JWKS", forgedRes.statusCode === 401, `HTTP ${forgedRes.statusCode}`)) failures++;
  if (!ok("the refusal does not echo the forged subject", !forgedRes.body.includes("attacker@example.test"))) failures++;

  // --- 3. Protected resource challenge (RFC 9728) ---------------------------
  const mcp = await app.inject({ method: "POST", url: "/mcp", headers: { "content-type": "application/json" }, payload: "{}" });
  const chal = String(mcp.headers["www-authenticate"] ?? "");
  if (!ok("unauthenticated /mcp returns 401", mcp.statusCode === 401, `HTTP ${mcp.statusCode}`)) failures++;
  if (!ok("challenge advertises resource_metadata", chal.includes("resource_metadata="), chal.slice(0, 60))) failures++;

  // --- 4. RFC 7009 revocation is non-oracular -------------------------------
  const revokeUnknown = await app.inject({
    method: "POST", url: "/oauth/revoke",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: "token=definitely-not-a-real-token",
  });
  if (!ok("revoking an unknown token still returns 200", revokeUnknown.statusCode === 200, `HTTP ${revokeUnknown.statusCode}`)) failures++;

  // --- 5. Hardening landed in this release line -----------------------------
  const dupForm = await app.inject({
    method: "POST", url: "/oauth/revoke",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: "token=a&token=b",
  });
  if (!ok("duplicate OAuth form field is rejected", dupForm.statusCode === 400, `HTTP ${dupForm.statusCode}`)) failures++;

  const badCt = await app.inject({
    method: "POST", url: "/oauth/register",
    headers: { "content-type": "text/plain" },
    payload: JSON.stringify({ redirect_uris: [APP] }),
  });
  if (!ok("unsupported Content-Type never becomes OAuth fields", badCt.statusCode === 400 && !badCt.body.includes("client_id"), `HTTP ${badCt.statusCode}`)) failures++;

  const dupCt = await app.inject({
    method: "POST", url: "/oauth/register",
    headers: { "content-type": ["application/json", "application/json"] },
    payload: JSON.stringify({ redirect_uris: [APP] }),
  });
  if (!ok("ambiguous duplicate Content-Type is rejected", dupCt.statusCode === 400, `HTTP ${dupCt.statusCode}`)) failures++;

  // redirectAllowlistMode is "extend" here, so a built-in hosted origin registers
  // while an unlisted third-party origin does not.
  const hosted = await app.inject({
    method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
    payload: JSON.stringify({ redirect_uris: ["https://claude.ai/api/mcp/auth_callback"], application_type: "web" }),
  });
  if (!ok("built-in hosted origin registers under extend", hosted.statusCode === 201, `HTTP ${hosted.statusCode}`)) failures++;

  const rogue = await app.inject({
    method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
    payload: JSON.stringify({ redirect_uris: ["https://evil.test/callback"], application_type: "web" }),
  });
  if (!ok("an unlisted redirect origin is refused", rogue.statusCode >= 400, `HTTP ${rogue.statusCode}`)) failures++;

  // --- 6. State-dir hardening actually applied ------------------------------
  const { statSync } = await import("node:fs");
  const mode = statSync(process.env.MCP_SSO_DIR).mode & 0o777;
  if (!ok("state directory is 0700 on disk", mode === 0o700, `mode ${mode.toString(8)}`)) failures++;
} finally {
  await app.close();
}

console.log(out.join("\n"));
console.log(`\n${out.filter((l) => l.startsWith("PASS")).length}/${out.length} checks passed`);
process.exit(failures > 0 ? 1 : 0);
