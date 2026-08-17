// Live Cloudflare Access leg + the hardening surface that does not need a
// browser. Boots the shipped example against the real Access application and
// verifies that an assertion signed outside Cloudflare is rejected by the
// provider's published keys. No secret is printed.
import { statSync } from "node:fs";
import { buildExample } from "../../examples/fastify-sqlite/app.ts";

const { SignJWT, generateKeyPair } = await import("jose");

const out = [];
const ok = (label, condition, detail = "") => {
  out.push(`${condition ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  return condition;
};

const built = await buildExample(process.env);
const app = built.app;
const callback = process.env.PROBE_APP_CALLBACK;
let failures = 0;

try {
  const certs = await fetch(process.env.CF_ACCESS_CERTS_URL);
  const certsJson = await certs.json();
  if (!ok("Cloudflare Access certs endpoint resolves", certs.status === 200, `HTTP ${certs.status}`)) failures++;
  if (!ok("Access publishes real signing keys", (certsJson.keys ?? []).length > 0,
    `${(certsJson.keys ?? []).length} keys`)) failures++;

  // Register first so the identity negatives cannot pass on an unrelated
  // unknown-client or malformed-authorize rejection.
  const identityClient = await app.inject({
    method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
    payload: JSON.stringify({ redirect_uris: [callback], application_type: "web" }),
  });
  const identityClientId = identityClient.statusCode === 201
    ? identityClient.json().client_id
    : undefined;
  if (!ok("identity-negative fixture registers a valid client",
    identityClient.statusCode === 201 && typeof identityClientId === "string",
    `HTTP ${identityClient.statusCode}`)) failures++;
  const identityQuery = new URLSearchParams({
    response_type: "code",
    client_id: identityClientId ?? "fixture-registration-failed",
    redirect_uri: callback,
    code_challenge: "A".repeat(43),
    code_challenge_method: "S256",
    scope: "mcp:read",
    state: "identity-negative",
  });
  const noHeader = await app.inject({ method: "GET", url: `/oauth/authorize?${identityQuery}` });
  if (!ok("authorize without an Access assertion is refused by identity verification",
    noHeader.statusCode === 401, `HTTP ${noHeader.statusCode}`)) failures++;

  const { privateKey } = await generateKeyPair("RS256");
  const forged = await new SignJWT({ email: "attacker@example.test" })
    .setProtectedHeader({ alg: "RS256", kid: "forged-key" })
    .setIssuer(process.env.CF_ACCESS_ISSUER)
    .setAudience(process.env.CF_ACCESS_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
  const forgedRes = await app.inject({
    method: "GET", url: `/oauth/authorize?${identityQuery}`,
    headers: { "cf-access-jwt-assertion": forged },
  });
  if (!ok("a self-signed Access assertion is refused by the live JWKS",
    forgedRes.statusCode === 401, `HTTP ${forgedRes.statusCode}`)) failures++;
  if (!ok("the refusal does not echo the forged subject",
    !forgedRes.body.includes("attacker@example.test"))) failures++;

  const mcp = await app.inject({
    method: "POST", url: "/mcp", headers: { "content-type": "application/json" }, payload: "{}",
  });
  const challenge = String(mcp.headers["www-authenticate"] ?? "");
  if (!ok("unauthenticated /mcp returns 401", mcp.statusCode === 401, `HTTP ${mcp.statusCode}`)) failures++;
  if (!ok("challenge advertises resource_metadata", challenge.includes("resource_metadata="),
    challenge.slice(0, 60))) failures++;

  const revokeUnknown = await app.inject({
    method: "POST", url: "/oauth/revoke",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: "token=definitely-not-a-real-token",
  });
  if (!ok("revoking an unknown token still returns 200",
    revokeUnknown.statusCode === 200, `HTTP ${revokeUnknown.statusCode}`)) failures++;

  const dupForm = await app.inject({
    method: "POST", url: "/oauth/revoke",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: "token=a&token=b",
  });
  if (!ok("duplicate OAuth form field is rejected", dupForm.statusCode === 400,
    `HTTP ${dupForm.statusCode}`)) failures++;

  const badContentType = await app.inject({
    method: "POST", url: "/oauth/register", headers: { "content-type": "text/plain" },
    payload: JSON.stringify({ redirect_uris: [callback] }),
  });
  if (!ok("unsupported Content-Type never becomes OAuth fields",
    badContentType.statusCode === 400 && !badContentType.body.includes("client_id"),
    `HTTP ${badContentType.statusCode}`)) failures++;

  const duplicateContentType = await app.inject({
    method: "POST", url: "/oauth/register",
    headers: { "content-type": ["application/json", "application/json"] },
    payload: JSON.stringify({ redirect_uris: [callback] }),
  });
  if (!ok("ambiguous duplicate Content-Type is rejected",
    duplicateContentType.statusCode === 400, `HTTP ${duplicateContentType.statusCode}`)) failures++;

  const hosted = await app.inject({
    method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
    payload: JSON.stringify({
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"], application_type: "web",
    }),
  });
  if (!ok("built-in hosted origin registers under extend",
    hosted.statusCode === 201, `HTTP ${hosted.statusCode}`)) failures++;

  const rogue = await app.inject({
    method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
    payload: JSON.stringify({
      redirect_uris: ["https://evil.test/callback"], application_type: "web",
    }),
  });
  if (!ok("an unlisted redirect origin is refused",
    rogue.statusCode >= 400, `HTTP ${rogue.statusCode}`)) failures++;

  if (process.platform === "win32") {
    // Node's POSIX mode bits do not describe the Windows DACL contract. This is
    // informational and is deliberately excluded from the evidence count.
    console.log("INFO  state-directory POSIX mode is not applicable on Windows; verify the deployer-private ACL");
  } else {
    const mode = statSync(built.dir).mode & 0o777;
    if (!ok("state directory is 0700 on disk", mode === 0o700,
      `mode ${mode.toString(8)}`)) failures++;
  }
} finally {
  await app.close();
}

console.log(out.join("\n"));
console.log(`\n${out.filter((line) => line.startsWith("PASS")).length}/${out.length} checks passed`);
process.exit(failures > 0 ? 1 : 0);
