// Cloudflare Access identity proof against the shipped Fastify/SQLite example.
// The provider assertion is supplied out of band and is never written to output.
import { buildExample } from "../../examples/fastify-sqlite/app.ts";

const { SignJWT, decodeProtectedHeader, generateKeyPair } = await import("jose");

const providerAssertion = process.env.CF_ACCESS_ASSERTION;
if (typeof providerAssertion !== "string" || providerAssertion.length === 0) {
  throw new Error("CF_ACCESS_ASSERTION must provide a current provider-signed assertion");
}
const callback = process.env.PROBE_APP_CALLBACK;
if (typeof callback !== "string" || callback.length === 0) {
  throw new Error("PROBE_APP_CALLBACK must provide the registered callback URL");
}

const out = [];
const ok = (label, condition, detail = "") => {
  out.push(`${condition ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  return condition;
};

let failures = 0;
let app;

try {
  const built = await buildExample(process.env);
  app = built.app;
  const registration = await app.inject({
    method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
    payload: JSON.stringify({ redirect_uris: [callback], application_type: "web" }),
  });
  const clientId = registration.statusCode === 201
    ? registration.json().client_id
    : undefined;
  if (!ok("identity fixture registers a valid client",
    registration.statusCode === 201 && typeof clientId === "string",
    `HTTP ${registration.statusCode}`)) failures++;

  const query = new URLSearchParams({
    response_type: "code",
    client_id: clientId ?? "fixture-registration-failed",
    redirect_uri: callback,
    code_challenge: "A".repeat(43),
    code_challenge_method: "S256",
    scope: "mcp:read",
    state: "cloudflare-live-proof",
  });

  // This request is the live positive control. It proves that the configured
  // issuer, audience, certs URL, and identity port accept a provider assertion.
  const accepted = await app.inject({
    method: "GET", url: `/oauth/authorize?${query}`,
    headers: { "cf-access-jwt-assertion": providerAssertion },
  });
  if (!ok("provider-signed Access assertion reaches the consent page",
    accepted.statusCode === 200 && accepted.body.includes("Authorize access"),
    `HTTP ${accepted.statusCode}`)) failures++;

  const header = decodeProtectedHeader(providerAssertion);
  const providerKid = header.alg === "RS256"
    && typeof header.kid === "string"
    && header.kid.length > 0
    ? header.kid
    : undefined;
  if (!ok("accepted assertion carries a usable RS256 key ID",
    providerKid !== undefined)) failures++;

  const missing = await app.inject({ method: "GET", url: `/oauth/authorize?${query}` });
  if (!ok("authorize without an Access assertion is refused by identity verification",
    missing.statusCode === 401, `HTTP ${missing.statusCode}`)) failures++;

  const { privateKey } = await generateKeyPair("RS256");
  const forged = await new SignJWT({ email: "attacker@example.test" })
    .setProtectedHeader({ alg: "RS256", kid: providerKid ?? "fixture-no-provider-kid" })
    .setIssuer(process.env.CF_ACCESS_ISSUER)
    .setAudience(process.env.CF_ACCESS_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
  const forgedResult = await app.inject({
    method: "GET", url: `/oauth/authorize?${query}`,
    headers: { "cf-access-jwt-assertion": forged },
  });
  if (!ok("an attacker signature under the provider key ID is refused",
    forgedResult.statusCode === 401, `HTTP ${forgedResult.statusCode}`)) failures++;
} catch {
  failures++;
  out.push("FAIL  probe aborted before completion");
} finally {
  if (app !== undefined) {
    try {
      await app.close();
    } catch {
      failures++;
      out.push("FAIL  probe cleanup failed");
    }
  }
  console.log(out.join("\n"));
  console.log(`\n${out.filter((line) => line.startsWith("PASS")).length}/${out.length} checks passed`);
  process.exitCode = failures > 0 ? 1 : 0;
}
