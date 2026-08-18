// Live Google discovery and authorization-redirect proof against the shipped
// Fastify/SQLite example. Credentials are supplied out of band and no value or
// provider identifier is written to output.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildExample } from "../../examples/fastify-sqlite/app.ts";
import { pkceChallenge } from "../../src/crypto.ts";
import { GOOGLE_ISSUER } from "../../src/identity/google.ts";
import { defaultDiscoveryTransport } from "../../src/identity/generic-oidc-discovery.ts";
import { assertRegistrationRedirectPolicy } from "../../src/redirect.ts";
import { countUsableRs256Keys, fetchJson } from "./probe-entra-support.mjs";
import { resolveFetchedGoogleDiscovery } from "./probe-google-support.mjs";

const required = ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI"];
for (const name of required) {
  if (typeof process.env[name] !== "string" || process.env[name].length === 0) {
    throw new Error(`${name} must provide the provisioned Google OAuth credential`);
  }
}
let clientRedirect;
try {
  clientRedirect = assertRegistrationRedirectPolicy(
    process.env.PROBE_CLIENT_REDIRECT,
    "web",
  );
} catch {
  throw new Error("PROBE_CLIENT_REDIRECT must provide a valid web redirect URL");
}

const out = [];
const ok = (label, condition, detail = "") => {
  out.push(`${condition ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  return condition;
};
let failures = 0;
let app;
let store;
let stateDir;

try {
  stateDir = await mkdtemp(join(tmpdir(), "mcp-sso-live-google-"));
  const isolatedEnv = {
    ...process.env,
    ENTRA_TENANT_ID: undefined,
    CF_ACCESS_AUDIENCE: undefined,
    OIDC_ISSUER: undefined,
    MCP_SSO_DIR: stateDir,
    OAUTH_SQLITE_FILE: join(stateDir, "auth.db"),
  };
  // This factory call uses createGoogleIdentity's default discovery transport.
  const built = await buildExample(isolatedEnv);
  app = built.app;
  store = built.store;
  const probeScope = built.config.scopeCatalog[0];

  const discoveryResponse = await defaultDiscoveryTransport.get(
    `${GOOGLE_ISSUER}/.well-known/openid-configuration`,
  );
  // Validate this exact response through the shipped resolver before using any
  // endpoint from it. It may differ from the document consumed during boot.
  const resolved = await resolveFetchedGoogleDiscovery(discoveryResponse);
  if (!ok("Google discovery resolves through the production trust policy",
    discoveryResponse.status === 200)) failures++;

  const jwks = await fetchJson(resolved.jwksUri);
  const usableKeys = await countUsableRs256Keys(jwks.body);
  if (!ok("Google JWKS serves usable RS256 verification keys",
    jwks.status === 200 && usableKeys > 0, `${usableKeys} usable keys`)) failures++;

  const registration = await app.inject({
    method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
    payload: JSON.stringify({ redirect_uris: [clientRedirect], application_type: "web" }),
  });
  const clientId = registration.statusCode === 201
    ? registration.json().client_id
    : undefined;
  if (!ok("DCR registers a client",
    registration.statusCode === 201 && typeof clientId === "string",
    `HTTP ${registration.statusCode}`)) failures++;

  const verifier = "live-google-probe-verifier-0123456789abcdef0123";
  const query = new URLSearchParams({
    response_type: "code",
    client_id: clientId ?? "fixture-registration-failed",
    redirect_uri: clientRedirect,
    code_challenge: pkceChallenge(verifier),
    code_challenge_method: "S256",
    scope: probeScope,
  });
  const authorization = await app.inject({
    method: "GET", url: `/oauth/authorize?${query}`,
  });
  const location = authorization.headers.location ?? "";
  const target = location.startsWith("http") ? new URL(location) : null;
  const targetBase = target === null ? null : new URL(target.href);
  if (targetBase !== null) {
    targetBase.search = "";
    targetBase.hash = "";
  }
  const advertised = new URL(resolved.authorizationEndpoint);
  const advertisedIsBare = advertised.username === ""
    && advertised.password === ""
    && advertised.search === ""
    && advertised.hash === "";

  if (!ok("authorize redirects to Google", authorization.statusCode === 302,
    `HTTP ${authorization.statusCode}`)) failures++;
  if (!ok("redirect matches the validated discovery endpoint",
    advertisedIsBare && targetBase?.href === advertised.href)) failures++;
  if (!ok("upstream client_id is the provisioned app",
    target?.searchParams.get("client_id") === process.env.GOOGLE_CLIENT_ID)) failures++;
  if (!ok("upstream redirect_uri is the provisioned callback",
    target?.searchParams.get("redirect_uri") === process.env.GOOGLE_REDIRECT_URI)) failures++;
  if (!ok("upstream scope requests openid profile email",
    (target?.searchParams.get("scope") ?? "").split(" ").sort().join(" ")
      === "email openid profile")) failures++;
  if (!ok("upstream PKCE is S256",
    target?.searchParams.get("code_challenge_method") === "S256")) failures++;
  if (!ok("upstream state present",
    (target?.searchParams.get("state") ?? "").length > 16)) failures++;
  if (!ok("upstream nonce present",
    (target?.searchParams.get("nonce") ?? "").length > 16)) failures++;
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
  if (store !== undefined) {
    try {
      await store.close();
    } catch {
      failures++;
      out.push("FAIL  probe store cleanup failed");
    }
  }
  if (stateDir !== undefined) {
    try {
      await rm(stateDir, { recursive: true, force: true });
    } catch {
      failures++;
      out.push("FAIL  probe state cleanup failed");
    }
  }
  console.log(out.join("\n"));
  console.log(`\n${out.filter((line) => line.startsWith("PASS")).length}/${out.length} live checks passed`);
  process.exitCode = failures > 0 ? 1 : 0;
}
