// Live Entra discovery and authorization-redirect proof against the shipped
// example, plus one explicitly local group-denial control. No credential or
// tenant-specific identifier is written to output.
import {
  buildExample, entraGroupAuthorizationFromEnv,
} from "../../examples/fastify-sqlite/app.ts";
import { generateKeyPair, SignJWT } from "jose";
import {
  assertGroupAuthorizationMapping, createEntraRedirectIdentity, entraIssuer, entraJwksUrl,
} from "../../src/identity/entra.ts";
import { assertRegistrationRedirectPolicy } from "../../src/redirect.ts";
import { countUsableRs256Keys, fetchJson } from "./probe-entra-support.mjs";

const out = [];
const ok = (label, condition, detail = "") => {
  out.push(`${condition ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  return condition;
};
const control = (label, condition, detail = "") => {
  out.push(`${condition ? "CONTROL" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  return condition;
};

let failures = 0;
const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const unmappedGroup = process.env.ENTRA_UNMAPPED_GROUP;
if (typeof unmappedGroup !== "string" || !guid.test(unmappedGroup)) {
  throw new Error("ENTRA_UNMAPPED_GROUP must provide the deny-fixture GUID");
}
let groupAuthorization;
try {
  groupAuthorization = entraGroupAuthorizationFromEnv(process.env);
  assertGroupAuthorizationMapping(groupAuthorization);
} catch {
  throw new Error("ENTRA_GROUP_AUTHORIZATION_JSON must provide a valid group mapping");
}
if (groupAuthorization === undefined) {
  throw new Error("ENTRA_GROUP_AUTHORIZATION_JSON must provide a valid group mapping");
}
const normalizedGroups = new Set(
  Object.keys(groupAuthorization.mapping).map((group) => group.toLowerCase()),
);
if (normalizedGroups.has(unmappedGroup.toLowerCase())) {
  throw new Error("ENTRA_UNMAPPED_GROUP must be absent from the group mapping");
}
let redirect;
try {
  redirect = assertRegistrationRedirectPolicy(
    process.env.PROBE_CLIENT_REDIRECT,
    "web",
  );
} catch {
  throw new Error("PROBE_CLIENT_REDIRECT must provide a valid web redirect URL");
}

let app;

try {
  const built = await buildExample(process.env);
  app = built.app;
  const probeScope = built.config.scopeCatalog[0];
  const tenant = process.env.ENTRA_TENANT_ID;
  const discovery = await fetchJson(
    `https://login.microsoftonline.com/${tenant}/v2.0/.well-known/openid-configuration`,
  );
  const discoveryJson = discovery.body;
  if (!ok("Entra discovery resolves",
    discovery.status === 200 && typeof discoveryJson.jwks_uri === "string",
    `HTTP ${discovery.status}`)) failures++;

  const expectedJwks = entraJwksUrl(tenant);
  if (discoveryJson.jwks_uri !== expectedJwks) {
    throw new Error("Entra discovery returned an untrusted JWKS endpoint");
  }
  const jwks = await fetchJson(expectedJwks);
  const usableKeys = await countUsableRs256Keys(jwks.body);
  if (!ok("Entra JWKS serves usable RS256 verification keys",
    jwks.status === 200 && usableKeys > 0, `${usableKeys} usable keys`)) failures++;

  const registration = await app.inject({
    method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
    payload: JSON.stringify({ redirect_uris: [redirect], application_type: "web" }),
  });
  const clientId = registration.statusCode === 201
    ? registration.json().client_id
    : undefined;
  if (!ok("DCR registers a client",
    registration.statusCode === 201 && typeof clientId === "string",
    `HTTP ${registration.statusCode}`)) failures++;

  const { pkceChallenge } = await import("../../src/crypto.ts");
  const verifier = "live-entra-probe-verifier-0123456789abcdef01234";
  const query = new URLSearchParams({
    response_type: "code",
    client_id: clientId ?? "fixture-registration-failed",
    redirect_uri: redirect,
    code_challenge: pkceChallenge(verifier),
    code_challenge_method: "S256",
    scope: probeScope,
  });
  const authorization = await app.inject({
    method: "GET", url: `/oauth/authorize?${query}`,
  });
  const location = authorization.headers.location ?? "";
  const target = location.startsWith("http") ? new URL(location) : null;
  const advertised = typeof discoveryJson.authorization_endpoint === "string"
    ? new URL(discoveryJson.authorization_endpoint)
    : null;
  const targetBase = target === null ? null : new URL(target.href);
  if (targetBase !== null) {
    targetBase.search = "";
    targetBase.hash = "";
  }
  const advertisedIsBare = advertised !== null
    && advertised.username === ""
    && advertised.password === ""
    && advertised.search === ""
    && advertised.hash === "";

  if (!ok("authorize redirects to Entra", authorization.statusCode === 302,
    `HTTP ${authorization.statusCode}`)) failures++;
  if (!ok("redirect matches the discovered authorization endpoint",
    advertisedIsBare && targetBase?.href === advertised.href)) failures++;
  if (!ok("upstream client_id is the provisioned app",
    target?.searchParams.get("client_id") === process.env.ENTRA_CLIENT_ID)) failures++;
  if (!ok("upstream redirect_uri is the provisioned callback",
    target?.searchParams.get("redirect_uri") === process.env.ENTRA_REDIRECT_URI)) failures++;
  if (!ok("upstream scope requests openid profile email",
    (target?.searchParams.get("scope") ?? "").split(" ").sort().join(" ")
      === "email openid profile")) failures++;
  if (!ok("upstream PKCE is S256",
    target?.searchParams.get("code_challenge_method") === "S256")) failures++;
  if (!ok("upstream state present",
    (target?.searchParams.get("state") ?? "").length > 16)) failures++;
  if (!ok("upstream nonce present",
    (target?.searchParams.get("nonce") ?? "").length > 16)) failures++;

  const cookie = String(authorization.headers["set-cookie"] ?? "");
  if (!ok("flow cookie is __Host- prefixed", cookie.includes("__Host-"))) failures++;
  if (!ok("flow cookie is SameSite=Lax", /SameSite=Lax/i.test(cookie))) failures++;
  if (!ok("flow cookie is HttpOnly and Secure",
    /HttpOnly/i.test(cookie) && /Secure/i.test(cookie))) failures++;

  // This does not prove that the tenant emits the group in a real token. It is
  // a local group-only control for the shipped mapping and reason-code path;
  // documented deployment base scopes are deliberately excluded from this
  // synthetic denial without changing the live example configuration above.
  const groupOnlyAuthorization = {
    mapping: groupAuthorization.mapping,
    baseScopes: [],
  };
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const now = Math.floor(Date.now() / 1000);
  const nonce = "live-unmapped-group-control";
  const denyToken = await new SignJWT({
    oid: "live-unmapped-group-control", tid: tenant, nonce, groups: [unmappedGroup],
  })
    .setProtectedHeader({ alg: "RS256", kid: "local-control" })
    .setIssuer(entraIssuer(tenant))
    .setAudience(process.env.ENTRA_CLIENT_ID)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(privateKey);
  const identity = createEntraRedirectIdentity({
    tenantId: tenant,
    clientId: process.env.ENTRA_CLIENT_ID,
    redirectUri: process.env.ENTRA_REDIRECT_URI,
    groupAuthorization: groupOnlyAuthorization,
  }, {
    verifyKey: publicKey,
    currentDate: new Date(now * 1000),
    transport: { async postForm() {
      return { status: 200, async text() {
        return JSON.stringify({ id_token: denyToken });
      } };
    } },
  });
  const denied = await identity.exchangeAndVerify({
    code: "local-control", codeVerifier: "V".repeat(43), nonce,
  });
  if (!control("local identity control rejects the unmapped group",
    !denied.ok
      && denied.kind === "identity_rejected"
      && denied.reason === "entra_no_mapped_groups",
    denied.ok ? "unexpectedly accepted" : `${denied.kind}:${denied.reason}`)) failures++;
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
  console.log(
    `\n${out.filter((line) => line.startsWith("PASS")).length} live checks passed; `
    + `${out.filter((line) => line.startsWith("CONTROL")).length} local controls passed`,
  );
  process.exitCode = failures > 0 ? 1 : 0;
}
