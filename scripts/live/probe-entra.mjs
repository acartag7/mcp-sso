// Live Entra-redirect probe. Boots the SHIPPED example against the real tenant
// and drives DCR -> authorize, asserting the redirect actually leaves for
// Microsoft with the real client, PKCE, and the flow cookie.
//
// No secret is printed. Values arrive through env and only derived facts
// (host, presence, lengths) are reported.
import { buildExample } from "../../examples/fastify-sqlite/app.ts";
import { generateKeyPair, SignJWT } from "jose";
import { createEntraRedirectIdentity, entraIssuer, entraJwksUrl } from "../../src/identity/entra.ts";

const out = [];
const ok = (label, cond, detail = "") => {
  out.push(`${cond ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  return cond;
};
const control = (label, cond, detail = "") => {
  out.push(`${cond ? "CONTROL" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  return cond;
};

let failures = 0;
const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const unmappedGroup = process.env.ENTRA_UNMAPPED_GROUP;
if (typeof unmappedGroup !== "string" || !guid.test(unmappedGroup)) {
  throw new Error("ENTRA_UNMAPPED_GROUP must provide the deny-fixture GUID");
}
const built = await buildExample(process.env);
const app = built.app;

try {
  // 1. Discovery + JWKS must resolve against the real tenant.
  const tenant = process.env.ENTRA_TENANT_ID;
  const disc = await fetch(`https://login.microsoftonline.com/${tenant}/v2.0/.well-known/openid-configuration`);
  const discJson = await disc.json();
  if (!ok("Entra discovery resolves", disc.status === 200 && typeof discJson.jwks_uri === "string", `HTTP ${disc.status}`)) failures++;

  const expectedJwks = entraJwksUrl(tenant);
  if (discJson.jwks_uri !== expectedJwks) {
    throw new Error("Entra discovery returned an untrusted JWKS endpoint");
  }
  const jwks = await fetch(expectedJwks);
  const jwksJson = await jwks.json();
  const rs256 = (jwksJson.keys ?? []).filter((k) => k.kty === "RSA");
  if (!ok("Entra JWKS serves RSA signing keys", jwks.status === 200 && rs256.length > 0, `${rs256.length} RSA keys`)) failures++;

  // 2. The bridge's own metadata is reachable.
  const prm = await app.inject({ method: "GET", url: "/.well-known/oauth-protected-resource" });
  if (!ok("protected-resource metadata served", prm.statusCode === 200, `HTTP ${prm.statusCode}`)) failures++;
  const asMeta = await app.inject({ method: "GET", url: "/.well-known/oauth-authorization-server" });
  if (!ok("authorization-server metadata served", asMeta.statusCode === 200, `HTTP ${asMeta.statusCode}`)) failures++;

  // 3. DCR registers a real client.
  const redirect = process.env.PROBE_CLIENT_REDIRECT;
  const reg = await app.inject({
    method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
    payload: JSON.stringify({ redirect_uris: [redirect], application_type: "web" }),
  });
  const clientId = reg.statusCode === 201 ? reg.json().client_id : undefined;
  if (!ok("DCR registers a client", reg.statusCode === 201 && !!clientId, `HTTP ${reg.statusCode}`)) failures++;

  // 4. Authorize must 302 to the REAL tenant carrying the real app + PKCE.
  const { pkceChallenge } = await import("../../src/crypto.ts");
  const verifier = "live-entra-probe-verifier-0123456789abcdef01234";
  const q = new URLSearchParams({
    response_type: "code", client_id: clientId ?? "x", redirect_uri: redirect,
    code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read",
  });
  const authz = await app.inject({ method: "GET", url: `/oauth/authorize?${q}` });
  const loc = authz.headers.location ?? "";
  const u = loc.startsWith("http") ? new URL(loc) : null;
  const advertisedAuthorization = typeof discJson.authorization_endpoint === "string"
    ? new URL(discJson.authorization_endpoint) : null;

  if (!ok("authorize redirects (302)", authz.statusCode === 302, `HTTP ${authz.statusCode}`)) failures++;
  if (!ok("redirect matches the discovered Entra authorization endpoint",
    u !== null && advertisedAuthorization !== null
      && u.origin === advertisedAuthorization.origin && u.pathname === advertisedAuthorization.pathname,
    u === null ? "no location" : `${u.origin}${u.pathname}`)) failures++;
  if (!ok("upstream client_id is the provisioned app", u?.searchParams.get("client_id") === process.env.ENTRA_CLIENT_ID)) failures++;
  if (!ok("upstream redirect_uri is the provisioned callback", u?.searchParams.get("redirect_uri") === process.env.ENTRA_REDIRECT_URI)) failures++;
  if (!ok("upstream scope requests openid profile email", (u?.searchParams.get("scope") ?? "").split(" ").sort().join(" ") === "email openid profile", u?.searchParams.get("scope") ?? "")) failures++;
  if (!ok("upstream PKCE is S256", u?.searchParams.get("code_challenge_method") === "S256")) failures++;
  if (!ok("upstream state present", (u?.searchParams.get("state") ?? "").length > 16)) failures++;
  if (!ok("upstream nonce present", (u?.searchParams.get("nonce") ?? "").length > 16)) failures++;

  const cookie = String(authz.headers["set-cookie"] ?? "");
  if (!ok("flow cookie is __Host- prefixed", cookie.includes("__Host-"))) failures++;
  if (!ok("flow cookie is SameSite=Lax", /SameSite=Lax/i.test(cookie), "Strict would break Google's redirect back")) failures++;
  if (!ok("flow cookie is HttpOnly + Secure", /HttpOnly/i.test(cookie) && /Secure/i.test(cookie))) failures++;

  // 5. The group-authorization mapping was accepted at boot against real GUIDs.
  // Count the MAPPING entries, not the wrapper object — an earlier version of
  // this check counted {"mapping":…} as one and would have passed on an empty map.
  const groupAuth = JSON.parse(process.env.ENTRA_GROUP_AUTHORIZATION_JSON ?? "{}");
  const groups = Object.keys(groupAuth.mapping ?? {});
  const normalizedGroups = new Set(groups.map((group) => group.toLowerCase()));
  if (!ok("boot accepted the real group mapping", groups.length >= 2, `${groups.length} real groups mapped`)) failures++;
  if (!ok("every mapped key is a real GUID, not a display name", groups.length > 0 && groups.every((g) => guid.test(g)))) failures++;
  if (!ok("the stack-provided deny-fixture GUID is absent from the mapping",
    !normalizedGroups.has(unmappedGroup.toLowerCase()), "configuration precondition holds")) failures++;

  // Explicitly NON-LIVE control: exercise the shipped redirect identity port
  // with a locally signed token carrying the stack-provided GUID. This proves
  // the local mapping/reason path only; it does not claim that the tenant emits
  // this group in a real token. Browser callback evidence is recorded separately.
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const now = Math.floor(Date.now() / 1000);
  const denyNonce = "live-unmapped-group-control";
  const denyToken = await new SignJWT({
    oid: "live-unmapped-group-control", tid: tenant, nonce: denyNonce,
    groups: [unmappedGroup],
  }).setProtectedHeader({ alg: "RS256", kid: "live-control" })
    .setIssuer(entraIssuer(tenant)).setAudience(process.env.ENTRA_CLIENT_ID)
    .setIssuedAt(now).setExpirationTime(now + 300).sign(privateKey);
  const denyIdentity = createEntraRedirectIdentity({
    tenantId: tenant, clientId: process.env.ENTRA_CLIENT_ID,
    redirectUri: process.env.ENTRA_REDIRECT_URI,
    groupAuthorization: groupAuth,
  }, {
    verifyKey: publicKey,
    currentDate: new Date(now * 1000),
    transport: { async postForm() {
      return { status: 200, async text() { return JSON.stringify({ id_token: denyToken }); } };
    } },
  });
  const denied = await denyIdentity.exchangeAndVerify({
    code: "live-control", codeVerifier: "V".repeat(43), nonce: denyNonce,
  });
  if (!control("local identity-port control rejects a signed token carrying only the unmapped group",
    !denied.ok && denied.kind === "identity_rejected" && denied.reason === "entra_no_mapped_groups",
    denied.ok ? "unexpectedly accepted" : `${denied.kind}:${denied.reason}`)) failures++;
} finally {
  await app.close();
}

console.log(out.join("\n"));
console.log(`\n${out.filter((l) => l.startsWith("PASS")).length} live checks passed; ${out.filter((l) => l.startsWith("CONTROL")).length} local controls passed`);
process.exit(failures > 0 ? 1 : 0);
