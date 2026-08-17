// Live Entra-redirect probe. Boots the SHIPPED example against the real tenant
// and drives DCR -> authorize, asserting the redirect actually leaves for
// Microsoft with the real client, PKCE, and the flow cookie.
//
// No secret is printed. Values arrive through env and only derived facts
// (host, presence, lengths) are reported.
import { buildExample } from "../../examples/fastify-sqlite/app.ts";

const out = [];
const ok = (label, cond, detail = "") => {
  out.push(`${cond ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  return cond;
};

const built = await buildExample(process.env);
const app = built.app;
let failures = 0;
const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const unmappedGroup = process.env.ENTRA_UNMAPPED_GROUP;
if (typeof unmappedGroup !== "string" || !guid.test(unmappedGroup)) {
  throw new Error("ENTRA_UNMAPPED_GROUP must provide the deny-fixture GUID");
}

try {
  // 1. Discovery + JWKS must resolve against the real tenant.
  const tenant = process.env.ENTRA_TENANT_ID;
  const disc = await fetch(`https://login.microsoftonline.com/${tenant}/v2.0/.well-known/openid-configuration`);
  const discJson = await disc.json();
  if (!ok("Entra discovery resolves", disc.status === 200 && typeof discJson.jwks_uri === "string", `HTTP ${disc.status}`)) failures++;

  const jwks = await fetch(discJson.jwks_uri);
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

  if (!ok("authorize redirects (302)", authz.statusCode === 302, `HTTP ${authz.statusCode}`)) failures++;
  if (!ok("redirect targets Microsoft login", u?.host === "login.microsoftonline.com", u?.host ?? "no location")) failures++;
  if (!ok("redirect path carries the real tenant", (u?.pathname ?? "").startsWith(`/${tenant}/`), "tenant path matched")) failures++;
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
  if (!ok("boot accepted the real group mapping", groups.length >= 2, `${groups.length} real groups mapped`)) failures++;
  if (!ok("every mapped key is a real GUID, not a display name", groups.length > 0 && groups.every((g) => guid.test(g)))) failures++;
  if (!ok("the unmapped deny-leg group is NOT in the mapping", !groups.includes(unmappedGroup), "no-mapped-group leg stays provable")) failures++;
} finally {
  await app.close();
}

console.log(out.join("\n"));
console.log(`\n${out.filter((l) => l.startsWith("PASS")).length}/${out.length} checks passed`);
process.exit(failures > 0 ? 1 : 0);
