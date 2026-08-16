// RM.14 — CIMD and stored-DCR clients in ONE deployment.
//
// Every dispatch cell is tested individually elsewhere. This is the combination
// nobody had run: a single bridge with `cimd.enabled` AND stored DCR, serving
// both client kinds for the SAME subject, against ONE granted-scope store.
//
// It matters because the two kinds carry deliberately OPPOSITE rules (§16, §9.3,
// §17.1.6): a stored-DCR opaque client accumulates granted scopes across
// sessions; a CIMD client "stands alone by documented profile decision".
//
//   accumulationAllowed = dcr.mode === "stored" && !isSchemeShaped(clientId)
//
// So the same store answers `findGrantedScopes` for both, and only one of them
// may be widened by it. If a CIMD client ever inherited an opaque client's
// accumulated scopes — or the reverse — that is silent privilege escalation
// across a profile boundary, and no single-kind test would see it.
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import type { CimdTransport, DnsResolver } from "../src/cimd/transport.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import { MemoryStore } from "../src/store/memory.ts";

const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;

const SUBJECT = "shared-operator";
const CIMD_ID = "https://cimd.test/client.json";
const CIMD_REDIRECT = "https://cimd.test/callback";
const OPAQUE_REDIRECT = "https://opaque.test/callback";
const VERIFIER = "coexistence-verifier-0123456789abcdef0123456789";

class Clients implements ClientStore {
  readonly rows = new Map<string, ClientRegistration>();
  async save(c: ClientRegistration): Promise<void> { this.rows.set(c.clientId, structuredClone(c)); }
  async find(id: string): Promise<ClientRegistration | null> { return structuredClone(this.rows.get(id) ?? null); }
}

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "coexist" } as JWK;
}

/** ONE bridge serving both client kinds, sharing ONE granted-scope store. */
function deployment() {
  const clients = new Clients();
  const store = new MemoryStore();
  const config = createBridgeConfig({
    issuer: "https://auth.test", resource: "https://resource.test/mcp",
    consentSigningSecret: "c".repeat(40), signingPrivateJwk: jwk(), signingKeyId: "coexist",
    redirectAllowlist: [OPAQUE_REDIRECT],
    scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stored", store: clients },
    cimd: { enabled: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  const resolver: DnsResolver = { async resolve() { return [{ address: "93.184.216.34", family: 4 }]; } };
  const transport: CimdTransport = {
    async connectAndGet() {
      async function* body(): AsyncGenerator<Uint8Array> {
        yield new TextEncoder().encode(JSON.stringify({
          client_id: CIMD_ID, client_name: "Coexistence client", redirect_uris: [CIMD_REDIRECT],
        }));
      }
      return {
        status: 200, redirected: false, finalUrl: CIMD_ID,
        headersDistinct: { "content-type": ["application/json"] }, encodedBody: body(),
      };
    },
  };
  const bridge = new Bridge({
    config, store, clock: { nowMs: () => Date.parse("2026-08-16T12:00:00Z") },
    audit: { async writeAuthEvent() {} }, cimdTransport: transport, cimdResolver: resolver,
  });
  return { bridge, clients, store };
}

/** Run authorize → approve → token for one client through the PUBLIC Bridge
 *  handlers, returning the scopes granted and the prior grants shown. */
async function grant(
  bridge: Bridge, clientId: string, redirectUri: string, scope: string,
): Promise<{ scopes: string[]; prior: string[] }> {
  const authz = await bridge.handleAuthorize({
    query: {
      response_type: "code", client_id: clientId, redirect_uri: redirectUri,
      code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
      scope, state: "s",
    },
    body: undefined, headers: {}, ip: "127.0.0.1",
  }, { subject: SUBJECT });
  assert.equal(authz.status, 200, `authorize failed: ${JSON.stringify(authz.body).slice(0, 160)}`);
  const page = String(authz.body);
  const consentToken = /name="consent_token" value="([^"]+)"/.exec(page)?.[1];
  assert.ok(consentToken, "consent page must carry a consent token");
  // The consent page is the deployer-visible surface: each requested scope is a
  // row, and a previously granted one is tagged "(already granted)". Reading the
  // rendered page (rather than a private field) is what a step-up actually shows
  // the user, so accumulation is asserted where it is visible.
  const rows = [...page.matchAll(/<div class="scope">([^<]+)(<span class="tag">\(already granted\)|<span class="tag new">)/g)];
  const scopes = rows.map((m) => m[1]!.trim());
  const prior = rows.filter((m) => m[2]!.includes("already granted")).map((m) => m[1]!.trim());

  const approved = await bridge.handleApprove({
    query: {}, body: { consent_token: consentToken, approved: "true" },
    headers: { origin: "https://auth.test", "content-type": "application/x-www-form-urlencoded" },
    ip: "127.0.0.1",
  });
  const code = new URL(approved.redirect ?? "https://x.test").searchParams.get("code");
  assert.ok(code, `approve did not mint a code: ${approved.status}`);

  // The grant must be BANKED, not merely approved: findGrantedScopes is derived
  // from active refresh records (§12.3, "no grant table"), so an approve-only
  // run would report empty accumulation and pass vacuously.
  const tok = await bridge.handleToken({
    query: {},
    body: {
      grant_type: "authorization_code", code, redirect_uri: redirectUri,
      client_id: clientId, code_verifier: VERIFIER,
    },
    headers: { "content-type": "application/x-www-form-urlencoded" }, ip: "127.0.0.1",
  });
  assert.equal(tok.status, 200, `token exchange failed: ${JSON.stringify(tok.body).slice(0, 160)}`);
  return { scopes, prior };
}

releaseTest("RM.14 an opaque stored-DCR client accumulates while a CIMD client in the same deployment does not", async () => {
  const { bridge, clients } = deployment();

  // Register the opaque client through real DCR.
  const reg = await bridge.handleRegister({
    query: {}, body: { redirect_uris: [OPAQUE_REDIRECT], application_type: "web" },
    headers: { "content-type": "application/json" }, ip: "127.0.0.1",
  });
  assert.equal(reg.status, 201, JSON.stringify(reg.body));
  const opaqueId = (reg.body as { client_id: string }).client_id;
  assert.ok(opaqueId.startsWith("mcpdc_"), "DCR must mint an opaque id");
  assert.ok(clients.rows.has(opaqueId), "the opaque client persisted to the shared client store");

  // --- the opaque client accumulates across sessions ------------------------
  await grant(bridge, opaqueId, OPAQUE_REDIRECT, "mcp:read");
  // A step-up REQUESTS both: the consent page lists only requested scopes, so
  // accumulation is visible as the earlier one being tagged already-granted.
  const opaqueSecond = await grant(bridge, opaqueId, OPAQUE_REDIRECT, "mcp:read mcp:write");
  assert.deepEqual(
    opaqueSecond.prior, ["mcp:read"],
    `stored-DCR step-up must show the earlier grant as already-granted; saw ${JSON.stringify(opaqueSecond.prior)}`,
  );
  assert.ok(
    opaqueSecond.scopes.includes("mcp:write") && !opaqueSecond.prior.includes("mcp:write"),
    "the newly requested scope must be offered as new, not silently pre-granted",
  );

  // --- the CIMD client, same subject, same store, does NOT ------------------
  await grant(bridge, CIMD_ID, CIMD_REDIRECT, "mcp:read");
  const cimdSecond = await grant(bridge, CIMD_ID, CIMD_REDIRECT, "mcp:read mcp:write");
  assert.deepEqual(
    cimdSecond.prior, [],
    `a CIMD client stands alone (§17.1.6) and must accumulate nothing; saw ${JSON.stringify(cimdSecond.prior)}`,
  );
});

releaseTest("RM.14 neither client kind inherits the other's grants for the same subject", async () => {
  const { bridge } = deployment();

  const reg = await bridge.handleRegister({
    query: {}, body: { redirect_uris: [OPAQUE_REDIRECT], application_type: "web" },
    headers: { "content-type": "application/json" }, ip: "127.0.0.1",
  });
  const opaqueId = (reg.body as { client_id: string }).client_id;

  // The opaque client banks mcp:write for this subject.
  await grant(bridge, opaqueId, OPAQUE_REDIRECT, "mcp:read");
  await grant(bridge, opaqueId, OPAQUE_REDIRECT, "mcp:write");

  // The CIMD client, same subject, must not see any of it — cross-kind
  // inheritance here would be silent privilege escalation across the profile
  // boundary, and it is the reason this row exists.
  const cimd = await grant(bridge, CIMD_ID, CIMD_REDIRECT, "mcp:read mcp:write");
  assert.deepEqual(cimd.prior, [], `CIMD inherited opaque grants: ${JSON.stringify(cimd.prior)}`);
  assert.deepEqual(cimd.scopes.sort(), ["mcp:read", "mcp:write"], "a CIMD client is offered exactly what it asked for");

  // And the reverse: a fresh opaque client must not inherit the CIMD grant.
  const reg2 = await bridge.handleRegister({
    query: {}, body: { redirect_uris: [OPAQUE_REDIRECT], application_type: "web" },
    headers: { "content-type": "application/json" }, ip: "127.0.0.1",
  });
  const secondOpaque = (reg2.body as { client_id: string }).client_id;
  const fresh = await grant(bridge, secondOpaque, OPAQUE_REDIRECT, "mcp:read mcp:write");
  assert.deepEqual(
    fresh.prior, [],
    `a different opaque client inherited grants: ${JSON.stringify(fresh.prior)}`,
  );
});

releaseTest("RM.14 dispatch cannot be crossed: an HTTPS client id never falls back to DCR", async () => {
  // The no-fallback property is what keeps the two profiles separate at all. An
  // HTTPS-shaped id with CIMD switched off must be REFUSED, never quietly
  // resolved through the DCR path that is still enabled in this deployment.
  const clients = new Clients();
  const config = createBridgeConfig({
    issuer: "https://auth.test", resource: "https://resource.test/mcp",
    consentSigningSecret: "c".repeat(40), signingPrivateJwk: jwk(), signingKeyId: "coexist",
    redirectAllowlist: [OPAQUE_REDIRECT, CIMD_REDIRECT],
    scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stored", store: clients },   // DCR is ON
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });                                           // cimd deliberately absent
  const bridge = new Bridge({
    config, store: new MemoryStore(), clock: { nowMs: () => Date.parse("2026-08-16T12:00:00Z") },
    audit: { async writeAuthEvent() {} },
  });

  const authz = await bridge.handleAuthorize({
    query: {
      response_type: "code", client_id: CIMD_ID, redirect_uri: CIMD_REDIRECT,
      code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
      scope: "mcp:read", state: "s",
    },
    body: undefined, headers: {}, ip: "127.0.0.1",
  }, { subject: SUBJECT });

  assert.notEqual(authz.status, 200, "an HTTPS client id must not reach the consent page with CIMD off");
  assert.equal(authz.redirect, undefined, "and must not be answered through the redirect channel");
  // It must not have been treated as an opaque client and looked up in the DCR
  // store — that would be the fallback this design forbids.
  assert.ok(!clients.rows.has(CIMD_ID), "an HTTPS id must never reach the DCR client store");
});
