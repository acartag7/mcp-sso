// RM.15 — the registration matrix: which client kind resolves under which
// deployment configuration.
//
// `dcr` is REQUIRED in BridgeConfig and no adapter option suppresses the
// register route, so "CIMD only" is not a deployment state — it is a client
// choice. The real configuration axes are therefore:
//
//     cimd enabled? × dcr stateless | stored          (4 deployments)
//
// crossed with the client kinds a deployment actually meets:
//
//     opaque DCR id · CIMD id (real published shape) · CIMD id (native) · CIMD id (exact redirect)
//
// The row exists because a regression shipped in v0.3.5 that no fixture could
// see: `d084a21` gated RFC 8252 loopback any-port matching on
// `application_type: "native"`, and every CIMD fixture in this repository sets
// that field because it was written alongside the rule. Claude Code's real
// published document does NOT set it, so the flagship client could not
// authenticate against any deployment. This matrix carries the REAL document
// shape as a row so a self-authored fixture can never mask it again.
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { cimdRedirectMatches } from "../src/cimd/registration.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import { MemoryStore } from "../src/store/memory.ts";
import type { CimdTransport, DnsResolver } from "../src/cimd/transport.ts";
import type { RateLimitPort } from "../src/ports/rate-limit.ts";

const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;

const OPAQUE_REDIRECT = "https://opaque.test/callback";
const VERIFIER = "registration-matrix-verifier-0123456789abcdef01";

/** Claude Code's real published document, as served today: port-less loopback
 *  redirects and NO `application_type`. Kept literal so a drift in our own
 *  fixtures cannot quietly re-break the client. */
const REAL_CLIENT_DOC = Object.freeze({
  client_id: "https://claude.ai/oauth/claude-code-client-metadata",
  client_name: "Claude Code",
  redirect_uris: Object.freeze(["http://localhost/callback", "http://127.0.0.1/callback"]),
});
/** The ephemeral loopback port a native client binds at run time. */
const EPHEMERAL = "http://localhost:3118/callback";

class Clients implements ClientStore {
  readonly rows = new Map<string, ClientRegistration>();
  /** Every id the DCR store was ASKED for. `rows` alone cannot reveal a wrong
   *  fallback, because a lookup does not mutate it — an HTTPS id could be routed
   *  to `find()` and a rows-only assertion would still pass. */
  readonly lookups: string[] = [];
  async save(c: ClientRegistration): Promise<void> { this.rows.set(c.clientId, structuredClone(c)); }
  async find(id: string): Promise<ClientRegistration | null> {
    this.lookups.push(id);
    return structuredClone(this.rows.get(id) ?? null);
  }
}

const boundedLimiter: RateLimitPort = { async check() { return true; } };
const resolver: DnsResolver = { async resolve() { return [{ address: "93.184.216.34", family: 4 }]; } };
/** A CIMD id whose document the deterministic transport below serves. */
const CIMD_DOC = {
  client_id: "https://cimd.test/client.json",
  client_name: "Matrix client",
  redirect_uris: ["http://localhost/callback"],
};

/** Deterministic CIMD transport, so a CIMD-enabled cell can require SUCCESS.
 *  Without it a failed fetch or resolver regression returns some non-200 and a
 *  "not 200 when disabled" assertion passes as if dispatch still worked. */
function cimdTransportFor(doc: Record<string, unknown>): CimdTransport {
  return {
    async connectAndGet() {
      async function* body(): AsyncGenerator<Uint8Array> {
        yield new TextEncoder().encode(JSON.stringify(doc));
      }
      return {
        status: 200, redirected: false, finalUrl: String(doc.client_id),
        headersDistinct: { "content-type": ["application/json"] }, encodedBody: body(),
      };
    },
  };
}

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "matrix" } as JWK;
}

function deployment(opts: { cimd: boolean; dcr: "stateless" | "stored" }) {
  const clients = new Clients();
  const config = createBridgeConfig({
    issuer: "https://auth.test", resource: "https://resource.test/mcp",
    consentSigningSecret: "m".repeat(40), signingPrivateJwk: jwk(), signingKeyId: "matrix",
    redirectAllowlist: [OPAQUE_REDIRECT],
    scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: opts.dcr === "stored" ? { mode: "stored", store: clients } : { mode: "stateless" },
    ...(opts.cimd ? { cimd: { enabled: true } } : {}),
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  // Stored DCR requires a bounded limiter since #253 (B1): an unbounded
  // anonymous durable-write path is a boot failure. Supply one so the row tests
  // dispatch rather than re-testing that guard.
  const bridge = new Bridge({
    config, store: new MemoryStore(), clock: { nowMs: () => Date.parse("2026-08-17T12:00:00Z") },
    audit: { async writeAuthEvent() {} },
    ...(opts.dcr === "stored" ? { rateLimit: boundedLimiter } : {}),
    ...(opts.cimd ? { cimdTransport: cimdTransportFor(CIMD_DOC), cimdResolver: resolver } : {}),
  });
  return { bridge, clients };
}

// Test names are spelled out literally rather than interpolated: the release
// matrix integrity check matches manifest evidence by exact substring, so a
// template-generated name cannot be gated.
const CONFIGS = [
  { cimd: true, dcr: "stateless" as const,
    opaque: "RM.15 [cimd on  + dcr stateless] an opaque DCR client registers and reaches consent",
    cimdCase: "RM.15 [cimd on  + dcr stateless] a CIMD client id is resolved, never routed to DCR" },
  { cimd: true, dcr: "stored" as const,
    opaque: "RM.15 [cimd on  + dcr stored] an opaque DCR client registers and reaches consent",
    cimdCase: "RM.15 [cimd on  + dcr stored] a CIMD client id is resolved, never routed to DCR" },
  { cimd: false, dcr: "stateless" as const,
    opaque: "RM.15 [cimd off + dcr stateless] an opaque DCR client registers and reaches consent",
    cimdCase: "RM.15 [cimd off + dcr stateless] a CIMD client id is refused, never routed to DCR" },
  { cimd: false, dcr: "stored" as const,
    opaque: "RM.15 [cimd off + dcr stored] an opaque DCR client registers and reaches consent",
    cimdCase: "RM.15 [cimd off + dcr stored] a CIMD client id is refused, never routed to DCR" },
];

// --- axis 1: the opaque DCR client, in all four deployments -----------------

for (const c of CONFIGS) {
  releaseTest(c.opaque, async () => {
    const { bridge } = deployment(c);
    const reg = await bridge.handleRegister({
      query: {}, body: { redirect_uris: [OPAQUE_REDIRECT], application_type: "web" },
      headers: { "content-type": "application/json" }, ip: "127.0.0.1",
    });
    assert.equal(reg.status, 201, `DCR must work in every deployment: ${JSON.stringify(reg.body)}`);
    const clientId = (reg.body as { client_id: string }).client_id;

    const authz = await bridge.handleAuthorize({
      query: {
        response_type: "code", client_id: clientId, redirect_uri: OPAQUE_REDIRECT,
        code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
        scope: "mcp:read", state: "s",
      },
      body: undefined, headers: {}, ip: "127.0.0.1",
    }, { subject: "matrix-user" });
    assert.equal(authz.status, 200, `opaque authorize must reach consent: ${JSON.stringify(authz.body)}`);
  });
}

// --- axis 2: a CIMD client id, in all four deployments ----------------------

for (const c of CONFIGS) {
  releaseTest(c.cimdCase, async () => {
    const { bridge, clients } = deployment(c);
    const authz = await bridge.handleAuthorize({
      query: {
        response_type: "code", client_id: CIMD_DOC.client_id, redirect_uri: EPHEMERAL,
        code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
        scope: "mcp:read", state: "s",
      },
      body: undefined, headers: {}, ip: "127.0.0.1",
    }, { subject: "matrix-user" });

    if (c.cimd) {
      // Require SUCCESS, not merely "some response": a failed fetch or resolver
      // regression also returns non-200, and asserting only the disabled case
      // would let that pass as if dispatch still worked.
      assert.equal(authz.status, 200, `a CIMD id must resolve and reach consent: ${JSON.stringify(authz.body).slice(0, 200)}`);
      assert.match(String(authz.body), /consent_token/, "the CIMD client must reach the consent page");
    } else {
      assert.notEqual(authz.status, 200, "an HTTPS client id must not reach consent with CIMD disabled");
      assert.equal(authz.redirect, undefined, "and must not be answered through the redirect channel");
    }
    assert.ok(!clients.rows.has(CIMD_DOC.client_id), "an HTTPS id must never enter the DCR client store");
    assert.deepEqual(
      clients.lookups.filter((id) => id.startsWith("https://")), [],
      `an HTTPS id reached the DCR store: ${JSON.stringify(clients.lookups)}`,
    );

    // POSITIVE CONTROL. An empty `lookups` only means something if the recorder
    // records at all; otherwise the assertion above passes vacuously. In stored
    // mode an opaque authorize MUST consult the store.
    if (c.dcr === "stored") {
      const reg = await bridge.handleRegister({
        query: {}, body: { redirect_uris: [OPAQUE_REDIRECT], application_type: "web" },
        headers: { "content-type": "application/json" }, ip: "127.0.0.1",
      });
      const opaqueId = (reg.body as { client_id: string }).client_id;
      clients.lookups.length = 0;
      await bridge.handleAuthorize({
        query: {
          response_type: "code", client_id: opaqueId, redirect_uri: OPAQUE_REDIRECT,
          code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
          scope: "mcp:read", state: "s",
        },
        body: undefined, headers: {}, ip: "127.0.0.1",
      }, { subject: "matrix-user" });
      assert.deepEqual(
        clients.lookups, [opaqueId],
        "the lookup recorder must observe an opaque authorize, or the HTTPS assertion is vacuous",
      );
    }
  });
}

// --- axis 3: the redirect shape that actually broke Claude Code -------------

releaseTest("RM.15 a real published CIMD document matches its ephemeral loopback port", () => {
  // THE REGRESSION. Claude Code publishes port-less loopback redirects and binds
  // an ephemeral port at run time; it cannot enumerate ports in a static
  // document, which is exactly why RFC 8252 any-port matching exists. Requiring
  // `application_type: "native"` — a field the document does not carry — made
  // every Claude Code authorization fail with `invalid_client`.
  assert.equal(
    cimdRedirectMatches(EPHEMERAL, REAL_CLIENT_DOC), true,
    "a real client's published document must match its ephemeral loopback port",
  );
});

releaseTest("RM.15 loopback elasticity does not leak beyond loopback", () => {
  // The exception must stay narrow: same scheme, same host, same path, port
  // free. Everything else still has to match exactly.
  const doc = REAL_CLIENT_DOC;
  assert.equal(cimdRedirectMatches("http://localhost/callback", doc), true, "exact port-less still matches");
  assert.equal(cimdRedirectMatches("http://127.0.0.1:51234/callback", doc), true, "the other loopback host is elastic too");
  assert.equal(cimdRedirectMatches("http://localhost:3118/other", doc), false, "a different path must not match");
  assert.equal(cimdRedirectMatches("https://localhost:3118/callback", doc), false, "https must not match an http entry");
  assert.equal(cimdRedirectMatches("http://evil.test:3118/callback", doc), false, "a non-loopback host must not match");

  const webDoc = { ...doc, redirect_uris: ["https://app.test/callback"] };
  assert.equal(cimdRedirectMatches("https://app.test:8443/callback", webDoc), false,
    "a NON-loopback https entry must never gain port elasticity");
});

releaseTest("RM.15 an explicit application_type still works in both directions", () => {
  // The field remains meaningful where a document does set it; the fix must not
  // regress documents that declare themselves.
  assert.equal(cimdRedirectMatches(EPHEMERAL, { ...REAL_CLIENT_DOC, application_type: "native" }), true);
  assert.equal(cimdRedirectMatches("http://localhost/callback", { ...REAL_CLIENT_DOC, application_type: "web" }), true,
    "an exact match must still succeed for a web document");
});
