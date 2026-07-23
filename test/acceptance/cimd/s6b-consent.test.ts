// FROZEN acceptance suite — S6b CIMD consent page (docs/contracts.md §17.1.6
// decision 1c + decision 3 + §17.1.4 consent obligations; threat-model row 17).
// The consent page displays the client_id host + the redirect host and renders
// `client_name` as HTML-escaped, unverified text; SHOULD warn when EVERY
// registered redirect is loopback; only `cimd_verified` is copied into the consent
// JWT (never other CIMD fields); a present non-true `cimd_verified` INVALIDATES the
// token (decision 3, fail-closed). Black-box: drive a real CIMD direct authorize
// and inspect the rendered HTML + the minted consent token. FAITHFULNESS: the XSS
// invariant is "raw markup absent" (not a specific entity encoding); the
// loopback-warn is a SHOULD asserted softly (a warning indicator present, wording
// not pinned) with no "must not warn" negative; page titles/copy are never frozen.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";

const phases = JSON.parse(readFileSync(new URL("../phases.json", import.meta.url), "utf8"));

if (phases["s6b-cimd-flow"] !== true) {
  test("s6b-cimd-flow inactive — activate via test/acceptance/phases.json", { skip: true }, () => {});
} else {
  const CFG = "../../../src/config.ts";
  const { createBridgeConfig } = (await import(CFG)) as any;
  const BRIDGE = "../../../src/adapters/bridge.ts";
  const { Bridge } = (await import(BRIDGE)) as any;
  const STORE = "../../../src/store/memory.ts";
  const { MemoryStore } = (await import(STORE)) as any;
  const CRYPTO = "../../../src/crypto.ts";
  const { pkceChallenge } = (await import(CRYPTO)) as any;
  const jose = (await import("jose")) as any;

  const NOW = Date.parse("2026-07-03T12:00:00.000Z");
  const CIMD_ID = "https://cdn.example.com/client";
  const HTTPS_REDIRECT = "https://app.example.com/cb";
  const LOOPBACK_REDIRECT = "http://127.0.0.1:5000/cb";
  const VERIFIER = "correct-horse-battery-staple-0123456789abcdef0123";
  const PUBLIC = { address: "93.184.216.34", family: 4 };
  const CONSENT_AUDIENCE = "mcp-sso/consent"; // matches crypto.ts CONSENT_AUDIENCE (used only to forge a fail-closed token)
  const CONSENT_TYP = "mcp-sso-consent";
  const enc = (s: string) => new TextEncoder().encode(s);
  async function* one(u8: Uint8Array) { yield u8; }
  const doc = (over: any = {}) => ({ client_id: CIMD_ID, client_name: "Example App", redirect_uris: [HTTPS_REDIRECT], ...over });
  const okResult = (d: any) => ({ status: 200, redirected: false, finalUrl: CIMD_ID, headersDistinct: { "content-type": ["application/json"] }, encodedBody: one(enc(JSON.stringify(d))) });
  const transport = (d: any) => ({ connectAndGet() { return Promise.resolve(okResult(d)); } });
  const resolver = () => ({ resolve() { return Promise.resolve([PUBLIC]); }, cancel() {} });

  class FakeClock { ms: number; constructor(ms: number) { this.ms = ms; } nowMs() { return this.ms; } }
  class MemoryAudit { async writeAuthEvent() {} }
  function jwk(): any { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" }; }
  function cfg(): any {
    return createBridgeConfig({
      issuer: "https://auth.test", resource: "https://api.test/mcp",
      consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k",
      redirectAllowlist: ["https://client.test/cb"], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
      allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" }, cimd: { enabled: true },
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    });
  }
  function bridgeFor(config: any, d: any) {
    return new Bridge({ config, store: new MemoryStore(), clock: new FakeClock(NOW), audit: new MemoryAudit(), cimdTransport: transport(d), cimdResolver: resolver() });
  }
  async function render(config: any, d: any, redirectUri: string): Promise<string> {
    const b = bridgeFor(config, d);
    const req = { query: { response_type: "code", client_id: CIMD_ID, redirect_uri: redirectUri, code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256", scope: "mcp:read" }, body: undefined, headers: {}, ip: "1.2.3.4" };
    const res = await b.handleAuthorize(req, { subject: "agent@test" });
    assert.equal(res.status, 200, "CIMD consent rendered");
    return String(res.body);
  }
  const consentOf = (html: string) => { const m = /name="consent_token" value="([^"]+)"/.exec(html); assert.ok(m?.[1], "consent token"); return m[1]!; };

  test("client_name is HTML-escaped (raw markup absent, threat row 17 XSS) and shown as unverified", async () => {
    const evil = `<script>alert("x")</script>`;
    const html = await render(cfg(), doc({ client_name: evil }), HTTPS_REDIRECT);
    assert.equal(html.includes(evil), false, "raw client_name markup never injected");
    assert.equal(html.includes("<script>"), false, "no raw <script> tag from client_name");
    assert.match(html, /unverified/i, "client_name shown as unverified text");
  });

  test("shows the client_id host and the redirect host", async () => {
    const html = await render(cfg(), doc(), HTTPS_REDIRECT);
    assert.ok(html.includes("cdn.example.com"), "client_id host shown");
    assert.ok(html.includes("app.example.com"), "redirect host shown");
  });

  test("SHOULD warn when EVERY registered redirect is loopback (soft — a warning indicator is present; wording not pinned)", async () => {
    const html = await render(cfg(), doc({ redirect_uris: ["http://127.0.0.1:3000/cb", "http://localhost:4000/cb"] }), LOOPBACK_REDIRECT);
    assert.match(html, /loopback|localhost|local (callback|device)|this device/i, "an all-loopback registration surfaces a warning indicator");
  });

  test("only cimd_verified is copied into the consent JWT (no other CIMD document fields)", async () => {
    const html = await render(cfg(), doc({ logo_uri: "https://cdn.example.com/logo.png" }), HTTPS_REDIRECT);
    const payload = jose.decodeJwt(consentOf(html));
    assert.equal(payload.cimd_verified, true, "provenance bit set for a genuinely-validated CIMD flow");
    for (const leaked of ["cimd", "client_name", "redirect_uris", "logo_uri", "raw", "jwks"]) {
      assert.equal(Object.hasOwn(payload, leaked), false, `consent JWT must not carry CIMD field ${leaked}`);
    }
  });

  // Decision 3 fail-closed: a present non-true cimd_verified INVALIDATES the token.
  // signConsentToken never emits `false`, so we forge a token in the exact consent
  // shape verifyConsentToken accepts, with cimd_verified:false.
  test("a present non-true cimd_verified claim invalidates the consent token (fail-closed)", async () => {
    const config = cfg();
    const b = bridgeFor(config, doc());
    const now = Math.floor(NOW / 1000);
    const token = await new jose.SignJWT({
      typ: CONSENT_TYP, jti: "j".repeat(24), client_id: CIMD_ID, redirect_uri: HTTPS_REDIRECT,
      resource: config.resource, scope: "mcp:read", code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
      cimd_verified: false,
    }).setProtectedHeader({ alg: "HS256", typ: "JWT" }).setIssuer(config.issuer).setAudience(CONSENT_AUDIENCE)
      .setSubject("agent@test").setIssuedAt(now).setExpirationTime(now + 300).sign(enc(config.consentSigningSecret));
    const res = await b.handleApprove({ query: {}, body: { consent_token: token, approved: "true" }, headers: { origin: "https://auth.test" }, ip: "1.2.3.4" });
    assert.equal(res.status, 400);
    assert.equal((res.body as any).error, "invalid_consent");
  });
}
