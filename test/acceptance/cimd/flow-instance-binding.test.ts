// FROZEN acceptance suite — §17.11 "flow-instance binding" (docs/contracts.md).
//
// CONTRACT UNDER TEST: the upstream flow JWT's audience is
// `"mcp-sso/upstream-flow" + callbackPath`, not the deployment-wide constant, so
// a flow accepts ONLY cookies it minted. A cookie whose binding does not match
// the callback's own value fails verification and reports as the EXISTING row 3
// `flow_cookie_invalid` — no new failure row, no new error code.
//
// WHY: before the amendment the audience carried no per-flow identity, so every
// flow built from one signing secret accepted every other flow's cookies. A
// deployment mounting two flows under one issuer could have a cookie minted for
// the intended IdP redeemed through a DIFFERENT configured one — an
// authentication-provider confused deputy. The initiating request is
// unauthenticated, so a remote caller can start flow A and reuse its
// state/challenge against IdP B.
//
// BLACK-BOX over the public `createUpstreamRedirectFlow` surface
// (handleAuthorize / handleCallback) plus the public Bridge + config seams —
// with ONE deliberate exception: the minted cookie's `aud` is decoded and
// asserted exactly. §17.11 does not merely require cross-flow rejection, it
// requires `aud === "mcp-sso/upstream-flow" + callbackPath`. Behaviour-only
// assertions would let an implementation keep the deployment-wide audience and
// add a separate binding claim — passing this PERMANENTLY FROZEN suite while
// violating the locked contract.
//
// FAITHFULNESS (the "could a WRONG implementation pass this?" pass):
//   - Cross-flow rejection is asserted on the EXCHANGE, not just the status: an
//     impl that 4xx'd late but still called the wrong IdP would pass a
//     status-only check. `exchangeCalls` must stay 0.
//   - The same-flow happy path is asserted in the SAME suite, so an impl that
//     rejects every cookie (trivially "secure", totally broken) fails.
//   - Both directions are asserted (A→B and B→A), so an impl that binds only
//     one flow, or compares with a substring/prefix rule, fails.
//   - The reason code is pinned to the CONTRACTED row-3 value, so an impl that
//     invents a new failure row or leaks a distinguishable error fails.
//   - A single-flow deployment is asserted unaffected, pinning the "shipped
//     adapters keep working" compatibility claim.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";

const phases = JSON.parse(readFileSync(new URL("../phases.json", import.meta.url), "utf8"));

if (phases["flow-instance-binding"] !== true) {
  test("flow-instance-binding inactive — activate via test/acceptance/phases.json", { skip: true }, () => {});
} else {
  const { createBridgeConfig, originOf } = (await import("../../../src/config.ts")) as any;
  const { Bridge } = (await import("../../../src/adapters/bridge.ts")) as any;
  const { createUpstreamRedirectFlow } = (await import("../../../src/adapters/upstream-flow.ts")) as any;
  const { MemoryStore } = (await import("../../../src/store/memory.ts")) as any;
  const { pkceChallenge } = (await import("../../../src/crypto.ts")) as any;

  const NOW = Date.parse("2026-07-25T12:00:00.000Z");
  const ISSUER = "https://auth.test";
  const RESOURCE = "https://api.test/mcp";
  const CLIENT_REDIRECT = "https://client.test/callback";
  const IP = "203.0.113.7";

  class FakeClock { ms: number; constructor(ms: number) { this.ms = ms; } nowMs() { return this.ms; } }
  class MemoryAudit {
    events: any[] = [];
    async writeAuthEvent(e: any) { this.events.push(e); }
    // FAILURE events only: a suite that keys on reason alone passes an
    // implementation auditing the rejection with status "success".
    callbackReasons() { return this.events.filter((e) => e.event === "oauth.upstream.callback" && e.status === "failure").map((e) => e.reason); }
  }
  function jwk(): any {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" };
  }

  function config(): any {
    return createBridgeConfig({
      issuer: ISSUER, resource: RESOURCE,
      consentSigningSecret: "test-consent-secret-with-enough-entropy-0123456789",
      signingPrivateJwk: jwk(), signingKeyId: "k",
      redirectAllowlist: [CLIENT_REDIRECT], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
      allowedOrigins: [ISSUER], dcr: { mode: "stateless" },
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000,
      consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    });
  }

  /** An identity port that records whether ITS exchange ran — the load-bearing
   *  observable. A rejected cross-flow callback must never reach it. */
  function fakeIdentity(name: string, callbackPath: string) {
    let calls = 0;
    let last: any;
    return {
      name,
      exchangeCalls: () => calls,
      lastArgs: () => last,
      port: {
        redirectUri: `${originOf(ISSUER)}${callbackPath}`,
        buildAuthorizationUrl(r: any) { return `https://idp-${name}.test/authorize?state=${r.state}&nonce=${r.nonce}`; },
        async exchangeAndVerify(args: any) { calls++; last = args; return { ok: true, identity: { subject: `user-from-${name}` } }; },
      },
    };
  }

  /** Two flows over ONE Bridge — same issuer, same signing secret, same store.
   *  This is the topology the exported factory permits and the contract now
   *  binds against. The two callback paths are deliberately PREFIX-RELATED
   *  (`/cb-a` vs `/cb-a/child`): a verifier that compares audiences with
   *  `startsWith`/substring instead of equality accepts flow A's cookie at
   *  flow B (both audiences begin `mcp-sso/upstream-flow/cb-a`), so every
   *  cross-flow row here also pins exact-match comparison. Unrelated paths
   *  would let that wrong implementation pass. */
  function twoFlows() {
    const cfg = config();
    const clock = new FakeClock(NOW);
    const audit = new MemoryAudit();
    const store = new MemoryStore();
    const bridge = new Bridge({ config: cfg, store, clock, audit });
    const idA = fakeIdentity("A", "/cb-a");
    const idB = fakeIdentity("B", "/cb-a/child");
    const flowA = createUpstreamRedirectFlow({ bridge, identity: idA.port, store, clock, audit, callbackPath: "/cb-a" });
    const flowB = createUpstreamRedirectFlow({ bridge, identity: idB.port, store, clock, audit, callbackPath: "/cb-a/child" });
    return { cfg, store, audit, flowA, flowB, idA, idB };
  }

  const query = (state = "client-state") => ({
    response_type: "code", client_id: "client-1", redirect_uri: CLIENT_REDIRECT,
    code_challenge: pkceChallenge("v".repeat(43)), code_challenge_method: "S256",
    scope: "mcp:read", state,
  });
  const req = (q: any, headers: any = {}) => ({ query: q, body: undefined, headers, ip: IP });
  const cookieOf = (res: any) => (res.headers["set-cookie"] ?? "").split(";")[0].split("=").slice(1).join("=");
  const upstreamState = (res: any) => new URL(res.headers.location).searchParams.get("state");

  /** Decode a JWT payload without verifying (we assert claims, not signature). */
  function payloadOf(jwt: string): any {
    const part = jwt.split(".")[1] ?? "";
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  }

  /** Start a flow and return the browser-held cookie + the upstream state. */
  async function begin(flow: any, callbackPath: string) {
    const res = await flow.handleAuthorize(req(query()));
    assert.equal(res.status, 302, "authorize must 302 to the IdP");
    const cookie = cookieOf(res);
    // §17.11 CONTRACTS this exact value (aud === "mcp-sso/upstream-flow" +
    // callbackPath) — asserting it here pins the contract, not an
    // implementation constant (the suite-faithfulness rule's carve-out: the
    // expected value is derived from the contracted formula, imported from
    // nowhere). Behavior-only assertions would pass an implementation that
    // keeps the deployment-wide audience and adds a side binding claim,
    // violating the locked contract while satisfying every cross-flow row.
    assert.equal(
      payloadOf(cookie).aud, `mcp-sso/upstream-flow${callbackPath}`,
      "flow token aud must be the prefix + this flow's callbackPath",
    );
    return { cookie, state: upstreamState(res) };
  }

  test("§17.11 binding: a cookie minted by flow A is REJECTED at flow B's callback, and IdP B is never called", async () => {
    const { flowA, flowB, idA, idB, audit, store } = twoFlows();
    const a = await begin(flowA, "/cb-a");

    // A's cookie + A's state presented to B's callback, with a code "issued by B".
    const res = await flowB.handleCallback(req(
      { state: a.state, code: "code-from-idp-B" },
      { cookie: `__Host-mcp-sso-upstream=${a.cookie}` },
    ));

    // The load-bearing assertion: the WRONG IdP's exchange must never run. A
    // status-only check would pass an implementation that rejects late.
    assert.equal(idB.exchangeCalls(), 0, "flow B must not exchange a code against a cookie it did not mint");
    assert.equal(idA.exchangeCalls(), 0, "flow A must not have exchanged either");

    // Contracted channel: the existing row 3 — a direct 4xx, never a redirect.
    assert.equal(res.status, 400, "cross-flow cookie is the existing row-3 direct 4xx");
    assert.equal(res.headers.location, undefined, "row 3 is direct — never a redirect");
    assert.equal((res as any).redirect, undefined, "the adapters key redirects on NormResponse.redirect — it must be unset too");
    assert.ok(audit.callbackReasons().includes("flow_cookie_invalid"), "must audit the contracted row-3 reason");
    // §17.11: EVERY callback response with a readable cookie clears it — this
    // new rejection path included, or an invalid cross-flow cookie lingers in
    // the browser until overwrite or expiry.
    assert.match(String(res.headers["set-cookie"] ?? ""), /Max-Age=0/, "the rejected cookie must be cleared");

    // ORDERING (§17.11: row 3 precedes row 6). An implementation could verify
    // the deployment-wide audience, CONSUME claims.jti, then bind — satisfying
    // every assertion above while burning A's single-use jti. A would then fail
    // `flow_replayed`. Prove A can still redeem its own cookie afterwards.
    const redeemed = await flowA.handleCallback(req(
      { state: a.state, code: "code-from-idp-A" },
      { cookie: `__Host-mcp-sso-upstream=${a.cookie}` },
    ));
    assert.equal(idA.exchangeCalls(), 1, "flow A must still redeem its own cookie after B rejected it");
    assert.equal(redeemed.status, 200, "B's rejection must not have consumed A's jti");
    await store.close();
  });

  test("§17.11 binding: the rejection is symmetric — B's cookie is rejected at A's callback too", async () => {
    // An implementation binding only one flow, or comparing with a substring or
    // prefix rule, would pass the first test and fail here.
    const { flowA, flowB, idA, idB, audit, store } = twoFlows();
    const b = await begin(flowB, "/cb-a/child");

    const res = await flowA.handleCallback(req(
      { state: b.state, code: "code-from-idp-A" },
      { cookie: `__Host-mcp-sso-upstream=${b.cookie}` },
    ));

    assert.equal(idA.exchangeCalls(), 0, "flow A must not exchange a code against a cookie it did not mint");
    assert.equal(idB.exchangeCalls(), 0);
    assert.equal(res.status, 400);
    assert.ok(audit.callbackReasons().includes("flow_cookie_invalid"));

    // Same jti-ordering proof as the A→B direction: a direction-sensitive
    // implementation could consume B's jti before rejecting here. B must still
    // redeem its own cookie afterwards.
    const redeemed = await flowB.handleCallback(req(
      { state: b.state, code: "code-from-idp-B" },
      { cookie: `__Host-mcp-sso-upstream=${b.cookie}` },
    ));
    assert.equal(idB.exchangeCalls(), 1, "flow B must still redeem its own cookie after A rejected it");
    assert.equal(redeemed.status, 200, "A's rejection must not have consumed B's jti");
    await store.close();
  });

  test("§17.11 binding: each flow still accepts its OWN cookie (binding must not break the happy path)", async () => {
    // Without this, an implementation that rejects EVERY cookie — trivially
    // "secure" and completely broken — would pass the suite.
    const { flowA, flowB, idA, idB, store } = twoFlows();

    const a = await begin(flowA, "/cb-a");
    const resA = await flowA.handleCallback(req(
      { state: a.state, code: "code-from-idp-A" },
      { cookie: `__Host-mcp-sso-upstream=${a.cookie}` },
    ));
    assert.equal(idA.exchangeCalls(), 1, "flow A must exchange its own code");
    // Row 13: a successful callback renders the consent page directly (200),
    // it does not redirect.
    assert.equal(resA.status, 200, "a valid same-flow callback reaches the consent page");

    const b = await begin(flowB, "/cb-a/child");
    const resB = await flowB.handleCallback(req(
      { state: b.state, code: "code-from-idp-B" },
      { cookie: `__Host-mcp-sso-upstream=${b.cookie}` },
    ));
    assert.equal(idB.exchangeCalls(), 1, "flow B must exchange its own code");
    assert.equal(resB.status, 200);
    await store.close();
  });

  test("§17.11 binding: a single-flow deployment (the shipped adapter shape) is unaffected", async () => {
    // Pins the compatibility claim: binding changes nothing for the topology
    // every shipped adapter actually mounts.
    const cfg = config();
    const clock = new FakeClock(NOW);
    const audit = new MemoryAudit();
    const store = new MemoryStore();
    const bridge = new Bridge({ config: cfg, store, clock, audit });
    const id = fakeIdentity("solo", "/oauth/callback");
    const flow = createUpstreamRedirectFlow({ bridge, identity: id.port, store, clock, audit });

    const started = await begin(flow, "/oauth/callback");
    const res = await flow.handleCallback(req(
      { state: started.state, code: "code-from-idp" },
      { cookie: `__Host-mcp-sso-upstream=${started.cookie}` },
    ));
    assert.equal(id.exchangeCalls(), 1);
    assert.equal(res.status, 200, "row 13: the consent page is the direct callback response");
    await store.close();
  });

  test("§17.11 binding: the cross-flow rejection is indistinguishable from any other row-3 failure", async () => {
    // Anti-oracle: a cross-flow cookie and a plain garbage cookie must produce
    // the SAME status, the same absence of a redirect, and the same audit
    // reason — otherwise the response tells a prober that a second flow exists
    // and that they hit a real one.
    const { flowA, flowB, audit, store } = twoFlows();
    const a = await begin(flowA, "/cb-a");

    const crossFlow = await flowB.handleCallback(req(
      { state: a.state, code: "c" }, { cookie: `__Host-mcp-sso-upstream=${a.cookie}` },
    ));
    const garbage = await flowB.handleCallback(req(
      { state: a.state, code: "c" }, { cookie: "__Host-mcp-sso-upstream=not-a-jwt" },
    ));

    assert.equal(crossFlow.status, garbage.status, "status must not distinguish a cross-flow cookie");
    assert.equal(crossFlow.headers.location, undefined);
    assert.equal(garbage.headers.location, undefined);
    assert.equal((crossFlow as any).redirect, undefined, "no NormResponse.redirect on the cross-flow rejection");
    assert.equal((garbage as any).redirect, undefined, "no NormResponse.redirect on the garbage rejection");
    // The BODY is the oracle that a status-only check misses: an implementation
    // can return a distinguishable `error`/`error_description` for an audience
    // mismatch while garbage gets the generic row-3 body, and still audit
    // `flow_cookie_invalid` for both. §17.11 requires the mismatch to use the
    // EXISTING row-3 `invalid_request`, so compare the public bodies and pin
    // the contracted code.
    assert.deepEqual(crossFlow.body, garbage.body, "the response body must not distinguish a cross-flow cookie");
    assert.equal((crossFlow.body as any)?.error, "invalid_request", "row 3 is the contracted invalid_request");
    const reasons = audit.callbackReasons();
    assert.equal(reasons.filter((r: string) => r === "flow_cookie_invalid").length, 2, "both must audit the same row-3 reason");
    await store.close();
  });
}
