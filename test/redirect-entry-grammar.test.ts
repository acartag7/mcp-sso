import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import type { RedirectExchangeResult } from "../src/ports/identity.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { createUpstreamRedirectFlow } from "../src/adapters/upstream-flow.ts";
import { signFlowToken } from "../src/adapters/upstream-flow-internals.ts";
import { validateCimdDocument } from "../src/cimd/document.ts";
import { CimdError } from "../src/cimd/errors.ts";
import { cimdRedirectMatches, projectCimdRegistration } from "../src/cimd/registration.ts";
import { AuthConfigError, createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { pkceChallenge, sha256Hex, signConsentToken } from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import { registerClient } from "../src/register.ts";
import { parseRedirectEntry, RedirectEntryError } from "../src/redirect-entry.ts";
import {
  DEFAULT_ALLOWED_REDIRECT_ORIGINS, assertAllowedRedirectUri, assertRedirectAllowedForClient,
} from "../src/redirect.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { OAuthAuthorizationUseCase } from "../src/authorize.ts";
import { OAuthTokenUseCase } from "../src/token.ts";

const NOW = Date.parse("2026-07-26T12:00:00.000Z");
const ISSUER = "https://auth.test";
const RESOURCE = "https://api.test/mcp";
const SECRET = "test-consent-secret-with-enough-entropy-0123456789";
const VERIFIER = "v".repeat(43);
const KEY = (() => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK;
})();

class Clock implements ClockPort { nowMs(): number { return NOW; } }
class Audit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(event); }
}
class Clients implements ClientStore {
  readonly values = new Map<string, ClientRegistration>();
  saveCalls = 0;
  async save(value: ClientRegistration): Promise<void> { this.saveCalls++; this.values.set(value.clientId, value); }
  async find(id: string): Promise<ClientRegistration | null> { return this.values.get(id) ?? null; }
}
class CountingStore extends MemoryStore {
  consentCalls = 0;
  codeSaves = 0;
  refreshSaves = 0;
  override async consumeConsentJti(jti: string, expiresAtIso: string): Promise<boolean> {
    this.consentCalls++; return await super.consumeConsentJti(jti, expiresAtIso);
  }
  override async saveAuthCode(input: Parameters<MemoryStore["saveAuthCode"]>[0]): Promise<void> {
    this.codeSaves++; await super.saveAuthCode(input);
  }
  override async saveRefreshToken(input: Parameters<MemoryStore["saveRefreshToken"]>[0]): Promise<void> {
    this.refreshSaves++; await super.saveRefreshToken(input);
  }
}

function config(over: Partial<BridgeConfig> = {}): BridgeConfig {
  return createBridgeConfig({
    issuer: ISSUER, resource: RESOURCE, consentSigningSecret: SECRET,
    signingPrivateJwk: KEY, signingKeyId: "k", redirectAllowlist: ["https://a.test/"],
    scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"], allowedOrigins: [ISSUER],
    dcr: { mode: "stateless" }, accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2592000, consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300, ...over,
  });
}

function request(body: unknown = undefined, query: Record<string, string> = {}, headers: Record<string, string> = {}) {
  return { body, query, headers, ip: "203.0.113.9" };
}

function grammarError(value: unknown): RedirectEntryError {
  try { parseRedirectEntry(value); } catch (error) {
    assert.ok(error instanceof RedirectEntryError);
    return error;
  }
  assert.fail(`expected rejection for ${JSON.stringify(value)}`);
}

const INVALID_ENTRIES: ReadonlyArray<[unknown, RegExp]> = [
  ["*", /must not contain '\*'/], ["https://*.a.test/cb", /must not contain '\*'/],
  ["https://a.test/cb*", /must not contain '\*'/], ["https://a.test/*", /must not contain '\*'/],
  ["javascript:alert(1)", /absolute http\(s\) URL/], ["data:text\/plain,x", /absolute http\(s\) URL/],
  ["ftp://a.test/cb", /scheme must be https or loopback http/], ["file://a.test/cb", /scheme must be https or loopback http/],
  ["custom://a.test/cb", /scheme must be https or loopback http/],
  ["https://u:p@a.test", /userinfo/], ["https://@a.test", /userinfo/], ["https://u:p@a.test/", /userinfo/],
  ["https://a.test?", /query delimiter/], ["https://a.test/?", /query delimiter/], ["https://a.test/cb?", /query delimiter/],
  ["https://a.test/#", /fragment delimiter/], ["https://a.test/cb#", /fragment delimiter/],
  ["https://a.test/cb%0A", /C0 control or DEL/], ["https://a.test/cb%0D", /C0 control or DEL/],
  ["https://a.test/cb%00", /C0 control or DEL/], ["https://a.test/cb%7F", /C0 control or DEL/],
  ["https://a.test.", /trailing dot/], ["https://a.test./", /trailing dot/],
  [" https://a.test/", /whitespace/], ["https://a.test/ ", /whitespace/], ["https://a.test/c b", /whitespace/],
  ["https://a.test/c\tb", /whitespace/], ["https://a.test/c\rb", /whitespace/], ["https://a.test/c\nb", /whitespace/],
  ["https://a.test/", /control characters/], ["https:\\a.test\\cb", /backslashes/],
  ["https://a.test/cb%", /malformed percent escape/], ["HTTPS://A.TEST", /canonical WHATWG spelling/],
  ["https://а.test", /canonical WHATWG spelling/],
  ["https://%65xample.com", /canonical WHATWG spelling/], ["https://a.test:443", /canonical WHATWG spelling/],
  ["http://localhost:80", /canonical WHATWG spelling/], ["https://2130706433", /canonical WHATWG spelling/],
  ["https://0x7f.0.0.1", /canonical WHATWG spelling/], ["https://0177.0.0.1", /canonical WHATWG spelling/],
  ["https://a.test:443/cb", /canonical WHATWG spelling/], ["https://a.test/x/../cb", /canonical WHATWG spelling/],
  ["https://a.test/./cb", /canonical WHATWG spelling/], ["", /must not be empty/], ["   ", /whitespace/],
  ["https://", /parseable absolute URL/], ["https:///cb", /canonical WHATWG spelling/],
  ["http://[0:0:0:0:0:0:0:1]/cb", /canonical WHATWG spelling/], ["http://a.test/cb", /http is allowed only/],
  [7, /primitive string/],
  // ASCII over-cap (also pins the error-message bound: full input is NOT reflected).
  ["https://a.test/" + "x".repeat(2049), /2048 UTF-8 bytes/],
  // Multibyte over-cap: 2049 UTF-8 bytes while well under 2048 UTF-16 code units,
  // so a `value.length` mutant cannot reject with the byte-cap reason.
  ["https://a.test/" + "é".repeat(1017), /2048 UTF-8 bytes/],
];

/** Short string entries are named verbatim; long ones are truncated in the error. */
function namesEntry(message: string, entry: string): boolean {
  if (entry.length <= 128) return message.includes(JSON.stringify(entry));
  // messageFor JSON-stringifies the whole truncated label including the byte count.
  return message.includes(JSON.stringify(
    `${entry.slice(0, 128)}…(${Buffer.byteLength(entry, "utf8")} bytes)`,
  ));
}

test("§10.0 closed rejection matrix names the entry and the grammar reason", () => {
  for (const [entry, reason] of INVALID_ENTRIES) {
    const error = grammarError(entry);
    assert.match(error.message, reason, String(entry));
    if (typeof entry === "string") {
      assert.ok(namesEntry(error.message, entry), `entry not named: ${entry.slice(0, 64)}`);
    }
  }
});

test("§10.0 positive grammar set remains accepted", () => {
  for (const entry of [
    "https://a.test/", "https://xn--80a.test/", "http://[::1]:9/",
    "https://a.test/cb%2F..%2Fadmin", "https://a.test/cb%2f..%2fadmin",
  ]) assert.equal(parseRedirectEntry(entry).raw, entry);
  for (const entry of ["https://a.test", "https://xn--80a.test", "http://[::1]:9"]) {
    assert.equal(parseRedirectEntry(entry, { allowOmittedRootSlash: true }).raw, entry);
  }
  assert.throws(() => parseRedirectEntry("https://a.test"), RedirectEntryError);
  const maxEntry = `https://a.test/${"x".repeat(2048 - Buffer.byteLength("https://a.test/", "utf8"))}`;
  assert.equal(Buffer.byteLength(maxEntry, "utf8"), 2048);
  assert.equal(parseRedirectEntry(maxEntry).raw, maxEntry);
  // Multibyte under-cap still fails for non-canonical reasons (not the byte cap).
  const multiUnder = "https://a.test/" + "é".repeat(1016);
  assert.ok(Buffer.byteLength(multiUnder, "utf8") <= 2048);
  assert.throws(() => parseRedirectEntry(multiUnder), (error: unknown) =>
    error instanceof RedirectEntryError && /canonical WHATWG spelling/.test(error.message));
  assert.equal(parseRedirectEntry("https://a.test//x").raw, "https://a.test//x");
  assert.throws(() => parseRedirectEntry("https://a.test//"), RedirectEntryError);
});
test("boot validates defaults, snapshots redirectAllowlist once, and publishes the frozen snapshot", () => {
  for (const entry of DEFAULT_ALLOWED_REDIRECT_ORIGINS) {
    assert.equal(parseRedirectEntry(entry, { allowOmittedRootSlash: true }).raw, entry);
  }
  const caller = ["https://a.test"];
  const c = config({ redirectAllowlist: caller });
  caller[0] = "javascript:alert(1)";
  assert.deepEqual(c.redirectAllowlist, ["https://a.test"]);
  assert.ok(Object.isFrozen(c.redirectAllowlist));
  assert.throws(() => (c.redirectAllowlist as string[]).push("https://b.test"), TypeError);
  assert.doesNotThrow(() => config({ redirectAllowlist: [] }));
  assert.deepEqual(config({ redirectAllowlist: ["https://xn--80a.test"] }).redirectAllowlist, ["https://xn--80a.test"]);
  assert.throws(() => config({ redirectAllowlist: "https://a.test" as never }), (error: unknown) =>
    error instanceof AuthConfigError && /redirectAllowlist must be an array/.test(error.message));

  let reads = 0;
  const accessor = [] as string[];
  Object.defineProperty(accessor, "0", { enumerable: true, get: () => ++reads === 1 ? "https://a.test" : "javascript:alert(1)" });
  Object.defineProperty(accessor, "length", { value: 1 });
  const snap = config({ redirectAllowlist: accessor });
  assert.deepEqual(snap.redirectAllowlist, ["https://a.test"]);
  assert.equal(reads, 1);
});

test("Bridge DCR rejects malformed containers, members, and scalar metadata without coercion", async () => {
  const bridge = new Bridge({ config: config(), store: new MemoryStore(), clock: new Clock(), audit: new Audit() });
  const cases: ReadonlyArray<[string, unknown, RegExp]> = [
    ["redirect_uris", "https://a.test/cb", /redirect_uris must be an array/],
    ["redirect_uris", "", /redirect_uris must be an array/],
    ["redirect_uris", 7, /redirect_uris must be an array/], ["redirect_uris", null, /redirect_uris must be an array/],
    ["redirect_uris", {}, /redirect_uris must be an array/],
    ["grant_types", "client_credentials", /grant_types must be an array/], ["grant_types", "", /grant_types must be an array/],
    ["grant_types", 7, /grant_types must be an array/],
    ["grant_types", null, /grant_types must be an array/], ["grant_types", {}, /grant_types must be an array/],
    ["grant_types", [7], /non-empty primitive strings/], ["grant_types", [null], /non-empty primitive strings/],
    ["grant_types", [""], /non-empty primitive strings/],
    ["token_endpoint_auth_method", 7, /non-empty string/], ["token_endpoint_auth_method", "", /non-empty string/],
    ["token_endpoint_auth_method", null, /non-empty string/], ["token_endpoint_auth_method", {}, /non-empty string/],
    ["application_type", 7, /application_type/], ["application_type", "", /application_type/],
    ["application_type", null, /application_type/], ["application_type", {}, /application_type/],
  ];
  for (const [field, value, reason] of cases) {
    const body: Record<string, unknown> = { redirect_uris: ["https://a.test/cb"], [field]: value };
    const response = await bridge.handleRegister(request(body));
    assert.equal(response.status, 400, `${field}=${JSON.stringify(value)}`);
    assert.equal((response.body as { error: string }).error, "invalid_client_metadata");
    assert.match((response.body as { error_description: string }).error_description, reason);
  }
  for (const member of [7, null]) {
    const response = await bridge.handleRegister(request({ redirect_uris: ["https://a.test/cb", member] }));
    assert.equal(response.status, 400);
    assert.equal((response.body as { error: string }).error, "invalid_redirect_uri");
    assert.match((response.body as { error_description: string }).error_description, /redirect entry <(number|null)> must be a primitive string/);
  }
});

test("DCR enforces 1..16, per-type stored policy, both modes, and read-once publication", async () => {
  for (const mode of ["stateless", "stored"] as const) {
    const clients = new Clients();
    const c = config({ dcr: mode === "stored" ? { mode, store: clients } : { mode } });
    const bridge = new Bridge({ config: c, store: new MemoryStore(), clock: new Clock(), audit: new Audit() });
    const sixteen = Array(16).fill("https://a.test/cb");
    const atCap = await bridge.handleRegister(request({ redirect_uris: sixteen }));
    assert.equal(atCap.status, 201);
    assert.deepEqual((atCap.body as { redirect_uris: string[] }).redirect_uris, sixteen);
    const tooMany = await bridge.handleRegister(request({ redirect_uris: Array(17).fill("https://a.test/cb") }));
    assert.equal(tooMany.status, 400);
    assert.match((tooMany.body as { error_description: string }).error_description, /redirect_uris must contain 1\.\.16 entries/);
    const omitted = await bridge.handleRegister(request({ redirect_uris: ["https://a.test"] }));
    assert.equal(omitted.status, 400);
    assert.match((omitted.body as { error_description: string }).error_description, /canonical WHATWG spelling/);
    assert.equal(clients.saveCalls, mode === "stored" ? 1 : 0);
  }
  const clients = new Clients();
  const c = config({ redirectAllowlist: ["https://a.test/", "http://[::1]:9"], dcr: { mode: "stored", store: clients } });
  const bridge = new Bridge({ config: c, store: new MemoryStore(), clock: new Clock(), audit: new Audit() });
  for (const body of [
    { redirect_uris: ["http://localhost/cb"], application_type: "web" },
    { redirect_uris: ["https://a.test/cb"], application_type: "native" },
  ]) assert.equal((await bridge.handleRegister(request(body))).status, 400);
  assert.equal((await bridge.handleRegister(request({ redirect_uris: ["https://a.test/"], application_type: "web" }))).status, 201);
  assert.equal((await bridge.handleRegister(request({ redirect_uris: ["http://[::1]:9/"], application_type: "native" }))).status, 201);

  let reads = 0;
  const accessor = [] as unknown[];
  Object.defineProperty(accessor, "0", { enumerable: true, get: () => ++reads === 1 ? "https://a.test/cb" : "javascript:alert(1)" });
  Object.defineProperty(accessor, "length", { value: 1 });
  const registered = await registerClient({ config: c, clock: new Clock(), audit: new Audit() }, { redirectUris: accessor });
  assert.deepEqual(registered.redirect_uris, ["https://a.test/cb"]);
  assert.equal(reads, 1);
  assert.deepEqual((await clients.find(registered.client_id))?.redirectUris, ["https://a.test/cb"]);

  let indexReads = 0;
  const oversized = new Proxy(Array(17).fill("https://a.test/cb"), {
    get(target, key, receiver) {
      if (typeof key === "string" && /^\d+$/.test(key)) indexReads++;
      return Reflect.get(target, key, receiver);
    },
  });
  await assert.rejects(registerClient({ config: c, clock: new Clock(), audit: new Audit() }, { redirectUris: oversized }),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_client_metadata");
  assert.equal(indexReads, 0, "cardinality rejects before traversing attacker-controlled members");

  let lengthReads = 0;
  const lengthShift = new Proxy(["https://a.test/cb"], {
    get(target, key, receiver) {
      if (key === "length") { lengthReads++; return lengthReads === 1 ? 1 : 100_000; }
      if (typeof key === "string" && /^\d+$/.test(key)) indexReads++;
      return Reflect.get(target, key, receiver);
    },
  });
  const shifted = await registerClient({ config: c, clock: new Clock(), audit: new Audit() }, { redirectUris: lengthShift });
  assert.deepEqual(shifted.redirect_uris, ["https://a.test/cb"]);
  assert.equal(lengthReads, 1, "snapshot captures attacker-controlled length once");

  // NaN / non-integer length cannot collapse a present array into an empty success.
  for (const badLength of [Number.NaN, 1.5, Number.POSITIVE_INFINITY, -1]) {
    const hostile = new Proxy(["https://a.test/cb", "https://a.test/other"], {
      get(target, key, receiver) {
        if (key === "length") return badLength;
        return Reflect.get(target, key, receiver);
      },
    });
    await assert.rejects(
      registerClient({ config: c, clock: new Clock(), audit: new Audit() }, { redirectUris: hostile }),
      (error: unknown) => error instanceof OAuthError && error.code === "invalid_client_metadata",
      `length=${String(badLength)}`,
    );
  }
});

test("boot and stored-read reject non-string and sparse entries (not just DCR)", () => {
  assert.throws(() => config({ redirectAllowlist: [7 as unknown as string] }), (error: unknown) =>
    error instanceof AuthConfigError && /primitive string/.test(error.message));
  // Sparse hole materializes as undefined and fails closed.
  const sparse: string[] = [];
  sparse.length = 2;
  sparse[1] = "https://a.test/cb";
  assert.throws(() => assertRedirectAllowedForClient("https://a.test/cb", {
    clientId: "legacy", redirectUris: sparse, applicationType: "web", issuedAtEpoch: 1,
  }), (error: unknown) => error instanceof OAuthError && error.code === "invalid_redirect_uri"
    && /primitive string|null/.test((error as OAuthError).message));
  // Non-string sibling in a stored record is rejected, never filtered then matched.
  assert.throws(() => assertRedirectAllowedForClient("https://a.test/cb", {
    clientId: "legacy", redirectUris: [7 as unknown as string, "https://a.test/cb"], applicationType: "web", issuedAtEpoch: 1,
  }), (error: unknown) => error instanceof OAuthError && error.code === "invalid_redirect_uri"
    && /primitive string/.test((error as OAuthError).message));
  // Stored-state sibling of the DCR 1..16 write cap: a legacy 17-entry record is
  // refused before the authorize-time scan materializes it.
  let storedIndexReads = 0;
  const oversizedStored = new Proxy(Array(17).fill("https://a.test/cb"), {
    get(target, key, receiver) {
      if (typeof key === "string" && /^\d+$/.test(key)) storedIndexReads++;
      return Reflect.get(target, key, receiver);
    },
  });
  assert.throws(() => assertRedirectAllowedForClient("https://a.test/cb", {
    clientId: "legacy", redirectUris: oversizedStored as string[], applicationType: "web", issuedAtEpoch: 1,
  }), (error: unknown) => error instanceof OAuthError && error.code === "invalid_redirect_uri"
    && /1\.\.16/.test((error as OAuthError).message));
  assert.equal(storedIndexReads, 0, "stored-read cap rejects before traversing members");
});

test("oversized entry rejection is bounded (does not re-amplify the raw input)", async () => {
  const huge = "https://a.test/" + "x".repeat(200_000);
  const error = grammarError(huge);
  assert.match(error.message, /2048 UTF-8 bytes/);
  assert.ok(error.message.length < 400, `error message stayed bounded, got ${error.message.length}`);
  assert.ok(!error.message.includes("x".repeat(200)), "full raw input is not reflected");
  const bridge = new Bridge({ config: config(), store: new MemoryStore(), clock: new Clock(), audit: new Audit() });
  const response = await bridge.handleRegister(request({ redirect_uris: [huge] }));
  assert.equal(response.status, 400);
  const description = (response.body as { error_description: string }).error_description;
  assert.ok(description.length < 400, `bridge error_description stayed bounded, got ${description.length}`);
});
test("read-side entry guards reject malformed legacy/direct entries even with valid presented URIs", () => {
  assert.throws(() => assertAllowedRedirectUri("https://a.test/other", ["https://a.test/?"]), (error: unknown) =>
    error instanceof OAuthError && error.code === "invalid_redirect_uri" && /query delimiter/.test(error.message));
  assert.throws(() => assertRedirectAllowedForClient("http://127.0.0.1:7000/cb", {
    clientId: "legacy", redirectUris: ["http://127.0.0.1/cb?"], applicationType: "native", issuedAtEpoch: 1,
  }), (error: unknown) => error instanceof OAuthError && error.code === "invalid_redirect_uri" && /query delimiter/.test(error.message));
});

test("presented redirects are rejected, never normalized, in stateless and stored authorize policies", async () => {
  const folds = [
    "HTTPS://a.test/cb", "https://A.TEST/cb", "https://a.test:443/cb",
    "https://a.test/x/../cb", "HTTPS://A.TEST:443/x/../cb", "https://a.test/cb#frag",
  ];
  const clients = new Clients();
  clients.values.set("web", { clientId: "web", redirectUris: ["https://a.test/cb"], applicationType: "web", issuedAtEpoch: 1 });
  const stored = new Bridge({ config: config({ dcr: { mode: "stored", store: clients } }), store: new MemoryStore(), clock: new Clock(), audit: new Audit() });
  const stateless = new Bridge({ config: config({ redirectAllowlist: ["https://a.test/"] }), store: new MemoryStore(), clock: new Clock(), audit: new Audit() });
  for (const presented of folds) {
    for (const [bridge, clientId] of [[stored, "web"], [stateless, "stateless"]] as const) {
      const response = await bridge.handleAuthorize(request(undefined, {
        client_id: clientId, redirect_uri: presented, response_type: "code",
        code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
      }), { subject: "user" });
      assert.equal(response.status, 400);
      assert.equal(response.redirect, undefined);
      assert.match((response.body as { error_description: string }).error_description, /redirect entry/);
    }
  }
});

test("positive round trips hold for stored web/native, stateless, and CIMD", async () => {
  const authorizeRegistered = async (bridge: Bridge, redirectUri: string, applicationType?: "web" | "native") => {
    const registration = await bridge.handleRegister(request({ redirect_uris: [redirectUri], ...(applicationType ? { application_type: applicationType } : {}) }));
    assert.equal(registration.status, 201, redirectUri);
    assert.deepEqual((registration.body as { redirect_uris: string[] }).redirect_uris, [redirectUri]);
    const authorize = await bridge.handleAuthorize(request(undefined, {
      client_id: (registration.body as { client_id: string }).client_id, redirect_uri: redirectUri,
      response_type: "code", code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
    }), { subject: "user" });
    assert.equal(authorize.status, 200, redirectUri);
  };

  const clients = new Clients();
  const stored = new Bridge({ config: config({ redirectAllowlist: [
    "https://a.test/", "http://localhost", "http://127.0.0.1", "http://[::1]:9", "https://localhost:444/cb",
  ], dcr: { mode: "stored", store: clients } }), store: new MemoryStore(), clock: new Clock(), audit: new Audit() });
  for (const redirectUri of ["https://a.test/", "https://a.test/cb%2F..%2Fadmin", "https://claude.ai/cb"]) {
    await authorizeRegistered(stored, redirectUri, "web");
  }
  for (const redirectUri of ["http://127.0.0.1/cb", "http://localhost/cb", "http://[::1]:9/"]) {
    await authorizeRegistered(stored, redirectUri, "native");
  }
  const httpsNative = await stored.handleRegister(request({ redirect_uris: ["https://localhost:444/cb"], application_type: "native" }));
  assert.equal(httpsNative.status, 201);
  const widenedHttps = await stored.handleAuthorize(request(undefined, {
    client_id: (httpsNative.body as { client_id: string }).client_id, redirect_uri: "https://localhost:555/cb",
    response_type: "code", code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
  }), { subject: "user" });
  assert.equal(widenedHttps.status, 400);

  const stateless = new Bridge({ config: config({
    redirectAllowlist: ["https://a.test/", "http://localhost", "http://127.0.0.1"],
  }), store: new MemoryStore(), clock: new Clock(), audit: new Audit() });
  for (const redirectUri of [
    "https://claude.ai/cb", "http://localhost/cb", "http://localhost:54321/cb",
    "http://127.0.0.1:8080/cb", "https://a.test/",
  ]) await authorizeRegistered(stateless, redirectUri);

  assert.throws(() => validateCimdDocument(JSON.stringify({
    client_id: "https://meta.test/client", client_name: "A", redirect_uris: ["https://a.test"],
  }), "https://meta.test/client"), (error: unknown) => error instanceof CimdError && error.reason === "document_invalid");
  const raw = JSON.stringify({ client_id: "https://meta.test/client", client_name: "A", redirect_uris: ["https://a.test/", "http://[::1]:9/"] });
  const doc = validateCimdDocument(raw, "https://meta.test/client");
  const projected = projectCimdRegistration(doc);
  assert.deepEqual(projected.redirect_uris, ["https://a.test/", "http://[::1]:9/"]);
  assert.throws(() => projectCimdRegistration({ ...doc, redirect_uris: ["https://a.test/cb?"] }), CimdError);
  assert.equal(cimdRedirectMatches("https://a.test/", projected.redirect_uris), true);
  assert.equal(cimdRedirectMatches("http://[::1]:7777/", projected.redirect_uris), true);
  for (const [registered, presented] of [["https://a.test/cb%2F", "https://a.test/cb%2f"], ["https://a.test/cb%2f", "https://a.test/cb%2F"]] as const) {
    assert.throws(() => assertAllowedRedirectUri(presented, [registered]), OAuthError);
    assert.throws(() => assertRedirectAllowedForClient(presented, {
      clientId: "case", redirectUris: [registered], applicationType: "web", issuedAtEpoch: 1,
    }), OAuthError);
    assert.equal(cimdRedirectMatches(presented, [registered]), false);
  }
});

test("nine-consumer differential rejects a canonical query-delimiter entry on every boundary", async () => {
  const forbidden = "https://a.test/cb?";
  // (1) boot.
  assert.throws(() => config({ redirectAllowlist: [forbidden] }), (error: unknown) =>
    error instanceof AuthConfigError && /query delimiter/.test(error.message) && error.message.includes(JSON.stringify(forbidden)));

  // (2) DCR write, both modes: no forbidden echo and no stored side effect.
  for (const mode of ["stateless", "stored"] as const) {
    const clients = new Clients();
    const c = config({ dcr: mode === "stored" ? { mode, store: clients } : { mode } });
    const bridge = new Bridge({ config: c, store: new MemoryStore(), clock: new Clock(), audit: new Audit() });
    const response = await bridge.handleRegister(request({ redirect_uris: [forbidden] }));
    assert.equal(response.status, 400);
    assert.match((response.body as { error_description: string }).error_description, /query delimiter/);
    assert.equal(JSON.stringify(response.body).includes(`"redirect_uris":["${forbidden}"]`), false);
    assert.equal(clients.saveCalls, 0);
  }

  // (3) §10.2 stored read: a valid presented loopback URI would match the legacy
  // query-bearing entry if the registered-entry revalidation were removed.
  const legacyClients = new Clients();
  legacyClients.values.set("legacy", { clientId: "legacy", redirectUris: ["http://127.0.0.1/cb?"], applicationType: "native", issuedAtEpoch: 1 });
  const legacyBridge = new Bridge({ config: config({ dcr: { mode: "stored", store: legacyClients } }), store: new MemoryStore(), clock: new Clock(), audit: new Audit() });
  const legacyAuthorize = await legacyBridge.handleAuthorize(request(undefined, {
    client_id: "legacy", redirect_uri: "http://127.0.0.1:7000/cb", response_type: "code", code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
  }), { subject: "user" });
  assert.equal(legacyAuthorize.status, 400);
  assert.equal(legacyAuthorize.redirect, undefined);

  // (4) CIMD document.
  assert.throws(() => validateCimdDocument(JSON.stringify({
    client_id: "https://meta.test/client", client_name: "A", redirect_uris: [forbidden],
  }), "https://meta.test/client"), (error: unknown) => error instanceof CimdError && error.reason === "document_invalid");

  // (5) exported matcher: valid presented bytes would be origin-widened by the
  // forbidden direct entry if the entry-side predicate were removed.
  assert.throws(() => assertAllowedRedirectUri("https://a.test/other", ["https://a.test/?"]), (error: unknown) =>
    error instanceof OAuthError && error.code === "invalid_redirect_uri" && /query delimiter/.test(error.message));

  const flowConfig = config({ cimd: { enabled: true } });
  const flowStore = new CountingStore();
  const flowClock = new Clock();
  const flowAudit = new Audit();
  let exchanges = 0;
  let exchangeResult: RedirectExchangeResult | "throw" = { ok: true, identity: { subject: "user" } };
  const identity = {
    redirectUri: `${ISSUER}/oauth/callback`, buildAuthorizationUrl: () => "https://idp.test/authorize",
    async exchangeAndVerify() { exchanges++; if (exchangeResult === "throw") throw new Error("exchange"); return exchangeResult; },
  };
  const flowBridge = new Bridge({ config: flowConfig, store: flowStore, clock: flowClock, audit: flowAudit });
  const flow = createUpstreamRedirectFlow({ bridge: flowBridge, identity, store: flowStore, clock: flowClock, audit: flowAudit });
  const cookieName = "__Host-mcp-sso-upstream";
  const base = { secret: SECRET, issuer: ISSUER, callbackPath: flow.callbackPath, clock: flowClock, jti: "upf_" + "a".repeat(40), state: "state", nonce: "nonce", codeVerifier: VERIFIER, ttlSeconds: 600 };

  // (6) flow-cookie CIMD registration: the presented value is valid, so only the
  // forbidden sibling entry in the carried registration can trigger this leg.
  const cimdCookie = await signFlowToken({ ...base, params: { client_id: "https://meta.test/client", redirect_uri: "https://a.test/cb" }, cimd: {
    client_id: "https://meta.test/client", client_name: "A", redirect_uris: ["https://a.test/cb", forbidden],
  } });
  const cimdResponse = await flow.handleCallback(request(undefined, { state: "state", code: "x" }, { cookie: `${cookieName}=${cimdCookie}` }));
  assert.equal(cimdResponse.status, 400);
  assert.equal(cimdResponse.redirect, undefined);
  assert.equal(exchanges, 0);

  // (7) consent token, both Deny and Approve, direct error before redirect/JTI/code.
  const consentStore = new CountingStore();
  const auth = new OAuthAuthorizationUseCase({ config: config(), store: consentStore, clock: new Clock(), audit: new Audit() });
  const consent = await signConsentToken({ clientId: "legacy", redirectUri: forbidden, resource: RESOURCE,
    scopes: ["mcp:read"], codeChallenge: pkceChallenge(VERIFIER), codeChallengeMethod: "S256", subject: "user" }, config(), new Clock());
  for (const approved of [false, true]) {
    await assert.rejects(auth.approve({ consentToken: consent, approved, origin: ISSUER }), (error: unknown) =>
      error instanceof OAuthError && error.code === "invalid_redirect_uri" && !error.redirect);
  }
  assert.equal(consentStore.consentCalls, 0);
  assert.equal(consentStore.codeSaves, 0);

  // (8) opaque flow-cookie params: the one extraction guard protects every later redirect branch.
  const paths: ReadonlyArray<{ query: Record<string, string>; result: RedirectExchangeResult | "throw" }> = [
    { query: { error: "access_denied" }, result: { ok: true, identity: { subject: "unused" } } },
    { query: { error: "other" }, result: { ok: true, identity: { subject: "unused" } } },
    { query: { code: "x" }, result: "throw" },
    { query: { code: "x" }, result: { ok: false, kind: "exchange_failed", reason: "failed" } },
    { query: { code: "x" }, result: { ok: false, kind: "identity_rejected", reason: "rejected" } },
  ];
  for (let i = 0; i < paths.length; i++) {
    exchangeResult = paths[i]!.result;
    const cookie = await signFlowToken({ ...base, jti: `upf_${String(i).padStart(40, "b")}`, params: { client_id: "legacy", redirect_uri: forbidden } });
    const callbackQuery = { state: "state", ...paths[i]!.query };
    const response = await flow.handleCallback(request(undefined, callbackQuery, { cookie: `${cookieName}=${cookie}` }));
    assert.equal(response.status, 400);
    assert.equal(response.redirect, undefined);
  }
  assert.equal(exchanges, 0);
  assert.equal(flowStore.consentCalls, 0);

  // (9) authorization-code record, planted out of band with matching bytes and PKCE.
  let redirectReads = 0;
  const dynamicRecord = {
    codeHash: sha256Hex("dynamic-code"), clientId: "legacy", subject: "user", resource: RESOURCE,
    scopes: ["mcp:read"], codeChallenge: pkceChallenge(VERIFIER), codeChallengeMethod: "S256" as const,
    expiresAt: new Date(NOW + 300000).toISOString(),
    get redirectUri() { return ++redirectReads === 1 ? "https://a.test/cb" : "javascript:alert(1)"; },
  };
  const dynamicStore = new MemoryStore();
  dynamicStore.consumeAuthCode = async () => dynamicRecord;
  const dynamicToken = new OAuthTokenUseCase({ config: config(), store: dynamicStore, clock: new Clock(), audit: new Audit() });
  await assert.rejects(dynamicToken.exchangeAuthorizationCode({ grantType: "authorization_code", code: "dynamic-code",
    clientId: "legacy", redirectUri: "javascript:alert(1)", codeVerifier: VERIFIER }), (error: unknown) =>
    error instanceof OAuthError && error.code === "invalid_grant");
  assert.equal(redirectReads, 1);

  const codeStore = new MemoryStore();
  const code = "legacy-code";
  await codeStore.saveAuthCode({ codeHash: sha256Hex(code), clientId: "legacy", subject: "user",
    redirectUri: forbidden, resource: RESOURCE, scopes: ["mcp:read"], codeChallenge: pkceChallenge(VERIFIER),
    codeChallengeMethod: "S256", expiresAt: new Date(NOW + 300000).toISOString() });
  const token = new OAuthTokenUseCase({ config: config(), store: codeStore, clock: new Clock(), audit: new Audit() });
  await assert.rejects(token.exchangeAuthorizationCode({ grantType: "authorization_code", code,
    clientId: "legacy", redirectUri: forbidden, codeVerifier: VERIFIER }), (error: unknown) =>
    error instanceof OAuthError && error.code === "invalid_grant");
});

test("every rejection row agrees across all nine consumers (incl. non-string)", async () => {
  // Include the non-string row: filtering to strings alone left boot/stored-read
  // free to silently drop non-strings while the "all-consumer" suite stayed green.
  const rows = INVALID_ENTRIES.filter((row) => {
    if (typeof row[0] !== "string") return true;
    // Skip multi-hundred-KB witnesses here: the nine-leg path is covered for the
    // grammar reason by the closed matrix + the bounded-error test.
    return (row[0] as string).length <= 256;
  }) as Array<[unknown, RegExp]>;
  const flowConfig = config({ cimd: { enabled: true } });
  const flowStore = new CountingStore();
  const flowClock = new Clock();
  const flowAudit = new Audit();
  let exchangeCalls = 0;
  const identity = {
    redirectUri: `${ISSUER}/oauth/callback`, buildAuthorizationUrl: () => "https://idp.test/authorize",
    async exchangeAndVerify(): Promise<RedirectExchangeResult> { exchangeCalls++; return { ok: true, identity: { subject: "user" } }; },
  };
  const flowBridge = new Bridge({ config: flowConfig, store: flowStore, clock: flowClock, audit: flowAudit });
  const flow = createUpstreamRedirectFlow({ bridge: flowBridge, identity, store: flowStore, clock: flowClock, audit: flowAudit });
  const cookieName = "__Host-mcp-sso-upstream";
  let sequence = 0;

  for (const [forbidden, reason] of rows) {
    const isString = typeof forbidden === "string";
    const label = isString ? JSON.stringify(forbidden) : `<${forbidden === null ? "null" : typeof forbidden}>`;
    // (1) boot — non-string and string entries both rejected with grammar reason.
    assert.throws(() => config({ redirectAllowlist: [forbidden as string] }), (error: unknown) =>
      error instanceof AuthConfigError && reason.test(error.message)
      && (isString ? namesEntry(error.message, forbidden as string) : error.message.includes(label)),
      `boot ${label}`);

    if (!isString) {
      // Non-string DCR members map through the shared predicate (invalid_redirect_uri).
      for (const mode of ["stateless", "stored"] as const) {
        const clients = new Clients();
        const bridge = new Bridge({
          config: config({ dcr: mode === "stored" ? { mode, store: clients } : { mode } }),
          store: new MemoryStore(), clock: new Clock(), audit: new Audit(),
        });
        const response = await bridge.handleRegister(request({ redirect_uris: ["https://a.test/cb", forbidden] }));
        assert.equal(response.status, 400, `DCR non-string ${mode}`);
        assert.equal((response.body as { error: string }).error, "invalid_redirect_uri");
        assert.match((response.body as { error_description: string }).error_description, reason);
        assert.equal(clients.saveCalls, 0);
      }
      assert.throws(() => assertRedirectAllowedForClient("https://a.test/cb", {
        clientId: "legacy", redirectUris: [forbidden as string, "https://a.test/cb"], applicationType: "web", issuedAtEpoch: 1,
      }), (error: unknown) => error instanceof OAuthError && error.code === "invalid_redirect_uri" && reason.test(error.message));
      assert.throws(() => assertAllowedRedirectUri("https://a.test/other", [forbidden]), (error: unknown) =>
        error instanceof OAuthError && error.code === "invalid_redirect_uri" && reason.test(error.message));
      continue;
    }

    const forbiddenString = forbidden as string;
    for (const mode of ["stateless", "stored"] as const) {
      const clients = new Clients();
      const bridge = new Bridge({
        config: config({ dcr: mode === "stored" ? { mode, store: clients } : { mode } }),
        store: new MemoryStore(), clock: new Clock(), audit: new Audit(),
      });
      const response = await bridge.handleRegister(request({ redirect_uris: [forbiddenString] }));
      assert.equal(response.status, 400, `DCR ${mode} ${label}`);
      assert.equal((response.body as { error: string }).error, "invalid_redirect_uri");
      assert.match((response.body as { error_description: string }).error_description, reason);
      assert.ok(namesEntry((response.body as { error_description: string }).error_description, forbiddenString));
      assert.equal(clients.saveCalls, 0);
    }

    assert.throws(() => assertRedirectAllowedForClient("https://a.test/cb", {
      clientId: "legacy", redirectUris: [forbiddenString], applicationType: "web", issuedAtEpoch: 1,
    }), (error: unknown) => error instanceof OAuthError && error.code === "invalid_redirect_uri"
      && reason.test(error.message) && namesEntry(error.message, forbiddenString), `stored read ${label}`);

    assert.throws(() => validateCimdDocument(JSON.stringify({
      client_id: "https://meta.test/client", client_name: "A", redirect_uris: [forbiddenString],
    }), "https://meta.test/client"), (error: unknown) => error instanceof CimdError && error.reason === "document_invalid", `CIMD doc ${label}`);

    assert.throws(() => assertAllowedRedirectUri("https://a.test/other", [forbiddenString]), (error: unknown) =>
      error instanceof OAuthError && error.code === "invalid_redirect_uri"
      && reason.test(error.message) && namesEntry(error.message, forbiddenString), `exported matcher ${label}`);

    const base = {
      secret: SECRET, issuer: ISSUER, callbackPath: flow.callbackPath, clock: flowClock,
      state: "state", nonce: "nonce", codeVerifier: VERIFIER, ttlSeconds: 600,
    };
    const cimdCookie = await signFlowToken({ ...base, jti: `upf_c_${sequence++}`,
      params: { client_id: "https://meta.test/client", redirect_uri: "https://a.test/cb" },
      cimd: { client_id: "https://meta.test/client", client_name: "A", redirect_uris: ["https://a.test/cb", forbiddenString] } });
    const cimdResponse = await flow.handleCallback(request(undefined, { state: "state", code: "x" }, { cookie: `${cookieName}=${cimdCookie}` }));
    assert.equal(cimdResponse.status, 400, `CIMD cookie ${label}`);
    assert.equal((cimdResponse.body as { error: string }).error, "invalid_request");
    assert.equal(cimdResponse.redirect, undefined);
    assert.equal(flowAudit.events.at(-1)?.reason, "flow_cookie_invalid");
    assert.equal(flowStore.consentCalls, 0);

    const consentStore = new CountingStore();
    const auth = new OAuthAuthorizationUseCase({ config: config(), store: consentStore, clock: new Clock(), audit: new Audit() });
    const consent = await signConsentToken({ clientId: "legacy", redirectUri: forbiddenString, resource: RESOURCE,
      scopes: ["mcp:read"], codeChallenge: pkceChallenge(VERIFIER), codeChallengeMethod: "S256", subject: "user" }, config(), new Clock());
    for (const approved of [false, true]) {
      await assert.rejects(auth.approve({ consentToken: consent, approved, origin: ISSUER }), (error: unknown) =>
        error instanceof OAuthError && error.code === "invalid_redirect_uri" && reason.test(error.message)
        && namesEntry(error.message, forbiddenString) && !error.redirect, `consent ${approved} ${label}`);
    }
    assert.equal(consentStore.consentCalls, 0);
    assert.equal(consentStore.codeSaves, 0);

    for (const query of [{ error: "access_denied" }, { error: "other" }, { code: "x" }]) {
      const opaqueCookie = await signFlowToken({ ...base, jti: `upf_o_${sequence++}`,
        params: { client_id: "legacy", redirect_uri: forbiddenString } });
      const callbackQuery: Record<string, string> = { state: "state" };
      if ("error" in query && query.error !== undefined) callbackQuery.error = query.error;
      else if ("code" in query && query.code !== undefined) callbackQuery.code = query.code;
      const response = await flow.handleCallback(request(undefined, callbackQuery, { cookie: `${cookieName}=${opaqueCookie}` }));
      assert.equal(response.status, 400, `opaque cookie ${label}`);
      assert.equal((response.body as { error: string }).error, "invalid_request");
      assert.equal(response.redirect, undefined);
      assert.equal(flowAudit.events.at(-1)?.reason, "flow_cookie_invalid");
      assert.equal(flowStore.consentCalls, 0);
    }

    const codeStore = new CountingStore();
    const code = `legacy-${sequence++}`;
    await codeStore.saveAuthCode({ codeHash: sha256Hex(code), clientId: "legacy", subject: "user",
      redirectUri: forbiddenString, resource: RESOURCE, scopes: ["mcp:read"], codeChallenge: pkceChallenge(VERIFIER),
      codeChallengeMethod: "S256", expiresAt: new Date(NOW + 300000).toISOString() });
    const token = new OAuthTokenUseCase({ config: config(), store: codeStore, clock: new Clock(), audit: new Audit() });
    await assert.rejects(token.exchangeAuthorizationCode({ grantType: "authorization_code", code,
      clientId: "legacy", redirectUri: forbiddenString, codeVerifier: VERIFIER }), (error: unknown) =>
      error instanceof OAuthError && error.code === "invalid_grant", `auth code ${label}`);
    assert.equal(codeStore.refreshSaves, 0);
  }
  assert.equal(exchangeCalls, 0);
});
