// Live-harness evidence guards. Two kinds, deliberately labelled:
//   - BEHAVIOUR: the shared support modules are imported and executed;
//   - CONTENT: claims that really are about file contents (no secret printed, no
//     process.exit, a probe calls a route, a doc row exists) are read as text.
// A content guard proves a call is written, not that it behaves; every unit with
// behaviour has a behaviour test here or in test/live-run-script.test.mjs and
// test/live-serve-script.test.mjs, which spawn the shipped shell scripts.
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync,
  symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  containsCredential, createProbeClientStore, extractConsentToken, parseJsonl,
} from "../scripts/live/probe-e2e-support.mjs";
import { execFileSync, spawnSync } from "node:child_process";
import {
  assertBasePreflight, assertLegPreflight, gatewayPortForLeg, groupAuthorizationJsonFromMapping,
  issuerOriginForLeg, prepareLiveStateDir, readGoogleCredentialFile,
} from "../scripts/live/run-support.mjs";
import { BLOCKED_REASON_NAMES } from "../scripts/live/rehearsal-support.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const read = (path) => readFileSync(join(ROOT, path), "utf8");
const PROBE = read("scripts/live/probe-e2e.mjs");
const IDENTITY_COMPLETION = read("scripts/live/probe-e2e-identity-support.mjs");
const README = read("scripts/live/README.md");
const CHECKLIST = read("scripts/live/CHECKLIST.md");
const DOC = read("docs/reference/live-harness.md");
const GUID_A = "11111111-2222-3333-4444-555555555555";
const GUID_B = "66666666-7777-8888-9999-aaaaaaaaaaaa";
const GUID_C = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
const SIGNING_JWK = JSON.stringify({
  ...generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k",
});

// ---------------------------------------------------------------- BEHAVIOUR

test("BEHAVIOUR run-support: stack-output parsers accept only the documented shapes", () => {
  const origins = JSON.stringify({ entra: "https://entra.example", google: "https://google.example" });
  assert.equal(issuerOriginForLeg(origins, "entra"), "https://entra.example");
  for (const [raw, leg] of [
    [origins, "cloudflare_access"], [origins, "../etc"], ["not json", "entra"], ["[]", "entra"], ['"str"', "entra"],
    [JSON.stringify({ entra: "http://entra.example" }), "entra"],
    [JSON.stringify({ entra: "https://user:pw@entra.example" }), "entra"],
    [JSON.stringify({ entra: "https://entra.example/" }), "entra"],
    [JSON.stringify({ entra: "https://entra.example/path" }), "entra"],
    [JSON.stringify({ entra: "" }), "entra"], [JSON.stringify({ entra: 5 }), "entra"],
  ]) {
    assert.throws(() => issuerOriginForLeg(raw, leg), `${raw} / ${leg}`);
  }
  const ports = JSON.stringify({ entra: { gateway: 43111, backend: 43112 } });
  assert.equal(gatewayPortForLeg(ports, "entra"), 43111);
  for (const raw of [JSON.stringify({ entra: { gateway: "43111" } }), JSON.stringify({ entra: { gateway: 0 } }),
    JSON.stringify({ entra: { gateway: 70000 } }), JSON.stringify({ entra: 8801 }), JSON.stringify({ google: { gateway: 1 } })]) {
    assert.throws(() => gatewayPortForLeg(raw, "entra"), raw);
  }
  assert.deepEqual(JSON.parse(groupAuthorizationJsonFromMapping(JSON.stringify({ [GUID_A]: ["mcp:read"] }))),
    { mapping: { [GUID_A]: ["mcp:read"] } });
  for (const raw of ["{}", "[]", JSON.stringify({ [GUID_A]: [] }), JSON.stringify({ [GUID_A]: "mcp:read" }),
    JSON.stringify({ "not-a-guid": ["mcp:read"] }), JSON.stringify({ [GUID_A]: [""] }), JSON.stringify({ [GUID_A]: [1] })]) {
    assert.throws(() => groupAuthorizationJsonFromMapping(raw), raw);
  }
});

test("BEHAVIOUR run-support: the Google credential file is read as owner-only data", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-live-cred-"));
  const file = join(dir, "google.env");
  const write = (text, mode = 0o600) => {
    if (existsSync(file)) chmodSync(file, 0o600);
    writeFileSync(file, text, { mode });
    chmodSync(file, mode);
  };
  try {
    write("GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=secret\n");
    assert.deepEqual(readGoogleCredentialFile(file), { GOOGLE_CLIENT_ID: "id", GOOGLE_CLIENT_SECRET: "secret" });
    write("# comment\r\n\r\nGOOGLE_CLIENT_ID=id\r\nOIDC_CLIENT_SECRET=alias=with=equals\r\n");
    assert.deepEqual(readGoogleCredentialFile(file), { GOOGLE_CLIENT_ID: "id", GOOGLE_CLIENT_SECRET: "alias=with=equals" });
    write("GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=$(id)\n");
    assert.equal(readGoogleCredentialFile(file).GOOGLE_CLIENT_SECRET, "$(id)", "values are data, never evaluated");
    write("GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=secret\n", 0o644);
    assert.throws(() => readGoogleCredentialFile(file), /group or other/);
    write("GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=secret\n", 0o400);
    assert.deepEqual(readGoogleCredentialFile(file).GOOGLE_CLIENT_ID, "id", "read-only owner mode is still private");
    write("GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=secret\n");
    assert.throws(() => readGoogleCredentialFile(file, 424242), /owned/);
    for (const text of [
      "GOOGLE_CLIENT_ID=id\n", "GOOGLE_CLIENT_SECRET=secret\n",
      "GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=a\nOIDC_CLIENT_SECRET=b\n",
      "export GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=secret\n",
      "GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=secret\nGOOGLE_HOSTED_DOMAIN=example.com\n",
      "GOOGLE_CLIENT_ID=\nGOOGLE_CLIENT_SECRET=secret\n",
      "GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_ID=id2\nGOOGLE_CLIENT_SECRET=secret\n",
      "GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=se\u0007cret\n",
      "GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=secret\nnot a pair\n",
      'GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET="quoted"\n',
      "GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET='quoted'\n",
      "GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=with space\n",
      `GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=${"x".repeat(5_000)}\n`,
    ]) {
      write(text);
      assert.throws(() => readGoogleCredentialFile(file), text.slice(0, 40));
    }
    write("GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=secret\n");
    const link = join(dir, "link.env");
    symlinkSync(file, link);
    assert.throws(() => readGoogleCredentialFile(link), /symlink/);
    assert.throws(() => readGoogleCredentialFile(dir), /regular file|opened/);
    assert.throws(() => readGoogleCredentialFile(join(dir, "missing")), /opened/);
    if (process.platform !== "win32") {
      // A FIFO at the path must fail the regular-file check, not block the open.
      // Probed in a child with a deadline so a regression fails instead of hanging.
      execFileSync("mkfifo", [join(dir, "fifo.env")]);
      const probe = spawnSync(process.execPath, ["--input-type=module", "-e",
        `import { readGoogleCredentialFile } from ${JSON.stringify(join(ROOT, "scripts/live/run-support.mjs"))};
         try { readGoogleCredentialFile(process.argv[1]); console.log("returned"); } catch (e) { console.log("threw:" + e.message); }`,
        join(dir, "fifo.env")], { encoding: "utf8", timeout: 5_000 });
      assert.equal(probe.status, 0, "the open must return (a blocked open times out here)");
      assert.match(probe.stdout, /threw:credential file is not a regular file/);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

const goodEnv = (leg) => {
  const base = {
    OAUTH_ISSUER: "https://mcp.example", OAUTH_RESOURCE: "https://mcp.example/mcp",
    OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
    OAUTH_SIGNING_PRIVATE_JWK: SIGNING_JWK,
    OAUTH_REDIRECT_ALLOWLIST: "https://mcp.example/app/callback", OAUTH_DCR_MODE: "stored",
  };
  if (leg === "entra") {
    return {
      ...base, ENTRA_TENANT_ID: GUID_A, ENTRA_CLIENT_ID: GUID_B, ENTRA_CLIENT_SECRET: "s", ENTRA_UNMAPPED_GROUP: GUID_C,
      ENTRA_REDIRECT_URI: "https://mcp.example/oauth/callback",
      ENTRA_GROUP_AUTHORIZATION_JSON: JSON.stringify({ mapping: { "cccccccc-0000-0000-0000-000000000000": ["mcp:read"] } }),
    };
  }
  if (leg === "cloudflare_access") {
    return { ...base, CF_ACCESS_AUDIENCE: "aud", CF_ACCESS_ISSUER: "https://team.cloudflareaccess.com", CF_ACCESS_CERTS_URL: "https://team.cloudflareaccess.com/cdn-cgi/access/certs" };
  }
  return { ...base, GOOGLE_CLIENT_ID: "id", GOOGLE_CLIENT_SECRET: "secret", GOOGLE_REDIRECT_URI: "https://mcp.example/oauth/callback" };
};

test("BEHAVIOUR run-support: the provider preflight admits exactly the shipped configuration", () => {
  for (const leg of ["entra", "cloudflare_access", "google"]) assertLegPreflight(leg, goodEnv(leg));
  const cases = [
    ["entra", { ENTRA_TENANT_ID: "not-a-guid" }], ["entra", { ENTRA_CLIENT_ID: "" }], ["entra", { ENTRA_CLIENT_SECRET: "" }],
    ["entra", { ENTRA_UNMAPPED_GROUP: "cccccccc-0000-0000-0000-000000000000".toUpperCase() }],
    ["entra", { ENTRA_REDIRECT_URI: "https://mcp.example/callback" }], ["entra", { ENTRA_REDIRECT_URI: "https://other.example/oauth/callback" }],
    ["entra", { ENTRA_GROUP_AUTHORIZATION_JSON: undefined }], ["entra", { ENTRA_GROUP_AUTHORIZATION_JSON: "{}" }],
    ["entra", { GOOGLE_CLIENT_ID: "second selector" }], ["entra", { ENTRA_TENANT_ID: undefined }],
    ["entra", { OAUTH_ISSUER: "http://mcp.example" }], ["entra", { OAUTH_SIGNING_PRIVATE_JWK: undefined }],
    ["entra", { OAUTH_REDIRECT_ALLOWLIST_MODE: "Replace" }],
    ["cloudflare_access", { CF_ACCESS_AUDIENCE: " " }], ["cloudflare_access", { CF_ACCESS_ISSUER: "http://team.cloudflareaccess.com" }],
    ["cloudflare_access", { CF_ACCESS_CERTS_URL: undefined }], ["cloudflare_access", { ENTRA_TENANT_ID: GUID_A }],
    ["google", { GOOGLE_CLIENT_SECRET: undefined }], ["google", { GOOGLE_REDIRECT_URI: "https://mcp.example/oauth/cb" }],
    ["google", { OIDC_ISSUER: "https://idp.example" }],
  ];
  for (const [leg, patch] of cases) {
    const env = { ...goodEnv(leg) };
    for (const [key, value] of Object.entries(patch)) {
      if (value === undefined) delete env[key];
      else env[key] = value;
    }
    assert.throws(() => assertLegPreflight(leg, env), `${leg} ${JSON.stringify(patch)}`);
  }
  assert.throws(() => assertLegPreflight("other", goodEnv("entra")), /unknown leg/);
  // The example's own pre-state gates are mirrored before any prior state moves.
  const loopback = "https://mcp.example/app/callback,http://localhost,http://127.0.0.1";
  assertLegPreflight("cloudflare_access", { ...goodEnv("cloudflare_access"), OAUTH_REDIRECT_ALLOWLIST: loopback });
  assertLegPreflight("cloudflare_access", { ...goodEnv("cloudflare_access"), OAUTH_DCR_MODE: "stateless", OAUTH_REDIRECT_ALLOWLIST: loopback });
  assertLegPreflight("cloudflare_access", { ...goodEnv("cloudflare_access"), OAUTH_DCR_MODE: "stateless" });
  assert.throws(() => assertLegPreflight("cloudflare_access", { ...goodEnv("cloudflare_access"), MCP_SSO_TRUSTED_PROXIES: "garbage" }), /trusted proxies/);
  assertLegPreflight("cloudflare_access", { ...goodEnv("cloudflare_access"), MCP_SSO_TRUSTED_PROXIES: "127.0.0.1" });
  const e2eEnv = { ...goodEnv("entra"), REDIS_URL: "redis://127.0.0.1:6379" };
  for (const key of ["ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET", "ENTRA_UNMAPPED_GROUP", "ENTRA_REDIRECT_URI", "ENTRA_GROUP_AUTHORIZATION_JSON"]) delete e2eEnv[key];
  assertBasePreflight(e2eEnv);
  assert.throws(() => assertBasePreflight({ ...e2eEnv, REDIS_URL: undefined }), /REDIS_URL/);
  assert.throws(() => assertBasePreflight({ ...e2eEnv, OAUTH_ISSUER: "http://mcp.example" }), /https/);
  assertBasePreflight({ ...e2eEnv, OAUTH_DCR_MODE: "stateless", OAUTH_REDIRECT_ALLOWLIST: loopback });
});

test("BEHAVIOUR run-support CLI: a shipped constructor's message never reaches output, only a fixed reason", () => {
  // createEntraRedirectIdentity / assertUpstreamConfigBeforeState quote the
  // value they reject; the CLI reduces anything that is not its own message.
  // The group mapping names a scope outside the catalog: the shipped constructor
  // quotes that scope in its message, and the group id beside it.
  const env = {
    ...goodEnv("entra"), PATH: process.env.PATH,
    ENTRA_GROUP_AUTHORIZATION_JSON: JSON.stringify({ mapping: { "cccccccc-0000-0000-0000-000000000000": ["mcp:REJECTEDVALUE"] } }),
  };
  const result = spawnSync(process.execPath, [join(ROOT, "scripts/live/run-support.mjs"), "preflight", "entra"], { env, encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.doesNotMatch(result.stderr, /REJECTEDVALUE|cccccccc-0000/, "the rejected value must not be echoed");
  assert.match(result.stderr, /run-support: preflight failed/);
  const own = spawnSync(process.execPath, [join(ROOT, "scripts/live/run-support.mjs"), "preflight", "entra"], { env: { ...env, ENTRA_TENANT_ID: "not-a-guid" }, encoding: "utf8" });
  assert.equal(own.status, 1);
  assert.match(own.stderr, /Entra identifiers are not GUIDs/, "the module's own fixed reasons do reach stderr");
});

test("BEHAVIOUR run-support: live state is prepared under a real private parent and never through a link", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-live-state-"));
  try {
    const root = join(dir, ".live-state");
    const leaf = prepareLiveStateDir(root, "entra");
    assert.equal(leaf, join(root, "entra"));
    assert.equal(lstatSync(root).isDirectory(), true);
    if (process.platform !== "win32") assert.equal(lstatSync(root).mode & 0o777, 0o700, "a created parent is owner-only");
    assert.equal(existsSync(leaf), false, "the leaf is left for the library to create");
    const previous = join(root, "entra.previous");
    mkdirSync(join(leaf, "nested"), { recursive: true });
    writeFileSync(join(leaf, "nested/auth.db"), "prior");
    writeFileSync(join(leaf, "audit.jsonl"), "{}\n");
    prepareLiveStateDir(root, "entra");
    assert.equal(existsSync(leaf), false, "the leaf is left for the library to create");
    assert.equal(readFileSync(join(previous, "nested/auth.db"), "utf8"), "prior", "the last run's evidence is rotated aside, not deleted");
    // A start that produced no evidence (a boot failure after the preflight)
    // is discarded on retry; the retained generation is untouched.
    mkdirSync(leaf);
    writeFileSync(join(leaf, "auth.db"), "failed start");
    prepareLiveStateDir(root, "entra");
    assert.equal(existsSync(leaf), false, "an evidence-less leaf is removed");
    assert.equal(readFileSync(join(previous, "nested/auth.db"), "utf8"), "prior", "the retained generation survives a failed-start retry");
    mkdirSync(leaf);
    writeFileSync(join(leaf, "audit.jsonl"), "");
    prepareLiveStateDir(root, "entra");
    assert.equal(readFileSync(join(previous, "nested/auth.db"), "utf8"), "prior", "an empty audit file is not evidence either");
    mkdirSync(leaf);
    writeFileSync(join(leaf, "auth.db"), "second");
    writeFileSync(join(leaf, "audit.jsonl"), "{}\n");
    prepareLiveStateDir(root, "entra");
    assert.equal(readFileSync(join(previous, "auth.db"), "utf8"), "second", "a generation with evidence replaces the one before it");
    assert.equal(existsSync(join(previous, "nested")), false);
    mkdirSync(leaf);
    symlinkSync(join(dir, "nowhere"), join(leaf, "audit.jsonl"));
    assert.throws(() => prepareLiveStateDir(root, "entra"), /not a regular file/, "evidence is judged through lstat, never through a link");
    assert.equal(readFileSync(join(previous, "auth.db"), "utf8"), "second");
    rmSync(leaf, { recursive: true });
    assert.throws(() => prepareLiveStateDir(root, "../escape"), /unknown leg/);
    mkdirSync(join(previous, "locked"), { recursive: true });
    writeFileSync(join(previous, "locked/file"), "x");
    chmodSync(join(previous, "locked"), 0o500);
    mkdirSync(leaf);
    writeFileSync(join(leaf, "audit.jsonl"), "{}\n"); // evidence, so the retained generation is due for replacement
    try {
      assert.throws(() => prepareLiveStateDir(root, "entra"), /cannot be removed/);
      assert.equal(existsSync(join(previous, "locked/file")), true, "a failed removal stops the run; nothing is silently kept");
      assert.equal(existsSync(join(leaf, "audit.jsonl")), true, "the leaf is untouched when the retained generation cannot be removed");
    } finally {
      chmodSync(join(previous, "locked"), 0o700);
    }
    prepareLiveStateDir(root, "entra");
    rmSync(previous, { recursive: true, force: true });
    symlinkSync(join(dir, "nowhere"), previous);
    assert.throws(() => prepareLiveStateDir(root, "entra"), /not a real directory/, "a symlinked previous generation is refused, not followed");
    rmSync(previous);
    // A rejected leaf must not have cost the retained generation first.
    rmSync(previous, { recursive: true, force: true });
    mkdirSync(previous);
    writeFileSync(join(previous, "audit.jsonl"), "retained");
    symlinkSync(join(dir, "nowhere"), leaf);
    assert.throws(() => prepareLiveStateDir(root, "entra"), /not a real directory/);
    assert.equal(readFileSync(join(previous, "audit.jsonl"), "utf8"), "retained", "both generations are inspected before either is touched");
    rmSync(leaf);
    rmSync(previous, { recursive: true });
    const elsewhere = join(dir, "elsewhere");
    mkdirSync(join(elsewhere, "google"), { recursive: true });
    chmodSync(elsewhere, 0o700); // owner-only, so a link to it is refused for being a link
    writeFileSync(join(elsewhere, "google/marker"), "outside");
    symlinkSync(elsewhere, leaf);
    assert.throws(() => prepareLiveStateDir(root, "entra"), /not a real directory/, "a symlinked leaf is refused, not followed");
    assert.equal(readFileSync(join(elsewhere, "google/marker"), "utf8"), "outside");
    rmSync(leaf);
    if (process.platform !== "win32") {
      chmodSync(root, 0o750);
      assert.throws(() => prepareLiveStateDir(root, "entra"), /group or other/);
      chmodSync(root, 0o700);
    }
    assert.throws(() => prepareLiveStateDir(root, "entra", 424242), /owned/);
    const linkedRoot = join(dir, "linked-root");
    symlinkSync(elsewhere, linkedRoot);
    assert.throws(() => prepareLiveStateDir(linkedRoot, "google"), /not a real directory/);
    assert.equal(readFileSync(join(elsewhere, "google/marker"), "utf8"), "outside", "the parent link's target is untouched");
    writeFileSync(join(dir, "file-root"), "x");
    assert.throws(() => prepareLiveStateDir(join(dir, "file-root"), "entra"), /not a real directory/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("BEHAVIOUR e2e support: the probe client store, consent parser, flow matcher, and leak check", async () => {
  const { store, bind } = createProbeClientStore();
  await assert.rejects(store.find("cid"), /not bound/);
  const sqliteRows = new Map();
  bind({ async save(c) { sqliteRows.set(c.clientId, c); }, async find(id) { return sqliteRows.get(id) ?? null; } });
  await store.save({ clientId: "user-1", redirectUris: [] });
  assert.equal((await store.find("user-1")).clientId, "user-1", "DCR clients round-trip through the bound SQLite store");
  const machine = { clientId: "mcc_1", version: 1, status: "active", secrets: [] };
  assert.equal(await store.createMachineClient(machine, { event: "oauth.client.provision" }), true);
  assert.equal(await store.createMachineClient(machine, { event: "oauth.client.provision" }), false, "collision is refused");
  const found = await store.find("mcc_1");
  assert.deepEqual(found, machine);
  found.status = "mutated";
  assert.equal((await store.find("mcc_1")).status, "active", "reads are copies");
  assert.equal(await store.compareAndSwapMachineClient(2, { ...machine, version: 3 }, {}), false, "stale version loses");
  assert.equal(await store.compareAndSwapMachineClient(1, { ...machine, version: 2, status: "disabled" }, {}), true);
  assert.equal((await store.find("mcc_1")).status, "disabled");
  assert.equal(await store.compareAndSwapMachineClient(1, { ...machine, clientId: "mcc_missing" }, {}), false);

  assert.equal(extractConsentToken('<input type="hidden" name="consent_token" value="ct.value" />'), "ct.value");
  assert.equal(extractConsentToken("<html>no form</html>"), undefined);
  assert.equal(extractConsentToken(undefined), undefined);

  assert.deepEqual(parseJsonl('{"a":1}\n{"b":2}\n'), [{ a: 1 }, { b: 2 }]);
  assert.deepEqual(parseJsonl(""), []);
  assert.throws(() => parseJsonl('{"a":1}\nnot json\n'), "a malformed line is a failure, not a skip");

  assert.equal(containsCredential("audit says mcs_abc here", ["mcs_abc"]), true);
  assert.equal(containsCredential("clean", ["mcs_abc"]), false);
  assert.equal(containsCredential("clean", [undefined]), true, "a missing credential fails closed");
  assert.equal(containsCredential("clean", [""]), true, "an empty credential fails closed");
});

// ------------------------------------------------------------------ CONTENT

test("CONTENT probe-e2e: exercises every subject it reports and prints no credential", () => {
  assert.doesNotMatch(PROBE, /\bSKIP\b/, "a skipped leg must never count as evidence");
  assert.doesNotMatch(PROBE, /process\.exit\(/);
  assert.match(PROBE, /process\.exitCode = failures > 0 \? 1 : 0/);
  assert.match(PROBE, /const dcrMode = process\.env\.OAUTH_DCR_MODE/,
    "the probe consumes the runner-selected DCR mode");
  assert.match(PROBE, /dcr: dcrMode === "stored" \? \{ mode: "stored", store: clientStore\.store \} : \{ mode: "stateless" \}/,
    "the selected mode reaches the built BridgeConfig");
  assert.match(PROBE, /client_id: "mcpdc_live_probe_unknown"/,
    "the probe exercises the stored-vs-stateless unknown-client differential");
  assert.match(PROBE, /if \(dcrMode === "stored" && clientStore !== undefined\)/,
    "machine-client claims remain restricted to the compatible stored run");
  assert.match(PROBE, /catch \{\s*failures\+\+;\s*out\.push\("FAIL  probe aborted before completion"\)/);
  assert.match(PROBE, /disableMachineClient\(machineDeps, provisioned\.clientId\)/, "the disable helper receives the client id string");
  assert.doesNotMatch(PROBE, /disableMachineClient\([^)]*\{\s*clientId/);
  assert.match(PROBE, /afterDisable\.statusCode === 401 && afterDisable\.json\(\)\.error === "invalid_client"/, "the disabled-client response is asserted exactly");
  assert.match(PROBE, /url: "\/oauth\/revoke"/, "revocation is exercised through the endpoint");
  assert.match(PROBE, /const replayed = await refresh\(userTokens\.refresh_token\);\n  const afterReplay = await refresh\(rotated\);/,
    "the consumed predecessor is replayed and the live successor re-checked");
  // Both halves are the claim: a refused replay alone is one dead token, not a
  // revoked family, so the row must assert the successor too.
  assert.match(PROBE, /replayed\.statusCode === 400 && replayed\.json\(\)\.error === "invalid_grant"\n\s*&& afterReplay\.statusCode === 400 && afterReplay\.json\(\)\.error === "invalid_grant",/,
    "the replay row asserts the refused replay AND the dead successor");
  assert.ok(PROBE.indexOf('await authorizationCodeGrant("revocation family"') > PROBE.indexOf("const afterReplay"),
    "revocation is proved on a family the replay did not already revoke");
  assert.match(PROBE, /afterRevoke\.statusCode === 400 && afterRevoke\.json\(\)\.error === "invalid_grant"/);
  assert.match(PROBE, /url: "\/oauth\/register"/);
  assert.match(PROBE, /url: "\/oauth\/authorize\/approve"/);
  assert.match(PROBE, /grant_type: "authorization_code"/);
  assert.match(PROBE, /grant_type: "refresh_token"/);
  assert.match(PROBE, /grant_type: "client_credentials"/);
  assert.match(PROBE, /sdkPing\(base, userTokens\.access_token/);
  assert.match(PROBE, /sdkPing\(base, machineAccess/);
  assert.match(PROBE, /createRedisRateLimit\(redis/);
  assert.match(PROBE, /new JsonlFileAudit\(jsonlPath\)/);
  assert.match(PROBE, /new WebhookAudit\(/);
  // The receipt and the leak scan are RECORDED as the run happens, not
  // hand-listed: expectations are pushed where each action occurs, credentials
  // where each is produced, and both are then compared exactly. That is what
  // stops either from falling behind the flow.
  assert.match(PROBE, /const credentials = secrets;/, "the leak scan is the registry, not a second list");
  assert.doesNotMatch(PROBE, /const requiredFlow = \[/, "no hand-written event list survives");
  assert.match(PROBE, /JSON\.stringify\(observedKinds\) === JSON\.stringify\(expected\)/,
    "the emitted sequence is compared exactly, in order and in count");
  assert.match(PROBE, /expect\("auth\.request", "success", SDK_AUTH_REQUESTS\)/,
    "each SDK session's full set of protected-call events is expected");
  assert.equal((PROBE.match(/expect\("auth\.request", "success", SDK_AUTH_REQUESTS\)/g) ?? []).length, 2,
    "both SDK sessions");
  assert.match(PROBE, /expect\("auth\.request", "failure"\)/);
  assert.match(PROBE, /expect\(limiterAuditEvent, "failure", admitted\)/,
    "the limiter burst's admitted calls are accounted for");
  assert.match(PROBE, /const rejectedSecret = secret\("rejected machine client secret"/,
    "the submitted-and-rejected secret is registered, not only the minted one");
  for (const registered of ["probe identity token", "webhook collector token", "signing private key",
    "consent signing credential", "identity completion session cookie", "identity completion thrown text",
    "machine client secret", "machine access token",
    "replay family rotated refresh token", "revocation family rotated access token"]) {
    assert.match(PROBE, new RegExp(`secret\\("${registered}"`), `${registered} is registered`);
  }
  // Both grants register their own consent token, code, verifier, access and
  // refresh token through the labelled helper.
  for (const part of ["consent token", "authorization code", "PKCE verifier", "access token", "refresh token"]) {
    assert.match(PROBE, new RegExp("secret\\(`\\$\\{label\\} " + part + "`"), `each grant registers its ${part}`);
  }
  assert.match(PROBE, /JSON\.stringify\(fileEvents\) === JSON\.stringify\(posted\)/);
  assert.match(PROBE, /redis\.on\("error", \(\) => \{\}\)/, "ioredis must not print the host and port itself");
  assert.doesNotMatch(PROBE, /console\.(?:log|warn|error)\([^\n]*(?:Secret|secret|Token|token|clientSecret|OAUTH_|REDIS_URL|error|message)/i);
  assert.doesNotMatch(PROBE, /OAUTH_CONSENT_SIGNING_SECRET[^\n]*(?:slice|substring|substr)/);
  const disableAt = PROBE.indexOf("await disableMachineClient(");
  const limiterAt = PROBE.indexOf("for (let i = 0; i < burst; i++)");
  assert.ok(disableAt > 0 && disableAt < limiterAt, "disablement is proved before the shared token bucket is exhausted");
  assert.ok(PROBE.indexOf("await app.close()") < PROBE.indexOf("await store.close()"));
  assert.ok(PROBE.indexOf("await store.close()") < PROBE.indexOf("redis.disconnect()"));
  assert.ok(PROBE.indexOf("redis.disconnect()") < PROBE.indexOf("await rm(stateDir, { recursive: true, force: true })"));
  assert.match(PROBE, /FAIL  probe limiter cleanup failed/);
  assert.match(PROBE, /FAIL  probe state cleanup failed/);
  assert.match(PROBE, /await runIdentityCompletionLeg\(/, "the claims-only leg runs inside the existing probe");
  assert.doesNotMatch(IDENTITY_COMPLETION, /\bSKIP\b/, "identity completion cannot count a skipped leg as evidence");
  for (const adapter of ["fastifyDriver", "expressDriver", "honoDriver"]) {
    assert.match(IDENTITY_COMPLETION, new RegExp(`\\b${adapter}\\b`), `${adapter} is part of the live leg`);
  }
  assert.match(IDENTITY_COMPLETION, /headers\.getSetCookie\(\)/, "the Fetch adapters assert separate Set-Cookie fields");
  assert.match(IDENTITY_COMPLETION, /\["probe-session", "__Host-mcp-sso-identity"\]/, "the host and clearing cookies are both asserted");
  assert.match(IDENTITY_COMPLETION, /"completion_failed"/, "the fixed audit reason is asserted");
  assert.match(IDENTITY_COMPLETION, /console\.error = \(\.\.\.values\)/, "stderr is captured around the thrown completion");
});

test("CONTENT provider probes: all three share the disposable-state helper before boot and dispose last", () => {
  for (const [file, prefix] of [["probe-cloudflare.mjs", "cloudflare"], ["probe-entra.mjs", "entra"], ["probe-google.mjs", "google"]]) {
    const source = read(`scripts/live/${file}`);
    const stateAt = source.indexOf(`await createDisposableProbeState("mcp-sso-live-${prefix}-")`);
    const buildAt = source.indexOf("await buildExample(isolatedEnv)");
    assert.ok(stateAt >= 0 && stateAt < buildAt, `${file}: state is prepared before boot`);
    assert.match(source, /\.\.\.disposable\.env,\n  \};/, `${file}: the helper's overrides are applied last`);
    assert.doesNotMatch(source, /mkdtemp|MCP_SSO_DIR: stateDir/, `${file}: no probe hands the temp root in as the state dir`);
    assert.ok(source.indexOf("await store.close()") < source.indexOf("await disposable.dispose()"), `${file}: dispose runs after the store closes`);
    assert.doesNotMatch(source, /\bSKIP\b/, `${file}: a skipped subject must never count as evidence`);
    assert.doesNotMatch(source, /process\.exit\(/, `${file}: evidence drains before exit`);
  }
});

test("CONTENT records: harness reference, README, and CHECKLIST agree with what the scripts do", () => {
  assert.match(DOC, /^\| `probe-e2e\.mjs` \|/m, "the harness table records the e2e probe");
  assert.match(DOC, /`run\.sh`/);
  assert.match(DOC, /`serve\.sh`/);
  assert.match(DOC, /`CHECKLIST\.md`/);
  assert.match(DOC, /scripts\/live\/README\.md/);
  assert.match(DOC, /none reports\s+`SKIP`/);
  assert.match(README, /run\.sh scripts\/live\/probe-e2e\.mjs/);
  // The records must name what the probe proves: replay detection and family
  // revocation are what an operator reads the receipt for.
  for (const [name, record] of [["docs", DOC], ["README", README]]) {
    assert.match(record, /replayed predecessor/, `${name}: the probe-e2e row records the replay proof`);
    assert.match(record, /live successor/, `${name}: the probe-e2e row records the revoked family`);
    assert.match(record, /second family/, `${name}: the probe-e2e row records that revocation uses its own family`);
    assert.match(record, /unknown opaque client/i, `${name}: the probe-e2e row records the DCR mode differential`);
    assert.match(record, /machine.{0,100}stored/i, `${name}: machine-client evidence is scoped to stored runs`);
  }
  assert.match(README, /MCP_SSO_READINESS_SECONDS/);
  assert.match(DOC, /MCP_SSO_READINESS_SECONDS/);
  assert.match(README, /~\/\.mcp-sso-google\.env/);
  assert.match(README, /MCP_SSO_GOOGLE_ENV/);
  assert.match(README, /OIDC_CLIENT_SECRET/);
  assert.match(README, /cloudflared access login/);
  assert.match(README, /lsof/);
  const before = CHECKLIST.indexOf("E1_BEFORE=$(audit_count");
  const after = CHECKLIST.indexOf("E1_AFTER=$(audit_count");
  const comparison = CHECKLIST.indexOf('test "$E1_AFTER" -eq "$E1_BEFORE"');
  assert.ok(before >= 0 && before < after && after < comparison, "E1 records a before/after count and fails when it changes");
  assert.doesNotMatch(CHECKLIST, /no audit row at all/i);
  assert.match(CHECKLIST, /serve\.sh cloudflare_access entra google/);
});

test("CONTENT rehearsal: the orchestrator, the CI adapter, and the workflow keep the harness's promises", () => {
  const rehearsal = read("scripts/live/rehearsal.mjs");
  const support = read("scripts/live/rehearsal-support.mjs");
  const workflow = read(".github/workflows/live.yml");
  assert.doesNotMatch(`${rehearsal}\n${support}`, /\bSKIP\b/, "a rehearsal row is PASS, FAIL, or BLOCKED; never skipped");
  assert.doesNotMatch(rehearsal, /process\.exit\(/, "the receipt is written before the process ends");
  assert.match(rehearsal, /process\.exitCode = receipt\.evidence \? 0 : 1/, "green means evidence, nothing weaker");
  assert.match(support, /"BLOCKED", reason/, "a blocked row carries its armable reason");
  assert.match(rehearsal, /private_value_in_output/, "a leaked configuration value fails the row");
  assert.doesNotMatch(workflow, /pull_request/, "the live workflow never runs for a pull request");
  assert.match(workflow, /^permissions: \{\}$/m, "no workflow-level token permissions");
  assert.match(workflow, /environment: \$\{\{ github\.ref == 'refs\/heads\/main' && 'live' \|\| 'live-branch' \}\}/,
    "main runs unattended under live; any other admitted ref waits for the reviewer under live-branch");
  assert.match(workflow, /refs\/heads\/main\|refs\/heads\/rehearsal\/\*\) echo "ref admitted/, "the ref rule is enforced in the file, before anything else");
  assert.ok(workflow.indexOf("refuse any ref but main or rehearsal/*") < workflow.indexOf("actions/checkout@"), "the ref guard is the first step");
  assert.match(workflow, /^\s+id-token: write/m);
  assert.match(workflow, /branches: \["rehearsal\/\*"\]/, "pushes run only for rehearsal branches, with the pattern the environment policy uses");
  assert.match(workflow, /role-to-assume: \$\{\{ secrets\.MCP_SSO_LIVE_ROLE_ARN \}\}/, "the role ARN is a masked secret, not a variable");
  assert.match(workflow, /run: google-chrome --version/, "the browser the driver runs is checked once, up front");
  assert.equal((workflow.match(/persist-credentials: false/g) ?? []).length, 2, "neither job persists a checkout credential");
  assert.match(workflow, /node scripts\/live\/ci\/mask-bundle\.mjs/, "private values are masked before the probes print");
  assert.ok(workflow.indexOf("mask-bundle.mjs") < workflow.indexOf("rehearsal.mjs"), "masking precedes the run");
  assert.match(workflow, /rm -rf -- "\$MCP_SSO_BUNDLE_DIR"/, "the bundle is removed on every exit path");
  assert.match(workflow, /MCP_SSO_INFRA_DIR: \$\{\{ github\.workspace \}\}\/scripts\/live\/ci\/infra/, "run.sh reads through the adapter");
  for (const [name, record] of [["README", README], ["docs", DOC]]) {
    assert.match(record, /rehearsal\.mjs/, `${name}: records the rehearsal`);
    assert.match(record, /BLOCKED/, `${name}: records the blocked outcome`);
    assert.match(record, /drive-identity\.mjs/, `${name}: records the identity driver`);
    assert.match(record, /login\.microsoftonline\.com/, `${name}: records the one host the password is typed on`);
  }
  // The driver: the password reaches exactly one host, and nothing a page
  // shows is ever printed.
  const driver = read("scripts/live/drive-identity.mjs");
  const browser = read("scripts/live/drive-identity-browser.mjs");
  const driverSupport = read("scripts/live/drive-identity-support.mjs");
  assert.match(driverSupport, /CREDENTIAL_HOST = "login\.microsoftonline\.com"/);
  const typeGate = browser.indexOf("if (!policy.mayTypeCredential(page.url())) return \"unexpected_host\";");
  const fill = browser.indexOf('.fill(password)');
  assert.ok(typeGate >= 0 && fill > typeGate, "the host is checked before the password is typed");
  assert.equal((browser.match(/mayTypeCredential\(page\.url\(\)\)/g) ?? []).length, 2, "checked at both the login and the password step");
  assert.equal((browser.match(/\.fill\(password\)/g) ?? []).length, 1, "one place types the password");
  assert.doesNotMatch(`${driver}\n${browser}`, /console\.(?:log|error|warn)/, "the driver prints through one fixed outcome line");
  assert.match(driver, /process\.stdout\.write\(`outcome: \$\{result\.outcome\}\\n`\)/);
  assert.doesNotMatch(`${driver}\n${browser}`, /screenshot|innerHTML|content\(\)/, "no page capture");
  assert.match(driver, /O_EXCL, 0o600/, "the result file is created owner-only");
  assert.equal((browser.match(/trace\.push\(`session:cleared:\$\{await clearSessionCookies\(context, origin\)\}`\)/g) ?? []).length, 2,
    "both browser tasks start from no session, so a reused or hosted browser cannot pass off another account's sign-in");
  assert.match(README, /access-edge-denial/);
  assert.match(CHECKLIST, /access-edge-denial/, "the checklist points E1 at its automated sibling");
  // The client probe against a served leg: no skipped subject, the documented
  // description from the shipped mapping, and the audit as the authority.
  const client = read("scripts/live/probe-client.mjs");
  const clientSupport = read("scripts/live/probe-client-support.mjs");
  assert.doesNotMatch(client, /\bSKIP\b|process\.exit\(/);
  assert.match(clientSupport, /identityRejectionDescription/, "expected descriptions come from src, never a copy");
  assert.doesNotMatch(clientSupport, /Entra returned no groups/, "no duplicated reason text");
  assert.match(client, /deniedFlowHolds\(events, options\.expect\)/, "a denial is proved from the audit reason");
  assert.match(client, /auditLeaks\(audit, secrets\)/, "the served audit is scanned for this flow's code and tokens");
  assert.match(client, /sdkPing\(origin, tokens\.access_token/, "the official SDK client is driven on the public origin");
  assert.doesNotMatch(client, /console\.(?:log|error|warn)\([^\n]*(?:password|user\b|redirectUrl|access_token|refresh_token)/);
  for (const [name, record] of [["README", README], ["docs", DOC]]) {
    assert.match(record, /probe-client\.mjs/, `${name}: records the client probe`);
    assert.match(record, /tunnel_already_served/, `${name}: records the refusal to double-serve`);
  }
  assert.match(CHECKLIST, /client-entra:overage/, "the checklist points the deny rows at their automated siblings");
  // The third-party CLI probe: the real CLI in a private HOME, no desktop
  // browser, the served audit as the authority, pinned installs in CI.
  const cliProbe = read("scripts/live/probe-cli.mjs");
  const cliSupport = read("scripts/live/probe-cli-support.mjs");
  assert.doesNotMatch(cliProbe, /\bSKIP\b|process\.exit\(/);
  assert.match(cliProbe, /"--no-browser"/, "Claude Code is told not to open a browser");
  assert.match(cliProbe, /for \(const name of BROWSER_LAUNCHERS\)/, "a CLI that opens the URL itself reaches a shim, never the operator's browser");
  const claudeBranch = cliProbe.slice(cliProbe.indexOf('if (options.cli === "claude") {\n      // The connection check'), cliProbe.indexOf("keys.ANTHROPIC_API_KEY"));
  assert.match(claudeBranch, /\["mcp", "list"\]/, "the connection check runs on every Claude Code row, before any key is consulted");
  assert.ok(cliProbe.indexOf("const home = mkdtempSync(") < cliProbe.indexOf("openBrowser()"), "the private HOME exists before the browser opens, so every exit path can remove it");
  assert.ok(cliProbe.indexOf("try {") < cliProbe.indexOf("openBrowser()"), "the browser is opened inside the try whose finally closes it");
  assert.match(cliProbe, /HOME: home/, "the CLI's configuration and credential store live in a private HOME");
  assert.match(cliProbe, /process\.platform === "darwin"[\s\S]{0,200}"security"[\s\S]{0,80}FAKE_KEYCHAIN/, "on macOS the CLI's keychain is a file in the private HOME, never the operator's login keychain");
  assert.match(cliProbe, /FAKE_KEYCHAIN = fileURLToPath\(new URL\("\.\/fake-keychain\.py"/);
  assert.match(read("scripts/live/fake-keychain.py"), /sys\.exit\(44\)/, "a missing item answers like the real tool");
  assert.match(cliProbe, /cliLoginHolds\(events, options\.cli/, "the login is proved from the served audit");
  assert.match(cliProbe, /readClientKeysFile\(/, "vendor keys are read through the owner-only file reader");
  assert.doesNotMatch(cliProbe, /console\.(?:log|error|warn)\([^\n]*(?:password|redirectUrl|authorize\.href|keys\.)/);
  assert.match(cliSupport, /pty-run\.py/, "the CLI runs on the wide pseudo-terminal");
  assert.match(read("scripts/live/pty-run.py"), /TIOCSWINSZ/, "the pseudo-terminal's width is set, wide enough for the URLs these CLIs print");
  assert.match(cliProbe, /opened = [^\n]*openBrowser\(\)/, "the browser is opened as a preflight");
  assert.ok(cliProbe.indexOf("openBrowser()") < cliProbe.indexOf("spawnPty("), "the browser preflight runs before the CLI touches the served leg");
  assert.match(cliProbe, /refuse\("browser is unavailable; install Chrome or set MCP_SSO_BROWSER_CDP_URL"\)/, "a missing browser is a runner-level refusal");
  assert.match(cliProbe, /refuse\("the CLI rows need a browser on this host/, "a hosted browser is refused: the callback is this host's loopback");
  assert.match(cliProbe, /OPEN_MARKER/, "the browser shims leave a marker the row checks");
  assert.match(cliProbe, /\(deny process-exec \(literal "\/usr\/bin\/open"\)\)/, "on macOS the login command cannot run /usr/bin/open");
  assert.match(cliProbe, /\["sandbox-exec", \["-p", DARWIN_SANDBOX, command, \.\.\.args\]\]/, "the sandbox wraps the login command");
  assert.equal((cliProbe.match(/spawnPty\(\.\.\.loginCommand\(/g) ?? []).length, 2, "both login commands run through the sandbox wrapper");
  assert.match(cliProbe, /existsSync\(join\(home, KEYCHAIN_STORE\)\)/, "the private keychain is proved reached");
  assert.match(cliProbe, /NOTE  tool call skipped/, "a skipped tool call is recorded, never silent");
  const installAt = workflow.indexOf("npm install -g --ignore-scripts");
  const roleAt = workflow.indexOf("configure-aws-credentials@");
  const connectorAt = workflow.indexOf("cloudflared-linux-amd64");
  assert.ok(installAt > 0 && installAt < roleAt, "third-party code is installed before the role is assumed");
  assert.ok(connectorAt > 0 && connectorAt < roleAt, "the tunnel connector is installed before the role is assumed");
  for (const [name, record] of [["README", README], ["docs", DOC]]) {
    assert.match(record, /probe-cli\.mjs/, `${name}: records the CLI probe`);
  }
  assert.match(CHECKLIST, /claude-code:cloudflare/, "the checklist points A1 at its automated sibling");
  assert.match(CHECKLIST, /codex-cli:entra/, "the checklist points B2 at its automated sibling");
  assert.match(workflow, /npm install -g --ignore-scripts @anthropic-ai\/claude-code@\d+\.\d+\.\d+ @openai\/codex@\d+\.\d+\.\d+/,
    "the CLIs are installed at pinned versions with install scripts disabled");
  assert.match(workflow, /node "\$\(npm root -g\)\/@anthropic-ai\/claude-code\/install\.cjs"/,
    "the one script the wrapper needs is run explicitly, never by enabling lifecycle scripts");
  assert.match(workflow, /\n\s+claude --version\n\s+codex --version\n/, "a broken CLI install fails in its own step, not as blocked rows");
  assert.match(README, /MCP_SSO_CLIENT_KEYS_FILE/);
  // The evidence record is rendered only from a passing receipt and checked
  // with the gate's parser; the writing job and the credentialed job are split.
  const renderer = read("scripts/live/render-evidence.mjs");
  assert.match(renderer, /receipt\.evidence !== true/, "a receipt that is not evidence is refused");
  assert.match(renderer, /evaluateReleaseReadiness\(/, "the gate's own parser checks the rendering before it is written");
  assert.ok(renderer.indexOf("evaluateReleaseReadiness(") < renderer.indexOf("writeFileSync(compatibilityPath"), "checked before written");
  const jobs = workflow.split(/^  record:$/m);
  assert.equal(jobs.length, 2, "one record job");
  assert.doesNotMatch(jobs[0].slice(jobs[0].indexOf("  rehearse:")), /contents: write|pull-requests: write/, "the rehearsal job holds no write token");
  assert.doesNotMatch(jobs[1], /environment:|configure-aws-credentials/, "the record job holds no AWS role");
  assert.doesNotMatch(jobs[1], /pnpm install|pnpm\/action-setup/, "the job with the write token installs no third-party code");
  assert.match(jobs[1], /persist-credentials: false/);
  assert.match(jobs[1], /--require-head/, "the record binds the receipt to the checked-out commit");
  assert.match(jobs[1], /if: github\.event_name == 'workflow_dispatch' && inputs\.record && github\.ref == 'refs\/heads\/main'/, "recording is opt-in and main only");
  assert.match(jobs[1], /render-evidence\.mjs --receipt .* --write/);
  assert.match(README, /render-evidence\.mjs/);
  assert.match(DOC, /render-evidence\.mjs/);
  assert.match(workflow, /cloudflared-linux-amd64/);
  assert.match(workflow, /sha256sum -c -/, "the connector binary is verified by digest before it runs");
  assert.match(workflow, /node scripts\/live\/ci\/install-tunnel\.mjs/);
  assert.match(workflow, /rm -rf -- "\$MCP_SSO_BUNDLE_DIR" "\$HOME\/\.cloudflared"/, "the tunnel credentials are removed with the bundle");
  assert.match(README, /live\.yml/);
  assert.match(README, /fetch-bundle\.mjs/);
  assert.match(README, /gh workflow run live\.yml/);
  // Every BLOCKED reason the code can record is named in both records, and no
  // record still speaks the retired undifferentiated denial.
  for (const reason of BLOCKED_REASON_NAMES) {
    assert.match(README, new RegExp(`\`${reason}\``), `README names ${reason}`);
    assert.match(DOC, new RegExp(`\`${reason}\``), `harness reference names ${reason}`);
  }
  const everything = readdirSync(join(ROOT, "scripts/live"), { recursive: true, withFileTypes: true }).filter((e) => e.isFile())
    .map((e) => read(`${e.parentPath.slice(ROOT.length)}/${e.name}`)).join("\n") + DOC + read("docs/live-verification.md");
  assert.doesNotMatch(everything, /denied_at_provider/, "the retired outcome name survives nowhere");
  // Every live test file is named in the harness reference.
  for (const name of readdirSync(join(ROOT, "test")).filter((n) => /^live-.*\.test\.mjs$/.test(n))) {
    assert.match(DOC, new RegExp(`\`test/${name.replace(/\./g, "\\.")}\``), `harness reference lists ${name}`);
  }
});

test("CONTENT hygiene: scripts/live and its records name no private infrastructure", () => {
  const allowedHosts = new Set([
    "claude.ai", "chatgpt.com", "login.microsoftonline.com", "accounts.google.com", "127.0.0.1", "localhost",
    "collector.example", "mcp.example", "www.googleapis.com", "oauth2.googleapis.com", "github.com",
  ]);
  const files = readdirSync(join(ROOT, "scripts/live"), { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => `${entry.parentPath.slice(ROOT.length)}/${entry.name}`)
    .concat(["docs/live-verification.md", ".github/workflows/live.yml"]);
  assert.ok(files.includes("scripts/live/ci/infra/scripts/tofu-run.sh"), "the scan reaches nested files");
  for (const file of files) {
    const text = read(file);
    for (const match of text.matchAll(/https?:\/\/([A-Za-z0-9.<>_-]+)/g)) {
      const host = match[1];
      const ok = allowedHosts.has(host) || host.startsWith("<") || host.endsWith(".example") || host.endsWith(".test");
      assert.ok(ok, `${file}: unexpected host in ${match[0]}`);
    }
    assert.doesNotMatch(text, /\$HOME\/project\/|\/Users\//, `${file}: no private checkout path`);
  }
});
