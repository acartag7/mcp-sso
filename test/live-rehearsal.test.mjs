// Behavioural coverage for the release rehearsal: the CI output adapter
// (scripts/live/ci) answering the REAL run.sh from a bundle on disk, the bundle
// fetcher against a stub `aws`, the log masker, and the orchestrator's
// classification of run.sh outcomes. Nothing here reads a script as text.
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import {
  chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  bundleOutput, leaksPrivateValue, maskCommand, parseBundle, privateValues, readBundleFile,
} from "../scripts/live/ci/bundle-support.mjs";
import { answer } from "../scripts/live/ci/bundle-output.mjs";
import { fetchBundles } from "../scripts/live/ci/fetch-bundle.mjs";
import { maskLines } from "../scripts/live/ci/mask-bundle.mjs";
import { ROWS, buildReceipt, classifyDriverRun, classifyRun, formatSummary } from "../scripts/live/rehearsal-support.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const TENANT = "11111111-2222-3333-4444-555555555555";
const CLIENT = "66666666-7777-8888-9999-aaaaaaaaaaaa";
const MAPPED = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
const UNMAPPED = "01234567-89ab-cdef-0123-456789abcdef";
const ENTRA = {
  entra_tenant_id: TENANT, entra_client_id: CLIENT, entra_client_secret: "fixture-entra-secret-value",
  entra_redirect_uri: "https://entra.example/oauth/callback", unmapped_group_object_id_do_not_map: UNMAPPED,
  group_authorization_mapping: { [MAPPED]: ["mcp:read"] }, test_users: { member: "member@fixture.example" },
  test_user_password: "fixture-password-value", overage_group_count: 201,
};
const CLOUDFLARE = {
  cf_access_audience: "fixture-audience-tag", cf_access_issuer: "https://team.cloudflareaccess.com",
  cf_access_certs_url: "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
  issuer_origins: { cloudflare_access: "https://cf.example", entra: "https://entra.example", google: "https://google.example" },
  tunnel_ingress_ports: { entra: { gateway: 43111, backend: 43112 } }, tunnel_id: "0f0f0f0f-1111-2222-3333-444444444444",
  cf_access_idp_name: "fixture tenant",
};
const JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln";
const executable = (path, source) => { writeFileSync(path, source); chmodSync(path, 0o700); };
const privateFile = (path, text) => { writeFileSync(path, text, { mode: 0o600 }); chmodSync(path, 0o600); };

function bundleDir() {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-bundle-"));
  privateFile(join(dir, "entra.json"), JSON.stringify(ENTRA));
  privateFile(join(dir, "cloudflare.json"), JSON.stringify(CLOUDFLARE));
  return dir;
}

test("BEHAVIOUR bundle-support: a bundle is read as owner-only data and answered like tofu output", () => {
  const dir = bundleDir();
  try {
    const bundle = readBundleFile(join(dir, "entra.json"));
    assert.equal(bundleOutput(bundle, "entra_tenant_id", "-raw"), TENANT);
    assert.equal(bundleOutput(bundle, "overage_group_count", "-raw"), "201");
    assert.deepEqual(JSON.parse(bundleOutput(bundle, "group_authorization_mapping", "-json")), { [MAPPED]: ["mcp:read"] });
    assert.equal(bundleOutput(bundle, "entra_tenant_id", "-json"), JSON.stringify(TENANT));
    assert.throws(() => bundleOutput(bundle, "group_authorization_mapping", "-raw"), /not a scalar/);
    assert.throws(() => bundleOutput(bundle, "missing", "-raw"), /unavailable/);
    assert.throws(() => bundleOutput(bundle, "entra_tenant_id", "-text"), /unsupported/);
    assert.throws(() => bundleOutput(bundle, "../x", "-raw"), /invalid/);
    assert.throws(() => bundleOutput({ v: "" }, "v", "-raw"), /empty/);
    assert.throws(() => bundleOutput({ v: "ab" }, "v", "-raw"), /control/);
    assert.throws(() => bundleOutput({ v: "x".repeat(5_000) }, "v", "-raw"), /oversized/);
    assert.throws(() => bundleOutput({ v: null }, "v", "-raw"), /not a scalar/);
    for (const text of ["[]", "\"s\"", "not json", JSON.stringify({ "Bad-Key": 1 }), JSON.stringify({ "": 1 })]) {
      assert.throws(() => parseBundle(text), text);
    }
    chmodSync(join(dir, "entra.json"), 0o644);
    assert.throws(() => readBundleFile(join(dir, "entra.json")), /group or other/);
    chmodSync(join(dir, "entra.json"), 0o600);
    assert.throws(() => readBundleFile(join(dir, "entra.json"), 424242), /owned/);
    symlinkSync(join(dir, "entra.json"), join(dir, "link.json"));
    assert.throws(() => readBundleFile(join(dir, "link.json")), /symlink/);
    assert.throws(() => readBundleFile(dir), /regular file|opened/);
    assert.throws(() => readBundleFile(join(dir, "missing.json")), /opened/);
    privateFile(join(dir, "big.json"), JSON.stringify({ v: "x".repeat(70_000) }));
    assert.throws(() => readBundleFile(join(dir, "big.json")), /too large/);
    const values = privateValues(readBundleFile(join(dir, "cloudflare.json")));
    assert.ok(values.has("https://entra.example") && values.has("entra.example"), "origins and their bare hosts are private");
    assert.ok(values.has("fixture tenant"), "a value under a credential or identity key is private at any length");
    assert.ok(!values.has("43111"), "ports are not private");
    const multi = privateValues({ TunnelSecret: "ab", note: "first line long enough\nsecond line long enough", short: "tiny" });
    assert.ok(multi.has("ab") && multi.has("first line long enough") && multi.has("second line long enough") && !multi.has("tiny"),
      "credential keys at any length, other values per line from the floor");
    assert.equal(maskCommand("a%b\r\nc"), "::add-mask::a%25b%0D%0Ac", "masks are encoded the way the runner decodes them");
    assert.equal(leaksPrivateValue("host=entra.example port=43111", values), true);
    assert.equal(leaksPrivateValue("PASS  authorize redirects to Entra", values), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("BEHAVIOUR bundle-output: the adapter accepts exactly the run.sh call shape", () => {
  const dir = bundleDir();
  try {
    const env = { MCP_SSO_BUNDLE_DIR: dir };
    assert.equal(answer(["entra", "output", "-raw", "entra_client_id"], env), CLIENT);
    assert.equal(answer(["cloudflare", "output", "-json", "issuer_origins"], env), JSON.stringify(CLOUDFLARE.issuer_origins));
    assert.throws(() => answer(["entra", "plan"], env), /only/);
    assert.throws(() => answer(["entra", "output", "-raw", "entra_client_id", "extra"], env), /only/);
    assert.throws(() => answer(["../entra", "output", "-raw", "entra_client_id"], env), /stack handle/);
    assert.throws(() => answer(["Entra", "output", "-raw", "entra_client_id"], env), /stack handle/);
    assert.throws(() => answer(["google", "output", "-raw", "x"], env), /opened/, "a missing bundle is a refusal, not an empty value");
    assert.throws(() => answer(["entra", "output", "-raw", "entra_client_id"], {}), /MCP_SSO_BUNDLE_DIR/);
    const cli = spawnSync(process.execPath, [join(ROOT, "scripts/live/ci/bundle-output.mjs"), "entra", "output", "-raw", "entra_client_secret"],
      { env: { PATH: process.env.PATH, MCP_SSO_BUNDLE_DIR: dir }, encoding: "utf8" });
    assert.equal(cli.status, 0);
    assert.equal(cli.stdout, ENTRA.entra_client_secret, "the value and nothing else, no trailing newline");
    const bad = spawnSync(process.execPath, [join(ROOT, "scripts/live/ci/bundle-output.mjs"), "entra", "output", "-raw", "nope"],
      { env: { PATH: process.env.PATH, MCP_SSO_BUNDLE_DIR: dir }, encoding: "utf8" });
    assert.equal(bad.status, 1);
    assert.equal(bad.stdout, "");
    assert.match(bad.stderr, /^bundle-output: required stack output unavailable$/m);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("BEHAVIOUR adapter + run.sh: the shipped runner assembles a leg from the bundle through scripts/live/ci/infra", async () => {
  const fixture = mkdtempSync(join(tmpdir(), "mcp-sso-rehearsal-run-"));
  try {
    const repo = join(fixture, "repo");
    mkdirSync(join(repo, "scripts/live/ci/infra/scripts"), { recursive: true });
    mkdirSync(join(repo, "examples/fastify-sqlite"), { recursive: true });
    symlinkSync(join(ROOT, "src"), join(repo, "src"));
    for (const file of ["app.ts", "registration-rate-limit.ts", "trusted-proxy.ts"]) {
      symlinkSync(join(ROOT, "examples/fastify-sqlite", file), join(repo, "examples/fastify-sqlite", file));
    }
    for (const file of ["run.sh", "run-support.mjs", "ci/bundle-support.mjs", "ci/bundle-output.mjs", "ci/infra/scripts/tofu-run.sh"]) {
      copyFileSync(join(ROOT, "scripts/live", file), join(repo, "scripts/live", file));
    }
    chmodSync(join(repo, "scripts/live/run.sh"), 0o700);
    chmodSync(join(repo, "scripts/live/ci/infra/scripts/tofu-run.sh"), 0o700);
    const capture = 'import { writeFileSync } from "node:fs";\nimport { join } from "node:path";\nwriteFileSync(join(process.env.TMPDIR, "capture.json"), JSON.stringify({ env: process.env, argv: process.argv.slice(2) }));\n';
    for (const entry of ["probe-entra.mjs", "probe-cloudflare.mjs", "drive-identity.mjs"]) writeFileSync(join(repo, "scripts/live", entry), capture);
    const git = (...args) => execFileSync("git", ["-C", repo, "-c", "user.name=f", "-c", "user.email=f@example.test", ...args], { stdio: "ignore" });
    git("init", "-q"); git("add", "-A"); git("commit", "-q", "-m", "fixture");
    const dir = bundleDir();
    const home = join(fixture, "home");
    mkdirSync(home);
    const runScript = (args, extraEnv = {}) => new Promise((resolve, reject) => {
      const runDir = join(fixture, `run-${Math.random().toString(16).slice(2)}`);
      mkdirSync(runDir);
      const child = spawn(join(repo, "scripts/live/run.sh"), args, {
        env: {
          PATH: process.env.PATH, HOME: home, TMPDIR: runDir, MCP_SSO_BUNDLE_DIR: dir,
          MCP_SSO_INFRA_DIR: join(repo, "scripts/live/ci/infra"), MCP_SSO_ENTRA_STACK: "entra", MCP_SSO_CLOUDFLARE_STACK: "cloudflare", ...extraEnv,
        },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stderr = "";
      child.stderr.setEncoding("utf8");
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.once("error", reject);
      child.once("exit", (code) => {
        const capturePath = join(runDir, "capture.json");
        resolve({ code, stderr, captured: existsSync(capturePath) ? JSON.parse(readFileSync(capturePath, "utf8")) : undefined });
      });
    });
    const probe = await runScript(["scripts/live/probe-entra.mjs", "entra"]);
    assert.equal(probe.code, 0, probe.stderr);
    const env = probe.captured.env;
    assert.equal(env.OAUTH_ISSUER, "https://entra.example");
    assert.equal(env.ENTRA_TENANT_ID, TENANT);
    assert.equal(env.ENTRA_CLIENT_SECRET, ENTRA.entra_client_secret);
    assert.deepEqual(JSON.parse(env.ENTRA_GROUP_AUTHORIZATION_JSON), { mapping: ENTRA.group_authorization_mapping });
    assert.equal(env.MCP_SSO_BUNDLE_DIR, undefined, "the bundle location never reaches the entry");
    assert.equal(env.IDP_TEST_USER_PASSWORD, undefined, "a probe never receives the test-user password");
    assert.deepEqual(probe.captured.argv, [], "a probe receives no arguments unless given");
    assert.doesNotMatch(probe.stderr, new RegExp(ENTRA.entra_client_secret));
    // The driver kind: test users and their password, the leg origin, and for
    // the Cloudflare leg the login method; no application credential; its
    // arguments forwarded verbatim.
    const driver = await runScript(["scripts/live/drive-identity.mjs", "cloudflare_access", "cloudflare-assertion", "--out", "/nowhere", "--user", "nogroups"]);
    assert.equal(driver.code, 0, driver.stderr);
    assert.deepEqual(driver.captured.argv, ["cloudflare-assertion", "--out", "/nowhere", "--user", "nogroups"]);
    assert.equal(driver.captured.env.OAUTH_ISSUER, "https://cf.example");
    assert.deepEqual(JSON.parse(driver.captured.env.IDP_TEST_USERS_JSON), ENTRA.test_users);
    assert.equal(driver.captured.env.IDP_TEST_USER_PASSWORD, ENTRA.test_user_password);
    assert.equal(driver.captured.env.CF_ACCESS_IDP_NAME, "fixture tenant");
    for (const key of ["CF_ACCESS_AUDIENCE", "CF_ACCESS_ASSERTION", "ENTRA_CLIENT_SECRET", "MCP_SSO_CF_ACCESS_ASSERTION_FILE",
      "OAUTH_SIGNING_PRIVATE_JWK", "OAUTH_CONSENT_SIGNING_SECRET"]) {
      assert.equal(driver.captured.env[key], undefined, `${key} never reaches the driver`);
    }
    assert.doesNotMatch(driver.stderr, new RegExp(ENTRA.test_user_password));
    // The client kind: the driver's inputs plus which leg it is on and where the
    // served leg's audit trail is; still no application credential.
    writeFileSync(join(repo, "scripts/live/probe-client.mjs"), capture);
    const clientRun = await runScript(["scripts/live/probe-client.mjs", "entra", "--user", "overage", "--expect", "entra_groups_overage"],
      { MCP_SSO_AUDIT_FILE: "/served/entra/audit.jsonl" });
    assert.equal(clientRun.code, 0, clientRun.stderr);
    assert.deepEqual(clientRun.captured.argv, ["--user", "overage", "--expect", "entra_groups_overage"]);
    assert.equal(clientRun.captured.env.MCP_SSO_LEG, "entra");
    assert.equal(clientRun.captured.env.MCP_SSO_AUDIT_FILE, "/served/entra/audit.jsonl");
    assert.equal(clientRun.captured.env.PROBE_APP_CALLBACK, "https://entra.example/app/callback");
    assert.equal(clientRun.captured.env.IDP_TEST_USER_PASSWORD, ENTRA.test_user_password);
    for (const key of ["ENTRA_CLIENT_SECRET", "ENTRA_TENANT_ID", "CF_ACCESS_AUDIENCE", "OAUTH_SIGNING_PRIVATE_JWK"]) {
      assert.equal(clientRun.captured.env[key], undefined, `${key} never reaches the client probe`);
    }
    const clientNoAudit = await runScript(["scripts/live/probe-client.mjs", "entra"]);
    assert.equal(clientNoAudit.captured.env.MCP_SSO_AUDIT_FILE, undefined, "the audit path is passed only when the caller names one");
    // The Cloudflare probe takes its assertion from the driver's result file
    // when one is named, and refuses a result that is not an approved sign-in.
    const approved = join(fixture, "approved.json");
    privateFile(approved, JSON.stringify({ task: "cloudflare-assertion", user: "member", outcome: "approved", assertion: JWT }));
    const withFile = await runScript(["scripts/live/probe-cloudflare.mjs", "cloudflare_access"], { MCP_SSO_CF_ACCESS_ASSERTION_FILE: approved });
    assert.equal(withFile.code, 0, withFile.stderr);
    assert.equal(withFile.captured.env.CF_ACCESS_ASSERTION, JWT);
    assert.equal(withFile.captured.env.MCP_SSO_CF_ACCESS_ASSERTION_FILE, undefined);
    const denied = join(fixture, "denied.json");
    privateFile(denied, JSON.stringify({ outcome: "denied_at_access_edge" }));
    const withDenied = await runScript(["scripts/live/probe-cloudflare.mjs", "cloudflare_access"], { MCP_SSO_CF_ACCESS_ASSERTION_FILE: denied });
    assert.equal(withDenied.code, 1);
    assert.equal(withDenied.captured, undefined, "the probe never starts without an approved assertion");
    assert.match(withDenied.stderr, /MCP_SSO_CF_ACCESS_ASSERTION_FILE is not an owner-only file holding one compact JWT/);
    const bin = join(fixture, "bin");
    mkdirSync(bin);
    executable(join(bin, "cloudflared"), "#!/usr/bin/env bash\nexit 1\n");
    const withoutFile = await runScript(["scripts/live/probe-cloudflare.mjs", "cloudflare_access"], { PATH: `${bin}:${process.env.PATH}` });
    assert.equal(withoutFile.code, 1);
    assert.match(withoutFile.stderr, /cloudflared could not mint an Access assertion/, "without a file the cloudflared path is the fallback");
    assert.doesNotMatch(withoutFile.stderr, /cf\.example/, "the operator hint names no private origin, so the refusal classifies BLOCKED and not as a leak");
    assert.equal(withoutFile.captured, undefined);
    const entraDriverRefused = await runScript(["scripts/live/drive-identity.mjs", "entra", "cloudflare-assertion", "--out", "/nowhere"]);
    assert.equal(entraDriverRefused.code, 1, "the driver has one task and it belongs to the Cloudflare leg");
    assert.match(entraDriverRefused.stderr, /unsupported entry\/leg pair/);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("BEHAVIOUR fetch-bundle: required secrets must exist, optional ones are recorded absent, files are private", async () => {
  const fixture = mkdtempSync(join(tmpdir(), "mcp-sso-fetch-"));
  try {
    const bin = join(fixture, "bin");
    mkdirSync(bin);
    const values = join(fixture, "values");
    mkdirSync(values);
    privateFile(join(values, "entra"), JSON.stringify(ENTRA));
    privateFile(join(values, "cloudflare"), JSON.stringify(CLOUDFLARE));
    privateFile(join(values, "google"), "GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=fixture-google-secret\n");
    // A stub aws: answers from files named after the secret, and reports the
    // documented ResourceNotFoundException for a container with no value.
    executable(join(bin, "aws"), `#!/usr/bin/env bash
[[ "$1 $2" == "secretsmanager get-secret-value" ]] || exit 2
name="\${4##*/}"
if [ -f "${values}/$name" ]; then cat "${values}/$name"; else echo "An error occurred (ResourceNotFoundException) when calling the GetSecretValue operation" >&2; exit 254; fi
`);
    const dir = join(fixture, "bundle");
    const githubEnv = join(fixture, "github.env");
    writeFileSync(githubEnv, "");
    const manifest = await fetchBundles({ dir, awsBin: join(bin, "aws"), githubEnv });
    assert.deepEqual(manifest, { entra: "present", cloudflare: "present", google: "present", "tunnel-credentials": "absent" });
    assert.equal(existsSync(join(dir, "browserbase.json")), false, "a credential no row consumes is never fetched");
    for (const file of ["entra.json", "cloudflare.json", "google.env"]) {
      assert.equal(readFileSync(join(dir, file), "utf8").length > 0, true);
      assert.equal(statSync(join(dir, file)).mode & 0o777, 0o600, `${file} is owner-only`);
    }
    assert.equal(existsSync(join(dir, "tunnel-credentials.json")), false);
    assert.match(readFileSync(githubEnv, "utf8"), /^MCP_SSO_GOOGLE_ENV=.*google\.env$/m, "the Google file is announced to later steps");
    await assert.rejects(fetchBundles({ dir, awsBin: join(bin, "aws") }), /already exists/, "a stale bundle is never reused");
    rmSync(join(values, "entra"));
    await assert.rejects(fetchBundles({ dir: join(fixture, "b2"), awsBin: join(bin, "aws") }), /required secret entra/);
    privateFile(join(values, "entra"), "not json");
    await assert.rejects(fetchBundles({ dir: join(fixture, "b3"), awsBin: join(bin, "aws") }), /not JSON/);
    privateFile(join(values, "entra"), JSON.stringify(ENTRA));
    privateFile(join(values, "google"), "export GOOGLE_CLIENT_ID=id\n");
    await assert.rejects(fetchBundles({ dir: join(fixture, "b4"), awsBin: join(bin, "aws") }), /google secret is not a valid/);
    assert.equal(existsSync(join(fixture, "b4/google.env")), false, "an invalid credential file does not stay on disk");
    privateFile(join(values, "google"), "GOOGLE_CLIENT_ID=id\nGOOGLE_CLIENT_SECRET=fixture-google-secret\n");
    privateFile(join(values, "tunnel-credentials"), JSON.stringify({ AccountTag: "a" }));
    await assert.rejects(fetchBundles({ dir: join(fixture, "b5"), awsBin: join(bin, "aws") }), /tunnel credentials are incomplete/);
    executable(join(bin, "aws"), "#!/usr/bin/env bash\necho 'An error occurred (AccessDeniedException)' >&2; exit 254\n");
    await assert.rejects(fetchBundles({ dir: join(fixture, "b7"), awsBin: join(bin, "aws") }), /could not be read/, "any other failure is not absence");
    const masks = maskLines(dir);
    assert.ok(masks.includes(`::add-mask::${ENTRA.entra_client_secret}`));
    assert.ok(masks.includes("::add-mask::fixture-google-secret"));
    assert.ok(masks.includes("::add-mask::entra.example"));
    assert.ok(!masks.some((line) => line === "::add-mask::mcp:read"), "short leaves are not masked");
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("BEHAVIOUR rehearsal-support: run.sh outcomes classify as PASS, FAIL, or an armable BLOCKED", () => {
  const pass = classifyRun({ code: 0, stderr: "", stdout: "PASS  a\nPASS  b\nCONTROL  c\n\n2 live checks passed; 1 local controls passed\n" });
  assert.deepEqual(pass, { status: "PASS", checks: { passed: 2, total: undefined, controls: 1 }, lines: [{ kind: "PASS", text: "a" }, { kind: "PASS", text: "b" }, { kind: "CONTROL", text: "c" }] });
  assert.equal(classifyRun({ code: 0, stderr: "", stdout: "PASS  a\n\n1/1 checks passed\n" }).status, "PASS");
  assert.equal(classifyRun({ code: 0, stderr: "", stdout: "PASS  a\n\n1/1 live checks passed\n" }).status, "PASS");
  assert.equal(classifyRun({ code: 0, stderr: "", stdout: "PASS  a\nFAIL  b\n\n1/2 checks passed\n" }).reason, "checks_failed");
  assert.equal(classifyRun({ code: 0, stderr: "", stdout: "PASS  a\n" }).reason, "no_summary", "a green exit without a summary is not a pass");
  assert.equal(classifyRun({ code: 0, stderr: "", stdout: "PASS  a\n\n2/2 checks passed\n" }).reason, "summary_mismatch", "the summary must match the lines");
  assert.equal(classifyRun({ code: 0, stderr: "", stdout: "PASS  a\n\n1/2 checks passed\n" }).reason, "summary_mismatch");
  assert.equal(classifyRun({ code: 0, stderr: "", stdout: "\n0/0 checks passed\n" }).reason, "no_summary", "zero checks is not evidence");
  assert.equal(classifyRun({ code: 0, stderr: "", stdout: "CONTROL  c\n\n0 live checks passed; 1 local controls passed\n" }).reason, "no_checks",
    "a control with no live check is not evidence in the two-count form either");
  assert.equal(classifyRun({ code: 1, stderr: "run.sh: cloudflared could not mint an Access assertion; run: cloudflared access login\n", stdout: "" }).reason, "cloudflare_access_login_required");
  assert.equal(classifyRun({ code: 1, stderr: "run.sh: Google credential file must be an owner-only KEY=VALUE file with the required keys\n", stdout: "" }).reason, "google_credentials_absent");
  assert.equal(classifyRun({ code: 1, stderr: "error: AWS session is not valid — run: aws sso login\n", stdout: "" }).reason, "infrastructure_session_expired");
  assert.equal(classifyRun({ code: 1, stderr: "run.sh: cloudflared could not mint an Access assertion\n", stdout: "FAIL  x\n" }).status, "FAIL", "a blocked reason after checks ran is a failure");
  assert.equal(classifyRun({ code: 1, stderr: "run.sh: REDIS_URL is required for probe-e2e.mjs\n", stdout: "" }).reason, "runner_refused");
  assert.equal(classifyRun({ code: 1, stderr: "", stdout: "PASS  a\nFAIL  probe aborted before completion\n\n1/2 checks passed\n" }).reason, "checks_failed");
  assert.deepEqual(ROWS.map((row) => row.id), [
    "release-matrix", "probe-entra", "probe-google", "access-login", "access-edge-denial", "probe-cloudflare", "probe-e2e:stored", "probe-e2e:stateless",
    "client-entra:member", "client-entra:nogroups", "client-entra:wronggroup", "client-entra:overage", "client-cloudflare:member",
    "client-entra:wrong-tenant", "client-entra:not-allowlisted",
  ]);
  assert.ok(ROWS.findIndex((row) => row.provides === "cloudflare-assertion") < ROWS.findIndex((row) => row.needs === "cloudflare-assertion"),
    "the assertion is produced before the probe that needs it");
  assert.equal(classifyDriverRun({ code: 0, stdout: "outcome: approved\n", stderr: "", expect: "approved" }).status, "PASS");
  assert.equal(classifyDriverRun({ code: 0, stdout: "outcome: denied_at_access_edge\n", stderr: "", expect: "denied_at_access_edge" }).status, "PASS");
  const wrongWay = classifyDriverRun({ code: 0, stdout: "outcome: approved\n", stderr: "", expect: "denied_at_access_edge" });
  assert.equal(wrongWay.status, "FAIL", "an admitted account that should have been denied is a failure, not a pass");
  assert.equal(wrongWay.reason, "outcome_approved");
  const atLogin = classifyDriverRun({ code: 0, stdout: "outcome: denied_at_login\n", stderr: "", expect: "denied_at_access_edge" });
  assert.equal(atLogin.reason, "outcome_denied_at_login", "a broken test account is never proof that the edge stopped it");
  assert.equal(classifyDriverRun({ code: 0, stdout: "outcome: denied_at_access_edge\n", stderr: "", expect: "approved" }).reason, "outcome_denied_at_access_edge");
  assert.equal(classifyDriverRun({ code: 2, stdout: "outcome: approved\n", stderr: "", expect: "approved" }).reason, "driver_exit_mismatch", "a driver that died after printing a definite outcome is not a pass");
  assert.equal(classifyDriverRun({ code: 0, stdout: "outcome: browser_unavailable\n", stderr: "", expect: "approved" }).reason, "driver_exit_mismatch", "an indefinite outcome with a clean exit is not a block either");
  assert.equal(classifyDriverRun({ code: 2, stdout: "outcome: browser_unavailable\n", stderr: "", expect: "approved" }).status, "BLOCKED");
  assert.equal(classifyDriverRun({ code: 2, stdout: "outcome: driver_error\n", stderr: "", expect: "approved" }).reason, "outcome_driver_error");
  assert.equal(classifyDriverRun({ code: 0, stdout: "outcome: approved\noutcome: denied_at_login\n", stderr: "", expect: "approved" }).reason, "outcome_denied_at_login", "the last outcome line decides");
  assert.equal(classifyDriverRun({ code: 2, stdout: "outcome: blocked_mfa_interstitial\n", stderr: "", expect: "approved" }).reason, "blocked_mfa_interstitial");
  assert.equal(classifyDriverRun({ code: 2, stdout: "outcome: unexpected_host\n", stderr: "", expect: "approved" }).status, "FAIL");
  assert.equal(classifyDriverRun({ code: 2, stdout: "outcome: timeout\n", stderr: "", expect: "approved" }).status, "FAIL");
  assert.equal(classifyDriverRun({ code: 1, stdout: "", stderr: "error: AWS session is not valid\n", expect: "approved" }).status, "BLOCKED");
  assert.equal(classifyDriverRun({ code: 1, stdout: "", stderr: "run.sh: test_users output is invalid\n", expect: "approved" }).reason, "runner_refused");
  assert.equal(classifyDriverRun({ code: 0, stdout: "outcome: approved\noutcome: approved\n", stderr: "", expect: "approved" }).status, "PASS");
  assert.equal(classifyDriverRun({ code: 1, stdout: "", stderr: "probe-client: browser is unavailable; install Chrome\n", expect: "approved" }).reason, "browser_unavailable");
  const rows = [
    { id: "probe-entra", entry: "e", leg: "entra", status: "PASS", checks: { passed: 2, controls: 1 }, durationMs: 10, lines: [] },
    { id: "probe-cloudflare", entry: "c", leg: "cloudflare_access", status: "BLOCKED", reason: "cloudflare_access_login_required", durationMs: 1, lines: [] },
  ];
  const receipt = buildReceipt({ runtimeCommit: "abc", dirty: false, startedAt: "s", finishedAt: "f", rows, runner: "local", totalRows: 2 });
  assert.equal(receipt.evidence, false, "a blocked row is never evidence");
  assert.equal(receipt.complete, true);
  assert.equal(buildReceipt({ runtimeCommit: "abc", dirty: false, startedAt: "s", finishedAt: "f", rows: [rows[0]], runner: "local", totalRows: 1 }).evidence, true);
  assert.equal(buildReceipt({ runtimeCommit: "abc", dirty: true, startedAt: "s", finishedAt: "f", rows: [rows[0]], runner: "local", totalRows: 1 }).evidence, false, "a dirty tree is never evidence");
  const partial = buildReceipt({ runtimeCommit: "abc", dirty: false, startedAt: "s", finishedAt: "f", rows: [rows[0]], runner: "local", totalRows: 2 });
  assert.equal(partial.complete, false);
  assert.equal(partial.evidence, false, "a subset is never evidence");
  assert.equal(buildReceipt({ runtimeCommit: "abc", dirty: false, startedAt: "s", finishedAt: "f", rows: [], runner: "local", totalRows: 0 }).evidence, false, "no rows is not evidence");
  assert.equal(buildReceipt({ runtimeCommit: "abc", dirty: false, startedAt: "s", finishedAt: "f", rows: [rows[0]], runner: "local" }).complete, false, "the default total is the full row list");
  assert.match(formatSummary(partial), /PARTIAL, not evidence/);
  const summary = formatSummary(receipt);
  assert.match(summary, /^PASS {4}probe-entra \(2 checks, 1 controls\)$/m);
  assert.match(summary, /^BLOCKED probe-cloudflare \[cloudflare_access_login_required\]$/m);
  assert.match(summary, /1 passed, 0 failed, 1 blocked; evidence=false/);
});

test("BEHAVIOUR rehearsal.mjs: rows run through run.sh, a leaked private value fails the row, and the exit code follows evidence", async () => {
  const fixture = mkdtempSync(join(tmpdir(), "mcp-sso-rehearsal-"));
  try {
    const repo = join(fixture, "repo");
    mkdirSync(join(repo, "scripts/live/ci"), { recursive: true });
    for (const file of ["rehearsal.mjs", "rehearsal-support.mjs", "run-support.mjs", "ci/bundle-support.mjs"]) {
      copyFileSync(join(ROOT, "scripts/live", file), join(repo, "scripts/live", file));
    }
    symlinkSync(join(ROOT, "src"), join(repo, "src"));
    symlinkSync(join(ROOT, "examples"), join(repo, "examples"));
    symlinkSync(join(ROOT, "node_modules"), join(repo, "node_modules"));
    // A fixture run.sh: each entry/leg pair replays a scripted outcome. The
    // driver fixture writes its result file exactly as the real driver does,
    // and the Cloudflare probe fixture reports whether the handoff reached it.
    executable(join(repo, "scripts/live/run.sh"), `#!/usr/bin/env bash
case "$1:\${MCP_SSO_DCR_MODE-}:\${5-}" in
  scripts/live/probe-entra.mjs::) printf 'PASS  a\\nCONTROL  c\\n\\n1 live checks passed; 1 local controls passed\\n' ;;
  scripts/live/probe-google.mjs::) echo "run.sh: Google credential file must be an owner-only KEY=VALUE file" >&2; exit 1 ;;
  scripts/live/drive-identity.mjs::member) if [ -n "\${FAKE_DRIVER_OUTCOME-}" ]; then printf '{"outcome":"%s","trace":["step:error"]}\\n' "$FAKE_DRIVER_OUTCOME" > "$7"; chmod 600 "$7"; echo "outcome: $FAKE_DRIVER_OUTCOME"; exit 2; fi; printf '{"outcome":"approved","assertion":"${JWT}","trace":["access:start","microsoft:password:typed","leg:elsewhere"]}\\n' > "$7"; chmod 600 "$7"; echo "outcome: approved" ;;
  scripts/live/drive-identity.mjs::nogroups) printf '{"outcome":"denied_at_access_edge","trace":["access:start","microsoft:password:typed","access:denied"]}\\n' > "$7"; chmod 600 "$7"; echo "outcome: denied_at_access_edge" ;;
  scripts/live/probe-cloudflare.mjs::) printf 'PASS  assertion file \${MCP_SSO_CF_ACCESS_ASSERTION_FILE:+present}\\nPASS  leaked ${ENTRA.entra_client_secret}\\n\\n2/2 checks passed\\n'; echo "$MCP_SSO_CF_ACCESS_ASSERTION_FILE" > "\${TMPDIR:-/tmp}/handoff-path" ;;
  scripts/live/probe-e2e.mjs:stored:) printf 'PASS  a\\n\\n1/1 checks passed\\n' ;;
  scripts/live/probe-e2e.mjs:stateless:) printf 'PASS  a\\nFAIL  b\\n\\n1/2 checks passed\\n'; exit 1 ;;
  *) exit 9 ;;
esac
`);
    const git = (...args) => execFileSync("git", ["-C", repo, "-c", "user.name=f", "-c", "user.email=f@example.test", ...args], { stdio: "ignore" });
    git("init", "-q"); git("add", "-A"); git("commit", "-q", "-m", "fixture");
    const dir = bundleDir();
    const out = join(fixture, "receipt.json");
    const tmp = join(fixture, "tmp");
    mkdirSync(tmp);
    const run = (args, extraEnv = {}) => spawnSync(process.execPath, [join(repo, "scripts/live/rehearsal.mjs"), "--out", out, ...args], {
      env: { PATH: process.env.PATH, HOME: fixture, TMPDIR: tmp, MCP_SSO_BUNDLE_DIR: dir, ...extraEnv }, encoding: "utf8", cwd: repo,
    });
    // A stub pnpm stands in for the release matrix and records the environment
    // the command row hands it.
    const cmdBin = join(fixture, "cmdbin");
    mkdirSync(cmdBin);
    executable(join(cmdBin, "pnpm"), `#!/usr/bin/env bash
node -e 'require("fs").writeFileSync(process.env.TMPDIR + "/command-env.json", JSON.stringify(process.env))'
printf 'PASS RM.1 a (1 evidence item)\\n\\nPASS release matrix: 1/1 required rows\\n'
`);
    const full = run([], {
      PATH: `${cmdBin}:${process.env.PATH}`, AWS_SECRET_ACCESS_KEY: "fixture-aws-secret", MCP_SSO_ENTRA_STACK: "entra",
      RUN_INTEGRATION: "true", MYSQL_URL: "mysql://x", REDIS_URL: "redis://y", PNPM_HOME: "/pnpm/home", npm_config_cache: "/npm/cache",
    });
    assert.equal(full.status, 1, full.stdout + full.stderr);
    const receipt = JSON.parse(readFileSync(out, "utf8"));
    assert.equal(receipt.kind, "mcp-sso-release-rehearsal");
    assert.match(receipt.runtimeCommit, /^[0-9a-f]{40}$/);
    assert.equal(receipt.dirty, false);
    assert.equal(receipt.complete, true, "every row in the list ran");
    assert.equal(receipt.evidence, false);
    const byId = Object.fromEntries(receipt.rows.map((row) => [row.id, row]));
    assert.equal(byId["release-matrix"].status, "PASS");
    const commandEnv = JSON.parse(readFileSync(join(tmp, "command-env.json"), "utf8"));
    assert.equal(commandEnv.AWS_SECRET_ACCESS_KEY, undefined, "the release matrix never holds the AWS session");
    assert.equal(commandEnv.MCP_SSO_BUNDLE_DIR, undefined, "nor the bundle location");
    assert.equal(commandEnv.MCP_SSO_ENTRA_STACK, undefined, "nor any run configuration");
    assert.equal(commandEnv.MYSQL_URL, "mysql://x");
    assert.equal(commandEnv.PNPM_HOME, "/pnpm/home", "the package manager's own configuration is kept");
    assert.equal(commandEnv.npm_config_cache, "/npm/cache");
    assert.equal(byId["probe-entra"].status, "PASS");
    assert.deepEqual(byId["probe-entra"].checks, { passed: 1, controls: 1 });
    assert.equal(byId["probe-google"].status, "BLOCKED");
    assert.equal(byId["probe-google"].reason, "google_credentials_absent");
    assert.equal(byId["access-login"].status, "PASS");
    assert.equal(byId["access-login"].outcome, "approved");
    assert.ok(byId["access-login"].lines.some((line) => line.kind === "NOTE" && line.text.startsWith("trace ")), "the trace is recorded on a passing driver row");
    assert.equal(byId["access-edge-denial"].status, "PASS");
    assert.equal(byId["access-edge-denial"].outcome, "denied_at_access_edge");
    assert.equal(byId["probe-cloudflare"].status, "FAIL");
    assert.equal(byId["probe-cloudflare"].reason, "private_value_in_output");
    assert.ok(receipt.rows.filter((row) => row.kind === "client").every((row) => row.status === "FAIL" && row.reason === "serve_failed"), "client rows without an infrastructure wrapper cannot be served");
    const handoffPath = readFileSync(join(tmp, "handoff-path"), "utf8").trim();
    assert.match(handoffPath, /mcp-sso-rehearsal-.*access-login\.json$/, "the probe received the driver's result file");
    assert.equal(existsSync(handoffPath), false, "the handoff directory is removed when the run ends");
    assert.equal(readdirSync(tmp).filter((name) => name.startsWith("mcp-sso-rehearsal-")).length, 0);
    assert.equal(byId["probe-e2e:stored"].status, "PASS");
    assert.equal(byId["probe-e2e:stored"].mode, "stored");
    assert.equal(byId["probe-e2e:stateless"].status, "FAIL");
    assert.equal(byId["probe-e2e:stateless"].reason, "checks_failed");
    const everything = `${full.stdout}\n${full.stderr}\n${readFileSync(out, "utf8")}`;
    assert.doesNotMatch(everything, new RegExp(ENTRA.entra_client_secret), "a leaked value reaches neither the log nor the receipt");
    assert.doesNotMatch(everything, new RegExp(JWT), "the captured assertion reaches neither the log nor the receipt");
    assert.match(full.stdout, /^BLOCKED probe-google \[google_credentials_absent\]/m);
    const subset = run(["--rows", "probe-entra,access-login,access-edge-denial,probe-e2e:stored"]);
    assert.equal(subset.status, 1, "a subset is a working run, never a green one");
    const subsetReceipt = JSON.parse(readFileSync(out, "utf8"));
    assert.equal(subsetReceipt.complete, false);
    assert.equal(subsetReceipt.evidence, false);
    assert.ok(subsetReceipt.rows.every((row) => row.status === "PASS"));
    assert.match(subset.stdout, /PARTIAL, not evidence/);
    rmSync(join(tmp, "handoff-path"), { force: true });
    const noHandoff = run(["--rows", "probe-cloudflare"]);
    assert.equal(noHandoff.status, 1);
    assert.equal(readFileSync(join(tmp, "handoff-path"), "utf8").trim(), "", "without the login row selected the probe falls back to the operator's login");
    rmSync(join(tmp, "handoff-path"), { force: true });
    const failedLogin = run(["--rows", "access-login,probe-cloudflare"], { FAKE_DRIVER_OUTCOME: "timeout" });
    assert.equal(failedLogin.status, 1);
    const failedReceipt = Object.fromEntries(JSON.parse(readFileSync(out, "utf8")).rows.map((row) => [row.id, row]));
    assert.equal(failedReceipt["access-login"].reason, "outcome_timeout");
    assert.equal(failedReceipt["probe-cloudflare"].status, "BLOCKED");
    assert.equal(failedReceipt["probe-cloudflare"].reason, "prerequisite_row_did_not_pass");
    assert.equal(existsSync(join(tmp, "handoff-path")), false, "the probe did not run on an operator credential after the driver failed");
    writeFileSync(join(repo, "scripts/live/rehearsal-support.mjs"), "// dirty\n", { flag: "a" });
    const dirty = run(["--rows", "probe-entra"]);
    assert.equal(dirty.status, 1, "a dirty tree is never green");
    assert.equal(JSON.parse(readFileSync(out, "utf8")).dirty, true);
    assert.equal(run(["--rows", "nope"]).status, 1);
    rmSync(dir, { recursive: true, force: true });
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
