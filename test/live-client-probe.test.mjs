// Behavioural coverage for the client probe's decisions (scripts/live/
// probe-client-support.mjs), the serve-generation grouping, and the CI tunnel
// credential installer. The probe's browser and network halves are exercised
// only by a live run; everything they decide on is here.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  EXPECTATIONS, approvedFlowOrder, auditLeaks, deniedFlowHolds, eventsSince, expectedDescription, inOrder, parseClientArgs,
} from "../scripts/live/probe-client-support.mjs";
import { ROWS, classifyServeFailure, generations } from "../scripts/live/rehearsal-support.mjs";
import { installTunnelCredentials } from "../scripts/live/ci/install-tunnel.mjs";

const event = (name, status, extra = {}) => ({ occurredAt: "t", event: name, status, ...extra });

test("BEHAVIOUR client args: a provisioned role and one of the documented expectations", () => {
  assert.deepEqual(parseClientArgs([]), { user: "member", expect: "approved" });
  assert.deepEqual(parseClientArgs(["--user", "nogroups", "--expect", "entra_no_groups"]), { user: "nogroups", expect: "entra_no_groups" });
  for (const argv of [["--user"], ["--user", "No Groups"], ["--expect", "entra_no_grouups"], ["--expect", "approved", "--extra"], ["--url", "x"]]) {
    assert.throws(() => parseClientArgs(argv), argv.join(" "));
  }
  assert.ok(EXPECTATIONS.includes("entra_bad_tid") && EXPECTATIONS.includes("entra_subject_not_allowed"));
});

test("BEHAVIOUR client expectations: descriptions come from the shipped mapping, never a copy", () => {
  assert.equal(expectedDescription("entra_no_groups"), "Entra returned no groups for this account");
  assert.equal(expectedDescription("entra_no_mapped_groups"), "Entra groups do not authorize this account for this resource");
  assert.equal(expectedDescription("entra_groups_overage"), "Entra group claims exceed the supported limit; operator configuration is required");
  assert.equal(expectedDescription("entra_bad_tid"), "upstream identity verification failed", "the anti-oracle default for a tenant mismatch");
  assert.equal(expectedDescription("entra_subject_not_allowed"), "upstream identity verification failed");
});

test("BEHAVIOUR client audit assertions: only the events one flow added, in order, with nothing minted on a denial", () => {
  const text = '{"event":"a","status":"success"}\n{"event":"b","status":"success"}\n\n{"event":"c","status":"failure"}\n';
  assert.deepEqual(eventsSince(text, 1).map((e) => e.event), ["b", "c"]);
  assert.deepEqual(eventsSince("", 0), []);
  assert.throws(() => eventsSince("not json\n", 0), "a malformed line is a failure, not a skip");
  // The sequence a served Entra leg really records (identity before prepare,
  // the callback's success after it), with a bystander event in the middle.
  const approved = [
    event("oauth.register", "success"), event("identity.verify", "success"), event("auth.request", "failure"),
    event("oauth.authorize.prepare", "success"), event("oauth.upstream.callback", "success"), event("oauth.authorize.approve", "success"),
    event("oauth.token.authorization_code", "success"), event("auth.request", "success"), event("oauth.token.refresh", "success"),
  ];
  assert.equal(inOrder(approved, approvedFlowOrder("entra")), true, "unrelated events between the named ones are allowed");
  assert.equal(inOrder(approved, approvedFlowOrder("cloudflare_access")), true, "a header leg needs no upstream callback");
  const swapped = [approved[1], approved[0], ...approved.slice(2)];
  assert.equal(inOrder(swapped, approvedFlowOrder("entra")), false, "registration precedes identity");
  assert.equal(inOrder(approved.filter((e) => e.event !== "oauth.upstream.callback"), approvedFlowOrder("entra")), false, "a redirect leg must record the callback");
  assert.equal(inOrder([...approved].reverse(), approvedFlowOrder("entra")), false, "order matters");
  assert.equal(inOrder(approved.filter((e) => e.event !== "oauth.token.refresh"), approvedFlowOrder("entra")), false);
  const denied = [
    event("oauth.register", "success"), event("oauth.authorize.prepare", "success"),
    event("identity.verify", "failure", { reason: "entra_no_groups" }), event("oauth.upstream.callback", "failure", { reason: "identity_rejected" }),
  ];
  assert.equal(deniedFlowHolds(denied, "entra_no_groups"), true);
  assert.equal(deniedFlowHolds(denied, "entra_no_mapped_groups"), false, "the exact reason, not any denial");
  assert.equal(deniedFlowHolds([...denied, event("oauth.token.authorization_code", "success")], "entra_no_groups"), false, "a denial that minted is a failure");
  assert.equal(deniedFlowHolds(denied.slice(0, 3), "entra_no_groups"), false, "the callback must record identity_rejected");
  assert.equal(auditLeaks("… code=abc …", ["abc"]), true);
  assert.equal(auditLeaks("clean", ["abc"]), false);
  assert.equal(auditLeaks("clean", [undefined]), true, "a missing secret fails closed");
});

test("BEHAVIOUR serve generations: consecutive rows sharing a generation run in one serve.sh lifetime", () => {
  const groups = generations(ROWS);
  const served = groups.filter((group) => group.serve !== undefined);
  assert.equal(served.length, 3, "one main generation and one per deny channel");
  assert.deepEqual(served[0].rows.map((row) => row.id), [
    "client-entra:member", "client-entra:nogroups", "client-entra:wronggroup", "client-entra:overage", "client-cloudflare:member",
  ]);
  assert.deepEqual(served[0].serve.legs, ["cloudflare_access", "entra"]);
  assert.deepEqual(Object.keys(served[1].serve.env), ["MCP_SSO_ENTRA_ALLOWED_TENANT_IDS"]);
  assert.deepEqual(Object.keys(served[2].serve.env), ["MCP_SSO_ENTRA_SUBJECT_ALLOWLIST"]);
  assert.equal(served[1].rows[0].args.includes("entra_bad_tid"), true);
  assert.equal(served[2].rows[0].args.includes("entra_subject_not_allowed"), true);
  assert.ok(groups.filter((group) => group.serve === undefined).every((group) => group.rows.length === 1), "standalone rows stand alone");
  assert.equal(classifyServeFailure("serve.sh: tunnel credentials file is missing for the given tunnel UUID").reason, "tunnel_credentials_absent");
  assert.equal(classifyServeFailure("serve.sh: cloudflared is required on PATH").reason, "cloudflared_unavailable");
  assert.deepEqual(classifyServeFailure("example server for leg entra failed readiness"), { status: "FAIL", reason: "serve_failed" });
});

test("BEHAVIOUR install-tunnel: the connector file lands owner-only under HOME, or is reported absent", () => {
  const fixture = mkdtempSync(join(tmpdir(), "mcp-sso-tunnel-"));
  try {
    const bundleDir = join(fixture, "bundle");
    const home = join(fixture, "home");
    mkdirSync(bundleDir, { mode: 0o700 });
    mkdirSync(home, { mode: 0o700 });
    assert.deepEqual(installTunnelCredentials({ bundleDir, home }), { installed: false });
    const id = "0f0f0f0f-1111-2222-3333-444444444444";
    const write = (value) => { const p = join(bundleDir, "tunnel-credentials.json"); writeFileSync(p, JSON.stringify(value), { mode: 0o600 }); chmodSync(p, 0o600); };
    write({ AccountTag: "a", TunnelSecret: "s", TunnelID: id });
    assert.deepEqual(installTunnelCredentials({ bundleDir, home }), { installed: true, tunnelId: id });
    const target = join(home, ".cloudflared", `${id}.json`);
    assert.equal(JSON.parse(readFileSync(target, "utf8")).TunnelID, id);
    assert.equal(statSync(target).mode & 0o777, 0o600);
    assert.throws(() => installTunnelCredentials({ bundleDir, home }), /EEXIST|exists/, "never overwrites an existing connector file");
    rmSync(target);
    write({ AccountTag: "a", TunnelSecret: "s", TunnelID: "not-a-uuid" });
    assert.throws(() => installTunnelCredentials({ bundleDir, home }), /name no tunnel/);
    assert.equal(existsSync(join(home, ".cloudflared", "not-a-uuid.json")), false);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
