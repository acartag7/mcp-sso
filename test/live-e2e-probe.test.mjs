// Behavioural coverage for scripts/live/probe-e2e.mjs: the probe is SPAWNED,
// with the environment run.sh assembles, and its rows are asserted. The
// content guards in test/live-evidence-scripts.test.mjs only prove what is
// written; this proves what runs. The positive leg needs a Redis, so it is
// gated on REDIS_URL exactly like test/rate-limit-redis.test.ts and hard-fails
// when RUN_INTEGRATION is set without one; the negative leg (an unreachable
// Redis) always runs.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const RUN_INTEGRATION = process.env.RUN_INTEGRATION === "true";
const REDIS_URL = process.env.REDIS_URL;

if (RUN_INTEGRATION && !REDIS_URL) {
  throw new Error("REDIS_URL is required when RUN_INTEGRATION is set — probe-e2e.mjs must be exercised.");
}

function runProbe(redisUrl, secret, dcrMode = "stored") {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["scripts/live/probe-e2e.mjs"], {
      cwd: ROOT,
      env: {
        PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: process.env.TMPDIR ?? "/tmp",
        OAUTH_ISSUER: "https://mcp.example", OAUTH_CONSENT_SIGNING_SECRET: secret, REDIS_URL: redisUrl,
        OAUTH_DCR_MODE: dcrMode,
        PROBE_APP_CALLBACK: "https://mcp.example/app/callback", OAUTH_REDIRECT_ALLOWLIST: "https://mcp.example/app/callback",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("probe-e2e did not exit")); }, 60_000);
    child.once("error", reject);
    child.once("exit", (code) => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}

test("probe-e2e: an unreachable Redis is a FAIL row and an abort, never a pass and never a printed address", async () => {
  const secret = randomBytes(24).toString("base64url");
  const result = await runProbe("redis://127.0.0.1:1", secret);
  assert.equal(result.code, 1);
  assert.match(result.stdout, /^FAIL  Redis limiter backend reachable$/m);
  assert.match(result.stdout, /^FAIL  probe aborted before completion$/m);
  assert.doesNotMatch(result.stdout, /^PASS/m, "nothing passes when the limiter backend is unreachable");
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /127\.0\.0\.1:1\b|ECONNREFUSED/, "the address is not echoed by the probe or by ioredis");
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, new RegExp(secret));
});

test("RM.18 probe-e2e runs both DCR modes and live identity completion without leaking credentials", { skip: REDIS_URL ? false : "REDIS_URL not set (CI hard-fails via RUN_INTEGRATION)" }, async () => {
  for (const dcrMode of ["stored", "stateless"]) {
    const secret = randomBytes(24).toString("base64url");
    const result = await runProbe(REDIS_URL, secret, dcrMode);
    assert.equal(result.code, 0, `${dcrMode}\n${result.stdout}\n${result.stderr}`);
    assert.doesNotMatch(result.stdout, /^FAIL/m, result.stdout);
    assert.match(result.stdout, /^(\d+)\/\1 checks passed$/m, "every row must pass");
    for (const row of [
      "probe composition uses the selected DCR mode",
      "selected DCR mode applies its documented unknown-client policy",
      "official SDK client completes a tool call with the user token",
      "claims-only completion delivers verified claims and the host response through all adapters",
      "claims-only completion preserves both Set-Cookie fields through all adapters",
      "claims-only completion produces no consent HTML or MCP token",
      "claims-only completion failure is consumed, cleared, fixed, audited, and redacted",
      "claims-only completion charges only website-login keys",
      "replaying a consumed refresh token is refused and revokes its whole family",
      "/oauth/revoke answers 200 and the revoked refresh token is refused as invalid_grant",
      "Redis limiter admits exactly the remaining window budget and refuses past it",
      "JSONL and webhook sinks received the same ordered events",
      "the audit sinks contain exactly the events this run caused, in order",
      "audit sinks never published the consent signing credential",
    ]) {
      assert.match(result.stdout, new RegExp(`^PASS  ${row.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}`, "m"), `${dcrMode}: ${row}`);
    }
    if (dcrMode === "stored") {
      for (const row of [
        "DCR registers a client into the shipped SQLite store",
        "official SDK client completes a tool call with the machine token",
        "a disabled credential is refused as invalid_client",
        "audit sinks never published the rejected machine client secret",
      ]) {
        assert.match(result.stdout, new RegExp(`^PASS  ${row.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}`, "m"), row);
      }
    } else {
      assert.match(result.stdout, /^PASS  DCR returns an opaque client without a registration store(?: —|$)/m);
      assert.doesNotMatch(result.stdout, /machine credential|machine token|rejected machine client secret/,
        "stateless evidence must not claim the incompatible machine-client leg");
    }
    assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, new RegExp(secret), "the consent signing credential never reaches the output");
    assert.doesNotMatch(result.stdout, /mcs_[A-Za-z0-9_-]{43}|eyJ[A-Za-z0-9_-]{20,}/, "no minted secret or token in the output");
  }
});
