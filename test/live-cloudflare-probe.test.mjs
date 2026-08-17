import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const PROBE = readFileSync(join(ROOT, "scripts/live/probe-cloudflare.mjs"), "utf8");

test("Cloudflare identity negatives reach verification after a valid client control", () => {
  const registerAt = PROBE.indexOf("identity-negative fixture registers a valid client");
  const forgedAt = PROBE.indexOf("const forgedRes");
  assert.ok(registerAt >= 0 && registerAt < forgedAt);
  assert.match(PROBE, /client_id: identityClientId \?\? "fixture-registration-failed"/);
  assert.match(PROBE, /const forgedRes[\s\S]*?url: `\/oauth\/authorize\?\$\{identityQuery\}`/);
  assert.match(PROBE, /forgedRes\.statusCode === 401/);
});

test("Cloudflare state evidence uses the resolved directory and is platform honest", () => {
  assert.match(PROBE, /statSync\(built\.dir\)/);
  assert.doesNotMatch(PROBE, /statSync\(process\.env\.MCP_SSO_DIR\)/);
  const windowsAt = PROBE.indexOf('process.platform === "win32"');
  const statAt = PROBE.indexOf("statSync(built.dir)");
  assert.ok(windowsAt >= 0 && windowsAt < statAt);
  assert.match(PROBE, /INFO  state-directory POSIX mode is not applicable on Windows/);
  assert.match(PROBE, /informational and is deliberately excluded from the evidence count/);
});
