// Behavioural coverage for the shared disposable-state helper every live probe
// boots from. The per-probe rows only assert that each probe CALLS the helper
// before buildExample; this file proves the helper hands the example a state
// directory the library will actually accept.
import assert from "node:assert/strict";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { ensureStateDir } from "../src/state-dir.ts";
import { createDisposableProbeState } from "../scripts/live/probe-state-support.mjs";

test("probe state: the disposable state dir is one the library can create", async () => {
  // The defect this pins: pointing MCP_SSO_DIR at the mkdtemp root itself makes
  // ensureStateDir refuse to boot (an existing dir without its managed
  // .gitignore), so every probe aborted before completion.
  const disposable = await createDisposableProbeState("mcp-sso-live-test-");
  try {
    assert.equal(existsSync(disposable.env.MCP_SSO_DIR), false, "the state dir must not pre-exist");
    assert.equal(disposable.env.OAUTH_SQLITE_FILE, join(disposable.env.MCP_SSO_DIR, "auth.db"));
    await ensureStateDir(disposable.env.MCP_SSO_DIR);
    assert.equal(readFileSync(join(disposable.env.MCP_SSO_DIR, ".gitignore"), "utf8").trim(), "*");
    if (process.platform !== "win32") assert.equal(statSync(disposable.env.MCP_SSO_DIR).mode & 0o777, 0o700);
    await assert.rejects(ensureStateDir(disposable.root), /quickstart/, "the mkdtemp root itself is refused — the old shape");
  } finally {
    await disposable.dispose();
  }
  assert.equal(existsSync(disposable.root), false, "dispose removes the whole container");
});
