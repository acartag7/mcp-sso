// Disposable state for one live probe run, shared by every probe.
//
// The example's production branches call ensureStateDir(MCP_SSO_DIR), which
// creates the directory 0700 itself and refuses a PRE-EXISTING directory that
// lacks its managed `.gitignore` (quickstart.ts). A probe that hands the
// mkdtemp root straight in as MCP_SSO_DIR therefore never boots — every run
// ends in "probe aborted before completion" — so the root here is only the
// disposable container and the state directory is a not-yet-existing child
// the library creates. OAUTH_SQLITE_FILE is pinned inside it explicitly: a
// stale value inherited from the shell would otherwise point the probe at a
// deployment's own database, the mutation this isolation exists to prevent.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export async function createDisposableProbeState(prefix) {
  const root = await mkdtemp(join(tmpdir(), prefix));
  const stateDir = join(root, "state");
  return {
    root,
    env: { MCP_SSO_DIR: stateDir, OAUTH_SQLITE_FILE: join(stateDir, "auth.db") },
    async dispose() {
      await rm(root, { recursive: true, force: true });
    },
  };
}
