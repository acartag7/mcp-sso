// The aggregate state-dir setup helper a consumer applies when it manages its OWN state
// dir (the Cloudflare/Entra/gateway path that does NOT use loadOrCreateQuickstartSecrets).
// Promoted from the in-repo example so package consumers get the SAME setup the
// examples do, instead of reimplementing it (contracts §15 DX).

import { chmod, mkdir } from "node:fs/promises";
import { assertRealDir, ensureGitignore } from "./quickstart.ts";
import { warnWindowsPermissionGap } from "./windows-permission-warning.ts";

/** Ensure the state dir exists AND meets the platform-applicable per-directory
 *  fs-trust bar — the same bar the zero-setup branch gets from
 *  `loadOrCreateQuickstartSecrets`. Creates the dir `0o700` if absent; for a
 *  pre-existing dir, `assertRealDir` rejects a symlink everywhere and a
 *  group/other-accessible mode on POSIX. Windows emits the shared warning and
 *  relies on the deployer-private ACL. Then `ensureGitignore` writes the managed `*`
 *  `.gitignore` so auth.db / audit.jsonl cannot be committed.
 *
 *  POSIX boundary: the dir is CREATED restrictive (mkdir mode `0o700` — atomic,
 *  with no world-writable race window between create and chmod; the retained chmod
 *  enforces the mode). On Windows, Node's mode is not DACL enforcement; creation
 *  inherits the parent ACL and the deployer-private ACL remains the boundary.
 *  This polices the state dir's OWN POSIX mode + symlink-ness + .gitignore, NOT any
 *  pre-existing ancestors — the deployer must place the state dir under a trusted
 *  parent (as with any secret store), since a group/other-writable, non-sticky parent
 *  that pre-dates this call would let another local user rename/replace the state dir
 *  after it returns. (Same scope `loadOrCreateQuickstartSecrets` has; both create
 *  atomically restrictive directories on POSIX.)
 *
 *  This aggregate helper — not the raw `ensureGitignore(dir, canCreate)` — is the
 *  public surface, because it DERIVES whether creating the `.gitignore` is safe from
 *  `mkdir`'s return (only a dir we just made). The raw boolean would let a caller
 *  pass `canCreate=true` for a pre-existing tree and drop a `*` ignore that hides the
 *  whole repo — the exact outcome the internal protocol prevents. Fail-safe by
 *  construction (contracts §15 DX). */
export async function ensureStateDir(dir: string): Promise<void> {
  // Third storage path in §17.8's four-call parity rule (which also includes the
  // standalone assertRealDir export): this helper skips the POSIX mode gate on win32
  // (both the chmod below and assertRealDir's mode check) and inspects no DACL.
  // A consumer using this path with external database state would otherwise
  // reach neither of the other two warnings and be silently unprotected.
  warnWindowsPermissionGap();
  // Atomic restrictive creation on POSIX; Windows inherits the private parent ACL.
  const created = await mkdir(dir, { recursive: true, mode: 0o700 });
  if (created !== undefined) {
    if (process.platform !== "win32") await chmod(dir, 0o700);
  } else {
    await assertRealDir(dir); // real/non-symlink; group/other mode is POSIX-only, Windows warns
  }
  await ensureGitignore(dir, created !== undefined);
}
