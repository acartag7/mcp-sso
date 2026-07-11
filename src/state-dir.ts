// The atomic state-dir setup helper a consumer applies when it manages its OWN state
// dir (the Cloudflare/Entra/gateway path that does NOT use loadOrCreateQuickstartSecrets).
// Promoted from the in-repo example so package consumers get the SAME setup the
// examples do, instead of reimplementing it (contracts §15 DX).

import { chmod, mkdir } from "node:fs/promises";
import { assertRealDir, ensureGitignore } from "./quickstart.ts";

/** Ensure the state dir exists AND meets the per-directory fs-trust bar — the same
 *  bar the zero-setup branch gets from `loadOrCreateQuickstartSecrets`. Creates the
 *  dir `0o700` if absent; for a pre-existing dir, `assertRealDir` rejects a symlink or
 *  group/other-accessible mode (another local user could otherwise replace auth.db
 *  with state they control). Then `ensureGitignore` writes the managed `*`
 *  `.gitignore` so auth.db / audit.jsonl cannot be committed.
 *
 *  Boundary: this polices the state dir's OWN mode + symlink-ness + .gitignore, NOT
 *  its ancestors. The deployer must place the state dir under a trusted parent (as
 *  with any secret store) — a group/other-writable, non-sticky parent would let
 *  another local user rename/replace the state dir after this returns. This is the
 *  same per-directory scope `loadOrCreateQuickstartSecrets` has always had; ancestor-
 *  chain hardening is tracked as a separate, pre-existing task (it would be a behavior
 *  change across both helpers, not a DX-A export concern).
 *
 *  This aggregate helper — not the raw `ensureGitignore(dir, canCreate)` — is the
 *  public surface, because it DERIVES whether creating the `.gitignore` is safe from
 *  `mkdir`'s return (only a dir we just made). The raw boolean would let a caller
 *  pass `canCreate=true` for a pre-existing tree and drop a `*` ignore that hides the
 *  whole repo — the exact outcome the internal protocol prevents. Fail-safe by
 *  construction (contracts §15 DX). */
export async function ensureStateDir(dir: string): Promise<void> {
  const created = await mkdir(dir, { recursive: true });
  if (created !== undefined) {
    if (process.platform !== "win32") await chmod(dir, 0o700);
  } else {
    await assertRealDir(dir); // pre-existing: real dir, not a symlink, not group/other-accessible
  }
  await ensureGitignore(dir, created !== undefined);
}
