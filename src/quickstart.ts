// Quickstart secret persistence (contracts §17.8, threat-model row 23) — the
// zero-setup boot helper. Loads or generates+persists { signingPrivateJwk,
// consentSigningSecret } under ${dir}/secrets.json.
//
// SECURITY POSTURE — fail-closed, never ephemeral:
//   - Dir 0700, secrets file 0600 (O_EXCL — never clobbers), `.gitignore` of `*`
//     is the only ignore trusted. A group/other-accessible dir or secrets file is
//     a BOOT FAILURE (skipped on Windows).
//   - FOLLOW-THE-LINK closed everywhere: dir/secrets.json/.gitignore must be REAL
//     (lstat/O_NOFOLLOW refuse symlinks); reads use open(O_NOFOLLOW)+fstat+read-fd
//     (no lstat→readFile race).
//   - Unwritable dir / partial write / unparseable / bad-shape ⇒ AuthConfigError.
//     NEVER an ephemeral fallback (silent key rotation masks misconfiguration).
//
// Plaintext key material on disk. On POSIX the boundary is the OS user account,
// enforced by the mode/ownership gates above. On Windows those gates are absent
// and no DACL is read or set, so the readers are whichever principals the
// inherited ACL admits — unmeasured here (issue #219). Production belongs in
// env/secret managers on both.

import { chmod, constants as fsc, lstat, mkdir, open, readFile, stat, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { exportJWK, generateKeyPair, type JWK } from "jose";
import { AuthConfigError } from "./config.ts";
import { validateSecrets, type QuickstartSecrets } from "./quickstart-shape.ts";
import { warnWindowsPermissionGap } from "./windows-permission-warning.ts";

export type { QuickstartSecrets } from "./quickstart-shape.ts";

// O_NOFOLLOW refuses symlinks; O_NONBLOCK stops a FIFO/special file hanging open.
const O_NOFOLLOW: number | undefined = (fsc as { O_NOFOLLOW?: number }).O_NOFOLLOW;
const O_NONBLOCK: number = (fsc as { O_NONBLOCK?: number }).O_NONBLOCK ?? 0;

export interface QuickstartOptions {
  /** Directory holding `secrets.json` + `.gitignore`. Default `./.mcp-sso`. */
  dir?: string;
}

const SECRETS_FILE = "secrets.json";
const GITIGNORE_FILE = ".gitignore";
const FILE_MODE = 0o600;
const DIR_MODE = 0o700;

/** Load persisted quickstart secrets, generating + persisting them on first boot. */
export async function loadOrCreateQuickstartSecrets(
  opts: QuickstartOptions = {},
): Promise<QuickstartSecrets> {
  const dir = opts.dir ?? "./.mcp-sso";
  const secretsPath = join(dir, SECRETS_FILE);

  warnWindowsPermissionGap();
  if (await pathExists(secretsPath)) {
    return loadExisting(dir, secretsPath);
  }
  return generateAndPersist(dir, secretsPath);
}

async function loadExisting(dir: string, secretsPath: string): Promise<QuickstartSecrets> {
  // Reload: dir + .gitignore must already be ours (we never create either here).
  await assertRealDir(dir);
  await ensureGitignore(dir, false);
  // Atomic read (O_NOFOLLOW + fstat + read-fd): refuses a symlink AND can't be
  // raced (lstat→readFile would let a swap-to-symlink slip in between).
  const { content: raw, mode } = await readOwnedFile(secretsPath);
  if (process.platform !== "win32" && mode & 0o077) {
    throw new AuthConfigError(`quickstart: ${secretsPath} is group/other-accessible (mode ${(mode & 0o777).toString(8).padStart(3, "0")}); run: chmod 600 ${secretsPath}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new AuthConfigError(`quickstart: ${secretsPath} is not valid JSON (refuse to fall back to ephemeral keys)`);
  }
  return validateSecrets(parsed, secretsPath);
}

async function generateAndPersist(dir: string, secretsPath: string): Promise<QuickstartSecrets> {
  // 1. Directory: mkdir returns the created path, or undefined if it pre-existed.
  //    Create restrictive ATOMICALLY (mode DIR_MODE — no world-writable window before
  //    the chmod, which verifies). chmod only a just-made dir; pre-existing ⇒ assertRealDir.
  let createdDir: string | undefined;
  try {
    createdDir = await mkdir(dir, { recursive: true, mode: DIR_MODE });
  } catch (error) {
    throw new AuthConfigError(`quickstart: cannot create directory ${dir}: ${errMsg(error)}`);
  }
  if (createdDir !== undefined && process.platform !== "win32") {
    await chmod(dir, DIR_MODE);
  } else if (createdDir === undefined) {
    // Pre-existing dir: must be a REAL directory, not a symlink (a symlinked dir
    // would route every following write/read into its target).
    await assertRealDir(dir);
  }

  // 2. .gitignore — write FIRST so the dir is never committable even if the
  //    secrets write fails partway. Only CREATE one in a dir we just made: writing
  //    `*` into a pre-existing repo/shared dir would silently ignore the operator's
  //    whole tree. A pre-existing dir must already carry our exact `*\n` ignore.
  await ensureGitignore(dir, createdDir !== undefined);

  // 3. Generate the material: EC P-256 keypair (extractable so we can export the
  //    private JWK) + a 48-byte base64url consent secret (64 chars, > 32).
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  const signingPrivateJwk = await exportJWK(privateKey);
  const consentSigningSecret = randomBytes(48).toString("base64url");

  // 4. secrets.json: O_EXCL ("wx") + 0600. EEXIST = a concurrent boot won the
  //    race — fail closed (do NOT clobber); the next load reads the winner.
  const content = JSON.stringify({ signingPrivateJwk, consentSigningSecret }) + "\n";
  try {
    await writeFile(secretsPath, content, { flag: "wx", mode: FILE_MODE });
  } catch (error) {
    if (isExist(error)) {
      throw new AuthConfigError(`quickstart: ${secretsPath} appeared concurrently; restart to load it`);
    }
    throw new AuthConfigError(`quickstart: cannot write ${secretsPath}: ${errMsg(error)}`);
  }
  return { signingPrivateJwk, consentSigningSecret };
}

/** The exact .gitignore content trusted. Anything else (negation, symlink, custom)
 *  fails closed — we never parse gitignore semantics. Covers first-boot + reload. */
const GITIGNORE_CONTENT = "*\n";

export async function ensureGitignore(dir: string, canCreate: boolean): Promise<void> {
  const path = join(dir, GITIGNORE_FILE);
  // Missing? Only CREATE one where we're allowed: a dir we just made (or our own
  // reload dir). Writing `*` into a pre-existing repo/shared dir would silently
  // ignore the operator's whole tree — fail closed there instead.
  if (!(await pathExists(path))) {
    if (!canCreate) {
      throw new AuthConfigError(
        `quickstart: ${dir} already exists and has no quickstart ${GITIGNORE_FILE}; refusing to create a \`*\` ignore in an existing directory (point MCP_SSO_DIR at a fresh directory)`,
      );
    }
    try {
      await writeFile(path, GITIGNORE_CONTENT, { flag: "wx", mode: FILE_MODE });
      return;
    } catch (error) {
      if (!isExist(error)) {
        throw new AuthConfigError(`quickstart: cannot write ${GITIGNORE_FILE}: ${errMsg(error)}`);
      }
    }
  }
  // Exists (or just appeared) — verify it is OURS via an atomic read (O_NOFOLLOW
  // refuses a symlink; read-fd can't be raced). Require the exact `*\n` content.
  const { content: existing } = await readOwnedFile(path);
  if (existing !== GITIGNORE_CONTENT) {
    throw new AuthConfigError(
      `quickstart: ${path} is not the quickstart-managed ignore (expected a single \`*\` line); move or remove it, or point MCP_SSO_DIR at a fresh directory`,
    );
  }
}

/** Reject a symlink, a non-directory, or (POSIX) a group/other-accessible mode —
 *  a world-writable state dir lets another user swap secrets.json for their key. */
export async function assertRealDir(dir: string): Promise<void> {
  // This helper is root-exported for standalone use. On Windows it omits the
  // POSIX mode admission just like its quickstart/ensureStateDir callers, so it
  // must surface the same fixed limitation even when neither caller is used.
  warnWindowsPermissionGap();
  let st;
  try {
    st = await lstat(dir);
  } catch (error) {
    throw new AuthConfigError(`quickstart: cannot stat directory ${dir}: ${errMsg(error)}`);
  }
  if (st.isSymbolicLink()) {
    throw new AuthConfigError(`quickstart: ${dir} is a symlink; point MCP_SSO_DIR at a real directory`);
  }
  if (!st.isDirectory()) {
    throw new AuthConfigError(`quickstart: ${dir} is not a directory`);
  }
  if (process.platform !== "win32" && st.mode & 0o077) {
    throw new AuthConfigError(`quickstart: ${dir} is group/other-accessible (mode ${(st.mode & 0o777).toString(8).padStart(3, "0")}); use a fresh directory or chmod 700 ${dir}`);
  }
}

/** O_NOFOLLOW + fstat + read-fd: atomic, refuses symlinks/FIFOs (O_NONBLOCK). Windows → lstat+read. */
async function readOwnedFile(path: string): Promise<{ content: string; mode: number }> {
  // The explicit platform branch makes the production Windows fallback
  // exercisable by the fake-win child probes even when they run on POSIX.
  if (process.platform === "win32" || O_NOFOLLOW === undefined) {
    let st;
    try {
      st = await lstat(path);
    } catch (error) {
      throw new AuthConfigError(`quickstart: cannot stat ${path}: ${errMsg(error)}`);
    }
    if (st.isSymbolicLink()) throw new AuthConfigError(`quickstart: ${path} is a symlink`);
    if (!st.isFile()) throw new AuthConfigError(`quickstart: ${path} is not a regular file`);
    try {
      return { content: await readFile(path, "utf8"), mode: st.mode };
    } catch (error) {
      throw new AuthConfigError(`quickstart: cannot read ${path}: ${errMsg(error)}`);
    }
  }
  let fh;
  try {
    fh = await open(path, O_NOFOLLOW | fsc.O_RDONLY | O_NONBLOCK);
  } catch (error) {
    throw new AuthConfigError(`quickstart: cannot open ${path} (symlink or missing): ${errMsg(error)}`);
  }
  try {
    const st = await fh.stat();
    if (!st.isFile()) throw new AuthConfigError(`quickstart: ${path} is not a regular file (FIFO/device rejected)`);
    const buf = Buffer.alloc(st.size);
    if (st.size > 0) await fh.read(buf, 0, st.size, 0);
    return { content: buf.toString("utf8"), mode: st.mode };
  } finally {
    await fh.close();
  }
}

async function pathExists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch (error) {
    if (isNotFound(error)) return false;
    throw new AuthConfigError(`quickstart: cannot stat ${p}: ${errMsg(error)}`);
  }
}

function isExist(error: unknown): boolean {
  return isErrorWithCode(error, ["EEXIST"]);
}
function isNotFound(error: unknown): boolean {
  return isErrorWithCode(error, ["ENOENT"]);
}
function isErrorWithCode(error: unknown, codes: string[]): boolean {
  return typeof error === "object" && error !== null && "code" in error &&
    codes.includes((error as { code: string }).code);
}
function errMsg(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
