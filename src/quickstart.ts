// Quickstart secret persistence (contracts §17.8, threat-model row 23) — the
// zero-setup boot helper. Loads `{ signingPrivateJwk, consentSigningSecret }`
// from `${dir}/secrets.json`, or generates them on first boot and persists with
// tight file permissions so the dir can never leak or be committed.
//
// SECURITY POSTURE — fail-closed, never ephemeral:
//   - POSIX: a group/other-readable secrets file is a BOOT FAILURE (the operator
//     must `chmod 600` it); the check is skipped on Windows (POSIX mode bits are
//     meaningless there) and that skip is documented in the thrown message.
//   - The directory is `0700`, the file is `0600` created with `O_EXCL` (flag
//     "wx": create-only, fail if it already exists — never clobbers a real key
//     with a freshly-generated one), and a `.gitignore` containing `*` is written
//     into the dir so it can never be committed by accident.
//   - An unwritable directory, partial write, unparseable JSON, or a bad-shape
//     file is an `AuthConfigError`. There is NEVER an ephemeral in-memory
//     fallback: silent key rotation on restart would invalidate every outstanding
//     token while masking the misconfiguration — the opposite of fail-closed.
//
// Env-var configuration remains the primary production path; this is the
// zero-setup path (same audience as §17.5 console pairing). Plaintext key
// material on disk is bounded by the OS user account; production belongs in
// env/secret managers.

import { chmod, lstat, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { exportJWK, generateKeyPair, type JWK } from "jose";
import { AuthConfigError } from "./config.ts";

export interface QuickstartSecrets {
  /** EC P-256 private JWK (kty/crv/d/x/y) — passes `createBridgeConfig`'s §5 check. */
  signingPrivateJwk: JWK;
  /** >=32-char HS256 consent secret (base64url of 48 random bytes). */
  consentSigningSecret: string;
}

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

  if (await pathExists(secretsPath)) {
    return loadExisting(dir, secretsPath);
  }
  return generateAndPersist(dir, secretsPath);
}

async function loadExisting(dir: string, secretsPath: string): Promise<QuickstartSecrets> {
  // The "can never be committed" guarantee holds on RELOAD too: if .gitignore was
  // deleted after first boot (or the dir was restored without it), re-create it;
  // if it has been tampered with, fail closed. Runs before the secrets perm check.
  // We did NOT create this dir this process (secrets.json pre-existed), so we
  // can't safely CREATE a .gitignore here — a stray secrets.json in a repo root
  // must not trigger a `*` write that hides the operator's tree. Require it exact.
  await ensureGitignore(dir, false);
  // POSIX perm check BEFORE reading: a loose-permission file is a boot failure
  // even if its contents are valid — never process a file the operator hasn't
  // locked down. Skipped on Windows (mode bits are not meaningful there).
  if (process.platform !== "win32") {
    let st;
    try {
      st = await stat(secretsPath);
    } catch (error) {
      throw new AuthConfigError(`quickstart: cannot stat ${secretsPath}: ${errMsg(error)}`);
    }
    if (st.mode & 0o077) {
      const octal = (st.mode & 0o777).toString(8).padStart(3, "0");
      throw new AuthConfigError(
        `quickstart: ${secretsPath} is group/other-accessible (mode ${octal}); run: chmod 600 ${secretsPath}`,
      );
    }
  }

  let raw: string;
  try {
    raw = await readFile(secretsPath, "utf8");
  } catch (error) {
    throw new AuthConfigError(`quickstart: cannot read ${secretsPath}: ${errMsg(error)}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new AuthConfigError(`quickstart: ${secretsPath} is not valid JSON (refuse to fall back to ephemeral keys)`);
  }
  return validateSecrets(parsed, secretsPath);
}

function validateSecrets(parsed: unknown, secretsPath: string): QuickstartSecrets {
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new AuthConfigError(`quickstart: ${secretsPath} must be a JSON object`);
  }
  const obj = parsed as Record<string, unknown>;
  const signingPrivateJwk = obj.signingPrivateJwk;
  const consentSigningSecret = obj.consentSigningSecret;
  if (typeof consentSigningSecret !== "string" || consentSigningSecret.trim().length < 32) {
    throw new AuthConfigError(`quickstart: ${secretsPath} consentSigningSecret missing or < 32 chars`);
  }
  // Mirror config.ts §5 shape validation so loaded material always passes createBridgeConfig.
  if (!isValidSigningJwk(signingPrivateJwk)) {
    throw new AuthConfigError(`quickstart: ${secretsPath} signingPrivateJwk must be an EC P-256 key with d, x, y`);
  }
  return { signingPrivateJwk: signingPrivateJwk as JWK, consentSigningSecret };
}

function isValidSigningJwk(value: unknown): value is JWK {
  if (typeof value !== "object" || value === null) return false;
  const jwk = value as Record<string, unknown>;
  return (
    jwk.kty === "EC" && jwk.crv === "P-256" &&
    typeof jwk.d === "string" && jwk.d.length > 0 &&
    typeof jwk.x === "string" && jwk.x.length > 0 &&
    typeof jwk.y === "string" && jwk.y.length > 0
  );
}

async function generateAndPersist(dir: string, secretsPath: string): Promise<QuickstartSecrets> {
  // 1. Directory: create it (recursive) or reuse it. `mkdir` returns the path of
  //    the first directory it created, or undefined if `dir` already existed — so
  //    we chmod ONLY a dir we just created (masking umask; we own it). Never mutate
  //    a pre-existing directory: it may be a repo root or shared path, and force-
  //    chmodding it to 0700 could lock other users out before later checks decide
  //    the dir is unfit. The secrets file itself is always 0600, so its content is
  //    protected regardless of the dir's listing perms.
  let createdDir: string | undefined;
  try {
    createdDir = await mkdir(dir, { recursive: true });
  } catch (error) {
    throw new AuthConfigError(`quickstart: cannot create directory ${dir}: ${errMsg(error)}`);
  }
  if (createdDir !== undefined && process.platform !== "win32") {
    await chmod(dir, DIR_MODE);
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

/** The exact .gitignore content the quickstart writes/manages. Anything else
 *  (an operator's file, a negation, a symlink) fails closed — we never parse
 *  arbitrary gitignore semantics (negations, anchoring, globs), which is a
 *  whack-a-mole every git semantic loses. Covers BOTH first-boot and reload. */
const GITIGNORE_CONTENT = "*\n";

async function ensureGitignore(dir: string, canCreate: boolean): Promise<void> {
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
  // Exists (or just appeared) — verify it is OURS. Refuse a symlink first (lstat
  // does NOT follow; git ignores symlinked .gitignore files). Then require the
  // exact content; any deviation fails closed.
  let lst;
  try {
    lst = await lstat(path);
  } catch (error) {
    throw new AuthConfigError(`quickstart: cannot lstat ${GITIGNORE_FILE}: ${errMsg(error)}`);
  }
  if (lst.isSymbolicLink()) {
    throw new AuthConfigError(
      `quickstart: ${path} is a symlink; git does not follow symlinked .gitignore files — replace it with a real file`,
    );
  }
  let existing: string;
  try {
    existing = await readFile(path, "utf8");
  } catch (error) {
    throw new AuthConfigError(`quickstart: cannot read ${GITIGNORE_FILE}: ${errMsg(error)}`);
  }
  if (existing !== GITIGNORE_CONTENT) {
    throw new AuthConfigError(
      `quickstart: ${path} is not the quickstart-managed ignore (expected a single \`*\` line); move or remove it, or point MCP_SSO_DIR at a fresh directory`,
    );
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
