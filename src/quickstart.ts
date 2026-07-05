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

import { chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
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
    return loadExisting(secretsPath);
  }
  return generateAndPersist(dir, secretsPath);
}

async function loadExisting(secretsPath: string): Promise<QuickstartSecrets> {
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
  // 1. mkdir 0700 (recursive; explicit chmod — mkdir's mode is masked by umask).
  try {
    await mkdir(dir, { recursive: true });
    if (process.platform !== "win32") await chmod(dir, DIR_MODE);
  } catch (error) {
    throw new AuthConfigError(`quickstart: cannot create directory ${dir}: ${errMsg(error)}`);
  }

  // 2. .gitignore (write FIRST so the dir is never committable even if the
  //    secrets write fails partway). On a fresh dir this writes `*`. If a
  //    .gitignore already exists (MCP_SSO_DIR pointed at a pre-existing dir),
  //    fail CLOSED unless it already covers secrets.json — the §17.8 "can never
  //    be committed" guarantee is unconditional, mirroring the dir-perm correction
  //    above; never silently degrade it.
  await ensureGitignore(dir);

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

async function ensureGitignore(dir: string): Promise<void> {
  const path = join(dir, GITIGNORE_FILE);
  try {
    await writeFile(path, "*\n", { flag: "wx", mode: FILE_MODE });
    return; // created fresh — covers everything
  } catch (error) {
    if (!isExist(error)) {
      throw new AuthConfigError(`quickstart: cannot write ${GITIGNORE_FILE}: ${errMsg(error)}`);
    }
  }
  // EEXIST: a .gitignore is already there. The guarantee only holds if it covers
  // the secrets file; fail closed if it does not (the operator adds an entry).
  let existing: string;
  try {
    existing = await readFile(path, "utf8");
  } catch (error) {
    throw new AuthConfigError(`quickstart: cannot read existing ${GITIGNORE_FILE}: ${errMsg(error)}`);
  }
  if (!gitignoreCoversSecrets(existing)) {
    throw new AuthConfigError(
      `quickstart: ${path} exists but does not cover ${SECRETS_FILE}; add a line matching it (e.g. '*' or '${SECRETS_FILE}') before boot`,
    );
  }
}

/** A blanket `*` or an exact `secrets.json` line covers the secrets file. Anything
 *  narrower fails closed — the operator makes the ignore explicit. */
function gitignoreCoversSecrets(content: string): boolean {
  const lines = content.split(/\r?\n/).map((l) => l.trim());
  return lines.some((l) => l === "*" || l === SECRETS_FILE);
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
