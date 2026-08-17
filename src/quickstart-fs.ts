import {
  chmod, constants as fsc, lstat, mkdir, open, readFile, stat, writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { AuthConfigError } from "./config.ts";
import { validateSecrets, type QuickstartSecrets } from "./quickstart-shape.ts";
import { warnWindowsPermissionGap } from "./windows-permission-warning.ts";

const O_NOFOLLOW: number | undefined = (fsc as { O_NOFOLLOW?: number }).O_NOFOLLOW;
const O_NONBLOCK: number = (fsc as { O_NONBLOCK?: number }).O_NONBLOCK ?? 0;
const GITIGNORE_FILE = ".gitignore";
const GITIGNORE_CONTENT = "*\n";
const FILE_MODE = 0o600;
const DIR_MODE = 0o700;

export async function loadQuickstartSecrets(
  dir: string, secretsPath: string,
): Promise<QuickstartSecrets> {
  await assertRealDir(dir);
  await ensureGitignore(dir, false);
  const { content: raw, mode } = await readOwnedFile(secretsPath);
  if (process.platform !== "win32" && mode & 0o077) {
    throw new AuthConfigError(`quickstart: ${secretsPath} is group/other-accessible (mode ${(mode & 0o777).toString(8).padStart(3, "0")}); run: chmod 600 ${secretsPath}`);
  }
  let parsed: unknown;
  try { parsed = JSON.parse(raw); }
  catch {
    throw new AuthConfigError(`quickstart: ${secretsPath} is not valid JSON (refuse to fall back to ephemeral keys)`);
  }
  return validateSecrets(parsed, secretsPath);
}

export async function persistQuickstartSecrets(
  dir: string, secretsPath: string, secrets: QuickstartSecrets,
): Promise<void> {
  let createdDir: string | undefined;
  try { createdDir = await mkdir(dir, { recursive: true, mode: DIR_MODE }); }
  catch (error) {
    throw new AuthConfigError(`quickstart: cannot create directory ${dir}: ${errMsg(error)}`);
  }
  if (createdDir !== undefined && process.platform !== "win32") {
    await chmod(dir, DIR_MODE);
  } else if (createdDir === undefined) {
    await assertRealDir(dir);
  }
  await ensureGitignore(dir, createdDir !== undefined);

  const content = JSON.stringify(secrets) + "\n";
  try { await writeFile(secretsPath, content, { flag: "wx", mode: FILE_MODE }); }
  catch (error) {
    if (isExist(error)) {
      throw new AuthConfigError(`quickstart: ${secretsPath} appeared concurrently; restart to load it`);
    }
    throw new AuthConfigError(`quickstart: cannot write ${secretsPath}: ${errMsg(error)}`);
  }
}

/** The exact .gitignore content trusted. Anything else (negation, symlink, custom)
 *  fails closed — we never parse gitignore semantics. Covers first-boot + reload. */
export async function ensureGitignore(dir: string, canCreate: boolean): Promise<void> {
  const path = join(dir, GITIGNORE_FILE);
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
  const { content: existing } = await readOwnedFile(path);
  if (existing !== GITIGNORE_CONTENT) {
    throw new AuthConfigError(
      `quickstart: ${path} is not the quickstart-managed ignore (expected a single \`*\` line); move or remove it, or point MCP_SSO_DIR at a fresh directory`,
    );
  }
}

/** Reject a symlink, a non-directory, or (POSIX) a group/other-accessible mode. */
export async function assertRealDir(dir: string): Promise<void> {
  warnWindowsPermissionGap();
  let st;
  try { st = await lstat(dir); }
  catch (error) {
    throw new AuthConfigError(`quickstart: cannot stat directory ${dir}: ${errMsg(error)}`);
  }
  if (st.isSymbolicLink()) {
    throw new AuthConfigError(`quickstart: ${dir} is a symlink; point MCP_SSO_DIR at a real directory`);
  }
  if (!st.isDirectory()) throw new AuthConfigError(`quickstart: ${dir} is not a directory`);
  if (process.platform !== "win32" && st.mode & 0o077) {
    throw new AuthConfigError(`quickstart: ${dir} is group/other-accessible (mode ${(st.mode & 0o777).toString(8).padStart(3, "0")}); use a fresh directory or chmod 700 ${dir}`);
  }
}

/** Supported POSIX: atomic O_NOFOLLOW+fstat+read-fd. Windows/no flag:
 *  lstat symlink/type precheck + pathname read (private-directory boundary). */
async function readOwnedFile(path: string): Promise<{ content: string; mode: number }> {
  if (process.platform === "win32" || O_NOFOLLOW === undefined) {
    let st;
    try { st = await lstat(path); }
    catch (error) {
      throw new AuthConfigError(`quickstart: cannot stat ${path}: ${errMsg(error)}`);
    }
    if (st.isSymbolicLink()) throw new AuthConfigError(`quickstart: ${path} is a symlink`);
    if (!st.isFile()) throw new AuthConfigError(`quickstart: ${path} is not a regular file`);
    try { return { content: await readFile(path, "utf8"), mode: st.mode }; }
    catch (error) {
      throw new AuthConfigError(`quickstart: cannot read ${path}: ${errMsg(error)}`);
    }
  }
  let fh;
  try { fh = await open(path, O_NOFOLLOW | fsc.O_RDONLY | O_NONBLOCK); }
  catch (error) {
    throw new AuthConfigError(`quickstart: cannot open ${path} (symlink or missing): ${errMsg(error)}`);
  }
  try {
    const st = await fh.stat();
    if (!st.isFile()) throw new AuthConfigError(`quickstart: ${path} is not a regular file (FIFO/device rejected)`);
    const buf = Buffer.alloc(st.size);
    if (st.size > 0) await fh.read(buf, 0, st.size, 0);
    return { content: buf.toString("utf8"), mode: st.mode };
  } finally { await fh.close(); }
}

export async function pathExists(path: string): Promise<boolean> {
  try { await stat(path); return true; }
  catch (error) {
    if (isErrorWithCode(error, ["ENOENT"])) return false;
    throw new AuthConfigError(`quickstart: cannot stat ${path}: ${errMsg(error)}`);
  }
}

function isExist(error: unknown): boolean { return isErrorWithCode(error, ["EEXIST"]); }
function isErrorWithCode(error: unknown, codes: string[]): boolean {
  return typeof error === "object" && error !== null && "code" in error
    && codes.includes((error as { code: string }).code);
}
function errMsg(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
