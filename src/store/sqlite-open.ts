import {
  closeSync, constants as fsc, fchmodSync, fstatSync, lstatSync,
  openSync, realpathSync, statSync, type BigIntStats,
} from "node:fs";
import { dirname, join, parse, resolve, sep } from "node:path";
import { isSqliteAncestorReplaceable } from "./sqlite-open-policy.ts";

const ERROR_PREFIX = "sqlite: unsafe persistent state:";
const FILE_MODE = 0o600n;
const FILE_MODE_MASK = 0o7777n;
const PRIVATE_MASK = 0o077n;
const O_NOFOLLOW = (fsc as { O_NOFOLLOW?: number }).O_NOFOLLOW ?? 0;
const O_NONBLOCK = (fsc as { O_NONBLOCK?: number }).O_NONBLOCK ?? 0;

export interface SqliteFileIdentity {
  dev: bigint;
  ino: bigint;
}

export interface AdmittedSqliteFile {
  path: string;
  fd: number;
  identity: SqliteFileIdentity;
}

export class SqliteStateError extends Error {
  constructor(reason: string) {
    super(`${ERROR_PREFIX} ${reason}`);
    this.name = "SqliteStateError";
  }
}

export function sqlitePath(filename: unknown): ":memory:" | string {
  if (filename === ":memory:") return filename;
  if (typeof filename !== "string") fail("path must be a string");
  if (filename.trim().length === 0) fail("path must not be blank");
  if (filename.includes("\0")) fail("path must not contain NUL");
  if (/^file:/i.test(filename)) fail("file: URI names are not supported; use an ordinary filesystem path");
  try {
    return resolve(filename);
  } catch {
    fail("cannot resolve the database path");
  }
}

export function admitSqliteFile(path: string): AdmittedSqliteFile {
  assertTrustedDirectory(dirname(path));
  let existing: BigIntStats | undefined;
  try {
    existing = lstatSync(path, { bigint: true });
  } catch (error) {
    if (!hasCode(error, "ENOENT")) fail("cannot inspect the database path");
  }
  if (existing?.isSymbolicLink()) fail("final path is a symlink or junction");
  if (existing && !existing.isFile()) fail("final path is not a regular file");
  return existing ? openExisting(path) : createNew(path);
}

export function verifySqlitePathIdentity(path: string, expected: SqliteFileIdentity): void {
  let current: BigIntStats;
  try {
    current = lstatSync(path, { bigint: true });
  } catch {
    fail("database path identity changed during open");
  }
  if (current.isSymbolicLink() || !current.isFile() || current.nlink !== 1n) {
    fail("database path identity changed during open");
  }
  if (current.dev !== expected.dev || current.ino !== expected.ino) {
    fail("database path identity changed during open");
  }
}

export function closeSqliteAdmission(fd: number): void {
  try {
    closeSync(fd);
  } catch {
    fail("cannot close the verification descriptor");
  }
}

function createNew(path: string): AdmittedSqliteFile {
  const flags = fsc.O_RDWR | fsc.O_CREAT | fsc.O_EXCL | O_NONBLOCK | O_NOFOLLOW;
  let fd: number;
  try {
    fd = openSync(path, flags, Number(FILE_MODE));
  } catch (error) {
    // A sibling process may win first creation after our lstat. Re-admit the exact
    // winner through the existing-file path; all existing-file checks still run.
    if (hasCode(error, "EEXIST")) return openExisting(path);
    if (hasCode(error, "ELOOP")) fail("final path is a symlink or junction");
    fail("cannot create the database file");
  }
  try {
    if (process.platform !== "win32") fchmodSync(fd, Number(FILE_MODE));
    return admitted(path, fd);
  } catch (error) {
    try { closeSync(fd); } catch { /* preserve the admission failure */ }
    if (error instanceof SqliteStateError) throw error;
    fail("cannot secure the new database file");
  }
}

function openExisting(path: string): AdmittedSqliteFile {
  let fd: number;
  try {
    fd = openSync(path, fsc.O_RDWR | O_NONBLOCK | O_NOFOLLOW);
  } catch (error) {
    if (hasCode(error, "ELOOP")) fail("final path is a symlink or junction");
    fail("cannot open the existing database file");
  }
  try {
    return admitted(path, fd);
  } catch (error) {
    try { closeSync(fd); } catch { /* preserve the admission failure */ }
    throw error;
  }
}

function admitted(path: string, fd: number): AdmittedSqliteFile {
  let st: BigIntStats;
  try {
    st = fstatSync(fd, { bigint: true });
  } catch {
    fail("cannot inspect the opened database file");
  }
  if (!st.isFile()) fail("opened target is not a regular file");
  if (st.nlink !== 1n) fail("database file must have exactly one link");
  if (st.dev === 0n && st.ino === 0n) fail("platform cannot verify database file identity");
  if (process.platform !== "win32") {
    const euid = effectiveUid();
    if (st.uid !== euid) fail("database file must be owned by the effective service user");
    if ((st.mode & FILE_MODE_MASK) !== FILE_MODE) {
      fail("existing database file must have mode 0600; verify provenance, then chmod 600 the configured path");
    }
  }
  return { path, fd, identity: { dev: st.dev, ino: st.ino } };
}

function assertTrustedDirectory(directory: string): void {
  let immediate: BigIntStats;
  try {
    immediate = lstatSync(directory, { bigint: true });
  } catch {
    fail("immediate database directory must already exist");
  }
  if (immediate.isSymbolicLink()) fail("immediate database directory is a symlink or junction");
  if (!immediate.isDirectory()) fail("immediate database directory is not a directory");
  if (process.platform !== "win32") {
    const euid = effectiveUid();
    if (immediate.uid !== euid) fail("immediate database directory must be owned by the effective service user");
    if ((immediate.mode & PRIVATE_MASK) !== 0n) {
      fail("immediate database directory must be inaccessible to group and other users; use mode 0700");
    }
  }
  assertAncestry(directory);
  let real: string;
  try {
    real = realpathSync.native(directory);
  } catch {
    fail("cannot resolve database directory ancestry");
  }
  if (real !== directory) assertAncestry(real);
}

function assertAncestry(directory: string): void {
  const { root } = parse(directory);
  let current = root;
  const euid = process.platform === "win32" ? -1n : effectiveUid();
  for (const segment of directory.slice(root.length).split(sep).filter(Boolean)) {
    const parent = current;
    current = join(current, segment);
    let parentSt: BigIntStats;
    let entrySt: BigIntStats;
    try {
      parentSt = statSync(parent, { bigint: true });
      entrySt = lstatSync(current, { bigint: true });
    } catch {
      fail("cannot inspect database directory ancestry");
    }
    if (process.platform === "win32") {
      if (entrySt.isSymbolicLink()) fail("database directory ancestry contains a symlink or junction");
      continue;
    }
    if (isSqliteAncestorReplaceable({
      parentUid: parentSt.uid,
      parentMode: parentSt.mode,
      entryUid: entrySt.uid,
      effectiveUid: euid,
    })) {
      fail("database directory ancestry is replaceable by another OS user");
    }
  }
}

function effectiveUid(): bigint {
  const uid = process.geteuid?.();
  if (uid === undefined) fail("effective service user is unavailable");
  return BigInt(uid);
}

function hasCode(error: unknown, code: string): boolean {
  return typeof error === "object" && error !== null && "code" in error
    && (error as { code?: unknown }).code === code;
}

function fail(reason: string): never {
  throw new SqliteStateError(reason);
}
