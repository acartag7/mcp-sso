import { constants as fsc, type BigIntStats } from "node:fs";
import { lstat, open, realpath, type FileHandle } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";
import { exportJWK, importPKCS8, importSPKI, type CryptoKey, type JWK } from "jose";
import { FIXTURES_ROOT } from "./corpus.ts";
import { FixtureRunnerError } from "./error.ts";

const rawNoFollow: number | undefined = (fsc as { O_NOFOLLOW?: number }).O_NOFOLLOW;
const O_NOFOLLOW: number | undefined = rawNoFollow && rawNoFollow !== 0 ? rawNoFollow : undefined;
const O_NONBLOCK: number = (fsc as { O_NONBLOCK?: number }).O_NONBLOCK ?? 0;
type FileIdentity = Pick<BigIntStats, "dev" | "ino">;

export async function validateOpenedFile(
  handle: FileHandle, name: string, expected: FileIdentity,
): Promise<void> {
  let actual: BigIntStats;
  try {
    actual = await handle.stat({ bigint: true });
  } catch (error) {
    throw new FixtureRunnerError(`${name}: fixture key cannot be read`, { cause: error });
  }
  if (!actual.isFile()) throw new FixtureRunnerError(`${name}: fixture key must be a regular non-symlink file`);
  if (!sameFileIdentity(expected, actual)) {
    throw new FixtureRunnerError(`${name}: fixture key changed between validation and open`);
  }
}

export async function publicKey(name: unknown, fixturesRoot = FIXTURES_ROOT): Promise<CryptoKey> {
  const pem = await readKey(name, fixturesRoot);
  try {
    return await importSPKI(pem, "ES256");
  } catch (error) {
    throw new FixtureRunnerError(`${String(name)}: malformed ES256 public key`, { cause: error });
  }
}

export async function privateJwk(name: unknown, fixturesRoot = FIXTURES_ROOT): Promise<JWK> {
  const pem = await readKey(name, fixturesRoot);
  try {
    return await exportJWK(await importPKCS8(pem, "ES256", { extractable: true }));
  } catch (error) {
    throw new FixtureRunnerError(`${String(name)}: malformed EC P-256 private key`, { cause: error });
  }
}

async function readKey(name: unknown, fixturesRoot: string): Promise<string> {
  if (typeof name !== "string" || name.length === 0 || name.startsWith("/") || name.includes("\\")) {
    throw new FixtureRunnerError("fixture key path must be relative and use forward slashes");
  }
  const keysRoot = resolve(fixturesRoot, "keys");
  const canonicalKeysRoot = await canonicalPath(keysRoot, name);
  const candidate = resolve(fixturesRoot, name);
  const lexical = relative(keysRoot, candidate);
  if (lexical === "" || lexical === ".." || lexical.startsWith(`..${sep}`)) {
    throw new FixtureRunnerError(`${name}: fixture key is outside fixtures/keys`);
  }
  const inspection = await inspectKeyPath(candidate, fixturesRoot, name);
  const { stat } = inspection;
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new FixtureRunnerError(`${name}: fixture key must be a regular non-symlink file`);
  }
  const canonical = await canonicalPath(candidate, name);
  const physical = relative(canonicalKeysRoot, canonical);
  if (physical === "" || physical === ".." || physical.startsWith(`..${sep}`)) {
    throw new FixtureRunnerError(`${name}: fixture key resolves outside fixtures/keys`);
  }
  if (inspection.hasSymlink) throw new FixtureRunnerError(`${name}: fixture key path contains a symlink`);
  return readAdmittedFile(canonical, name, stat);
}

async function inspectKeyPath(path: string, root: string, name: string): Promise<{
  stat: BigIntStats; hasSymlink: boolean;
}> {
  const parts = relative(root, path).split(sep).filter(Boolean);
  let current = root;
  let stat: BigIntStats | undefined;
  let hasSymlink = false;
  for (const part of parts) {
    current = resolve(current, part);
    stat = await inspectPath(current, name);
    hasSymlink ||= stat.isSymbolicLink();
  }
  if (stat === undefined) throw new FixtureRunnerError(`${name}: fixture key cannot be inspected`);
  return { stat, hasSymlink };
}

async function inspectPath(path: string, name: string): Promise<BigIntStats> {
  try {
    return await lstat(path, { bigint: true });
  } catch (error) {
    throw new FixtureRunnerError(`${name}: fixture key cannot be inspected`, { cause: error });
  }
}

async function canonicalPath(path: string, name: string): Promise<string> {
  try {
    return await realpath(path);
  } catch (error) {
    throw new FixtureRunnerError(`${name}: fixture key cannot be inspected`, { cause: error });
  }
}

async function readAdmittedFile(path: string, name: string, expected: FileIdentity): Promise<string> {
  if (O_NOFOLLOW === undefined) {
    throw new FixtureRunnerError(`${name}: fixture key cannot be opened without no-follow support`);
  }
  let handle;
  try { handle = await open(path, O_NOFOLLOW | fsc.O_RDONLY | O_NONBLOCK); }
  catch (error) { throw new FixtureRunnerError(`${name}: fixture key cannot be opened`, { cause: error }); }
  let outcome: { value: string } | { error: FixtureRunnerError };
  try {
    await validateOpenedFile(handle, name, expected);
    outcome = { value: await handle.readFile("utf8") };
  } catch (error) {
    outcome = {
      error: error instanceof FixtureRunnerError
        ? error : new FixtureRunnerError(`${name}: fixture key cannot be read`, { cause: error }),
    };
  }
  let closeFailure: FixtureRunnerError | undefined;
  try { await handle.close(); }
  catch (error) { closeFailure = new FixtureRunnerError(`${name}: fixture key cannot be closed`, { cause: error }); }
  if ("error" in outcome) throw outcome.error;
  if (closeFailure !== undefined) throw closeFailure;
  return outcome.value;
}

function sameFileIdentity(expected: FileIdentity, actual: FileIdentity): boolean {
  if (typeof expected.dev !== "bigint" || typeof expected.ino !== "bigint"
    || typeof actual.dev !== "bigint" || typeof actual.ino !== "bigint") return false;
  if (expected.dev <= 0n || expected.ino <= 0n || actual.dev <= 0n || actual.ino <= 0n) return false;
  return expected.dev === actual.dev && expected.ino === actual.ino;
}
