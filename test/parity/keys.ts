import { constants as fsc } from "node:fs";
import { lstat, open, readFile, realpath } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";
import { exportJWK, importPKCS8, importSPKI, type CryptoKey, type JWK } from "jose";
import { FIXTURES_ROOT } from "./corpus.ts";
import { FixtureRunnerError } from "./error.ts";

const rawNoFollow: number | undefined = (fsc as { O_NOFOLLOW?: number }).O_NOFOLLOW;
const O_NOFOLLOW: number | undefined = rawNoFollow && rawNoFollow !== 0 ? rawNoFollow : undefined;
const O_NONBLOCK: number = (fsc as { O_NONBLOCK?: number }).O_NONBLOCK ?? 0;

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
  return readAdmittedFile(canonical, name);
}

async function inspectKeyPath(path: string, root: string, name: string): Promise<{
  stat: Awaited<ReturnType<typeof lstat>>; hasSymlink: boolean;
}> {
  const parts = relative(root, path).split(sep).filter(Boolean);
  let current = root;
  let stat: Awaited<ReturnType<typeof lstat>> | undefined;
  let hasSymlink = false;
  for (const part of parts) {
    current = resolve(current, part);
    stat = await inspectPath(current, name);
    hasSymlink ||= stat.isSymbolicLink();
  }
  if (stat === undefined) throw new FixtureRunnerError(`${name}: fixture key cannot be inspected`);
  return { stat, hasSymlink };
}

async function inspectPath(path: string, name: string): Promise<Awaited<ReturnType<typeof lstat>>> {
  try {
    return await lstat(path);
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

async function readAdmittedFile(path: string, name: string): Promise<string> {
  if (O_NOFOLLOW === undefined) {
    try { return await readFile(path, "utf8"); }
    catch (error) { throw new FixtureRunnerError(`${name}: fixture key cannot be read`, { cause: error }); }
  }
  let handle;
  try { handle = await open(path, O_NOFOLLOW | fsc.O_RDONLY | O_NONBLOCK); }
  catch (error) { throw new FixtureRunnerError(`${name}: fixture key cannot be opened`, { cause: error }); }
  let outcome: { value: string } | { error: FixtureRunnerError };
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new FixtureRunnerError(`${name}: fixture key must be a regular non-symlink file`);
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
