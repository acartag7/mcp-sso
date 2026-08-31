import { lstat, readFile, realpath } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";
import { exportJWK, importPKCS8, importSPKI, type JWK } from "jose";
import { createBridgeConfig, type BridgeConfig } from "../../src/config.ts";
import type { FixtureStore } from "./store.ts";
import { FIXTURES_ROOT } from "./schema.ts";
import { FixtureRunnerError } from "./error.ts";

export interface FixtureKeys { signingPrivate?: string; signingPublic?: string }

export async function materializeConfig(
  literal: unknown, keys: FixtureKeys, store: FixtureStore,
): Promise<BridgeConfig> {
  const input = structuredClone(literal);
  if (keys.signingPrivate !== undefined) {
    if (!isRecord(input)) throw new FixtureRunnerError("a signingPrivate key requires an object config");
    if (Object.hasOwn(input, "signingPrivateJwk")) {
      throw new FixtureRunnerError("config and given.keys both supply signingPrivateJwk");
    }
    input.signingPrivateJwk = await privateJwk(keys.signingPrivate);
  }
  if (isRecord(input) && isRecord(input.dcr) && input.dcr.mode === "stored") input.dcr = { mode: "stored", store };
  return createBridgeConfig(input as unknown as BridgeConfig);
}

export async function publicKey(path: string): Promise<Awaited<ReturnType<typeof importSPKI>>> {
  const pem = await readKey(path);
  try { return await importSPKI(pem, "ES256"); }
  catch (error) { throw new FixtureRunnerError(`${path}: malformed ES256 public key`, { cause: error }); }
}

async function privateJwk(path: string): Promise<JWK> {
  const pem = await readKey(path);
  try { return await exportJWK(await importPKCS8(pem, "ES256", { extractable: true })); }
  catch (error) { throw new FixtureRunnerError(`${path}: malformed EC P-256 private key`, { cause: error }); }
}

async function readKey(name: string): Promise<string> {
  if (typeof name !== "string" || name.length === 0 || name.startsWith("/") || name.includes("\\")) {
    throw new FixtureRunnerError("fixture key path must be relative and use forward slashes");
  }
  const keysRoot = await realpath(resolve(FIXTURES_ROOT, "keys"));
  const candidate = resolve(FIXTURES_ROOT, name);
  const lexical = relative(keysRoot, candidate);
  if (lexical === "" || lexical === ".." || lexical.startsWith(`..${sep}`)) {
    throw new FixtureRunnerError(`${name}: fixture key is outside fixtures/keys`);
  }
  const stat = await lstat(candidate).catch((error: unknown) => {
    throw new FixtureRunnerError(`${name}: fixture key cannot be inspected`, { cause: error });
  });
  if (stat.isSymbolicLink() || !stat.isFile()) throw new FixtureRunnerError(`${name}: fixture key must be a regular non-symlink file`);
  const canonical = await realpath(candidate);
  const physical = relative(keysRoot, canonical);
  if (physical === "" || physical === ".." || physical.startsWith(`..${sep}`)) {
    throw new FixtureRunnerError(`${name}: fixture key resolves outside fixtures/keys`);
  }
  return readFile(canonical, "utf8");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
