// Boot-time snapshots for mutable BridgeConfig containers (contracts §5).
// Each helper reads caller-owned members once, validates that snapshot, and
// publishes only an explicit allowlisted copy.

import type { JWK } from "jose";
import type { ClientStore } from "./ports/client-store.ts";
import type {
  BridgeConfig, ClientCredentialsOptions, DcrMode, DevOptions,
} from "./config.ts";

type MakeError = (message: string) => Error;
const MAX_CONFIG_ARRAY_ENTRIES = 4096;

export function snapshotStringArray(
  label: string,
  value: unknown,
  makeError: MakeError,
): string[] {
  const entries = snapshotArray(label, value, makeError);
  for (const entry of entries) {
    if (typeof entry !== "string") {
      throw makeError(`${label} entries must be strings`);
    }
  }
  return entries as string[];
}

export function snapshotArray(
  label: string,
  value: unknown,
  makeError: MakeError,
): readonly unknown[] {
  if (!isArrayValue(value, label, makeError)) throw makeError(`${label} must be an array`);
  const length = read(value, "length", label, makeError);
  if (!Number.isInteger(length) || (length as number) < 0
    || (length as number) > MAX_CONFIG_ARRAY_ENTRIES) {
    throw makeError(
      `${label} must have an integer length in [0, ${MAX_CONFIG_ARRAY_ENTRIES}]`,
    );
  }
  const snapshot: unknown[] = [];
  for (let index = 0; index < (length as number); index += 1) {
    snapshot.push(read(value, index, `${label}[${index}]`, makeError));
  }
  return Object.freeze(snapshot);
}

export function configOwnKeys(value: object, makeError: MakeError): Array<string | symbol> {
  try {
    return Reflect.ownKeys(value);
  } catch {
    throw makeError("BridgeConfig keys could not be read");
  }
}

export function isArrayValue(
  value: unknown,
  label: string,
  makeError: MakeError,
): value is unknown[] {
  try {
    return Array.isArray(value);
  } catch {
    throw makeError(`${label} could not be classified`);
  }
}

export function configValue<K extends keyof BridgeConfig>(
  value: BridgeConfig,
  key: K,
  makeError: MakeError,
): BridgeConfig[K] {
  return read(value, key, `BridgeConfig.${String(key)}`, makeError) as BridgeConfig[K];
}

export function snapshotDcr(value: unknown, makeError: MakeError): DcrMode {
  const source = record(value, "dcr", makeError);
  const mode = read(source, "mode", "dcr.mode", makeError);
  if (mode === "stateless") return Object.freeze({ mode: "stateless" });
  if (mode !== "stored") throw makeError("dcr.mode must be 'stateless' or 'stored'");

  const store = read(source, "store", "dcr.store", makeError);
  if (!isClientStore(store)) {
    throw makeError("dcr.mode 'stored' requires a ClientStore with save and find methods");
  }
  // The wrapper is owned; the live port deliberately remains the same object.
  return Object.freeze({ mode: "stored", store });
}

export function snapshotDev(value: unknown, makeError: MakeError): DevOptions | undefined {
  if (value === undefined) return undefined;
  const source = record(value, "dev", makeError);
  const allowInsecureLocalhost = read(
    source, "allowInsecureLocalhost", "dev.allowInsecureLocalhost", makeError,
  );
  if (typeof allowInsecureLocalhost !== "boolean") {
    throw makeError("dev.allowInsecureLocalhost must be a boolean");
  }
  return Object.freeze({ allowInsecureLocalhost });
}

export function snapshotClientCredentials(
  value: unknown,
  makeError: MakeError,
): ClientCredentialsOptions | undefined {
  if (value === undefined) return undefined;
  const source = record(value, "clientCredentials", makeError);
  const enabled = read(source, "enabled", "clientCredentials.enabled", makeError);
  if (typeof enabled !== "boolean") {
    throw makeError("clientCredentials must be { enabled: boolean }");
  }
  return Object.freeze({ enabled });
}

export function snapshotJwk(value: unknown, makeError: MakeError): JWK {
  const source = record(value, "signingPrivateJwk", makeError);
  const snapshot: Record<string, unknown> = {};
  for (const key of JWK_STRING_KEYS) {
    const member = read(source, key, `signingPrivateJwk.${key}`, makeError);
    if (member === undefined) continue;
    if (typeof member !== "string") {
      throw makeError(`signingPrivateJwk.${key} must be a string`);
    }
    snapshot[key] = member;
  }

  const ext = read(source, "ext", "signingPrivateJwk.ext", makeError);
  if (ext !== undefined) {
    if (typeof ext !== "boolean") {
      throw makeError("signingPrivateJwk.ext must be a boolean");
    }
    snapshot.ext = ext;
  }

  const keyOps = read(source, "key_ops", "signingPrivateJwk.key_ops", makeError);
  if (keyOps !== undefined) {
    snapshot.key_ops = snapshotStringArray(
      "signingPrivateJwk.key_ops", keyOps, makeError,
    );
  }
  return Object.freeze(snapshot) as JWK;
}

export function isEcP256PrivateJwk(jwk: JWK): boolean {
  return jwk.kty === "EC" && jwk.crv === "P-256"
    && typeof jwk.d === "string" && jwk.d.length > 0
    && typeof jwk.x === "string" && jwk.x.length > 0
    && typeof jwk.y === "string" && jwk.y.length > 0;
}

const JWK_STRING_KEYS: readonly string[] = [
  "kty", "crv", "x", "y", "d", "alg", "kid", "use",
];

function record(value: unknown, label: string, makeError: MakeError): Record<PropertyKey, unknown> {
  if (typeof value !== "object" || value === null || isArrayValue(value, label, makeError)) {
    throw makeError(`${label} must be an object`);
  }
  return value as Record<PropertyKey, unknown>;
}

function read(
  source: object,
  key: PropertyKey,
  label: string,
  makeError: MakeError,
): unknown {
  try {
    return (source as Record<PropertyKey, unknown>)[key];
  } catch {
    throw makeError(`${label} could not be read`);
  }
}

function isClientStore(value: unknown): value is ClientStore {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) return false;
  try {
    const candidate = value as Partial<ClientStore>;
    return typeof candidate.save === "function" && typeof candidate.find === "function";
  } catch {
    return false;
  }
}
