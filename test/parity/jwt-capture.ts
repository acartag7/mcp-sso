import assert from "node:assert/strict";
import { compactVerify, type CryptoKey } from "jose";
import type { CaptureSpec } from "./types.ts";
import { FixtureRunnerError } from "./error.ts";
import { parseStrictJson } from "./strict-json.ts";

type JwtExpectation = NonNullable<CaptureSpec["jwt"]>;

const INVALID_TOKEN = "captured JWT is invalid";
const INVALID_HEADER = "captured JWT protected header is invalid";
const INVALID_PAYLOAD = "captured JWT payload is invalid";
const HEADER_MISMATCH = "captured JWT protected header does not match fixture";
const CLAIMS_MISMATCH = "captured JWT claims do not match fixture";

export async function assertJwt(
  token: unknown, expected: JwtExpectation, signingPublicKey: CryptoKey,
): Promise<void> {
  const parts = compactParts(token);
  const protectedBytes = canonicalBytes(parts[0]);
  canonicalBytes(parts[1]);
  canonicalBytes(parts[2]);
  const protectedHeader = jsonObject(protectedBytes, INVALID_HEADER);

  let verified;
  try {
    verified = await compactVerify(token as string, signingPublicKey, { algorithms: ["ES256"] });
  } catch {
    throw new FixtureRunnerError(INVALID_TOKEN);
  }
  if (!sameValue(protectedHeader, expected.header)) throw new FixtureRunnerError(HEADER_MISMATCH);
  const claims = jsonObject(verified.payload, INVALID_PAYLOAD);
  if (!sameValue(claims, expected.claims)) throw new FixtureRunnerError(CLAIMS_MISMATCH);
}

function compactParts(token: unknown): [string, string, string] {
  if (typeof token !== "string") throw new FixtureRunnerError(INVALID_TOKEN);
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new FixtureRunnerError(INVALID_TOKEN);
  }
  return [parts[0]!, parts[1]!, parts[2]!];
}

function canonicalBytes(segment: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(segment) || segment.length % 4 === 1) {
    throw new FixtureRunnerError(INVALID_TOKEN);
  }
  const bytes = Buffer.from(segment, "base64url");
  if (bytes.toString("base64url") !== segment) throw new FixtureRunnerError(INVALID_TOKEN);
  return bytes;
}

function jsonObject(bytes: Uint8Array, errorMessage: string): Record<string, unknown> {
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    if (source.startsWith("\uFEFF")) throw new SyntaxError("BOM");
    const value = parseStrictJson(source);
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new SyntaxError("object required");
    }
    return value as Record<string, unknown>;
  } catch {
    throw new FixtureRunnerError(errorMessage);
  }
}

function sameValue(actual: unknown, expected: unknown): boolean {
  try {
    assert.deepStrictEqual(actual, expected);
    return true;
  } catch {
    return false;
  }
}
