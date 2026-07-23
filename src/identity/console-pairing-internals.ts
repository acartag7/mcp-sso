import { randomBytes, timingSafeEqual } from "node:crypto";
import { snapshotOwnDataRecord } from "../own-property.ts";

export const PAIRING_CHARSET = "BCDFGHJKLMNPQRSTVWXZ";
const BASE = 20;
const CODE_LENGTH = 12;
const REJECT_THRESHOLD = Math.floor(256 / BASE) * BASE;

export function canonicalizePairingCode(input: string): string {
  let out = "";
  for (const char of input.toUpperCase()) {
    if (PAIRING_CHARSET.includes(char)) out += char;
  }
  return out;
}

export function timingSafeStringEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  return left.length === right.length && timingSafeEqual(left, right);
}

export function generatePairingCode(): string {
  let out = "";
  while (out.length < CODE_LENGTH) {
    const bytes = randomBytes(CODE_LENGTH * 2);
    for (let index = 0; index < bytes.length && out.length < CODE_LENGTH; index += 1) {
      const byte = bytes[index];
      if (byte === undefined || byte >= REJECT_THRESHOLD) continue;
      out += PAIRING_CHARSET[byte % BASE]!;
    }
  }
  return out;
}

export function formatPairingCode(code: string): string {
  return `${code.slice(0, 4)}-${code.slice(4, 8)}-${code.slice(8, 12)}`;
}

export function asVerifyInput(input: unknown): { code?: string; nonce?: string; ip?: string } {
  if (typeof input === "string") return { code: input, nonce: "" };
  const fields = snapshotOwnDataRecord(input);
  if (fields === null) return {};
  const stringValue = (value: unknown): string | undefined =>
    typeof value === "string" ? value : undefined;
  return {
    code: stringValue(fields.code), nonce: stringValue(fields.nonce),
    ip: stringValue(fields.ip),
  };
}

export function positiveIntegerOption(value: unknown, fallback: number, name: string): number {
  const result = value === undefined ? fallback : value;
  if (typeof result !== "number" || !Number.isInteger(result) || result <= 0) {
    throw new TypeError(`${name} must be a positive integer`);
  }
  return result;
}
