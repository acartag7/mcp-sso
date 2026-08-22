// Shared runtime boundary for verified identity subjects and claims
// (contracts §6.5 / §17.11). Identity-port values remain untrusted even when
// TypeScript says `IdentityClaims`.

import type { IdentityClaims } from "./ports/identity.ts";
import { assertAllowedScopesCeiling } from "./scopes.ts";
import { isProxy } from "node:util/types";

const MAX_SUBJECT_SCALARS = 384;
const MAX_CLAIM_DEPTH = 4;
const MAX_CLAIM_ITEMS = 64;
const MAX_CLAIM_KEY_BYTES = 128;
const MAX_CLAIM_STRING_BYTES = 4096;
const MAX_CLAIMS_JSON_BYTES = 16384;

export function identitySubject(value: unknown): string {
  if (typeof value !== "string"
    || !isWellFormed(value)
    || value.includes("\uFFFD")
    || value !== value.trim()) {
    throw new TypeError("identity subject is malformed");
  }
  let scalars = 0;
  for (const _character of value) {
    scalars += 1;
    if (scalars > MAX_SUBJECT_SCALARS) throw new TypeError("identity subject is too long");
  }
  if (scalars === 0) throw new TypeError("identity subject is empty");
  return value;
}

/** Snapshot the identity fields used by either completion. `includeClaims`
 * keeps bridge completion compatible: optional attributes stay unread there. */
export function snapshotIdentityClaims(value: unknown, includeClaims: boolean): IdentityClaims {
  const record = requiredRecord(value, "identity");
  const subject = identitySubject(record.subject);
  const allowedScopes = assertAllowedScopesCeiling(record.allowedScopes);
  const scopeSnapshot = allowedScopes === undefined
    ? undefined : Object.freeze([...allowedScopes]) as string[];
  const claims = includeClaims && Object.hasOwn(record, "claims")
    ? snapshotVerifiedClaims(record.claims) : undefined;
  return Object.freeze({
    subject,
    ...(scopeSnapshot === undefined ? {} : { allowedScopes: scopeSnapshot }),
    ...(claims === undefined ? {} : { claims }),
  });
}

export function snapshotVerifiedClaims(value: unknown): Record<string, unknown> | undefined {
  if (value === undefined) return undefined;
  const state = { items: 0, stack: new WeakSet<object>() };
  const snapshot = projectRecord(value, 0, state);
  let serialized: string;
  try { serialized = JSON.stringify(snapshot); }
  catch { throw new TypeError("identity claims cannot be serialized"); }
  if (Buffer.byteLength(serialized, "utf8") > MAX_CLAIMS_JSON_BYTES) {
    throw new TypeError("identity claims are too large");
  }
  return snapshot;
}

interface ProjectionState {
  items: number;
  stack: WeakSet<object>;
}

function projectValue(value: unknown, depth: number, state: ProjectionState): unknown {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("identity claim number must be finite");
    return value;
  }
  if (typeof value === "string") {
    if (!isWellFormed(value)
      || Buffer.byteLength(value, "utf8") > MAX_CLAIM_STRING_BYTES) {
      throw new TypeError("identity claim string is malformed or too large");
    }
    return value;
  }
  if (typeof value !== "object") throw new TypeError("identity claim is not JSON data");
  if (depth > MAX_CLAIM_DEPTH) throw new TypeError("identity claims are too deep");
  return Array.isArray(value)
    ? projectArray(value, depth, state)
    : projectRecord(value, depth, state);
}

function projectArray(value: unknown[], depth: number, state: ProjectionState): readonly unknown[] {
  if (isProxy(value)) throw new TypeError("identity claim array cannot be a proxy");
  let proto: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    proto = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value) as unknown as PropertyDescriptorMap;
  } catch { throw new TypeError("identity claim array cannot be inspected"); }
  if (proto !== Array.prototype) throw new TypeError("identity claim array has an unexpected prototype");
  const length = value.length;
  if (!Number.isSafeInteger(length) || length < 0) throw new TypeError("identity claim array length is malformed");
  enter(value, state);
  try {
    const out: unknown[] = [];
    for (let index = 0; index < length; index += 1) {
      countItem(state);
      const descriptor = descriptors[String(index)];
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new TypeError("identity claim array must be dense data");
      }
      if (descriptor.value === undefined) throw new TypeError("identity claim array member is undefined");
      out.push(projectValue(descriptor.value, depth + 1, state));
    }
    const keys = Reflect.ownKeys(descriptors).filter((key) => key !== "length");
    if (keys.length !== length || keys.some((key) => typeof key !== "string" || !/^\d+$/u.test(key))) {
      throw new TypeError("identity claim array has unexpected properties");
    }
    return Object.freeze(out);
  } finally { state.stack.delete(value); }
}

function projectRecord(value: unknown, depth: number, state: ProjectionState): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("identity claims must be a record");
  }
  if (isProxy(value)) throw new TypeError("identity claim record cannot be a proxy");
  let proto: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    proto = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch { throw new TypeError("identity claim record cannot be inspected"); }
  if (proto !== Object.prototype && proto !== null) {
    throw new TypeError("identity claim record has an unexpected prototype");
  }
  enter(value, state);
  try {
    const out = Object.create(null) as Record<string, unknown>;
    for (const key of Reflect.ownKeys(descriptors)) {
      if (typeof key !== "string") throw new TypeError("identity claim symbol keys are not allowed");
      countItem(state);
      if (Buffer.byteLength(key, "utf8") > MAX_CLAIM_KEY_BYTES) {
        throw new TypeError("identity claim key is too large");
      }
      const descriptor = descriptors[key];
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new TypeError("identity claims must contain enumerable data properties");
      }
      if (descriptor.value === undefined) continue;
      Object.defineProperty(out, key, {
        value: projectValue(descriptor.value, depth + 1, state),
        enumerable: true, configurable: false, writable: false,
      });
    }
    return Object.freeze(out);
  } finally { state.stack.delete(value); }
}

function enter(value: object, state: ProjectionState): void {
  if (state.stack.has(value)) throw new TypeError("identity claims contain a cycle");
  state.stack.add(value);
}

function countItem(state: ProjectionState): void {
  state.items += 1;
  if (state.items > MAX_CLAIM_ITEMS) throw new TypeError("identity claims contain too many items");
}

function isWellFormed(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xD800 && unit <= 0xDBFF) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xDC00 || next > 0xDFFF) return false;
      index += 1;
    } else if (unit >= 0xDC00 && unit <= 0xDFFF) return false;
  }
  return true;
}

function requiredRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  if (isProxy(value)) throw new TypeError(`${label} cannot be a proxy`);
  return value as Record<string, unknown>;
}
