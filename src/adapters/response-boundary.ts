import type { NormResponse } from "./http.ts";
import { isProxy } from "node:util/types";

const RESPONSE_KEYS = new Set(["status", "headers", "setCookies", "body", "redirect"]);
const FORBIDDEN_HEADERS = new Set(["connection", "content-length", "trailer", "transfer-encoding", "upgrade"]);
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u;
const URI_REFERENCE = /^(?:[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})+$/u;

export function snapshotCompletionResponse(value: unknown): NormResponse {
  const response = inspectRecord(value, "completion response");
  rejectUnknownKeys(response.descriptors, RESPONSE_KEYS, "completion response");
  const status = dataValue(response.descriptors, "status", true);
  if (!Number.isInteger(status)) throw new TypeError("completion status must be an integer");
  const headers = snapshotHeaders(dataValue(response.descriptors, "headers", true));
  const setCookiesMember = optionalDataValue(response.descriptors, "setCookies");
  const setCookies = setCookiesMember.present ? snapshotCookies(setCookiesMember.value) : undefined;
  const bodyMember = optionalDataValue(response.descriptors, "body");
  const redirectMember = optionalDataValue(response.descriptors, "redirect");
  const outputHeaders = withNoStore(headers);
  if (!redirectMember.present) {
    if ((status as number) < 200 || (status as number) > 299) throw new TypeError("completion body status is invalid");
    if (bodyMember.present && typeof bodyMember.value !== "string") throw new TypeError("completion body must be a string");
    if (typeof bodyMember.value === "string") {
      if (Buffer.byteLength(bodyMember.value, "utf8") > 65_536) throw new TypeError("completion body is too large");
      if (!hasNonEmptyHeader(outputHeaders, "content-type")) throw new TypeError("completion string body requires Content-Type");
    }
    if (((status as number) === 204 || (status as number) === 205) && bodyMember.present) throw new TypeError("completion status cannot carry a body");
    return Object.freeze({ status: status as number, headers: Object.freeze(outputHeaders), ...(setCookies ? { setCookies } : {}), ...(bodyMember.present ? { body: bodyMember.value } : {}) });
  }
  const redirect = redirectMember.value;
  if (typeof redirect !== "string" || !REDIRECT_STATUSES.has(status as number)
    || Buffer.byteLength(redirect, "ascii") > 2048 || !URI_REFERENCE.test(redirect)) {
    throw new TypeError("completion redirect is invalid");
  }
  if (bodyMember.present) throw new TypeError("completion redirect cannot carry a body");
  const location = headerValue(outputHeaders, "location");
  if (location !== undefined && location !== redirect) throw new TypeError("completion Location does not match redirect");
  defineHeader(outputHeaders, "location", redirect);
  return Object.freeze({ status: status as number, headers: Object.freeze(outputHeaders), ...(setCookies ? { setCookies } : {}), redirect });
}

function snapshotHeaders(value: unknown): Record<string, string> {
  const input = inspectRecord(value, "completion headers");
  const keys = Reflect.ownKeys(input.descriptors);
  if (keys.length > 64) throw new TypeError("completion has too many headers");
  const output = Object.create(null) as Record<string, string>;
  const folded = new Set<string>();
  let bytes = 0;
  for (const key of keys) {
    if (typeof key !== "string" || !TOKEN.test(key) || Buffer.byteLength(key, "ascii") > 256) throw new TypeError("completion header name is invalid");
    const lower = key.toLowerCase();
    if (folded.has(lower)) throw new TypeError("completion header name is duplicated");
    folded.add(lower);
    if (FORBIDDEN_HEADERS.has(lower)) throw new TypeError("completion header is transport-owned");
    const item = descriptorValue(input.descriptors[key], "completion header");
    if (typeof item !== "string") throw new TypeError("completion header value must be a string");
    const limit = lower === "set-cookie" ? 4096 : 8192;
    if (lower === "set-cookie" && item.length === 0) throw new TypeError("completion cookie is empty");
    if (lower === "set-cookie") validateCookieValue(item);
    else validateAsciiValue(item, limit, "completion header value");
    bytes += Buffer.byteLength(key, "ascii") + Buffer.byteLength(item, "ascii");
    if (bytes > 32_768) throw new TypeError("completion headers are too large");
    defineHeader(output, key, item);
  }
  return output;
}

function snapshotCookies(value: unknown): string[] {
  if (!Array.isArray(value)) throw new TypeError("completion setCookies must be an array");
  if (isProxy(value)) throw new TypeError("completion setCookies cannot be a proxy");
  const descriptors = safeDescriptors(value);
  if (value.length > 15) throw new TypeError("completion has too many cookies");
  const keys = Reflect.ownKeys(descriptors).filter((key) => key !== "length");
  if (keys.length !== value.length) throw new TypeError("completion cookies must be dense");
  const output: string[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const item = descriptorValue(descriptors[String(index)], "completion cookie");
    if (typeof item !== "string" || item.length === 0) throw new TypeError("completion cookie must be a non-empty string");
    validateCookieValue(item);
    output.push(item);
  }
  return Object.freeze(output) as string[];
}

function validateCookieValue(value: string): void {
  validateAsciiValue(value, 4096, "completion cookie");
  if (value.includes("\t")) throw new TypeError("completion cookie is invalid");
}

function validateAsciiValue(value: string, limit: number, label: string): void {
  if (Buffer.byteLength(value, "ascii") > limit || /[^\x09\x20-\x7E]/u.test(value)
    || (value.length > 0 && (value[0] === " " || value.at(-1) === " "))) throw new TypeError(`${label} is invalid`);
}

function withNoStore(headers: Record<string, string>): Record<string, string> {
  const output = Object.create(null) as Record<string, string>;
  for (const [key, value] of Object.entries(headers)) if (key.toLowerCase() !== "cache-control") defineHeader(output, key, value);
  defineHeader(output, "cache-control", "no-store");
  return output;
}

function defineHeader(target: Record<string, string>, key: string, value: string): void {
  for (const existing of Object.keys(target)) if (existing.toLowerCase() === key.toLowerCase()) delete target[existing];
  Object.defineProperty(target, key, { value, enumerable: true, writable: false, configurable: true });
}

function hasNonEmptyHeader(headers: Record<string, string>, name: string): boolean {
  const value = headerValue(headers, name);
  return value !== undefined && value.length > 0;
}

function headerValue(headers: Record<string, string>, name: string): string | undefined {
  return Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1];
}

function inspectRecord(value: unknown, label: string): { descriptors: PropertyDescriptorMap } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`${label} must be a record`);
  if (isProxy(value)) throw new TypeError(`${label} cannot be a proxy`);
  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  try { prototype = Object.getPrototypeOf(value); descriptors = safeDescriptors(value); }
  catch { throw new TypeError(`${label} cannot be inspected`); }
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError(`${label} has an unexpected prototype`);
  return { descriptors };
}

function safeDescriptors(value: object): PropertyDescriptorMap {
  return Object.getOwnPropertyDescriptors(value) as PropertyDescriptorMap;
}

function rejectUnknownKeys(descriptors: PropertyDescriptorMap, allowed: Set<string>, label: string): void {
  for (const key of Reflect.ownKeys(descriptors)) if (typeof key !== "string" || !allowed.has(key)) throw new TypeError(`${label} has an unknown key`);
}

function dataValue(descriptors: PropertyDescriptorMap, key: string, required: boolean): unknown {
  const descriptor = descriptors[key];
  if (!descriptor) {
    if (required) throw new TypeError(`completion response missing ${key}`);
    return undefined;
  }
  return descriptorValue(descriptor, `completion response ${key}`);
}

function optionalDataValue(descriptors: PropertyDescriptorMap, key: string): { present: boolean; value?: unknown } {
  const descriptor = descriptors[key];
  return descriptor === undefined
    ? { present: false }
    : { present: true, value: descriptorValue(descriptor, `completion response ${key}`) };
}

function descriptorValue(descriptor: PropertyDescriptor | undefined, label: string): unknown {
  if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) throw new TypeError(`${label} must be an enumerable data property`);
  return descriptor.value;
}
