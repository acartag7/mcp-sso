import assert from "node:assert/strict";
import { compactVerify } from "jose";
import type {
  CaptureReference, CaptureSpec, CaptureValues, HeaderMap, ObservedMessage, RequestSpec,
} from "./types.ts";
import { publicKey } from "./config.ts";
import { FixtureRunnerError } from "./error.ts";

export function materializeRequest(
  request: RequestSpec, captures: CaptureValues,
): { method: string; path: string; headers: Array<[string, string]>; body?: Buffer } {
  const headers = resolveHeaders(request.headers ?? {}, captures);
  const contentTypes = headers.filter(([name]) => name === "content-type").map(([, value]) => value);
  const body = request.body;
  if (body === undefined) return { method: request.method, path: request.path, headers };
  if ("json" in body) {
    requireEssence(contentTypes, "application/json", "JSON");
    return { method: request.method, path: request.path, headers,
      body: Buffer.from(JSON.stringify(resolveJson(body.json, captures)), "utf8") };
  }
  if ("form" in body) {
    requireEssence(contentTypes, "application/x-www-form-urlencoded", "form");
    const fields = body.form.map(({ name, value }) => [name, resolveString(value, captures, false)] as [string, string]);
    return { method: request.method, path: request.path, headers,
      body: Buffer.from(new URLSearchParams(fields).toString(), "utf8") };
  }
  if (contentTypes.length !== 1) throw new FixtureRunnerError("text body requires one Content-Type occurrence");
  return { method: request.method, path: request.path, headers,
    body: Buffer.from(resolveString(body.text, captures, false), "utf8") };
}

export async function captureResponse(
  fixtureId: string, specs: CaptureSpec[] | undefined, response: ObservedMessage,
  publicKeyPath: string, captures: CaptureValues,
): Promise<void> {
  if (!specs?.length) return;
  const values = new Map<string, string>();
  for (const spec of specs) {
    if (values.has(spec.name)) throw new FixtureRunnerError(`${fixtureId}: duplicate capture name ${spec.name}`);
    const value = "bodyPointer" in spec.source
      ? bodyPointer(response, spec.source.bodyPointer)
      : headerQuery(response, spec.source.header, spec.source.urlQuery);
    if (spec.jwt) await assertJwt(value, spec.jwt, publicKeyPath);
    values.set(spec.name, value);
  }
  captures.set(fixtureId, values);
}

function resolveHeaders(headers: HeaderMap, captures: CaptureValues): Array<[string, string]> {
  const output: Array<[string, string]> = [];
  for (const [name, raw] of Object.entries(headers)) {
    for (const value of Array.isArray(raw) ? raw : [raw]) {
      output.push([name, resolveString(value, captures, name === "authorization")]);
    }
  }
  return output;
}

function resolveJson(value: unknown, captures: CaptureValues): unknown {
  if (isCapture(value)) return resolveString(value, captures, false);
  if (Array.isArray(value)) return value.map((entry) => resolveJson(entry, captures));
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, resolveJson(entry, captures)]));
  }
  return value;
}

function resolveString(value: string | CaptureReference, captures: CaptureValues, allowBearer: boolean): string {
  if (typeof value === "string") return value;
  if (value.$capture.format === "bearer" && !allowBearer) {
    throw new FixtureRunnerError("bearer capture format is valid only for an Authorization header");
  }
  const raw = captureValue(value, captures);
  return value.$capture.format === "bearer" ? `Bearer ${raw}` : raw;
}

function captureValue(reference: CaptureReference, captures: CaptureValues): string {
  const { fixture, name } = reference.$capture;
  const value = captures.get(fixture)?.get(name);
  if (value === undefined) throw new FixtureRunnerError(`missing or out-of-chain capture ${fixture}:${name}`);
  return value;
}

function isCapture(value: unknown): value is CaptureReference {
  return typeof value === "object" && value !== null && Object.hasOwn(value, "$capture");
}

function requireEssence(values: string[], expected: string, label: string): void {
  const essence = values.length === 1 ? values[0]!.split(";", 1)[0]!.trim().toLowerCase() : undefined;
  if (essence !== expected) throw new FixtureRunnerError(`${label} body requires Content-Type ${expected}`);
}

function bodyPointer(response: ObservedMessage, pointer: string): string {
  const contentType = response.headers["content-type"];
  if (typeof contentType !== "string" || contentType.split(";", 1)[0]!.trim().toLowerCase() !== "application/json") {
    throw new FixtureRunnerError("body capture requires one application/json Content-Type occurrence");
  }
  let value: unknown;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(response.body)); }
  catch (error) { throw new FixtureRunnerError("body capture response is not valid JSON", { cause: error }); }
  for (const token of pointer.slice(1).split("/")) {
    if (/~(?:[^01]|$)/u.test(token)) throw new FixtureRunnerError(`JSON Pointer escape is malformed: ${pointer}`);
    const key = token.replace(/~1/gu, "/").replace(/~0/gu, "~");
    if (typeof value !== "object" || value === null || !Object.hasOwn(value, key)) {
      throw new FixtureRunnerError(`JSON Pointer did not select a value: ${pointer}`);
    }
    value = (value as Record<string, unknown>)[key];
  }
  if (typeof value !== "string") throw new FixtureRunnerError(`JSON Pointer capture is not a string: ${pointer}`);
  return value;
}

function headerQuery(response: ObservedMessage, name: string, parameter: string): string {
  const raw = response.headers[name];
  if (typeof raw !== "string") throw new FixtureRunnerError(`header capture requires exactly one ${name} occurrence`);
  let url: URL;
  try { url = new URL(raw); }
  catch (error) { throw new FixtureRunnerError(`header capture ${name} is not a URL`, { cause: error }); }
  const values = url.searchParams.getAll(parameter);
  if (values.length !== 1) throw new FixtureRunnerError(`header capture query ${parameter} is missing or ambiguous`);
  return values[0]!;
}

async function assertJwt(
  token: string, expected: NonNullable<CaptureSpec["jwt"]>, publicKeyPath: string,
): Promise<void> {
  const verified = await compactVerify(token, await publicKey(publicKeyPath), { algorithms: ["ES256"] });
  let claims: unknown;
  try { claims = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(verified.payload)); }
  catch (error) { throw new FixtureRunnerError("captured JWT payload is not JSON", { cause: error }); }
  assert.deepStrictEqual(verified.protectedHeader, expected.header, "captured JWT protected header");
  assert.deepStrictEqual(claims, expected.claims, "captured JWT claims");
}
