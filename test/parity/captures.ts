import type { CaptureReference, CaptureValues, HeaderMap, RequestSpec } from "./types.ts";
import { contentTypeEssence } from "./content-type.ts";
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
    const encoded = JSON.stringify(resolveJson(body.json, captures));
    if (encoded === undefined) throw new FixtureRunnerError("JSON body value is not JSON-serializable");
    return { method: request.method, path: request.path, headers, body: Buffer.from(encoded, "utf8") };
  }
  if ("form" in body && body.form !== undefined) {
    requireEssence(contentTypes, "application/x-www-form-urlencoded", "form");
    const fields = body.form.map(({ name, value }) => [name, resolveString(value, captures, false)] as [string, string]);
    return { method: request.method, path: request.path, headers,
      body: Buffer.from(new URLSearchParams(fields).toString(), "utf8") };
  }
  if (contentTypes.length !== 1) throw new FixtureRunnerError("text body requires one Content-Type occurrence");
  return { method: request.method, path: request.path, headers,
    body: Buffer.from(resolveString(body.text, captures, false), "utf8") };
}

function resolveHeaders(headers: HeaderMap, captures: CaptureValues): Array<[string, string]> {
  const output: Array<[string, string]> = [];
  for (const [name, raw] of Object.entries(headers)) {
    for (const value of Array.isArray(raw) ? raw : [raw]) {
      const resolved = resolveString(value, captures, name === "authorization");
      if (/[\r\n]/u.test(resolved)) throw new FixtureRunnerError("HTTP request headers cannot contain CR or LF");
      output.push([name, resolved]);
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
  if (!isExactObject(value, ["$capture"])) return false;
  const capture = value.$capture;
  return isExactObject(capture, ["fixture", "name", "format"])
    && typeof capture.fixture === "string" && typeof capture.name === "string"
    && (capture.format === "raw" || capture.format === "bearer");
}

function isExactObject(value: unknown, keys: string[]): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function requireEssence(values: string[], expected: string, label: string): void {
  const essence = values.length === 1 ? contentTypeEssence(values[0]!) : undefined;
  if (essence !== expected) throw new FixtureRunnerError(`${label} body requires Content-Type ${expected}`);
}
