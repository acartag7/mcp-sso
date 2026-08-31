import type { BodyValue } from "./types.ts";
import { FixtureRunnerError } from "./error.ts";

type ResponseHeaders = Record<string, string | string[]>;

export function encodeResponseBody(body: BodyValue, headers: ResponseHeaders): Buffer {
  if ("absent" in body) return Buffer.alloc(0);
  const encoded = hasJsonContentType(headers)
    ? JSON.stringify(body.value)
    : typeof body.value === "string" ? body.value : JSON.stringify(body.value);
  if (encoded === undefined) throw new FixtureRunnerError("response body value is not JSON-serializable");
  return Buffer.from(encoded, "utf8");
}

function hasJsonContentType(headers: ResponseHeaders): boolean {
  const raw = headers["content-type"];
  const value = Array.isArray(raw) && raw.length === 1 ? raw[0] : raw;
  if (typeof value !== "string") return false;
  return value.split(";", 1)[0]!.trim().toLowerCase() === "application/json";
}
