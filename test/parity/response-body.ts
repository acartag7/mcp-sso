import type { BodyValue } from "./types.ts";
import { FixtureRunnerError } from "./error.ts";
import { isApplicationJsonContentType } from "./content-type.ts";
import { headerObservation } from "./observations.ts";

type ResponseHeaders = Record<string, string | string[]>;

export function encodeResponseBody(body: BodyValue, headers: ResponseHeaders): Buffer {
  if ("absent" in body) return Buffer.alloc(0);
  const contentType = headerObservation(headers, "content-type");
  const raw = contentType.present ? contentType.value : undefined;
  const value = typeof raw === "string" ? raw
    : Array.isArray(raw) && raw.length === 1 && typeof raw[0] === "string" ? raw[0] : undefined;
  const isJson = value !== undefined && isApplicationJsonContentType(value);
  const encoded = isJson
    ? JSON.stringify(body.value)
    : typeof body.value === "string" ? body.value : JSON.stringify(body.value);
  if (encoded === undefined) throw new FixtureRunnerError("response body value is not JSON-serializable");
  return Buffer.from(encoded, "utf8");
}
