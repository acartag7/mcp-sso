import { FixtureRunnerError } from "./error.ts";
import { isApplicationJsonContentType } from "./content-type.ts";
import { parseStrictJson } from "./strict-json.ts";

export type Observation =
  | { present: false; value?: never }
  | { present: true; value: unknown };

export function headerObservation(
  headers: Record<string, string | string[]>, name: string,
): Observation {
  const key = name.toLowerCase();
  if (!Object.hasOwn(headers, key)) return { present: false };
  return { present: true, value: headers[key] };
}

export function bodyObservation(
  body: Buffer | undefined, headers: Record<string, string | string[]>,
): Observation {
  if (body === undefined || body.byteLength === 0) return { present: false };
  const text = decodeUtf8(body);
  const contentType = headerObservation(headers, "content-type");
  const value = contentType.present && typeof contentType.value === "string"
    ? contentType.value : undefined;
  if (value !== undefined && isApplicationJsonContentType(value)) {
    try { return { present: true, value: parseStrictJson(text) }; }
    catch (error) {
      throw new FixtureRunnerError("observed application/json body is invalid", { cause: error });
    }
  }
  return { present: true, value: text };
}

function decodeUtf8(body: Buffer): string {
  try { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body); }
  catch (error) { throw new FixtureRunnerError("observed body is not valid UTF-8", { cause: error }); }
}
