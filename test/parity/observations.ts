import { FixtureRunnerError } from "./error.ts";

export type Observation = { present: false; value?: never } | { present: true; value: unknown };

export function headerObservation(
  headers: Record<string, string | string[]>, name: string,
): Observation {
  const value = headers[name.toLowerCase()];
  return value === undefined ? { present: false } : { present: true, value };
}

export function bodyObservation(
  body: Buffer | undefined, headers: Record<string, string | string[]>,
): Observation {
  if (body === undefined || body.byteLength === 0) return { present: false };
  const text = decodeUtf8(body);
  const contentType = headers["content-type"];
  const single = typeof contentType === "string" ? contentType : undefined;
  const essence = single?.split(";", 1)[0];
  if (trimHttpWhitespace(essence).toLowerCase() === "application/json") {
    try { return { present: true, value: JSON.parse(text) }; }
    catch (error) { throw new FixtureRunnerError("observed application/json body is invalid", { cause: error }); }
  }
  return { present: true, value: text };
}

function trimHttpWhitespace(value: string | undefined): string {
  return value?.replace(/^[ \t]+|[ \t]+$/g, "") ?? "";
}

function decodeUtf8(body: Buffer): string {
  try { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body); }
  catch (error) { throw new FixtureRunnerError("observed body is not valid UTF-8", { cause: error }); }
}
