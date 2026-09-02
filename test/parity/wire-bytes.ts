import type { HeaderMap } from "./types.ts";
import { FixtureRunnerError } from "./error.ts";

export const WIRE_HEADER_BYTE_BOUND = 65536;

/** Contract 19.2: all name and value bytes of one wire header map total at most
 *  65536 UTF-8 bytes, counted after capture resolution, because JSON Schema
 *  counts characters and a resolved capture carries bytes no schema saw. */
export function assertWireHeaderPairBytes(pairs: Array<[string, string]>): void {
  let total = 0;
  for (const [name, value] of pairs) {
    total += Buffer.byteLength(name, "utf8") + Buffer.byteLength(value, "utf8");
  }
  if (total > WIRE_HEADER_BYTE_BOUND) {
    throw new FixtureRunnerError(`wire header map totals ${total} UTF-8 bytes, above the 65536 byte bound`);
  }
}

export function assertWireHeaderBytes(headers: HeaderMap | Record<string, string | string[]>): void {
  let total = 0;
  for (const [name, raw] of Object.entries(headers)) {
    for (const value of Array.isArray(raw) ? raw : [raw]) {
      if (typeof value !== "string") continue;
      total += Buffer.byteLength(name, "utf8") + Buffer.byteLength(value, "utf8");
    }
  }
  if (total > WIRE_HEADER_BYTE_BOUND) {
    throw new FixtureRunnerError(`wire header map totals ${total} UTF-8 bytes, above the 65536 byte bound`);
  }
}
