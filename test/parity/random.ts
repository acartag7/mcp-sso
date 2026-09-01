import { createHash, createHmac } from "node:crypto";
import type { RandomPort } from "../../src/ports/random.ts";
import { FixtureRunnerError } from "./error.ts";

const DOMAIN = Buffer.from("mcp-sso-fixture-random-v1", "ascii");
const MAX_COUNTER = 0xffff_ffff_ffff_ffffn;

export class SeededRandom implements RandomPort {
  readonly #key: Buffer;
  #counter = 0n;
  #unused = Buffer.alloc(0);

  constructor(seed: string) {
    if (typeof seed !== "string" || seed.length === 0 || hasUnpairedSurrogate(seed)) {
      throw new FixtureRunnerError("random seed must be a non-empty well-formed UTF-8 string");
    }
    const bytes = Buffer.from(seed, "utf8");
    if (bytes.byteLength > 1_024) throw new FixtureRunnerError("random seed exceeds 1024 UTF-8 bytes");
    this.#key = createHash("sha256").update(DOMAIN).update(Buffer.of(0)).update(bytes).digest();
  }

  bytes(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length <= 0) {
      throw new FixtureRunnerError("random byte count must be a positive safe integer");
    }
    while (this.#unused.byteLength < length) {
      if (this.#counter > MAX_COUNTER) throw new FixtureRunnerError("random counter exhausted");
      const counter = Buffer.alloc(8);
      counter.writeBigUInt64BE(this.#counter);
      const block = createHmac("sha256", this.#key).update(counter).digest();
      this.#unused = Buffer.concat([this.#unused, block]);
      this.#counter += 1n;
    }
    const output = Buffer.from(this.#unused.subarray(0, length));
    this.#unused = Buffer.from(this.#unused.subarray(length));
    return output;
  }
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) return true;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}
