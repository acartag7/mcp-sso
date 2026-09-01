import { randomBytes } from "node:crypto";

/** Byte-oriented entropy seam used by fixture runs. Production uses Node CSPRNG. */
export interface RandomPort {
  bytes(length: number): Uint8Array;
}

export const systemRandom: RandomPort = Object.freeze({
  bytes(length: number): Uint8Array {
    return randomBytes(length);
  },
});
