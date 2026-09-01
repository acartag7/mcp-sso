import { randomBytes } from "node:crypto";

const typedArrayByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype) as object, "byteLength",
)?.get as (this: Uint8Array) => number;

/** Byte-oriented entropy seam used by fixture runs. Production uses Node CSPRNG. */
export interface RandomPort {
  bytes(length: number): Uint8Array;
}

export const systemRandom: RandomPort = Object.freeze({
  bytes(length: number): Uint8Array {
    return randomBytes(length);
  },
});

/** Snapshot and validate a custom port result before a generated value uses it. */
export function randomBytesFrom(random: RandomPort, length: number): Buffer {
  if (!Number.isSafeInteger(length) || length <= 0) {
    throw new RangeError("random byte length must be a positive safe integer");
  }
  const value = random.bytes(length);
  if (!(value instanceof Uint8Array)) {
    throw new TypeError("RandomPort returned the wrong byte count");
  }
  try {
    if (typedArrayByteLength.call(value) !== length) {
      throw new TypeError("RandomPort returned the wrong byte count");
    }
    const snapshot = Buffer.from(value);
    if (snapshot.byteLength !== length) {
      throw new TypeError("RandomPort returned the wrong byte count");
    }
    return snapshot;
  } catch {
    throw new TypeError("RandomPort returned the wrong byte count");
  }
}
