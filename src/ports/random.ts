import { randomBytes } from "node:crypto";

const safeApply = Reflect.apply;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
const typedArrayByteLength = Object.getOwnPropertyDescriptor(
  typedArrayPrototype, "byteLength",
)?.get as (this: Uint8Array) => number;
const typedArrayName = Object.getOwnPropertyDescriptor(
  typedArrayPrototype, Symbol.toStringTag,
)?.get as (this: Uint8Array) => string;
const setUint8Array = Uint8Array.prototype.set;
const allocateBuffer = Buffer.allocUnsafe;

const WRONG_BYTE_COUNT = "RandomPort returned the wrong byte count";

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
  try {
    const name = safeApply(typedArrayName, value, []);
    const byteLength = safeApply(typedArrayByteLength, value, []);
    if (name !== "Uint8Array" || byteLength !== length) {
      throw new TypeError(WRONG_BYTE_COUNT);
    }

    const snapshot = allocateBuffer(length);
    safeApply(setUint8Array, snapshot, [value]);
    if (safeApply(typedArrayByteLength, snapshot, []) !== length) {
      throw new TypeError(WRONG_BYTE_COUNT);
    }
    return snapshot;
  } catch {
    throw new TypeError(WRONG_BYTE_COUNT);
  }
}
