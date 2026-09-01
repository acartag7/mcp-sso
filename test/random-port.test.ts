import assert from "node:assert/strict";
import { test } from "node:test";

import { randomBytesFrom, systemRandom } from "../src/ports/random.ts";
import type { RandomPort } from "../src/ports/random.ts";

const WRONG_BYTE_COUNT = "RandomPort returned the wrong byte count";
const typedArrayByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype) as object, "byteLength",
)?.get as (this: Uint8Array) => number;

function malformedPort(value: unknown): RandomPort {
  return { bytes: () => value as Uint8Array };
}

function assertWrongByteCount(value: unknown, length: number): void {
  assert.throws(() => randomBytesFrom(malformedPort(value), length), {
    name: "TypeError",
    message: WRONG_BYTE_COUNT,
  });
}

test("randomBytesFrom rejects invalid lengths before calling the port", () => {
  for (const length of [
    0,
    -1,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
    Number.MAX_SAFE_INTEGER + 1,
  ]) {
    let calls = 0;
    let thrown: unknown;
    try {
      randomBytesFrom({
        bytes: () => {
          calls += 1;
          return new Uint8Array(1);
        },
      }, length);
    } catch (error) {
      thrown = error;
    }

    assert.equal(calls, 0, `port was called for ${String(length)}`);
    assert.deepEqual(thrown, new RangeError(
      "random byte length must be a positive safe integer",
    ));
  }
});

test("randomBytesFrom rejects wrong result types and intrinsic byte counts", () => {
  assertWrongByteCount(new ArrayBuffer(4), 4);
  assertWrongByteCount(new DataView(new ArrayBuffer(4)), 4);
  assertWrongByteCount(new Int8Array(4), 4);
  assertWrongByteCount(new Uint16Array(2), 4);
  assertWrongByteCount(new Uint8Array(3), 4);
  assertWrongByteCount(new Uint8Array(5), 4);
  assertWrongByteCount(new Proxy(new Uint8Array(4), {}), 4);
});

test("randomBytesFrom rejects shadowed typed-array sizes", () => {
  const disguisedShort = new Uint8Array(3);
  Object.defineProperties(disguisedShort, {
    byteLength: { value: 4 },
    length: { value: 4 },
  });
  assertWrongByteCount(disguisedShort, 4);

  const poisonedBuffer = Buffer.from([1, 2, 3]);
  Object.defineProperties(poisonedBuffer, {
    byteLength: { value: 4 },
    length: { value: 4 },
  });
  assertWrongByteCount(poisonedBuffer, 4);
});

test("randomBytesFrom measures copied buffers through the intrinsic getter", () => {
  const advertisedLong = new Uint8Array([1, 2, 3]);
  Object.defineProperty(advertisedLong, "length", { value: 4 });
  const original = Object.getOwnPropertyDescriptor(Buffer.prototype, "byteLength");

  try {
    Object.defineProperty(Buffer.prototype, "byteLength", {
      configurable: true,
      value: 3,
    });
    const snapshot = randomBytesFrom(malformedPort(advertisedLong), 3);
    assert.deepEqual(snapshot, Buffer.from([1, 2, 3]));
  } finally {
    if (original) {
      Object.defineProperty(Buffer.prototype, "byteLength", original);
    } else {
      delete (Buffer.prototype as { byteLength?: number }).byteLength;
    }
  }
});

test("randomBytesFrom does not invoke a poisoned intrinsic getter call property", () => {
  const original = Object.getOwnPropertyDescriptor(typedArrayByteLength, "call");

  try {
    const short = new Uint8Array(3);
    assert.throws(() => randomBytesFrom({
      bytes: () => {
        Object.defineProperty(typedArrayByteLength, "call", {
          configurable: true,
          value: () => 4,
        });
        return short;
      },
    }, 4), { name: "TypeError", message: WRONG_BYTE_COUNT });
  } finally {
    if (original) {
      Object.defineProperty(typedArrayByteLength, "call", original);
    } else {
      delete (typedArrayByteLength as { call?: unknown }).call;
    }
  }
});

test("randomBytesFrom does not consult an own length getter while copying", () => {
  const owned = new Uint8Array([1, 2, 3]);
  const original = Object.getOwnPropertyDescriptor(typedArrayByteLength, "call");
  let getterCalls = 0;
  Object.defineProperty(owned, "length", {
    get: () => {
      getterCalls += 1;
      Object.defineProperty(typedArrayByteLength, "call", {
        configurable: true,
        value: () => 3,
      });
      return 4;
    },
  });

  try {
    const snapshot = randomBytesFrom(malformedPort(owned), 3);
    assert.equal(getterCalls, 0);
    assert.deepEqual(snapshot, Buffer.from([1, 2, 3]));
    assert.equal(Object.hasOwn(typedArrayByteLength, "call"), false);
  } finally {
    if (original) {
      Object.defineProperty(typedArrayByteLength, "call", original);
    } else {
      delete (typedArrayByteLength as { call?: unknown }).call;
    }
  }
});

test("randomBytesFrom snapshots the port-owned bytes", () => {
  const owned = Buffer.from([1, 2, 3, 4]);
  const snapshot = randomBytesFrom(malformedPort(owned), owned.byteLength);

  owned[0] = 9;
  owned[3] = 8;
  assert.ok(Buffer.isBuffer(snapshot));
  assert.deepEqual(snapshot, Buffer.from([1, 2, 3, 4]));
});

test("systemRandom implements the RandomPort contract", () => {
  const random: RandomPort = systemRandom;
  const first = random.bytes(32);
  const second = random.bytes(32);

  assert.ok(Object.isFrozen(systemRandom));
  assert.ok(first instanceof Uint8Array);
  assert.ok(Buffer.isBuffer(first));
  assert.equal(first.byteLength, 32);
  assert.equal(second.byteLength, 32);
  assert.notDeepEqual(first, second);
  assert.ok(first.some((byte) => byte !== 0));
});
