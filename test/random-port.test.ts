import assert from "node:assert/strict";
import { test } from "node:test";
import { randomBytesFrom, systemRandom } from "../src/ports/random.ts";

test("randomBytesFrom rejects invalid lengths before calling the port", () => {
  let calls = 0;
  const random = { bytes: (_length: number): Uint8Array => {
    calls += 1;
    return new Uint8Array();
  } };

  for (const length of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => randomBytesFrom(random, length), {
      name: "RangeError",
      message: "random byte length must be a positive safe integer",
    });
  }
  assert.equal(calls, 0);
});

test("randomBytesFrom rejects non-Uint8Array, short, and long results", () => {
  assert.throws(() => randomBytesFrom({
    bytes: () => new ArrayBuffer(4) as unknown as Uint8Array,
  }, 4), { name: "TypeError", message: "RandomPort returned the wrong byte count" });
  assert.throws(() => randomBytesFrom({
    bytes: () => new Uint8Array(3),
  }, 4), { name: "TypeError", message: "RandomPort returned the wrong byte count" });
  assert.throws(() => randomBytesFrom({
    bytes: () => new Uint8Array(5),
  }, 4), { name: "TypeError", message: "RandomPort returned the wrong byte count" });
});

test("randomBytesFrom snapshots the port-owned bytes", () => {
  const owned = new Uint8Array([1, 2, 3, 4]);
  const snapshot = randomBytesFrom({ bytes: () => owned }, owned.byteLength);

  owned[0] = 9;
  owned[3] = 8;
  assert.deepEqual(snapshot, Buffer.from([1, 2, 3, 4]));
});

test("systemRandom returns the requested bytes from Node's CSPRNG", () => {
  const value = systemRandom.bytes(32);
  const second = systemRandom.bytes(32);

  assert.ok(Object.isFrozen(systemRandom));
  assert.ok(value instanceof Uint8Array);
  assert.ok(Buffer.isBuffer(value));
  assert.equal(value.byteLength, 32);
  assert.notDeepEqual(value, Buffer.alloc(32));
  assert.notDeepEqual(value, second);
});
