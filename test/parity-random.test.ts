import assert from "node:assert/strict";
import { test } from "node:test";
import { SeededRandom } from "./parity/random.ts";

const VECTOR = "dda46198e668964d43f395ded2b195190c4faafebf113b2fd50ad2b0e30f42c05b202c7f0d3757bed3151fded3028ef32fa052b4bfcfbaab4ac4691461281731254a28fd11d29da17b20af3dbbdf3f8804e5003114e9f198d925a4cf23fa9f4a";

test("SeededRandom follows the fixture derivation vector", () => {
  const whole = Buffer.from(new SeededRandom("fixture-seed").bytes(96)).toString("hex");
  assert.equal(whole, VECTOR);
});

test("SeededRandom preserves an unused block suffix across segmented calls", () => {
  const split = new SeededRandom("fixture-seed");
  const segmented = Buffer.concat([Buffer.from(split.bytes(7)), Buffer.from(split.bytes(25)), Buffer.from(split.bytes(64))]);
  assert.equal(segmented.toString("hex"), VECTOR);
});

test("SeededRandom rejects malformed seeds and byte counts", () => {
  const random = new SeededRandom("seed");
  for (const length of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => random.bytes(length), /positive safe integer/);
  }
  for (const seed of ["", null, 7, "\ud800", "\udc00"] as unknown[]) {
    assert.throws(() => new SeededRandom(seed as string), /non-empty|well-formed/);
  }
  assert.doesNotThrow(() => new SeededRandom("é".repeat(512)));
  assert.throws(() => new SeededRandom("é".repeat(513)), /1024/);
  assert.throws(() => new SeededRandom("a".repeat(1_025)), /1024/);
});

test("SeededRandom does not normalize seed bytes", () => {
  assert.notDeepEqual(new SeededRandom("é").bytes(32), new SeededRandom("e\u0301").bytes(32));
});
