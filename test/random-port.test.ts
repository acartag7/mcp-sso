import assert from "node:assert/strict";
import { test } from "node:test";

import { systemRandom } from "../src/ports/random.ts";
import type { RandomPort } from "../src/ports/random.ts";

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
