import assert from "node:assert/strict";
import { test } from "node:test";
import { snapshotOwnDataArray } from "../src/own-property.ts";

test("array snapshots reject sparse arrays even when inherited descriptor data balances the shape", () => {
  const inherited = Object.getOwnPropertyDescriptor(Object.prototype, "0");
  Object.defineProperty(Object.prototype, "0", {
    configurable: true, value: { enumerable: true, value: "inherited" },
  });
  try {
    const sparse: unknown[] = [];
    sparse.length = 1;
    Object.defineProperty(sparse, "extra", { enumerable: true, value: "balancing-own-key" });
    assert.equal(snapshotOwnDataArray(sparse), null);
  } finally {
    if (inherited === undefined) delete (Object.prototype as Record<string, unknown>)["0"];
    else Object.defineProperty(Object.prototype, "0", inherited);
  }
});
