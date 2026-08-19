// §6.3 types `startExpiryCollection` as OPTIONAL: a custom store may omit it
// "only when it provides an equivalent lifecycle using the same configured
// clock". The shipped suite must therefore judge such a store on its behaviour
// instead of refusing it at the first row — while never skipping the expiry
// rows, because a skipped row is not evidence.
import assert from "node:assert/strict";
import { test } from "node:test";
import { MemoryStore } from "../src/store/memory.ts";
import { startExpiryCollection } from "../src/testing/store-conformance-fixtures.ts";
import { runStoreConformance } from "../src/testing/store-conformance.ts";

/** A store that hides the optional hook, delegating everything else — the shape
 *  of an adapter that owns its own equivalent lifecycle. */
function hideOptionalHook(store) {
  return new Proxy(store, {
    get(target, property) {
      if (property === "startExpiryCollection") return undefined;
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
    set(target, property, value) { return Reflect.set(target, property, value, target); },
    has(target, property) { return property !== "startExpiryCollection" && Reflect.has(target, property); },
  });
}

test("the hook is used when a store has it", () => {
  const clock = { nowMs: () => 0 };
  let received;
  startExpiryCollection({ startExpiryCollection: (c) => { received = c; } }, clock);
  assert.equal(received, clock, "the store's own hook is called with the configured clock");
});

test("a store that omits the hook runs the rows through its supplied lifecycle", () => {
  const clock = { nowMs: () => 0 };
  const store = {};
  const calls = [];
  startExpiryCollection(store, clock, {
    startExpiryCollection: (received, receivedClock) => { calls.push([received, receivedClock]); },
  });
  assert.deepEqual(calls, [[store, clock]], "the adapter's equivalent lifecycle is started instead");
});

test("a store that omits the hook and supplies nothing fails loudly — never skipped", () => {
  assert.throws(() => startExpiryCollection({}, { nowMs: () => 0 }), (error) => {
    assert.match(error.message, /omits the optional startExpiryCollection hook/);
    assert.match(error.message, /options\.startExpiryCollection/, "the message names the way out");
    return true;
  });
  // The old shape refused such a store outright; nothing may quietly pass it.
  assert.doesNotMatch(String(startExpiryCollection), /skip/i);
});

// The whole suite, against a store whose optional hook is absent and whose
// equivalent lifecycle arrives through options. This is the case the shipped
// path previously made impossible.
const hidden = new WeakMap();
runStoreConformance("HookOmittingStore", () => {
  const real = new MemoryStore();
  const proxied = hideOptionalHook(real);
  hidden.set(proxied, real);
  return proxied;
}, {
  startExpiryCollection: (store, clock) => { hidden.get(store).startExpiryCollection(clock); },
});
