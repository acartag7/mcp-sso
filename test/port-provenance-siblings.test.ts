// Siblings of the StorePort provenance boundary. Each of these is caller-supplied
// code that runs BEFORE the use-case try, so an OAuthError raised there would
// reach `asOAuth` and select the public response — the same escape the store
// wrapping closes, reached through a different port.
//
// Every case below uses the shape a real deployment produces: a port that throws
// the library's own published OAuthError, because that is what a deployer reaches
// for when writing one.
import assert from "node:assert/strict";
import { test } from "node:test";

import { OAuthError } from "../src/errors.ts";
import { PortFailureError } from "../src/port-failure.ts";
import { finiteClockSnapshot } from "../src/ports/clock.ts";
import { storeInstanceId } from "../src/store-instance.ts";
import type { StorePort } from "../src/ports/store.ts";

const HOSTILE = () => { throw new OAuthError("invalid_token", "shard 7 unreachable", 401); };

// --- ClockPort --------------------------------------------------------------

test("a ClockPort that throws cannot select the public response", () => {
  // Every token operation snapshots the clock before its try block, so an
  // OAuthError here would travel straight to asOAuth with the port's 401.
  assert.throws(
    () => finiteClockSnapshot({ nowMs: HOSTILE }),
    (error: unknown) => {
      assert.ok(!(error instanceof OAuthError), "a port's throw must not stay an OAuthError");
      assert.ok(error instanceof RangeError, "it becomes the same shape an out-of-range value produces");
      assert.doesNotMatch(String((error as Error).message), /shard 7|unreachable/);
      return true;
    },
  );
});

test("the clock re-cast does not disturb valid or out-of-range values", () => {
  assert.equal(finiteClockSnapshot({ nowMs: () => 1_700_000_000_000 }), 1_700_000_000_000);
  // Out-of-range still throws RangeError — one failure shape either way.
  assert.throws(() => finiteClockSnapshot({ nowMs: () => -62_167_219_200_001 }), RangeError); // before 0000-01-01
  assert.throws(() => finiteClockSnapshot({ nowMs: () => 1.5 }), RangeError);
});

// --- StorePort capability probe ---------------------------------------------

/** A store whose capability PROPERTIES throw on read — an accessor or Proxy,
 *  which is exactly what the §5 read-once rules exist to defend against. */
function hostileGetterStore(): StorePort {
  return new Proxy({} as StorePort, {
    get(_target, prop) {
      if (prop === "getStoreInstanceId") HOSTILE();
      return undefined;
    },
  });
}

test("a capability read that throws is contained, not just the method call", () => {
  // The probe reads three properties before any method runs. Wrapping only the
  // invocation would leave the reads outside the boundary — the incomplete-fix
  // shape this repo keeps producing.
  return assert.rejects(
    () => storeInstanceId(hostileGetterStore()),
    (error: unknown) => {
      assert.ok(error instanceof PortFailureError, "a throwing property read must be re-cast");
      assert.ok(!(error instanceof OAuthError));
      assert.doesNotMatch(String((error as Error).message), /shard 7|unreachable/);
      return true;
    },
  );
});

test("a store missing the capability still fails with the explanatory error", () => {
  // Containment must not swallow the diagnostic for the ordinary misconfiguration.
  return assert.rejects(
    () => storeInstanceId({} as StorePort),
    (error: unknown) => {
      assert.ok(error instanceof PortFailureError);
      assert.match(String((error as { cause?: Error }).cause?.message ?? ""), /getStoreInstanceId is required/);
      return true;
    },
  );
});
