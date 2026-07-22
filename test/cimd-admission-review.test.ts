// Supplementary (non-frozen) regression tests for S6a review fixes (Seat 4 / Grok
// cross-family review). Frozen contract coverage lives in test/acceptance/cimd/;
// these lock impl-specific fixes the frozen suite did not reach.
import { test } from "node:test";
import assert from "node:assert/strict";
import { admitCimdUrl } from "../src/cimd/admission.ts";

const denied = (raw: string) =>
  assert.throws(
    () => admitCimdUrl(raw),
    (e: unknown) => e instanceof Error && (e as { reason?: string }).reason === "url_admission_denied",
    `expected url_admission_denied for ${raw}`,
  );

test("admission rejects port 0 (raw `:0` must not connect to the :443 default)", () => {
  // `new URL("https://h:0/c").port` === "0"; node:https would coerce 0 -> 443, a
  // raw-identity(:0)/connect(:443) differential. Admission fails closed on it.
  denied("https://cdn.example.com:0/client");
});

test("admission still admits valid explicit ports (default 443, 8443, 65535)", () => {
  assert.equal(admitCimdUrl("https://cdn.example.com/client").port, 443);
  assert.equal(admitCimdUrl("https://cdn.example.com:8443/client").port, 8443);
  assert.equal(admitCimdUrl("https://cdn.example.com:65535/client").port, 65535);
});
