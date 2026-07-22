// Supplementary (non-frozen) tests for the BUILT-IN NodeDnsResolver — the injected
// resolver seam in the frozen suite cannot reach §17.1.5 rule 8's one-family-no-data
// path (Codex round 7 / Fable residual). Tested here against the real resolver.
import { test } from "node:test";
import assert from "node:assert/strict";
import { NodeDnsResolver } from "../src/cimd/guarded-fetcher.ts";

test("built-in resolver: one family ENODATA + the other OK returns the OK addresses", async () => {
  const r = new NodeDnsResolver();
  (r.resolver as unknown as { resolve4: unknown }).resolve4 = async () => ["93.184.216.34"];
  (r.resolver as unknown as { resolve6: unknown }).resolve6 = async () => {
    const e = new Error("no data") as Error & { code: string };
    e.code = "ENODATA";
    throw e;
  };
  assert.deepEqual(await r.resolve("example.com"), [{ address: "93.184.216.34", family: 4 }]);
});

test("built-in resolver: a non-nodata resolver error rejects the whole lookup (fail-closed)", async () => {
  const r = new NodeDnsResolver();
  (r.resolver as unknown as { resolve4: unknown }).resolve4 = async () => {
    const e = new Error("boom") as Error & { code: string };
    e.code = "ESERVFAIL";
    throw e;
  };
  (r.resolver as unknown as { resolve6: unknown }).resolve6 = async () => [];
  await assert.rejects(() => r.resolve("example.com"));
});
