// FROZEN acceptance suite — S6a guarded fetcher primitive (docs/contracts.md
// §17.1.2 + §17.1.5 C/D/E rules 8-17 + brand). Black-box: exercised ONLY through
// the pinned injected transport + resolver seams (§17.1.5 rule 14).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const phases = JSON.parse(readFileSync(new URL("../phases.json", import.meta.url), "utf8"));

if (phases["s6a-cimd-primitives"] !== true) {
  test("s6a-cimd-primitives inactive — activate via test/acceptance/phases.json", { skip: true }, () => {});
} else {
  // Non-literal specifier keeps typecheck green while src/cimd is absent.
  const GUARDED = "../../../src/cimd/guarded-fetcher.ts";
  const { createGuardedFetcher, isGuardedFetcher } = (await import(GUARDED)) as any;

  const ID = "https://cdn.example.com/client";
  const PUBLIC = { address: "93.184.216.34", family: 4 };
  const enc = (s: any) => new TextEncoder().encode(s);
  async function* chunk(u8: any) {
    yield u8;
  }
  const docBody = (id: any = ID) =>
    JSON.stringify({ client_id: id, client_name: "Example", redirect_uris: ["https://app.example.com/cb"] });

  // Resolver seam: resolve(hostname) -> [{address, family}] (ALL A+AAAA in one call).
  function resolver(answer: any, opts: any = {}) {
    let calls = 0;
    return {
      resolve(hostname: any) {
        calls++;
        if (opts.never) return new Promise(() => {});
        return Promise.resolve(typeof answer === "function" ? answer(calls, hostname) : answer);
      },
      get calls() {
        return calls;
      },
    };
  }

  // Transport seam (§17.1.5 rule 14): connectAndGet(req) -> result. Fresh body per call.
  const okResult = (over: any = {}) => ({
    status: 200,
    redirected: false,
    finalUrl: ID,
    headersDistinct: { "content-type": ["application/json"] },
    encodedBody: chunk(enc(docBody())),
    ...over,
  });
  function transport(factory: any, opts: any = {}) {
    let calls = 0;
    let last: any = null;
    return {
      connectAndGet(req: any) {
        calls++;
        last = req;
        if (opts.never) return new Promise(() => {});
        return Promise.resolve(typeof factory === "function" ? factory(req) : factory);
      },
      get calls() {
        return calls;
      },
      get last() {
        return last;
      },
    };
  }

  const fetcher = (t: any, r: any, opts: any = {}) => createGuardedFetcher({ transport: t, resolver: r, ...opts });
  const rejectsReason = (p: any, reason: any) =>
    assert.rejects(p, (e: any) => e && e.reason === reason, `expected CimdError reason=${reason}`);

  test("happy path: fetches, validates against raw client_id, returns the document", async () => {
    const res = await fetcher(transport(() => okResult()), resolver([PUBLIC])).fetch(ID);
    assert.equal(res.document.client_id, ID);
    assert.equal(res.document.client_name, "Example");
  });

  test("transport gets the validated IP + ORIGINAL hostname (never IP) + origin-form target", async () => {
    const t = transport(() => okResult());
    const r = resolver([PUBLIC]);
    await fetcher(t, r).fetch(ID);
    assert.equal(t.last.connectIp, "93.184.216.34");
    assert.equal(t.last.servername, "cdn.example.com");
    assert.equal(t.last.hostHeader, "cdn.example.com");
    assert.equal(t.last.requestTarget, "/client");
    assert.equal(t.last.redirect, "manual"); // rule 14: transport must be told not to follow redirects
    assert.equal(r.calls, 1); // exactly one resolution
  });

  test("non-default port propagates to connect port + Host header (rule 13)", async () => {
    const PORTED = "https://cdn.example.com:8443/client";
    const t = transport(() => okResult({ finalUrl: PORTED, encodedBody: chunk(enc(docBody(PORTED))) }));
    await fetcher(t, resolver([PUBLIC])).fetch(PORTED);
    assert.equal(t.last.port, 8443);
    assert.equal(t.last.hostHeader, "cdn.example.com:8443");
    assert.equal(t.last.requestTarget, "/client");
  });

  test("exactly ONE resolution; a 2nd (private) answer cannot re-point the connect target", async () => {
    const t = transport(() => okResult());
    const r = resolver((n: any) => (n === 1 ? [PUBLIC] : [{ address: "10.0.0.1", family: 4 }]));
    const res = await fetcher(t, r).fetch(ID);
    assert.equal(res.document.client_id, ID);
    assert.equal(r.calls, 1);
    assert.equal(t.last.connectIp, "93.184.216.34");
  });

  test("ALL A/AAAA checked: ANY blocked address rejects (ip_blocked); transport never connects", async () => {
    const t = transport(() => okResult());
    await rejectsReason(fetcher(t, resolver([PUBLIC, { address: "10.0.0.1", family: 4 }])).fetch(ID), "ip_blocked");
    assert.equal(t.calls, 0);
  });

  test("a malformed / family-mismatched resolver record rejects the WHOLE fetch (never skipped); no connect", async () => {
    const t = transport(() => okResult());
    await assert.rejects(fetcher(t, resolver([PUBLIC, { address: "1.2.3.4", family: 6 }])).fetch(ID), (e: any) => e && typeof e.reason === "string");
    await assert.rejects(fetcher(t, resolver([PUBLIC, { address: "fe80::1%eth0", family: 6 }])).fetch(ID), (e: any) => e && typeof e.reason === "string");
    assert.equal(t.calls, 0);
  });

  test("zero-record resolver answer rejects (NOT a vacuous [].every() pass); no connect", async () => {
    const t = transport(() => okResult());
    await assert.rejects(fetcher(t, resolver([])).fetch(ID), (e: any) => e && typeof e.reason === "string");
    assert.equal(t.calls, 0);
  });

  test("redirect rejected on explicit redirected===true even when finalUrl serializes identically", async () => {
    const t = transport(() => okResult({ redirected: true, finalUrl: ID }));
    await rejectsReason(fetcher(t, resolver([PUBLIC])).fetch(ID), "redirect_refused");
  });

  test("status !== 200 rejects (201, 204, 3xx+Location, 404, 500)", async () => {
    const cases = [
      { status: 201 },
      { status: 204 },
      { status: 301, headersDistinct: { "content-type": ["application/json"], location: ["https://evil.example/"] } },
      { status: 404 },
      { status: 500 },
    ];
    for (const over of cases) {
      const t = transport(() => okResult({ redirected: false, ...over }));
      await rejectsReason(fetcher(t, resolver([PUBLIC])).fetch(ID), "status_not_200");
    }
  });

  test("duplicate / multi Content-Type rejects", async () => {
    const t = transport(() => okResult({ headersDistinct: { "content-type": ["application/json", "application/json"] } }));
    await rejectsReason(fetcher(t, resolver([PUBLIC])).fetch(ID), "content_type");
  });

  test("wrong Content-Type essence rejects", async () => {
    const t = transport(() => okResult({ headersDistinct: { "content-type": ["text/html"] } }));
    await rejectsReason(fetcher(t, resolver([PUBLIC])).fetch(ID), "content_type");
  });

  test("application/json;charset=utf-8 and a +json suffix type are accepted", async () => {
    for (const ct of ["application/json;charset=utf-8", "application/scim+json", "APPLICATION/JSON"]) {
      const t = transport(() => okResult({ headersDistinct: { "content-type": [ct] } }));
      const res = await fetcher(t, resolver([PUBLIC])).fetch(ID);
      assert.equal(res.document.client_id, ID);
    }
  });

  test("ANY present Content-Encoding rejects incl. bare identity (only ABSENT accepted)", async () => {
    // §17.1.5 rule 16: a present header rejects even for a no-op `identity` — only
    // an absent Content-Encoding is accepted. (A guarded fetcher that allowed a bare
    // `identity` would pass a gzip-only table yet diverge from the contract.)
    for (const ce of ["gzip", "x-gzip", "br", "deflate", "zstd", "identity", "gzip, gzip", "identity, gzip"]) {
      const t = transport(() => okResult({ headersDistinct: { "content-type": ["application/json"], "content-encoding": [ce] } }));
      await rejectsReason(fetcher(t, resolver([PUBLIC])).fetch(ID), "encoding");
    }
  });

  test("over-cap wire body rejects (never truncates-and-parses)", async () => {
    const t = transport(() => okResult({ encodedBody: chunk(enc("x".repeat(4000))) }));
    await rejectsReason(fetcher(t, resolver([PUBLIC]), { maxDocumentBytes: 1024 }).fetch(ID), "size_exceeded");
  });

  test("timeout enforced when the resolver never settles", async () => {
    const t = transport(() => okResult());
    await rejectsReason(fetcher(t, resolver(null, { never: true }), { fetchTimeoutMs: 1000 }).fetch(ID), "timeout");
  });

  test("the deadline CANCELS the DNS resolver (rule 12), not just races it", async () => {
    let cancelled = false;
    const r = { resolve() { return new Promise(() => {}); }, cancel() { cancelled = true; } };
    await rejectsReason(fetcher(transport(() => okResult()), r, { fetchTimeoutMs: 1000 }).fetch(ID), "timeout");
    assert.equal(cancelled, true);
  });

  test("more than 64 resolved addresses rejects (rule 8 upper bound); no connect", async () => {
    const many = Array.from({ length: 65 }, (_, i) => ({ address: `93.184.216.${i}`, family: 4 }));
    const t = transport(() => okResult());
    await assert.rejects(fetcher(t, resolver(many)).fetch(ID), (e: any) => e && typeof e.reason === "string");
    assert.equal(t.calls, 0);
  });

  test("timeout enforced when the transport never settles", async () => {
    const t = transport(() => okResult(), { never: true });
    await rejectsReason(fetcher(t, resolver([PUBLIC]), { fetchTimeoutMs: 1000 }).fetch(ID), "timeout");
  });

  test("injected transport cannot bypass the blocklist guard", async () => {
    const t = transport(() => okResult()); // would succeed if ever reached
    await rejectsReason(fetcher(t, resolver([{ address: "169.254.169.254", family: 4 }])).fetch(ID), "ip_blocked");
    assert.equal(t.calls, 0);
  });

  test("admission runs before DNS + transport (an inadmissible url never resolves/connects)", async () => {
    const t = transport(() => okResult());
    const r = resolver([PUBLIC]);
    await rejectsReason(fetcher(t, r).fetch("http://cdn.example.com/c"), "url_admission_denied");
    assert.equal(r.calls, 0);
    assert.equal(t.calls, 0);
  });

  test("allowLoopback: localhost that resolves to loopback is fetched; a non-loopback record rejects", async () => {
    const LID = "https://localhost:8443/client";
    const body = () =>
      okResult({
        finalUrl: LID,
        encodedBody: chunk(enc(JSON.stringify({ client_id: LID, client_name: "L", redirect_uris: ["http://127.0.0.1:5000/cb"] }))),
      });
    const res = await fetcher(transport(body), resolver([{ address: "127.0.0.1", family: 4 }]), { allowLoopback: true }).fetch(LID);
    assert.equal(res.document.client_id, LID);
    // a single non-loopback record must reject the whole fetch even under the flag
    const t2 = transport(body);
    const mixed = resolver([{ address: "127.0.0.1", family: 4 }, { address: "93.184.216.34", family: 4 }]);
    await assert.rejects(fetcher(t2, mixed, { allowLoopback: true }).fetch(LID), (e: any) => e && typeof e.reason === "string");
    assert.equal(t2.calls, 0); // the every-record guard rejects BEFORE any connect
  });

  test("isGuardedFetcher: true only for a constructed fetcher; a spread-clone is false", () => {
    const f = fetcher(transport(() => okResult()), resolver([PUBLIC]));
    assert.equal(isGuardedFetcher(f), true);
    assert.equal(isGuardedFetcher({ ...f }), false);
    for (const x of [null, undefined, {}, 42, "x", () => {}, []]) assert.equal(isGuardedFetcher(x), false);
  });

  test("redirect refused when finalUrl differs even if redirected===false (defense-in-depth)", async () => {
    const t = transport(() => okResult({ redirected: false, finalUrl: "https://cdn.example.com/other" }));
    await rejectsReason(fetcher(t, resolver([PUBLIC])).fetch(ID), "redirect_refused");
  });

  test("absent Content-Type rejects (a 200 with no media type is not trusted)", async () => {
    const t = transport(() => okResult({ headersDistinct: {} }));
    await rejectsReason(fetcher(t, resolver([PUBLIC])).fetch(ID), "content_type");
  });

  test("over-cap body across MULTIPLE sub-cap chunks rejects (accumulated, not per-chunk)", async () => {
    async function* multi() { yield enc("x".repeat(600)); yield enc("x".repeat(600)); }
    const t = transport(() => okResult({ encodedBody: multi() }));
    await rejectsReason(fetcher(t, resolver([PUBLIC]), { maxDocumentBytes: 1024 }).fetch(ID), "size_exceeded");
  });

  test("allowLoopback does NOT relax the blocklist for a non-localhost host (DNS-rebinding)", async () => {
    // https://attacker.example/client whose attacker DNS returns 127.0.0.1 must still be
    // ip_blocked under the dev flag — relaxation is scoped to localhost/*.localhost only.
    const t = transport(() => okResult());
    await rejectsReason(
      fetcher(t, resolver([{ address: "127.0.0.1", family: 4 }]), { allowLoopback: true }).fetch("https://attacker.example/client"),
      "ip_blocked",
    );
    assert.equal(t.calls, 0);
  });

  test("the fetcher validates the document client_id against the RAW requested id (mismatch => document_invalid)", async () => {
    const evil = JSON.stringify({ client_id: "https://evil.example/client", client_name: "x", redirect_uris: ["https://app.example.com/cb"] });
    const t = transport(() => okResult({ encodedBody: chunk(enc(evil)) }));
    await rejectsReason(fetcher(t, resolver([PUBLIC])).fetch(ID), "document_invalid");
  });

  test("an IPv6 blocked resolved record rejects at the fetcher (family-correct blocklist); no connect", async () => {
    const t = transport(() => okResult());
    await rejectsReason(fetcher(t, resolver([{ address: "fd00::1", family: 6 }])).fetch(ID), "ip_blocked");
    assert.equal(t.calls, 0);
  });

  test("the deadline ABORTS the transport's signal (rule 14), not just races it", async () => {
    const t = transport(() => okResult(), { never: true });
    await rejectsReason(fetcher(t, resolver([PUBLIC]), { fetchTimeoutMs: 1000 }).fetch(ID), "timeout");
    assert.equal(t.last.signal.aborted, true);
  });

  test("a body stream that never yields is bounded by the deadline (timeout)", async () => {
    async function* stall() { await new Promise(() => {}); yield new Uint8Array(); }
    const t = transport(() => okResult({ encodedBody: stall() }));
    await rejectsReason(fetcher(t, resolver([PUBLIC]), { fetchTimeoutMs: 1000 }).fetch(ID), "timeout");
  });

  test("a legitimately admitted :443 client_id is NOT spuriously rejected by the finalUrl check", async () => {
    const RAW = "https://cdn.example.com:443/client";
    const t = transport(() => okResult({ finalUrl: "https://cdn.example.com/client", redirected: false, encodedBody: chunk(enc(docBody(RAW))) }));
    const res = await fetcher(t, resolver([PUBLIC])).fetch(RAW);
    assert.equal(res.document.client_id, RAW);
  });

  test("a json-SUBSTRING but wrong-essence Content-Type rejects (application/json-seq, text/json)", async () => {
    for (const ct of ["application/json-seq", "text/json", "application/xjson"]) {
      const t = transport(() => okResult({ headersDistinct: { "content-type": [ct] } }));
      await rejectsReason(fetcher(t, resolver([PUBLIC])).fetch(ID), "content_type");
    }
  });

  test("a null cap value is REJECTED, not silently defaulted (rule 21 fail-closed)", () => {
    assert.throws(() => createGuardedFetcher({ maxDocumentBytes: null as unknown as number }));
    assert.throws(() => createGuardedFetcher({ fetchTimeoutMs: null as unknown as number }));
  });

  test("out-of-domain cap values are ALL rejected (rule 21 closed domain, not just null)", () => {
    for (const v of [0, 1023, 65537, -1, 1.5, NaN, Infinity, "5120"])
      assert.throws(() => createGuardedFetcher({ maxDocumentBytes: v as unknown as number }));
    for (const v of [0, 999, 30001, -1, 1.5, NaN, Infinity, "5000"])
      assert.throws(() => createGuardedFetcher({ fetchTimeoutMs: v as unknown as number }));
  });
}
