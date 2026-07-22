// FROZEN acceptance suite — S6a CIMD admission primitive (docs/contracts.md
// §17.1.1 + §17.1.5 A/B). Black-box: imports ONLY the pinned public primitive.
// Activate via test/acceptance/phases.json (never edit the assertions).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const phases = JSON.parse(readFileSync(new URL("../phases.json", import.meta.url), "utf8"));

if (phases["s6a-cimd-primitives"] !== true) {
  test("s6a-cimd-primitives inactive — activate via test/acceptance/phases.json", { skip: true }, () => {});
} else {
  // Non-literal specifier: keeps `tsc --noEmit` green while src/cimd is absent
  // (this frozen suite lands BEFORE the implementation); resolved at runtime.
  const ADMISSION = "../../../src/cimd/admission.ts";
  const { admitCimdUrl } = (await import(ADMISSION)) as any;

  // Every rejection MUST be a CimdError whose reason is exactly "url_admission_denied".
  const denied = (raw: any, opts?: any) =>
    assert.throws(
      () => admitCimdUrl(raw, opts),
      (e: any) => e && e.reason === "url_admission_denied",
      "expected CimdError reason=url_admission_denied",
    );

  test("admits a well-formed https CIMD url; default port is 443; raw is verbatim", () => {
    const r = admitCimdUrl("https://cdn.example.com/client");
    assert.equal(r.raw, "https://cdn.example.com/client");
    assert.equal(r.hostname, "cdn.example.com");
    assert.equal(r.port, 443);
  });

  test("admits an explicit non-denied port (:8443)", () => {
    const r = admitCimdUrl("https://cdn.example.com:8443/client");
    assert.equal(r.port, 8443);
    assert.equal(r.raw, "https://cdn.example.com:8443/client");
  });

  test("admits a path-@ (legal pchar), distinct from an authority-@", () => {
    const r = admitCimdUrl("https://cdn.example.com/@scope/c.json");
    assert.equal(r.hostname, "cdn.example.com");
  });

  test("admits %252e (decode-once — NOT a dot segment)", () => {
    const r = admitCimdUrl("https://cdn.example.com/%252e/c");
    assert.equal(r.raw, "https://cdn.example.com/%252e/c");
  });

  test("admits notlocalhost (localhost matcher is suffix/exact, not substring)", () => {
    assert.equal(admitCimdUrl("https://notlocalhost/c").hostname, "notlocalhost");
  });

  test("2048 UTF-8 bytes admitted; 2049 rejected (byte boundary)", () => {
    const prefix = "https://cimd.example.com/";
    const at2048 = prefix + "a".repeat(2048 - prefix.length);
    assert.equal(Buffer.byteLength(at2048, "utf8"), 2048);
    assert.equal(admitCimdUrl(at2048).raw, at2048);
    const at2049 = prefix + "a".repeat(2049 - prefix.length);
    assert.equal(Buffer.byteLength(at2049, "utf8"), 2049);
    denied(at2049);
  });

  test("length is UTF-8 BYTES, not chars (multibyte path over the byte cap rejects)", () => {
    // 1500 U+20AC = 4500 bytes but only 1500 chars.
    denied("https://cimd.example.com/" + "€".repeat(1500));
  });

  test("non-string and empty inputs reject pre-parse", () => {
    for (const v of [123, 0, null, undefined, {}, [], true, false, NaN]) denied(v);
    denied("");
  });

  test("scheme: only a literal lowercase https:// prefix is admitted", () => {
    denied("http://cdn.example.com/c");
    denied("HTTPS://cdn.example.com/c");
    denied("Https://cdn.example.com/c");
    denied("ftp://cdn.example.com/c");
    denied("//cdn.example.com/c");
    denied(" https://cdn.example.com/c"); // leading whitespace
  });

  test("raw pre-parse rejects: backslash, authority-@, query, fragment, whitespace", () => {
    denied("https://h.example/a\\..\\b"); // raw backslash (WHATWG maps \\ -> /)
    denied("https://@h.example/c"); // empty userinfo
    denied("https://user@h.example/c"); // userinfo
    denied("https://user:pw@h.example/c");
    denied("https://h.example/c?"); // trailing ? (empty search)
    denied("https://h.example/c?x=1"); // query string
    denied("https://h.example/c#"); // trailing # (empty hash)
    denied("https://h.example/c#f"); // fragment
    denied("https://h.example/c "); // trailing space
  });

  test("raw pre-parse rejects control chars + raw/encoded CR-LF in all case variants", () => {
    denied("https://h.example/c\u0001"); // C0
    denied("https://h.example/c\u007f"); // DEL
    denied("https://h.example/c\r");
    denied("https://h.example/c\n");
    denied("https://h.example/c%0d");
    denied("https://h.example/c%0A");
    denied("https://h.example/c%0D%0a"); // mixed case
  });

  test("dot-segment rejection (literal, %2e, %2E, mixed) pre-parse", () => {
    for (const p of ["/a/./b", "/a/../b", "/a/%2e/b", "/a/%2E/b", "/a/%2e%2E/b", "/%2e%2e/b", "/.", "/.."])
      denied("https://h.example" + p);
  });

  test("root or path-less url rejected (a real path component is required)", () => {
    denied("https://h.example/"); // root path
    denied("https://h.example"); // no path
  });

  test("IP-literal hosts rejected (v4, bracketed v6, dword, octal, hex, fullwidth)", () => {
    for (const h of [
      "https://1.2.3.4/x",
      "https://[::1]/x",
      "https://[2001:db8::1]/x",
      "https://2130706433/x", // dword -> 127.0.0.1
      "https://0177.0.0.1/x", // octal -> 127.0.0.1
      "https://0x7f.0.0.1/x", // hex
      "https://1．2．3．4/x", // fullwidth dots -> 1.2.3.4
    ]) denied(h);
  });

  test("non-ASCII / IDNA hostnames rejected (v0.2 fail-closed policy)", () => {
    denied("https://exämple.com/x");
    denied("https://пример.example/x");
    denied("https://xn--exmple-cua.com/x"); // pre-encoded IDNA A-label
  });

  test("localhost family rejected by default; a.b.localhost matches, notlocalhost does not", () => {
    denied("https://localhost/c");
    denied("https://a.b.localhost/c");
    denied("https://x.localhost/c");
  });

  test("trailing-dot hostnames rejected (blanket rule, never relaxed)", () => {
    denied("https://example.com./x");
    denied("https://localhost./x");
  });

  test("every denied cross-protocol port is rejected", () => {
    for (const p of [22, 25, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 6379, 9200, 11211, 27017])
      denied(`https://cdn.example.com:${p}/c`);
  });

  test("allowLoopback=true admits https localhost (default + explicit port)", () => {
    assert.equal(admitCimdUrl("https://localhost/c", { allowLoopback: true }).hostname, "localhost");
    const r = admitCimdUrl("https://localhost:8443/c", { allowLoopback: true });
    assert.equal(r.hostname, "localhost");
    assert.equal(r.port, 8443);
    assert.equal(admitCimdUrl("https://api.localhost/c", { allowLoopback: true }).hostname, "api.localhost");
  });

  test("allowLoopback=true still rejects non-https + IP-literals + denied ports", () => {
    denied("http://localhost/c", { allowLoopback: true }); // scheme never relaxed
    denied("https://10.0.0.1/c", { allowLoopback: true });
    denied("https://169.254.169.254/c", { allowLoopback: true });
    denied("https://[::1]/c", { allowLoopback: true });
    denied("https://localhost:6379/c", { allowLoopback: true }); // denied port
  });

  test("allowLoopback=false rejects all loopback hosts", () => {
    denied("https://localhost/c", { allowLoopback: false });
    denied("https://x.localhost/c", { allowLoopback: false });
  });
}
