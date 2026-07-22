// FROZEN acceptance suite — S6a CIMD IP blocklist primitive (docs/contracts.md
// §17.1.2 blocked ranges + §17.1.5 C rules 9/10). Black-box.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const phases = JSON.parse(readFileSync(new URL("../phases.json", import.meta.url), "utf8"));

if (phases["s6a-cimd-primitives"] !== true) {
  test("s6a-cimd-primitives inactive — activate via test/acceptance/phases.json", { skip: true }, () => {});
} else {
  // Non-literal specifier keeps typecheck green while src/cimd is absent.
  const BLOCKLIST = "../../../src/cimd/blocklist.ts";
  const { isBlockedAddress, parseIp, isBlockedIp } = (await import(BLOCKLIST)) as any;

  const blocked = (t: any, opts?: any) => assert.equal(isBlockedAddress(t, opts), true, `${t} MUST be blocked`);
  const allowed = (t: any, opts?: any) => assert.equal(isBlockedAddress(t, opts), false, `${t} MUST be allowed`);

  test("representative public addresses are allowed", () => {
    allowed("93.184.216.34");
    allowed("8.8.8.8");
    allowed("1.1.1.1");
    allowed("2606:2800:220:1:248:1893:25c8:1946");
  });

  test("boundary addresses just outside each blocked range are allowed", () => {
    allowed("9.255.255.255"); // just below 10.0.0.0/8
    allowed("100.128.0.1"); // just past 100.64.0.0/10
    allowed("172.32.0.1"); // just past 172.16.0.0/12
    allowed("198.20.0.1"); // just past 198.18.0.0/15
  });

  // One representative per enumerated §17.1.2 IPv4 CIDR (registry-complete + multicast).
  const IPV4 = [
    "0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1",
    "192.0.0.1", "192.0.2.1", "192.31.196.1", "192.52.193.1", "192.88.99.1", "192.168.1.1",
    "192.175.48.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1",
  ];
  test("every enumerated IPv4 CIDR is blocked", () => {
    for (const a of IPV4) blocked(a);
  });

  // One representative per enumerated §17.1.2 IPv6 CIDR.
  const IPV6 = [
    "::", "::1", "::10.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "64:ff9b:1::a00:1",
    "100::1", "100:0:0:1::1", "2001:0:0:0:0:0:0:1", "2001:db8::1", "2002:a00:1::",
    "2620:4f:8000::1", "3fff::1", "5f00::1", "fc00::1", "fd00::1", "fe80::1", "fec0::1",
    "ff02::1", "ff00::1",
  ];
  test("every enumerated IPv6 CIDR is blocked", () => {
    for (const a of IPV6) blocked(a);
  });

  test("SUPERSET special-purpose blocks (broader than common SSRF lists)", () => {
    for (const a of ["192.0.0.9", "192.0.0.170", "2001:2::1", "2001:4:112::1", "255.255.255.255"])
      blocked(a);
  });

  test("IPv4-embedding IPv6 forms (mapped, compat, NAT64, 6to4, Teredo) blocked", () => {
    for (const a of ["::ffff:10.0.0.1", "::10.0.0.1", "64:ff9b::a00:1", "64:ff9b:1::a00:1", "2002:a00:1::", "2001:0:0:0:0:0:0:1"])
      blocked(a);
  });

  test("zone-scoped IPv6 is blocked; parseIp rejects the zone form", () => {
    blocked("fe80::1%eth0");
    assert.equal(parseIp("fe80::1%eth0"), null);
  });

  test("IPv6 rows are blocked via isBlockedAddress (catches BlockList family fail-open)", () => {
    for (const a of ["::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1"]) blocked(a);
  });

  test("unparseable inputs are treated as blocked (fail closed)", () => {
    for (const a of ["", "garbage", "999.999.999.999", "0x7f.0.0.1", "12345", "127.0.0.1 ", "1.2.3.4.5", ":::", "example.com"])
      blocked(a);
  });

  test("parseIp yields family + binary length; null on malformed", () => {
    const v4 = parseIp("1.2.3.4");
    assert.equal(v4.family, 4);
    assert.equal(v4.bytes.length, 4);
    const v6 = parseIp("::1");
    assert.equal(v6.family, 6);
    assert.equal(v6.bytes.length, 16);
    assert.equal(parseIp("nope"), null);
    assert.equal(parseIp(""), null);
  });

  test("isBlockedIp classifies parsed addresses", () => {
    assert.equal(isBlockedIp(parseIp("10.0.0.1")), true);
    assert.equal(isBlockedIp(parseIp("fc00::1")), true);
    assert.equal(isBlockedIp(parseIp("::1")), true);
    assert.equal(isBlockedIp(parseIp("93.184.216.34")), false);
  });

  test("allowLoopback un-blocks ONLY 127.0.0.0/8 + ::1, nothing else", () => {
    allowed("127.0.0.1", { allowLoopback: true });
    allowed("127.5.6.7", { allowLoopback: true });
    allowed("::1", { allowLoopback: true });
    blocked("10.0.0.1", { allowLoopback: true });
    blocked("169.254.169.254", { allowLoopback: true });
    blocked("fc00::1", { allowLoopback: true });
    blocked("fe80::1", { allowLoopback: true });
    blocked("::", { allowLoopback: true }); // ::/128 is not the loopback row
  });

  test("loopback is blocked by default and with allowLoopback=false", () => {
    blocked("127.0.0.1");
    blocked("::1");
    blocked("127.0.0.1", { allowLoopback: false });
    blocked("::1", { allowLoopback: false });
  });
}
