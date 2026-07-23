import { ownBooleanTrue, snapshotOwnDataRecord } from "../own-property.ts";

export interface ParsedIp {
  readonly family: 4 | 6;
  readonly bytes: Uint8Array;
}

interface CidrRange {
  readonly network: Uint8Array;
  readonly prefix: number;
}

export function parseIp(text: string): ParsedIp | null {
  if (typeof text !== "string" || text === "" || text.includes("%")) return null;
  const v4 = parseIpv4(text);
  if (v4) return Object.freeze({ family: 4 as const, bytes: v4 });
  if (!text.includes(":")) return null;
  const v6 = parseIpv6(text);
  return v6 ? Object.freeze({ family: 6 as const, bytes: v6 }) : null;
}

export function isBlockedIp(ip: ParsedIp, opts: { allowLoopback?: boolean } = {}): boolean {
  const parsed = snapshotOwnDataRecord(ip);
  const family = parsed?.family;
  const rawBytes = parsed?.bytes;
  if ((family !== 4 && family !== 6) || !(rawBytes instanceof Uint8Array)
    || rawBytes.length !== (family === 4 ? 4 : 16)) return true;
  const bytes = new Uint8Array(rawBytes);
  if (ownBooleanTrue(opts, "allowLoopback")) {
    if (family === 4 && bytes[0] === 127) return false;
    if (family === 6 && isIpv6Loopback(bytes)) return false;
  }
  const ranges = family === 4 ? IPV4_RANGES : IPV6_RANGES;
  return ranges.some((range) => contains(range, bytes));
}

export function isBlockedAddress(text: string, opts: { allowLoopback?: boolean } = {}): boolean {
  const parsed = parseIp(text);
  return parsed === null || isBlockedIp(parsed, opts);
}

function parseIpv4(text: string): Uint8Array | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let index = 0; index < parts.length; index++) {
    const part = parts[index]!;
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    bytes[index] = value;
  }
  return bytes;
}

function parseIpv6(input: string): Uint8Array | null {
  let text = input;
  if (!/^[0-9a-f:.]+$/i.test(text)) return null;
  if (text.includes(".")) {
    const colon = text.lastIndexOf(":");
    if (colon < 0) return null;
    const v4 = parseIpv4(text.slice(colon + 1));
    if (!v4) return null;
    const high = ((v4[0]! << 8) | v4[1]!).toString(16);
    const low = ((v4[2]! << 8) | v4[3]!).toString(16);
    text = `${text.slice(0, colon + 1)}${high}:${low}`;
  }
  const firstCompression = text.indexOf("::");
  if (firstCompression !== text.lastIndexOf("::")) return null;
  const compressed = firstCompression >= 0;
  const halves = compressed ? text.split("::") : [text];
  if (halves.length > 2) return null;
  const left = parseHextets(halves[0]!);
  const right = compressed ? parseHextets(halves[1]!) : [];
  if (left === null || right === null) return null;
  const missing = 8 - left.length - right.length;
  if ((compressed && missing < 1) || (!compressed && missing !== 0)) return null;
  const words = [...left, ...new Array<number>(missing).fill(0), ...right];
  if (words.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let index = 0; index < words.length; index++) {
    bytes[index * 2] = words[index]! >>> 8;
    bytes[index * 2 + 1] = words[index]! & 0xff;
  }
  return bytes;
}

function parseHextets(text: string): number[] | null {
  if (text === "") return [];
  const parts = text.split(":");
  if (parts.some((part) => !/^[0-9a-f]{1,4}$/i.test(part))) return null;
  return parts.map((part) => Number.parseInt(part, 16));
}

function isIpv6Loopback(bytes: Uint8Array): boolean {
  for (let index = 0; index < 15; index++) if (bytes[index] !== 0) return false;
  return bytes[15] === 1;
}

function contains(range: CidrRange, address: Uint8Array): boolean {
  const wholeBytes = Math.floor(range.prefix / 8);
  for (let index = 0; index < wholeBytes; index++) {
    if (range.network[index] !== address[index]) return false;
  }
  const remaining = range.prefix % 8;
  if (remaining === 0) return true;
  const mask = (0xff << (8 - remaining)) & 0xff;
  return (range.network[wholeBytes]! & mask) === (address[wholeBytes]! & mask);
}

function cidrs(family: 4 | 6, values: readonly string[]): readonly CidrRange[] {
  return values.map((value) => {
    const slash = value.lastIndexOf("/");
    const parsed = parseIp(value.slice(0, slash));
    const prefix = Number(value.slice(slash + 1));
    const max = family === 4 ? 32 : 128;
    if (!parsed || parsed.family !== family || !Number.isInteger(prefix) || prefix < 0 || prefix > max) {
      throw new Error("Invalid internal CIMD blocklist range");
    }
    return { network: parsed.bytes, prefix };
  });
}

const IPV4_RANGES = cidrs(4, [
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
  "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
  "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
  "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
  "224.0.0.0/4", "240.0.0.0/4",
]);

const IPV6_RANGES = cidrs(6, [
  "::/128", "::1/128", "::/96", "::ffff:0:0/96", "64:ff9b::/96",
  "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64", "2001::/23",
  "2001:db8::/32", "2002::/16", "2620:4f:8000::/48", "3fff::/20",
  "5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
]);
