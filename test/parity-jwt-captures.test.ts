import assert from "node:assert/strict";
import { test } from "node:test";
import { CompactSign, generateKeyPair, type CryptoKey } from "jose";
import { FixtureRunnerError } from "./parity/error.ts";
import { assertJwt } from "./parity/jwt-capture.ts";
import { parseStrictJson } from "./parity/strict-json.ts";
import type { CaptureSpec } from "./parity/types.ts";

type Expectation = NonNullable<CaptureSpec["jwt"]>;
const encoder = new TextEncoder();
const header = { alg: "ES256", kid: "capture-key", typ: "JWT" } as const;
const claims = {
  sub: "alice", exp: -1, iss: "not a URI", aud: 17,
  nested: { roles: ["reader"] },
};
const expected: Expectation = { key: "signingPublic", header, claims };
const es256 = generateKeyPair("ES256");

function bytes(value: string | Uint8Array): Uint8Array {
  return typeof value === "string" ? encoder.encode(value) : value;
}

function segment(value: string | Uint8Array): string {
  return Buffer.from(bytes(value)).toString("base64url");
}

async function signSegments(
  protectedSegment: string, payloadSegment: string, privateKey: CryptoKey,
): Promise<string> {
  const input = encoder.encode(`${protectedSegment}.${payloadSegment}`);
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, privateKey, input,
  );
  return `${protectedSegment}.${payloadSegment}.${Buffer.from(signature).toString("base64url")}`;
}

async function rawJwt(
  protectedSource: string | Uint8Array, payloadSource: string | Uint8Array,
  privateKey?: CryptoKey,
): Promise<string> {
  const key = privateKey ?? (await es256).privateKey;
  return signSegments(segment(protectedSource), segment(payloadSource), key);
}

async function objectJwt(
  protectedValue: Record<string, unknown>, payloadValue: unknown, privateKey?: CryptoKey,
): Promise<string> {
  return rawJwt(JSON.stringify(protectedValue), JSON.stringify(payloadValue), privateKey);
}

function unsafeExpected(
  protectedValue: unknown, payloadValue: unknown = claims,
): Expectation {
  return { key: "signingPublic", header: protectedValue, claims: payloadValue } as unknown as Expectation;
}

async function reject(
  token: unknown, expectation: Expectation = expected,
  key?: CryptoKey, message?: string,
): Promise<FixtureRunnerError> {
  const publicKey = key ?? (await es256).publicKey;
  let caught: unknown;
  try { await assertJwt(token, expectation, publicKey); } catch (error) { caught = error; }
  assert.ok(caught instanceof FixtureRunnerError);
  if (message !== undefined) assert.equal(caught.message, message);
  return caught;
}

function tamper(token: string, part: 0 | 1 | 2): string {
  const pieces = token.split(".");
  const changed = Buffer.from(pieces[part]!, "base64url");
  changed[0] = changed[0]! ^ 1;
  pieces[part] = changed.toString("base64url");
  return pieces.join(".");
}

function nonCanonical(canonical: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const index = alphabet.indexOf(canonical.at(-1)!);
  const unusedBits = canonical.length % 4 === 2 ? 4 : 2;
  assert.notEqual(canonical.length % 4, 0);
  const replacement = (index >> unusedBits << unusedBits) | ((index + 1) & ((1 << unusedBits) - 1));
  return `${canonical.slice(0, -1)}${alphabet[replacement]}`;
}

test("accepts exact ES256 objects without comparing compact token bytes or JWT semantics", async () => {
  const { privateKey, publicKey } = await es256;
  const reorderedClaims = {
    nested: { roles: ["reader"] }, aud: 17, iss: "not a URI", exp: -1, sub: "alice",
  };
  assert.deepEqual(reorderedClaims, claims);
  assert.notEqual(JSON.stringify(reorderedClaims), JSON.stringify(claims));
  const first = await objectJwt(header, claims, privateKey);
  const second = await objectJwt(header, reorderedClaims, privateKey);
  assert.notEqual(first, second);
  await assert.doesNotReject(() => assertJwt(first, expected, publicKey));
  await assert.doesNotReject(() => assertJwt(second, expected, publicKey));
});

test("pins verification to ES256", async () => {
  const secret = await crypto.subtle.generateKey(
    { name: "HMAC", hash: "SHA-256", length: 256 }, true, ["sign", "verify"],
  );
  const hsHeader = { alg: "HS256", kid: header.kid, typ: "JWT" };
  const hsToken = await new CompactSign(encoder.encode(JSON.stringify(claims)))
    .setProtectedHeader(hsHeader).sign(secret);
  await reject(hsToken, unsafeExpected(hsHeader), secret);

  const rsa = await generateKeyPair("RS256");
  const rsHeader = { alg: "RS256", kid: header.kid, typ: "JWT" };
  const rsToken = await new CompactSign(encoder.encode(JSON.stringify(claims)))
    .setProtectedHeader(rsHeader).sign(rsa.privateKey);
  await reject(rsToken, unsafeExpected(rsHeader), rsa.publicKey);

  const noneHeader = segment(JSON.stringify({ alg: "none", kid: header.kid, typ: "JWT" }));
  await reject(`${noneHeader}.${segment(JSON.stringify(claims))}.AA`, unsafeExpected({
    alg: "none", kid: header.kid, typ: "JWT",
  }));
});

test("rejects wrong keys, curves, tampered content, and malformed compact serialization", async () => {
  const token = await objectJwt(header, claims);
  const other = await generateKeyPair("ES256");
  const p384 = await generateKeyPair("ES384");
  for (const key of [other.publicKey, p384.publicKey]) await reject(token, expected, key);
  await reject(tamper(token, 0));
  await reject(tamper(token, 1));
  await reject(tamper(token, 2));
  for (const malformed of [undefined, "", "one.two", "one.two.three.four", ".two.three",
    "one..three", "one.two.", "one.*.three", "one.two.*"]) await reject(malformed);
});

test("rejects padded, noncanonical, invalid, and empty protected-header base64url", async () => {
  const { privateKey } = await es256;
  const canonical = segment(JSON.stringify(header));
  const payload = segment(JSON.stringify(claims));
  const altered = nonCanonical(canonical);
  assert.deepEqual(Buffer.from(altered, "base64url"), Buffer.from(canonical, "base64url"));
  for (const protectedSegment of ["", `${canonical}=`, altered, `${canonical}*`]) {
    const token = protectedSegment === "" ? `.${payload}.AA`
      : await signSegments(protectedSegment, payload, privateKey);
    await reject(token);
  }
});

test("strictly decodes and parses the protected header before jose", async () => {
  const malformedUtf8 = Buffer.concat([
    Buffer.from('{"alg":"ES256","kid":"'), Buffer.from([0xc3, 0x28]),
    Buffer.from('","typ":"JWT"}'),
  ]);
  const replacementHeader = { alg: "ES256", kid: "�(", typ: "JWT" };
  const invalid: Array<[string | Uint8Array, unknown]> = [
    [`\uFEFF${JSON.stringify(header)}`, header], [malformedUtf8, replacementHeader],
    ['{"alg":"ES256","kid":"attacker-marker"', header], ["[]", []],
    ['"scalar"', "scalar"], ["null", null],
    ['{"alg":"ES256","alg":"ES256","kid":"capture-key","typ":"JWT"}', header],
    ['{"alg":"ES256","kid":"capture-key","typ":"JWT","meta":{"use":"sig","use":"sig"}}',
      { ...header, meta: { use: "sig" } }],
    ['{"alg":"ES256","\\u0061lg":"ES256","kid":"capture-key","typ":"JWT"}', header],
  ];
  for (const [source, lastWins] of invalid) {
    const token = await rawJwt(source, JSON.stringify(claims));
    const error = await reject(token, unsafeExpected(lastWins), undefined,
      "captured JWT protected header is invalid");
    assert.doesNotMatch(error.message, /attacker-marker/u);
  }
});

test("strictly decodes and parses the verified payload", async () => {
  const prefix = Buffer.from('{"value":"');
  const malformedUtf8 = Buffer.concat([prefix, Buffer.from([0xc3, 0x28]), Buffer.from('"}')]);
  const invalid: Array<[string | Uint8Array, unknown]> = [
    [`\uFEFF${JSON.stringify(claims)}`, claims], [malformedUtf8, { value: "�(" }],
    ['{"attacker-marker":', {}], ["[]", []], ['"scalar"', "scalar"], ["null", null],
    ['{"sub":"alice","sub":"alice"}', { sub: "alice" }],
    ['{"nested":{"role":"reader","role":"reader"}}', { nested: { role: "reader" } }],
    ['{"sub":"alice","s\\u0075b":"alice"}', { sub: "alice" }],
  ];
  for (const [source, lastWins] of invalid) {
    const token = await rawJwt(JSON.stringify(header), source);
    const error = await reject(token, unsafeExpected(header, lastWins), undefined,
      "captured JWT payload is invalid");
    assert.doesNotMatch(error.message, /attacker-marker/u);
  }
});

test("rejects JSON numbers that lose their distinct value", async () => {
  const lossyHeader = { ...header, sequence: 9007199254740992 };
  const headerToken = await rawJwt(
    '{"alg":"ES256","kid":"capture-key","typ":"JWT","sequence":9007199254740993}',
    JSON.stringify(claims),
  );
  await reject(headerToken, unsafeExpected(lossyHeader), undefined,
    "captured JWT protected header is invalid");
  const invalid: Array<[string, unknown]> = [
    ['{"value":9007199254740993}', { value: 9007199254740992 }],
    ['{"nested":{"value":1.0000000000000001}}', { nested: { value: 1 } }],
    ['{"value":1e-400}', { value: 0 }],
    ['{"value":1e400}', { value: Infinity }],
  ];
  for (const [source, rounded] of invalid) {
    const token = await rawJwt(JSON.stringify(header), source);
    await reject(token, unsafeExpected(header, rounded), undefined,
      "captured JWT payload is invalid");
  }
});

test("strict JSON parsing rejects lossy fixture numbers and preserves exact spellings", () => {
  assert.throws(() => parseStrictJson('{"fixture":{"value":9007199254740993}}'),
    /lossy JSON number/u);
  const parsed = parseStrictJson(
    '{"large":9007199254740992,"integer":1,"decimal":1.0,"exponent":1e0}');
  assert.deepEqual(parsed, { large: 9007199254740992, integer: 1, decimal: 1, exponent: 1 });
});

test("accepts exact large numbers and equivalent decimal spellings", async () => {
  const exactClaims = { large: 9007199254740992, integer: 1, decimal: 1, exponent: 1 };
  const token = await rawJwt(JSON.stringify(header),
    '{"large":9007199254740992,"integer":1,"decimal":1.0,"exponent":1e0}');
  const { publicKey } = await es256;
  await assert.doesNotReject(() => assertJwt(token, unsafeExpected(header, exactClaims), publicKey));
});

test("requires exact protected-header and claims structures", async () => {
  const headerCases: Record<string, unknown>[] = [
    { alg: "ES256", kid: header.kid },
    { ...header, kid: "changed" },
    { ...header, extra: true },
  ];
  for (const actual of headerCases) {
    await reject(await objectJwt(actual, claims), expected, undefined,
      "captured JWT protected header does not match fixture");
  }
  const claimCases = [
    { ...claims, sub: undefined }, { ...claims, sub: "mallory" }, { ...claims, extra: true },
  ];
  delete claimCases[0]!.sub;
  for (const actual of claimCases) {
    await reject(await objectJwt(header, actual), expected, undefined,
      "captured JWT claims do not match fixture");
  }
});
