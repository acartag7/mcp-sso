import { strict as assert } from "node:assert";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { FIXTURES_ROOT } from "./parity/corpus.ts";
import { materializeConfigInput } from "./parity/config.ts";
import { FixtureRunnerError } from "./parity/error.ts";
import { privateJwk } from "./parity/keys.ts";

const privateKeyName = "keys/signing-private.pem";
const publicKeyName = "keys/signing-public.pem";

test("materializes a private JWK into a clone", async () => {
  const literal = { issuer: "https://issuer.example", scopes: ["read"] };
  const materialized = await materializeConfigInput(literal, { signingPrivate: privateKeyName });
  const expected = await privateJwk(privateKeyName);

  assert.notStrictEqual(materialized, literal);
  assert.deepEqual(materialized, { ...literal, signingPrivateJwk: expected });
  assert.deepEqual(literal, { issuer: "https://issuer.example", scopes: ["read"] });
  assert.deepEqual((materialized as { signingPrivateJwk: unknown }).signingPrivateJwk, expected);
  assert.equal((materialized as { signingPrivateJwk: { kty: string; crv: string } }).signingPrivateJwk.kty, "EC");
  assert.equal((materialized as { signingPrivateJwk: { kty: string; crv: string } }).signingPrivateJwk.crv, "P-256");
});

test("boot omission leaves signingPrivateJwk absent", async () => {
  const literal = { entrypoint: "Bridge" };
  const materialized = await materializeConfigInput(literal, {});

  assert.notStrictEqual(materialized, literal);
  assert.deepEqual(materialized, literal);
  assert.equal(Object.hasOwn(materialized as object, "signingPrivateJwk"), false);
});

test("a non-object config rejects a named private key", async () => {
  await assert.rejects(
    materializeConfigInput("not-an-object", { signingPrivate: privateKeyName }),
    (error: unknown) => error instanceof FixtureRunnerError
      && error.message === "a signingPrivate key requires an object config",
  );
});

test("an own literal signingPrivateJwk conflicts with a named private key", async () => {
  await assert.rejects(
    materializeConfigInput({ signingPrivateJwk: { kty: "EC" } }, { signingPrivate: privateKeyName }),
    (error: unknown) => error instanceof FixtureRunnerError
      && error.message === "config and given.keys both supply signingPrivateJwk",
  );
});

test("an inherited signingPrivateJwk is not an own conflict after cloning", async () => {
  const literal = Object.create({ signingPrivateJwk: { kty: "RSA" } }) as Record<string, unknown>;
  literal.issuer = "https://issuer.example";
  const materialized = await materializeConfigInput(literal, { signingPrivate: privateKeyName });

  assert.notStrictEqual(materialized, literal);
  assert.equal((materialized as { signingPrivateJwk: { kty: string } }).signingPrivateJwk.kty, "EC");
  assert.equal(Object.hasOwn(materialized as object, "signingPrivateJwk"), true);
});

test("a named valid public key is accepted without injection", async () => {
  const literal = { issuer: "https://issuer.example" };
  const materialized = await materializeConfigInput(literal, {
    signingPrivate: privateKeyName, signingPublic: publicKeyName,
  });
  const expected = await privateJwk(privateKeyName);

  assert.notStrictEqual(materialized, literal);
  assert.deepEqual(materialized, { ...literal, signingPrivateJwk: expected });
  assert.equal(Object.hasOwn(materialized as object, "signingPublicJwk"), false);
});

async function withFixtureRoot(run: (root: string) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "mcp-sso-parity-config-"));
  try {
    await mkdir(join(root, "keys"));
    await run(root);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
}

test("a named missing public key rejects before anything uses it", async () => {
  await assert.rejects(
    materializeConfigInput({}, { signingPublic: publicKeyName.replace("signing-public.pem", "missing.pem") }),
    (error: unknown) => error instanceof FixtureRunnerError
      && error.message.includes("fixture key cannot be inspected"),
  );
});

test("a missing public key rejects before private materialization", async () => {
  const literal = { issuer: "https://issuer.example" };
  const expectedLiteral = { ...literal };
  await assert.rejects(
    materializeConfigInput(literal, {
      signingPrivate: privateKeyName,
      signingPublic: publicKeyName.replace("signing-public.pem", "missing.pem"),
    }),
    (error: unknown) => error instanceof FixtureRunnerError
      && error.message.includes("fixture key cannot be inspected"),
  );
  assert.deepEqual(literal, expectedLiteral);
  assert.equal(Object.hasOwn(literal, "signingPrivateJwk"), false);
});

test("a named symlinked public key rejects before anything uses it", async () => {
  await withFixtureRoot(async (root) => {
    await symlink(join(FIXTURES_ROOT, "keys", "signing-public.pem"), join(root, "keys", "public.pem"));
    await assert.rejects(
      materializeConfigInput({}, { signingPublic: "keys/public.pem" }, root),
      (error: unknown) => error instanceof FixtureRunnerError
        && error.message.includes("fixture key must be a regular non-symlink file"),
    );
  });
});

test("a named malformed public key rejects before anything uses it", async () => {
  await withFixtureRoot(async (root) => {
    await writeFile(join(root, "keys", "public.pem"), "not a PEM key\n", "utf8");
    await assert.rejects(
      materializeConfigInput({}, { signingPublic: "keys/public.pem" }, root),
      (error: unknown) => error instanceof FixtureRunnerError
        && error.message.includes("malformed ES256 public key"),
    );
  });
});

test("no keys preserve a cloned literal", async () => {
  const literal = { nested: { enabled: true }, list: ["read"] };
  const materialized = await materializeConfigInput(literal, {});

  assert.notStrictEqual(materialized, literal);
  assert.deepEqual(materialized, literal);
  (literal.nested as { enabled: boolean }).enabled = false;
  assert.equal((materialized as { nested: { enabled: boolean } }).nested.enabled, true);
});
