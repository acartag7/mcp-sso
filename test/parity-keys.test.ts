import assert from "node:assert/strict";
import { copyFile, lstat, mkdir, mkdtemp, open, rm, symlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { FIXTURES_ROOT } from "./parity/corpus.ts";
import { FixtureRunnerError } from "./parity/error.ts";
import { privateJwk, publicKey, validateOpenedFile } from "./parity/keys.ts";

const loaders: Array<(name: unknown, root: string) => Promise<unknown>> = [privateJwk, publicKey];

async function withKeys(run: (root: string) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "mcp-sso-parity-keys-"));
  try {
    await mkdir(join(root, "keys"));
    await copyFile(resolve(FIXTURES_ROOT, "keys/signing-private.pem"), join(root, "keys/private.pem"));
    await copyFile(resolve(FIXTURES_ROOT, "keys/signing-public.pem"), join(root, "keys/public.pem"));
    await run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function expectRunnerError(action: () => Promise<unknown>, pattern: RegExp): Promise<void> {
  await assert.rejects(action, (error: unknown) => {
    assert.ok(error instanceof FixtureRunnerError);
    assert.match(error.message, pattern);
    return true;
  });
}

async function expectPathCases(root: string, cases: Array<[unknown, RegExp]>): Promise<void> {
  for (const [name, pattern] of cases) {
    for (const load of loaders) await expectRunnerError(() => load(name, root), pattern);
  }
}

test("materializes valid ES256 private and public keys", async () => withKeys(async (root) => {
  const jwk = await privateJwk("keys/private.pem", root);
  assert.deepEqual({ kty: jwk.kty, crv: jwk.crv }, { kty: "EC", crv: "P-256" });
  assert.equal(typeof jwk.d, "string");
  const key = await publicKey("keys/public.pem", root);
  assert.equal(key.type, "public");
  assert.equal(key.algorithm.name, "ECDSA");
}));

test("rejects an opened descriptor with a different file identity", async () => withKeys(async (root) => {
  const privatePath = join(root, "keys", "private.pem");
  const publicPath = join(root, "keys", "public.pem");
  const expected = await lstat(privatePath, { bigint: true });
  const handle = await open(publicPath, "r");
  try {
    await expectRunnerError(
      () => validateOpenedFile(handle, "keys/public.pem", expected),
      /changed between validation and open/,
    );
    await expectRunnerError(
      () => validateOpenedFile(handle, "keys/public.pem", { dev: 0n, ino: 0n }),
      /changed between validation and open/,
    );
  } finally {
    await handle.close();
  }
  const sameFile = await open(privatePath, "r");
  try {
    await assert.doesNotReject(() => validateOpenedFile(sameFile, "keys/private.pem", expected));
  } finally {
    await sameFile.close();
  }
}));

test("rejects invalid key path values and spelling", async () => withKeys(async (root) => {
  await expectPathCases(root, [
    [null, /must be relative/], [42, /must be relative/], ["", /must be relative/],
    ["/tmp/key.pem", /must be relative/], ["keys\\private.pem", /forward slashes/],
  ]);
}));

test("rejects lexical escapes and uninspectable keys", async () => withKeys(async (root) => {
  await expectPathCases(root, [
    ["../outside.pem", /outside fixtures\/keys/], ["keys/missing.pem", /cannot be inspected/],
    ["keys/\0.pem", /cannot be inspected/],
  ]);
}));

test("rejects final symlinks and non-regular targets", async () => withKeys(async (root) => {
  await symlink("private.pem", join(root, "keys", "final-link.pem"));
  await mkdir(join(root, "keys", "directory"));
  await expectPathCases(root, [
    ["keys/final-link.pem", /regular non-symlink/], ["keys/directory", /regular non-symlink/],
  ]);
}));

test("rejects physical escapes through an ancestor symlink", async () => withKeys(async (root) => {
  await mkdir(join(root, "outside"));
  await writeFile(join(root, "outside", "escaped.pem"), "outside", "utf8");
  await symlink("../outside", join(root, "keys", "ancestor"));
  await expectPathCases(root, [["keys/ancestor/escaped.pem", /resolves outside/]]);
}));

test("rejects an in-root ancestor symlink", async () => withKeys(async (root) => {
  await mkdir(join(root, "keys", "real"));
  await copyFile(join(root, "keys", "private.pem"), join(root, "keys", "real", "private.pem"));
  await symlink("real", join(root, "keys", "ancestor"));
  await expectPathCases(root, [["keys/ancestor/private.pem", /contains a symlink/]]);
}));

test("rejects a symlinked keys directory", async () => withKeys(async (root) => {
  await mkdir(join(root, "real-keys"));
  await copyFile(join(root, "keys", "private.pem"), join(root, "real-keys", "private.pem"));
  await copyFile(join(root, "keys", "public.pem"), join(root, "real-keys", "public.pem"));
  await rm(join(root, "keys"), { recursive: true });
  await symlink("real-keys", join(root, "keys"));
  await expectPathCases(root, [["keys/private.pem", /contains a symlink/]]);
}));

test("wraps malformed private PEM imports", async () => withKeys(async (root) => {
  await writeFile(join(root, "keys", "bad-private.pem"), "not a private key", "utf8");
  await expectRunnerError(() => privateJwk("keys/bad-private.pem", root), /malformed EC P-256 private key/);
}));

test("wraps malformed public PEM imports", async () => withKeys(async (root) => {
  await writeFile(join(root, "keys", "bad-public.pem"), "not a public key", "utf8");
  await expectRunnerError(() => publicKey("keys/bad-public.pem", root), /malformed ES256 public key/);
}));

test("wraps a valid public PEM passed to the private materializer", async () => withKeys(async (root) => {
  await expectRunnerError(() => privateJwk("keys/public.pem", root), /malformed EC P-256 private key/);
}));

test("wraps a valid private PEM passed to the public materializer", async () => withKeys(async (root) => {
  await expectRunnerError(() => publicKey("keys/private.pem", root), /malformed ES256 public key/);
}));
