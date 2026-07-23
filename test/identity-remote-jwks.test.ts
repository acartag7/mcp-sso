import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createRemoteJWKSet, customFetch, errors, exportJWK, generateKeyPair, jwtVerify, SignJWT,
} from "jose";
import {
  createValidatedRemoteJWKSet, isRemoteJwksInfrastructureError,
} from "../src/identity/remote-jwks.ts";

test("token-side unsupported features are not remote JWKS infrastructure failures", () => {
  assert.equal(
    isRemoteJwksInfrastructureError(new errors.JOSENotSupported("unsupported token feature")),
    false,
  );
});

test("malformed remote JWKS is an infrastructure failure", () => {
  assert.equal(
    isRemoteJwksInfrastructureError(new errors.JWKSInvalid("malformed remote JWKS")),
    true,
  );
});

test("validated remote JWKS requires key selectors to be own data", async () => {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(publicKey);
  const token = await new SignJWT({ sub: "subject" })
    .setProtectedHeader({ alg: "RS256", kid: "selected-key" })
    .setExpirationTime("5m")
    .sign(privateKey);
  const response = () => new Response(JSON.stringify({ keys: [publicJwk] }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
  const options = { [customFetch]: async () => response() };

  let reads = 0;
  Object.defineProperty(Object.prototype, "kid", {
    configurable: true,
    enumerable: false,
    get() { reads += 1; return "selected-key"; },
  });
  try {
    const baseline = createRemoteJWKSet(new URL("https://issuer.test/baseline-jwks"), options);
    await assert.doesNotReject(jwtVerify(token, baseline, { algorithms: ["RS256"] }));
    assert.ok(reads > 0, "control did not exercise inherited selector lookup");

    reads = 0;
    const guarded = createValidatedRemoteJWKSet(new URL("https://issuer.test/guarded-jwks"), options);
    await assert.rejects(jwtVerify(token, guarded, { algorithms: ["RS256"] }));
    assert.equal(reads, 0, "selector accessor ran before the defensive check");
  } finally {
    delete (Object.prototype as Record<string, unknown>).kid;
  }
});

test("validated remote JWKS rejects response fields from a plain prototype", async () => {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(publicKey);
  const token = await new SignJWT({ sub: "subject" })
    .setProtectedHeader({ alg: "RS256", kid: "selected-key" })
    .setExpirationTime("5m")
    .sign(privateKey);
  let reads = 0;
  const prototype = Object.create(null) as Record<string, unknown>;
  Object.defineProperty(prototype, "status", {
    get() { reads += 1; return 200; },
  });
  const response = Object.assign(Object.create(prototype), {
    async json() { return { keys: [{ ...publicJwk, kid: "selected-key" }] }; },
  });
  const guarded = createValidatedRemoteJWKSet(
    new URL("https://issuer.test/guarded-response"),
    { [customFetch]: async () => response },
  );
  await assert.rejects(jwtVerify(token, guarded, { algorithms: ["RS256"] }));
  assert.equal(reads, 0);
});

test("validated remote JWKS drops unknown nested extensions without reading them", async () => {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  let reads = 0;
  const metadata = {};
  Object.defineProperty(metadata, "label", {
    enumerable: true,
    get() { reads += 1; return "accessor-value"; },
  });
  const publicJwk = {
    ...await exportJWK(publicKey),
    kid: "nested-key",
    metadata,
  };
  const token = await new SignJWT({ sub: "subject" })
    .setProtectedHeader({ alg: "RS256", kid: "nested-key" })
    .setExpirationTime("5m")
    .sign(privateKey);
  const guarded = createValidatedRemoteJWKSet(
    new URL("https://issuer.test/nested-jwks"),
    {
      [customFetch]: async () => ({
        status: 200,
        async json() { return { keys: [publicJwk] }; },
      }) as Response,
    },
  );

  await assert.doesNotReject(jwtVerify(token, guarded, { algorithms: ["RS256"] }));
  assert.equal(reads, 0);
  const cached = guarded.jwks() as { keys: Array<Record<string, unknown>> };
  assert.equal(Object.hasOwn(cached.keys[0]!, "metadata"), false);
});

test("validated remote JWKS preserves key_ops restrictions", async () => {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = {
    ...await exportJWK(publicKey),
    kid: "purpose-bound-key",
    key_ops: ["encrypt"],
  };
  const token = await new SignJWT({ sub: "subject" })
    .setProtectedHeader({ alg: "RS256", kid: "purpose-bound-key" })
    .setExpirationTime("5m")
    .sign(privateKey);
  const guarded = createValidatedRemoteJWKSet(
    new URL("https://issuer.test/key-purpose-jwks"),
    {
      [customFetch]: async () =>
        new Response(JSON.stringify({ keys: [publicJwk] }), { status: 200 }),
    },
  );

  await assert.rejects(
    jwtVerify(token, guarded, { algorithms: ["RS256"] }),
    (error: unknown) => error instanceof Error && "code" in error
      && error.code === "ERR_JWKS_NO_MATCHING_KEY",
  );
});

test("validated remote JWKS requires RSA and EC key material to be own data", async () => {
  const cases = [
    { alg: "RS256", kty: "RSA", material: ["n", "e"] as const },
    { alg: "ES256", kty: "EC", material: ["x", "y"] as const },
  ];
  for (const { alg, kty, material } of cases) {
    const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
    const publicJwk = await exportJWK(publicKey) as Record<string, unknown>;
    const token = await new SignJWT({ sub: "subject" })
      .setProtectedHeader({ alg, kid: `${kty.toLowerCase()}-missing-material` })
      .setExpirationTime("5m")
      .sign(privateKey);
    const previous = material.map((field) =>
      [field, Object.getOwnPropertyDescriptor(Object.prototype, field)] as const);
    for (const field of material) {
      Object.defineProperty(Object.prototype, field, {
        configurable: true, value: publicJwk[field],
      });
    }
    try {
      const incomplete = {
        kty,
        ...(kty === "EC" ? { crv: publicJwk.crv } : {}),
        kid: `${kty.toLowerCase()}-missing-material`,
        alg,
      };
      const guarded = createValidatedRemoteJWKSet(
        new URL(`https://issuer.test/${kty.toLowerCase()}-jwks`),
        {
          [customFetch]: async () =>
            new Response(JSON.stringify({ keys: [incomplete] }), { status: 200 }),
        },
      );
      await assert.rejects(jwtVerify(token, guarded, { algorithms: [alg] }));
    } finally {
      for (const [field, descriptor] of previous) {
        if (descriptor === undefined) delete (Object.prototype as Record<string, unknown>)[field];
        else Object.defineProperty(Object.prototype, field, descriptor);
      }
    }
  }
});
