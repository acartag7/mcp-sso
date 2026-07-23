import assert from "node:assert/strict";
import { test } from "node:test";
import { generateKeyPair, jwtVerify, SignJWT } from "jose";
import { WebhookAudit } from "../src/audit/webhook.ts";
import {
  defaultDiscoveryTransport, defaultTokenTransport,
} from "../src/identity/generic-oidc-discovery.ts";
import { createEntraRedirectIdentity } from "../src/identity/entra-redirect.ts";
import { createValidatedRemoteJWKSet } from "../src/identity/remote-jwks.ts";
import {
  assertDefaultTlsVerification, guardedGlobalFetch,
} from "../src/outbound-tls.ts";

test("ambient TLS guard walks descriptors without accessors and enforces a fixed bound", () => {
  const key = "NODE_TLS_REJECT_UNAUTHORIZED";
  const previousEnv = process.env[key];
  const originalPrototype = Object.getPrototypeOf(process.env) as object | null;
  let accessorReads = 0;
  try {
    delete process.env[key];
    const accessorPrototype = Object.create(originalPrototype) as object;
    Object.defineProperty(accessorPrototype, key, {
      configurable: true,
      get() { accessorReads += 1; return "0"; },
    });
    Object.setPrototypeOf(process.env, accessorPrototype);
    assert.throws(
      assertDefaultTlsVerification,
      /default_outbound_tls_verification_disabled/,
    );
    assert.equal(accessorReads, 0);

    const trappedPrototype = new Proxy(Object.create(originalPrototype) as object, {
      getOwnPropertyDescriptor() { throw new Error("descriptor trap"); },
    });
    Object.setPrototypeOf(process.env, trappedPrototype);
    assert.throws(
      assertDefaultTlsVerification,
      /default_outbound_tls_verification_disabled/,
    );

    let longPrototype: object | null = null;
    for (let index = 0; index < 33; index += 1) {
      longPrototype = Object.create(longPrototype) as object;
    }
    Object.setPrototypeOf(process.env, longPrototype);
    assert.throws(
      assertDefaultTlsVerification,
      /default_outbound_tls_verification_disabled/,
    );

    Object.setPrototypeOf(process.env, originalPrototype);
    process.env[key] = "1";
    assert.doesNotThrow(assertDefaultTlsVerification);
  } finally {
    Object.setPrototypeOf(process.env, originalPrototype);
    if (previousEnv === undefined) delete process.env[key];
    else process.env[key] = previousEnv;
  }
});

test("default outbound transports refuse disabled TLS verification before fetch", async () => {
  const previousEnv = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  const previousInherited = Object.getOwnPropertyDescriptor(
    Object.prototype,
    "NODE_TLS_REJECT_UNAUTHORIZED",
  );
  const previousFetch = globalThis.fetch;
  const previousError = console.error;
  let fetchCalls = 0;
  globalThis.fetch = (async () => {
    fetchCalls += 1;
    return new Response("unexpected transport call", { status: 503 });
  }) as typeof fetch;
  console.error = () => undefined;

  try {
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    Object.defineProperty(Object.prototype, "NODE_TLS_REJECT_UNAUTHORIZED", {
      configurable: true,
      value: "0",
    });
    await assert.rejects(
      () => guardedGlobalFetch("https://identity.test/inherited-tls-setting"),
      /default_outbound_tls_verification_disabled/,
    );
    delete (Object.prototype as Record<string, unknown>).NODE_TLS_REJECT_UNAUTHORIZED;

    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    await assert.rejects(
      () => guardedGlobalFetch("https://identity.test/metadata"),
      /default_outbound_tls_verification_disabled/,
    );
    await assert.rejects(
      defaultDiscoveryTransport.get("https://identity.test/.well-known/openid-configuration"),
      /default_outbound_tls_verification_disabled/,
    );
    await assert.rejects(
      defaultTokenTransport.postForm(
        "https://identity.test/token",
        new URLSearchParams({ grant_type: "authorization_code" }),
      ),
      /default_outbound_tls_verification_disabled/,
    );

    const { privateKey } = await generateKeyPair("RS256");
    const token = await new SignJWT({ sub: "subject" })
      .setProtectedHeader({ alg: "RS256", kid: "key-1" })
      .setExpirationTime("5m")
      .sign(privateKey);
    const jwks = createValidatedRemoteJWKSet(new URL("https://identity.test/jwks"));
    await assert.rejects(jwtVerify(token, jwks, { algorithms: ["RS256"] }));

    const entra = createEntraRedirectIdentity({
      tenantId: "11111111-2222-3333-4444-555555555555",
      clientId: "client-id",
      redirectUri: "https://auth.test/oauth/callback",
    });
    const exchange = await entra.exchangeAndVerify({
      code: "code",
      codeVerifier: "v".repeat(43),
      nonce: "nonce",
    });
    assert.ok(!exchange.ok && exchange.kind === "exchange_failed");

    const webhook = new WebhookAudit("https://audit.test/ingest");
    await webhook.writeAuthEvent({
      occurredAt: "2026-07-23T12:00:00.000Z",
      event: "identity.verify",
      status: "failure",
      reason: "transport_unavailable",
    });
    assert.equal(fetchCalls, 0);
  } finally {
    if (previousEnv === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previousEnv;
    if (previousInherited === undefined) {
      delete (Object.prototype as Record<string, unknown>).NODE_TLS_REJECT_UNAUTHORIZED;
    } else {
      Object.defineProperty(
        Object.prototype,
        "NODE_TLS_REJECT_UNAUTHORIZED",
        previousInherited,
      );
    }
    globalThis.fetch = previousFetch;
    console.error = previousError;
  }
});
