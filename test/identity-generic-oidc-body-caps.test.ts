// §17.6 body caps (owner decision D5): the default discovery and token
// transports stream-count IdP-fetched bodies and abort the download the moment
// the cap is exceeded, so a hostile or broken IdP cannot force the bridge to
// materialize an oversized discovery document or token response before any
// validation runs. Transcribed from the executed assessment PoC
// (p2-oidc-body.mjs): there a 32 MB discovery document was fully downloaded
// and parsed; here it must be rejected mid-download at 65536 bytes.
//
// The identity-level legs stand up a LOCAL https server with a self-signed
// certificate (test/fixtures/oidc-cap-test-*.pem) and relax TLS verification
// via NODE_TLS_REJECT_UNAUTHORIZED for those legs only — the same local-harness
// trick the PoC used, reproduced honestly: the property under test is the BYTE
// CAP, not chain validation (the ports enforce https issuers everywhere, and
// the CIMD guarded fetcher even pins rejectUnauthorized against this env var —
// src/cimd/node-io.ts). node:test runs each file in its own process and these
// tests are sequential, so the variable is restored in each finally.

import assert from "node:assert/strict";
import { once } from "node:events";
import http from "node:http";
import https from "node:https";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import type { AddressInfo } from "node:net";
import {
  createDiscoveryTransport, createTokenTransport,
  DEFAULT_MAX_DISCOVERY_DOCUMENT_BYTES, DEFAULT_MAX_TOKEN_RESPONSE_BYTES,
} from "../src/identity/generic-oidc-transports.ts";
import { resolveEndpoints } from "../src/identity/generic-oidc-discovery.ts";
import { createGenericOidcIdentity, createGenericOidcRedirectIdentity, type GenericOidcConfig } from "../src/identity/generic-oidc.ts";

const KEY = readFileSync(new URL("fixtures/oidc-cap-test-key.pem", import.meta.url));
const CERT = readFileSync(new URL("fixtures/oidc-cap-test-cert.pem", import.meta.url));

/** Write `totalBytes` in `chunkSize` chunks, honoring backpressure, and stop
 *  early once the response is destroyed (the client cancels at the cap). The
 *  1 ms inter-chunk pace keeps the producer slower than the aborted
 *  connection's RST, so `written` measures what was actually pushed — without
 *  it, a small body hands entirely to the kernel's socket buffer before the
 *  cancel lands and the counter cannot discriminate. The 25 ms arm bounds a
 *  "close already emitted" race so the loop can re-check `destroyed`. Resolves
 *  with the bytes handed to the socket — the non-materialization signal (the
 *  pre-cap code drained the whole body, so this counter reached `totalBytes`). */
async function streamChunked(res: http.ServerResponse, totalBytes: number, chunkSize: number): Promise<number> {
  const chunk = Buffer.alloc(chunkSize, 0x78); // "x" — plausible JSON padding
  let written = 0;
  while (written < totalBytes && !res.destroyed && !res.writableEnded) {
    written += chunk.length;
    if (!res.write(chunk)) await Promise.race([once(res, "drain"), new Promise((r) => setTimeout(r, 25))]);
    else await new Promise((r) => setTimeout(r, 1));
  }
  res.end();
  return written;
}

function listen(server: http.Server | https.Server): Promise<number> {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)));
}

test("createDiscoveryTransport: within-cap document parses; oversized document is rejected mid-download, not drained", async () => {
  let done: Promise<number> | undefined;
  const server = http.createServer((req, res) => {
    if (req.url === "/small") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    done = streamChunked(res, 8 * 1024 * 1024, 64 * 1024);
  });
  const port = await listen(server);
  const transport = createDiscoveryTransport(DEFAULT_MAX_DISCOVERY_DOCUMENT_BYTES);
  try {
    const small = await transport.get(`http://127.0.0.1:${port}/small`);
    assert.equal(small.status, 200);
    assert.deepEqual(await small.json(), { ok: true }); // control: the instrument passes small docs through
    const big = await transport.get(`http://127.0.0.1:${port}/big`);
    await assert.rejects(big.json(), /generic_oidc_discovery_failed: discovery document exceeded the 65536-byte cap/);
    const written = await done!;
    assert.ok(written < 4 * 1024 * 1024, `server wrote ${written} bytes of an 8 MiB body — the download must abort near the cap`);
  } finally {
    server.close();
    server.closeAllConnections();
  }
});

test("createTokenTransport: oversized token response is rejected mid-download at the 16384-byte cap", async () => {
  let done: Promise<number> | undefined;
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    done = streamChunked(res, 256 * 1024, 16 * 1024);
  });
  const port = await listen(server);
  const transport = createTokenTransport(DEFAULT_MAX_TOKEN_RESPONSE_BYTES);
  try {
    const resp = await transport.postForm(`http://127.0.0.1:${port}/token`, new URLSearchParams({ code: "c", code_verifier: "v" }));
    await assert.rejects(resp.text(), /generic_oidc_exchange_failed: token response exceeded the 16384-byte cap/);
    const written = await done!;
    assert.ok(written < 128 * 1024, `server wrote ${written} bytes of a 256 KiB body — the download must abort near the cap`);
  } finally {
    server.close();
    server.closeAllConnections();
  }
});

test("body caps: closed integer domain [1024, 1048576], boot-validated in BOTH modes; in-domain values boot", async () => {
  const base = { issuer: "https://idp.example.com", clientId: "cid", redirectUri: "https://bridge.test/cb" };
  const manual = { authorizationEndpoint: "https://idp.example.com/auth", tokenEndpoint: "https://idp.example.com/token", jwksUri: "https://idp.example.com/jwks" };
  const bad = [1023, 1048577, 4096.5, NaN, Infinity, "65536", null];
  for (const v of bad) {
    const asForged = v as unknown as number;
    await assert.rejects(
      createGenericOidcIdentity({ ...base, endpoints: manual, maxDiscoveryDocumentBytes: asForged } as GenericOidcConfig),
      /generic_oidc_bad_config: maxDiscoveryDocumentBytes must be an integer in \[1024, 1048576\]/,
    );
    await assert.rejects(
      createGenericOidcIdentity({ ...base, endpoints: manual, maxTokenResponseBytes: asForged } as GenericOidcConfig),
      /generic_oidc_bad_config: maxTokenResponseBytes must be an integer in \[1024, 1048576\]/,
    );
  }
  for (const v of [1024, 65536, 1048576]) {
    const identity = await createGenericOidcIdentity({ ...base, endpoints: manual, maxDiscoveryDocumentBytes: v, maxTokenResponseBytes: v });
    assert.equal(typeof identity.exchangeCodeForToken, "function");
  }
});

test("resolveEndpoints: an out-of-domain discovery cap fails boot before ANY fetch (even with a custom transport)", async () => {
  const never = { get: () => { throw new Error("transport must not be reached"); } };
  await assert.rejects(
    resolveEndpoints({ issuer: "https://idp.example.com", endpoints: "discover", maxDiscoveryDocumentBytes: 1023 }, never),
    /generic_oidc_bad_config: maxDiscoveryDocumentBytes/,
  );
});

test("createGenericOidcIdentity: a 32 MB discovery document is rejected at the byte cap without being materialized", async () => {
  const prev = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // local-harness trick — see file header
  const TOTAL = 32 * 1024 * 1024; // the PoC's size: comfortably past any socket buffering
  let done: Promise<number> | undefined;
  const server = https.createServer({ key: KEY, cert: CERT }, (_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.write('{"issuer":"https://idp.example.com","padding":"'); // plausible opener, then megabytes
    done = streamChunked(res, TOTAL, 64 * 1024);
  });
  try {
    const port = await listen(server);
    await assert.rejects(
      createGenericOidcIdentity({ issuer: `https://127.0.0.1:${port}`, clientId: "cid", redirectUri: `https://127.0.0.1:${port}/cb`, endpoints: "discover" }),
      /generic_oidc_discovery_failed: discovery document exceeded the 65536-byte cap/,
    );
    const written = await done!;
    assert.ok(written < TOTAL / 2, `server wrote ${written} bytes of the 32 MiB document — the download must abort near the cap, not drain`);
  } finally {
    if (prev === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = prev;
    server.close();
    server.closeAllConnections();
  }
});

test("redirect port: an oversized token response is exchange_failed, never identity_rejected (§17.11 throw rule)", async () => {
  const prev = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // local-harness trick — see file header
  let done: Promise<number> | undefined;
  const server = https.createServer({ key: KEY, cert: CERT }, (_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    done = streamChunked(res, 1024 * 1024, 16 * 1024);
  });
  try {
    const port = await listen(server);
    const identity = await createGenericOidcRedirectIdentity({
      issuer: `https://127.0.0.1:${port}`,
      clientId: "cid",
      redirectUri: `https://127.0.0.1:${port}/cb`,
      endpoints: {
        authorizationEndpoint: `https://127.0.0.1:${port}/auth`,
        tokenEndpoint: `https://127.0.0.1:${port}/token`,
        jwksUri: `https://127.0.0.1:${port}/jwks`,
      },
    });
    const result = await identity.exchangeAndVerify({ code: "c", codeVerifier: "v", nonce: "n" });
    if (result.ok) assert.fail("an oversized token response must not succeed");
    assert.equal(result.kind, "exchange_failed"); // never identity_rejected — no identity decision was made
    assert.match(result.reason, /exceeded the 16384-byte cap/);
    const written = await done!;
    assert.ok(written < 512 * 1024, `server wrote ${written} bytes of a 1 MiB token response — the download must abort near the cap`);
  } finally {
    if (prev === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = prev;
    server.close();
    server.closeAllConnections();
  }
});
