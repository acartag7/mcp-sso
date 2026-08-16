// A consent token outlives the process that minted it. `redirectAllowlistMode`
// is read at request time, so a token minted while `https://claude.ai` was
// trusted is still presentable after the operator restarts into `"replace"`.
//
// The entry-point guards (DCR write, authorize, stored re-validation) all run
// BEFORE the token exists. `approve` is the stored-state sibling: without a
// re-check there, a flow begun seconds before the trust change still delivers a
// code — or a Deny redirect — to the exact origin the operator removed.
//
// Both exits matter. A Deny that redirects to the removed origin leaks the
// flow's existence and its `state` to that origin just as surely as the code does.
import assert from "node:assert/strict";
import { test } from "node:test";

import type { BridgeConfig } from "../src/config.ts";
import { createBridgeConfig } from "../src/config.ts";
import { OAuthAuthorizationUseCase } from "../src/authorize.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { pkceChallenge } from "../src/crypto.ts";
import type { AuditPort } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";

const BUILT_IN = "https://claude.ai/cb";
const OWN = "https://private.test/cb";
const SUBJECT = "user-1";
const NOW_MS = 1_700_000_000_000;

const audit: AuditPort = { writeAuthEvent: async () => {} };
const clock: ClockPort = { nowMs: () => NOW_MS };

function config(mode?: "extend" | "replace"): BridgeConfig {
  return createBridgeConfig({
    issuer: "https://auth.test",
    resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: { kty: "EC", crv: "P-256", d: "d", x: "x", y: "y" },
    signingKeyId: "key-1",
    redirectAllowlist: [OWN],
    ...(mode ? { redirectAllowlistMode: mode } : {}),
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  } as BridgeConfig);
}

/** Mint a consent token for `redirectUri` under `extend`, then hand it to a
 *  use-case built on the SAME store but a different mode — the restart. */
async function consentMintedUnderExtend(redirectUri: string) {
  const store = new MemoryStore();
  const before = new OAuthAuthorizationUseCase({ config: config("extend"), store, clock, audit });
  const prepared = await before.prepare({
    clientId: "client-1", redirectUri, responseType: "code",
    codeChallenge: pkceChallenge("correct-horse-battery-staple-0123456789abcdef0123"),
    codeChallengeMethod: "S256", scope: "mcp:read", state: "state-1", subject: SUBJECT,
  });
  return { store, consentToken: prepared.consentToken };
}

test("approve refuses a carried consent for an origin dropped by the mode change", async () => {
  const { store, consentToken } = await consentMintedUnderExtend(BUILT_IN);
  const after = new OAuthAuthorizationUseCase({ config: config("replace"), store, clock, audit });

  await assert.rejects(
    () => after.approve({ consentToken, approved: true, origin: "https://auth.test" }),
    (error: unknown) => {
      assert.match(String((error as Error).message), /redirect_uri is not allowed/);
      // It must NOT be reported by redirecting to the very origin under dispute.
      assert.equal((error as { redirect?: unknown }).redirect, undefined,
        "the rejection must be a direct error, never a redirect to the untrusted URI");
      return true;
    },
  );
});

test("the Deny exit is covered too, not just approval", async () => {
  // Deny redirects without minting a code, so it is easy to leave unguarded —
  // but it still hands `state` to the removed origin.
  const { store, consentToken } = await consentMintedUnderExtend(BUILT_IN);
  const after = new OAuthAuthorizationUseCase({ config: config("replace"), store, clock, audit });

  await assert.rejects(
    () => after.approve({ consentToken, approved: false, origin: "https://auth.test" }),
    (error: unknown) => {
      assert.match(String((error as Error).message), /redirect_uri is not allowed/);
      return true;
    },
  );
});

// --- what must NOT change ---------------------------------------------------

test("a carried consent for a still-trusted origin approves normally", async () => {
  const { store, consentToken } = await consentMintedUnderExtend(OWN);
  const after = new OAuthAuthorizationUseCase({ config: config("replace"), store, clock, audit });
  const approved = await after.approve({ consentToken, approved: true, origin: "https://auth.test" });
  assert.ok(approved.code, "the operator's own origin still works after the switch");
  assert.match(approved.redirectTo, /^https:\/\/private\.test\/cb/);
});

test("without a mode change the built-in origin still approves", async () => {
  const { store, consentToken } = await consentMintedUnderExtend(BUILT_IN);
  const after = new OAuthAuthorizationUseCase({ config: config("extend"), store, clock, audit });
  const approved = await after.approve({ consentToken, approved: true, origin: "https://auth.test" });
  assert.ok(approved.code, "extend must be unaffected — this guard is mode-aware, not a blanket re-check");
});

test("Deny to a still-trusted origin still redirects", async () => {
  const { store, consentToken } = await consentMintedUnderExtend(OWN);
  const after = new OAuthAuthorizationUseCase({ config: config("replace"), store, clock, audit });
  const denied = await after.approve({ consentToken, approved: false, origin: "https://auth.test" });
  assert.match(denied.redirectTo, /error=access_denied/);
});
