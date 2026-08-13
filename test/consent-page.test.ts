import assert from "node:assert/strict";
import { test } from "node:test";
import type { PreparedConsent } from "../src/authorize.ts";
import type { BridgeConfig } from "../src/config.ts";
import { renderConsentPage } from "../src/adapters/consent-page.ts";

const prepared: PreparedConsent = {
  clientId: "https://client.example.test/metadata.json",
  redirectUri: "https://callback.example.test/oauth/callback",
  resource: "https://api.example.test/mcp",
  scopes: ["mcp:read"],
  codeChallenge: "challenge",
  codeChallengeMethod: "S256",
  subject: "subject",
  consentToken: "consent",
  priorScopes: [],
  cimdVerified: true,
  cimd: {
    clientIdHost: "client.example.test",
    redirectHost: "callback.example.test",
    clientName: "Example Client",
    allRedirectsLoopback: false,
  },
};

test("consent page makes host anchors primary and the self-reported name secondary", () => {
  const html = renderConsentPage({} as BridgeConfig, prepared);
  const clientHostAt = html.indexOf("client.example.test");
  const redirectHostAt = html.indexOf("callback.example.test");
  const clientNameAt = html.indexOf("Example Client");

  assert.match(html, /Client ID host/);
  assert.match(html, /Redirect destination host/);
  assert.ok(clientHostAt >= 0 && redirectHostAt > clientHostAt);
  assert.ok(clientNameAt > redirectHostAt, "the cosmetic name follows both host anchors");
  assert.match(html, /Self-reported name/);
  assert.match(html, /\(unverified\)/);
  assert.match(html, /Check the two hosts above before approving/);
  assert.match(
    html,
    /\.client p\.client-host\{font-size:1rem;font-weight:700/,
    "the host values are visually emphasized as the primary identity anchors",
  );
  assert.match(
    html,
    /\.client-name,\.client-help\{font-size:\.85rem/,
    "the self-reported name and guidance remain visually secondary",
  );
});

test("consent page always displays the exact bound redirect URI", () => {
  const opaque = { ...prepared, cimdVerified: undefined, cimd: undefined };
  const html = renderConsentPage({} as BridgeConfig, opaque);
  assert.match(html, /Authorization code destination/);
  assert.match(html, /https:\/\/callback\.example\.test\/oauth\/callback/);
});

test("consent page escapes the displayed redirect URI", () => {
  const html = renderConsentPage({} as BridgeConfig, {
    ...prepared, redirectUri: "https://callback.example.test/cb?<unsafe>&x=\"quoted\"",
  });
  assert.doesNotMatch(html, /<unsafe>/);
  assert.match(html, /&lt;unsafe&gt;&amp;x=&quot;quoted&quot;/);
});
