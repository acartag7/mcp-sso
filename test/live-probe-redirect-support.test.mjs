// Behavioural coverage for the shared probe callback preflight.
//
// The per-probe rows assert that each probe CALLS assertProbeClientRedirect.
// That is a wiring check: it cannot see whether the helper still consults the
// allowlist, reads the right environment, or honours the mode. Without the
// cases below, dropping assertAllowedRedirectUri from the helper would leave
// every other test green while callbacks outside the effective allowlist again
// reached provider I/O — the exact defect this preflight exists to stop.
import assert from "node:assert/strict";
import { test } from "node:test";
import { assertProbeClientRedirect } from "../scripts/live/probe-redirect-support.mjs";

const HOSTED = "https://claude.ai/api/mcp/auth_callback";
const OWN = "https://mcp.example/auth/callback";
const OTHER = "https://elsewhere.example/auth/callback";

test("probe preflight: extend mode trusts the built-in hosted origins", () => {
  assert.equal(assertProbeClientRedirect(HOSTED, {}), HOSTED);
});

test("probe preflight: extend mode also trusts a configured origin", () => {
  const env = { OAUTH_REDIRECT_ALLOWLIST: "https://mcp.example" };
  assert.equal(assertProbeClientRedirect(OWN, env), OWN);
  assert.equal(assertProbeClientRedirect(HOSTED, env), HOSTED,
    "extend must keep the built-ins alongside the configured entries");
});

test("probe preflight: replace mode drops the built-ins", () => {
  const env = {
    OAUTH_REDIRECT_ALLOWLIST: "https://mcp.example",
    OAUTH_REDIRECT_ALLOWLIST_MODE: "replace",
  };
  assert.equal(assertProbeClientRedirect(OWN, env), OWN);
  assert.throws(() => assertProbeClientRedirect(HOSTED, env), /not allowed/,
    "replace must refuse a built-in origin the operator deliberately dropped");
});

test("probe preflight: a callback outside the effective allowlist is refused", () => {
  // The reported defect: syntactically valid https, absent from the allowlist.
  // It must fail HERE, before any provider I/O — not later at /oauth/register.
  assert.throws(
    () => assertProbeClientRedirect(OTHER, {
      OAUTH_REDIRECT_ALLOWLIST: "https://mcp.example",
      OAUTH_REDIRECT_ALLOWLIST_MODE: "replace",
    }),
    /not allowed/,
  );
});

test("probe preflight: a non-https web callback is refused on scheme", () => {
  // http is admissible in the allowlist on loopback, so the allowlist parses
  // cleanly and the refusal can only come from the web-client scheme check.
  assert.throws(
    () => assertProbeClientRedirect("http://localhost:8787/auth/callback", {
      OAUTH_REDIRECT_ALLOWLIST: "http://localhost",
    }),
    /https/,
    "the scheme check must survive alongside the allowlist check",
  );
});

test("probe preflight: a malformed mode is rejected, never coerced to extend", () => {
  assert.throws(() => assertProbeClientRedirect(HOSTED, {
    OAUTH_REDIRECT_ALLOWLIST: "https://mcp.example",
    OAUTH_REDIRECT_ALLOWLIST_MODE: "Replace",
  }));
});

test("probe preflight: the mode is read from the environment, not assumed", () => {
  // Same callback, same allowlist, opposite outcomes — proves the env drives it.
  const allowlist = "https://mcp.example";
  assert.equal(assertProbeClientRedirect(HOSTED, { OAUTH_REDIRECT_ALLOWLIST: allowlist }), HOSTED);
  assert.throws(() => assertProbeClientRedirect(HOSTED, {
    OAUTH_REDIRECT_ALLOWLIST: allowlist, OAUTH_REDIRECT_ALLOWLIST_MODE: "replace",
  }));
});
