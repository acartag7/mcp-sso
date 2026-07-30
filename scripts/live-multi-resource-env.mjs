#!/usr/bin/env node
// Generate a ready-to-source .env for the two-resource live gate
// (docs/live-verification.md checklist E).
//
//   node scripts/live-multi-resource-env.mjs https://mcp.example > live.env
//
// Writes real signing material to STDOUT. Everything CF-Access-specific is left
// as a placeholder you must fill from your Zero Trust dashboard — the script
// cannot know your AUD tag or team name, and guessing them would produce a file
// that boots and then fails identity verification in a confusing way.
//
// The generated secrets are single-use for one verification run. Do not reuse
// them for anything else and do not commit the file.

import { generateKeyPairSync, randomBytes } from "node:crypto";

const issuer = process.argv[2];
if (!issuer) {
  console.error("usage: node scripts/live-multi-resource-env.mjs https://<your-host>");
  process.exit(2);
}

let origin;
try {
  const url = new URL(issuer);
  if (url.protocol !== "https:") throw new Error("issuer must be https");
  origin = url.origin;
} catch (error) {
  console.error(`invalid issuer: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(2);
}

const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const kid = `live-${randomBytes(4).toString("hex")}`;
const jwk = { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid };

// Redirect URIs for the clients checklist E drives. Claude Code registers its
// own loopback callback via DCR, so only the hosted clients need listing.
const redirects = [
  "https://claude.ai/api/mcp/auth_callback",
  "https://chatgpt.com/connector_platform_oauth_redirect",
];

process.stdout.write(`# Generated for the two-resource live gate — do NOT commit.
# Issuer: ${origin}
# Resources: ${origin}/grafana/mcp and ${origin}/memory/mcp

OAUTH_ISSUER=${origin}
OAUTH_SIGNING_KEY_ID=${kid}
OAUTH_SIGNING_PRIVATE_JWK=${JSON.stringify(jwk)}
OAUTH_CONSENT_SIGNING_SECRET=${randomBytes(32).toString("hex")}
OAUTH_REDIRECT_ALLOWLIST=${redirects.join(",")}

# --- Fill these from Cloudflare Zero Trust ------------------------------------
# CF_ACCESS_AUDIENCE  = the application's hex AUD tag (NOT the hostname)
# CF_ACCESS_ISSUER    = https://<team>.cloudflareaccess.com  (NO trailing slash)
# Scope the Access application to /oauth/authorize* ONLY. A whole-hostname app
# gates /mcp and /oauth/token too, so the client's server-side calls get a login
# redirect and the flow cannot complete.
CF_ACCESS_AUDIENCE=
CF_ACCESS_ISSUER=https://<team>.cloudflareaccess.com
CF_ACCESS_CERTS_URL=https://<team>.cloudflareaccess.com/cdn-cgi/access/certs
CF_ACCESS_EMAIL_ALLOWLIST=you@example.com

# --- Server -------------------------------------------------------------------
SQLITE_FILE=./live-multi-resource.db
PORT=8787
HOST=127.0.0.1
`);
