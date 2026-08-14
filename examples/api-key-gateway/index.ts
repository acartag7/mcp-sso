// Standalone entry: `node examples/api-key-gateway/index.ts`.
//
// Two servers in one node invocation: a token-only stub backend (backend.ts) on a
// local port, and the mcp-sso gateway (app.ts) in front of it. The gateway reads
// BACKEND_API_KEY ONCE at boot into a closure (getBackendCredential); a missing key
// is a boot failure. The key is injected server-side on every proxied backend call
// and NEVER reaches an MCP client, a config file, or a laptop.
//
// Identity = console pairing by default (zero-setup local dev: paste a one-time code
// from the console), with the SAME env-switch to Cloudflare Access / Entra redirect /
// Google / generic OIDC as examples/fastify-sqlite. Ambiguous provider selection is
// rejected before backend configuration or listeners. For a real multi-user gateway
// use an IdP-backed port (console pairing is single-operator by design — see
// docs/gateway-deployment.md).

import { buildBackend } from "./backend.ts";
import {
  buildGatewayExample,
  defaultListenHost,
  productionIdentityConfigured,
} from "./app.ts";
import {
  assertConsolePairingListenHostBeforeState,
  assertSingleIdentityProviderSelector,
  UNSAFE_NON_LOOPBACK_PAIRING_ENV,
} from "../fastify-sqlite/app.ts";

async function main(): Promise<void> {
  assertSingleIdentityProviderSelector(process.env);
  if (!productionIdentityConfigured(process.env)
    && process.env[UNSAFE_NON_LOOPBACK_PAIRING_ENV] !== "true") {
    // The gateway has a second listener. Reject the public pairing bind before
    // even reading backend config or starting that backend. The exact unsafe
    // escape is warned by buildGatewayExample before state or either listener.
    assertConsolePairingListenHostBeforeState(process.env);
  }
  // Read the backend credential ONCE, behind a closure. Missing = boot failure.
  // NEVER place this in createBridgeConfig: (1) it would be rejected as an unknown
  // key with a boot AuthConfigError (contracts §5), and (2) even if accepted it
  // would ship on the public frozen bridge.config passed around the whole app. The
  // two paths stay separate: signing/consent material → createBridgeConfig; the
  // backend credential → this closure. (docs/gateway-deployment.md §"Kubernetes notes")
  const backendApiKey = process.env.BACKEND_API_KEY;
  if (!backendApiKey) {
    console.error(
      "[mcp-sso-gateway] BACKEND_API_KEY is required: the static credential the gateway injects for the backend MCP server. " +
        "Set it in the environment (or a secret manager that exports it); the gateway reads it once at boot and never logs, audits, or returns it.",
    );
    process.exit(1);
  }
  const getBackendCredential = (): string => backendApiKey;

  // Derive the trusted backend URL without starting a listener. buildGatewayExample
  // runs the no-IdP public-HOST preflight before creating state, so an unsafe public
  // bind is rejected (or its explicit escape warned) before this backend side effect.
  const backendPort = Number(process.env.BACKEND_PORT ?? 8788);
  const backendHost = process.env.BACKEND_HOST ?? "127.0.0.1";
  const backendUrl = `http://${backendHost}:${backendPort}/mcp`;

  // Build the gateway first (identity branch selected by env, same as
  // fastify-sqlite), then start the token-only stub backend on its local port.
  const { app, config } = await buildGatewayExample(process.env, { backendUrl, getBackendCredential });
  const backend = await buildBackend({ apiKey: backendApiKey });
  await backend.app.listen({ port: backendPort, host: backendHost });
  const port = Number(process.env.PORT ?? 3000);
  const host = process.env.HOST ?? defaultListenHost(process.env);
  await app.listen({ port, host });

  const mode = process.env.ENTRA_TENANT_ID !== undefined ? "Entra redirect" : process.env.CF_ACCESS_AUDIENCE !== undefined ? "Cloudflare Access" : process.env.GOOGLE_CLIENT_ID !== undefined ? "Google" : process.env.OIDC_ISSUER !== undefined ? "generic OIDC" : "console pairing";
  console.error(`mcp-sso api-key-gateway listening on ${host}:${port}  (identity: ${mode})`);
  console.error(`  issuer=${config.issuer}  resource=${config.resource}`);
  console.error(`  proxying /mcp → ${backendUrl}  (backend credential injected server-side; never exposed to clients)`);
}

main().catch((error) => { console.error(error); process.exit(1); });
