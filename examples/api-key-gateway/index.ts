// Standalone entry: `node examples/api-key-gateway/index.ts`.
//
// Two servers in one node invocation: a token-only stub backend (backend.ts) on a
// local port, and the mcp-sso gateway (app.ts) in front of it. The gateway reads
// BACKEND_API_KEY ONCE at boot into a closure (getBackendCredential); a missing key
// is a boot failure. The key is injected server-side on every proxied backend call
// and NEVER reaches an MCP client, a config file, or a laptop.
//
// Identity = console pairing by default (zero-setup local dev: paste a one-time code
// from the console), with the SAME env-switch to Cloudflare Access / Entra redirect
// as examples/fastify-sqlite. For a real multi-user gateway use an IdP-backed port
// (console pairing is single-operator by design — see docs/gateway-deployment.md).

import { buildBackend } from "./backend.ts";
import { buildGatewayExample, defaultListenHost } from "./app.ts";

async function main(): Promise<void> {
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

  // Start the token-only stub backend on a local port. In production this is YOUR
  // internal MCP server / API that only accepts a static credential; bind it to
  // loopback (or behind a NetworkPolicy) so only the gateway can reach it — then the
  // static credential is useless even to someone who finds the backend's address.
  const backendPort = Number(process.env.BACKEND_PORT ?? 8788);
  const backendHost = process.env.BACKEND_HOST ?? "127.0.0.1";
  const backend = await buildBackend({ apiKey: backendApiKey });
  await backend.app.listen({ port: backendPort, host: backendHost });
  const backendUrl = `http://${backendHost}:${backendPort}/mcp`;

  // Build + listen the gateway (identity branch selected by env, same as fastify-sqlite).
  const { app, config } = await buildGatewayExample(process.env, { backendUrl, getBackendCredential });
  const port = Number(process.env.PORT ?? 3000);
  const host = process.env.HOST ?? defaultListenHost(process.env);
  // Warn if console pairing (single-operator envelope) is bound off-loopback.
  if (!process.env.CF_ACCESS_AUDIENCE && !process.env.ENTRA_TENANT_ID && host !== "127.0.0.1" && host !== "localhost") {
    console.error(
      `[mcp-sso-gateway] WARNING: console pairing is bound to ${host} (non-loopback). The pairing code is the identity gate — ` +
        "anyone who can reach this port can attempt it. Pairing is for single-operator / private-console deployments only; " +
        "use the Cloudflare Access or Entra path for network-exposed deployments.",
    );
  }
  await app.listen({ port, host });

  const mode = process.env.ENTRA_TENANT_ID ? "Entra redirect" : process.env.CF_ACCESS_AUDIENCE ? "Cloudflare Access" : "console pairing";
  console.error(`mcp-sso api-key-gateway listening on ${host}:${port}  (identity: ${mode})`);
  console.error(`  issuer=${config.issuer}  resource=${config.resource}`);
  console.error(`  proxying /mcp → ${backendUrl}  (backend credential injected server-side; never exposed to clients)`);
}

main().catch((error) => { console.error(error); process.exit(1); });
