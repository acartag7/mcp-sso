/** README emitted by `mcp-sso init`, isolated from the executable server template. */
export function generatedReadme(name: string): string {
  return `# ${name}

An [mcp-sso](https://github.com/acartag7/mcp-sso) MCP server — OAuth 2.1 for a remote
MCP server, zero-setup (console pairing: no identity provider, no keys to generate).

## Run

\`\`\`bash
# LOCALHOST-ONLY. Do not expose this generated server to the internet.
npm install

# Terminal 1 — the server (stays foreground):
npm start

# Terminal 2 — once the server is up (it prints a one-time code ONLY when a client connects):
claude mcp add --transport http my-bridge http://127.0.0.1:3000/mcp
# → the server prints the code to Terminal 1; a browser opens — paste the code, approve.
\`\`\`

\`npm install\` creates \`package-lock.json\` — commit it. The top-level pins above are
exact (the versions mcp-sso is tested against); the lockfile fixes the transitive graph.

The server binds loopback (127.0.0.1) by default — the printed pairing code is the
identity gate, so it must not be exposed to the network. You may change PORT or select
another loopback HOST; the server rejects an internet-facing HOST, issuer, or resource
before it creates persistent state.

Set \`OAUTH_REDIRECT_ALLOWLIST_MODE=replace\` to drop the built-in hosted-client
origins for opaque/DCR clients. In that mode \`OAUTH_REDIRECT_ALLOWLIST\` must contain
at least one entry. Invalid mode configuration is rejected before persistent state.

## Production identity provider

Console pairing is for single-operator / private-console use. For a real identity
provider (Cloudflare Access, Microsoft Entra ID, Google, or a generic OIDC issuer),
graduate to the env-driven composition root in
[examples/fastify-sqlite](https://github.com/acartag7/mcp-sso/tree/main/examples/fastify-sqlite)
and follow [docs/gateway-deployment.md](https://github.com/acartag7/mcp-sso/blob/main/docs/gateway-deployment.md)
+ [docs/live-verification.md](https://github.com/acartag7/mcp-sso/blob/main/docs/live-verification.md).
`;
}
