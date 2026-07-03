# mcp-idp-bridge

OAuth 2.1 for remote MCP servers, self-hosted, one runtime dependency.

MCP clients (claude.ai, ChatGPT, Claude Code, Cursor) expect **Dynamic Client
Registration** to self-onboard against a remote MCP server. Your identity
provider (Microsoft Entra ID, Okta, Cloudflare Access, …) doesn't do DCR. This
library is the bridge:

- **Verifier** — spec-correct resource-server protection for any Streamable
  HTTP `/mcp` endpoint: RFC 9728 protected-resource metadata, proper
  `WWW-Authenticate` challenges, JWKS-cached JWT verification with
  **fail-closed audience validation**.
- **Bridge** — a small authorization server that speaks DCR + PKCE + consent
  to MCP clients while your IdP stays the identity source. It mints its own
  audience-bound tokens; upstream IdP tokens never pass through.

Extracted from a production MCP deployment. Security posture is the product:
hashed single-use codes, refresh rotation with family theft-detection,
anchored redirect allowlists, timing-safe PKCE, alg pinning, fail-closed
configuration, npm provenance, and a published threat model.

**Status: pre-release scaffold.**

## License

MIT
