# Field report: SSO in front of a token-only MCP backend

A real deployment of mcp-sso as an SSO gateway in front of an internal MCP
server that only accepted a static API key. Internal details (hostname, scopes,
OAuth parameters) are redacted. The tools + flow described here are what shipped.

## Problem

An internal MCP backend only accepted a static API key. The key was shared
across users — no per-user identity, no expiry, no revocation. Security flagged
it. The goal: users paste one MCP URL, log in with SSO, and the API key never
reaches a client config.

## Result

Claude Code and Claude Desktop both completed the full flow:

```
client → DCR + PKCE → Entra login → mcp-sso consent → callback → connected tools
```

Each client self-registered (`mcpdc_…`), redirected through Entra, saw the
mcp-sso consent screen, and connected with scoped tools. The backend API key was
injected server-side — it never appeared in any client config, response, or log.

## Architecture

```
MCP client ──OAuth (DCR + PKCE)──▶ mcp-sso gateway ──▶ Entra ID (login)
     │                                    │
     └── /mcp + bridge token ──▶ RequestAuthorizer
                                          │  valid ⇒ forward with the
                                          ▼  backend API key injected
                                    token-only MCP backend
```

## What mcp-sso handled

DCR, PKCE, consent, the Entra redirect flow (via `createUpstreamRedirectFlow`),
audience-bound token minting, and request authorization on `/mcp`.

## What the gateway handled

Server-side backend API-key injection (read once at boot into a closure, never
logged), header allowlist (client `Authorization` stripped before forwarding),
upstream proxying with the outbound target pinned to trusted config, and the
`WWW-Authenticate` failure path for unauthenticated requests.

## Lessons learned

1. **Do not forward upstream 401/403 challenges to MCP clients.** An upstream
   auth failure (wrong/expired backend key) is a server-side fault — relaying it
   as a 401 makes the client think *its* token is bad and re-run the entire
   OAuth login for nothing. Translate upstream 401/403 → 502. (The shipped
   `examples/api-key-gateway/` does not implement this yet — it relays
   `backendResp.status` verbatim. This was deployment-specific code in the field.
   Tracked in [issue #35](https://github.com/acartag7/mcp-sso/issues/35).)
2. **Use sqlite (or mysql), not memory, for DCR/auth state.** The memory store
   wipes registrations on restart, so clients silently re-DCR on every boot.
   Fine for a spike; not fine when you're debugging auth flows and restarting
   constantly.
3. **Add a startup preflight for the backend credential.** One `initialize` call
   against the backend at boot (or in `/healthz`) catches an expired/wrong key
   in seconds, not at first tool call.
4. **Path-scope the CF Access app (or equivalent) to the authorize leg only.** A
   whole-hostname app gates `/mcp` and `/oauth/token` too, breaking the client.
