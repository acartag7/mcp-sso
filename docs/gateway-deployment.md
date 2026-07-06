# Gateway deployment — SSO in front of token-only MCP servers

> The most common production shape for `mcp-sso`: an internal MCP server (or
> plain API) that only understands a **static credential** — an API key, a
> bearer token — needs to be shared with many people, and nobody wants to
> hand that credential out. You put a small **gateway** in front: users
> authenticate through your real IdP (Entra, Cloudflare Access, console
> pairing), the gateway verifies its own short-lived tokens on `/mcp`, and
> the static credential is injected **server-side only** — it never reaches
> an MCP client, a laptop, or a config file.
>
> Everything on this page uses shipped APIs. A worked `examples/` gateway is
> planned (contracts §17.9); this guide documents the pattern itself.

## The shape

```
coding agent ──OAuth (DCR + PKCE)──▶ gateway (mcp-sso) ──▶ upstream IdP (login)
     │                                    │
     └── /mcp + bridge-minted token ──▶ RequestAuthorizer
                                          │  valid ⇒ forward with the
                                          ▼  backend credential injected
                                    internal MCP server / API
```

- The agent adds the **gateway's** URL. RFC 9728 metadata tells it where to
  register (DCR) and authorize; the browser leg goes through your IdP.
- The bridge mints its own audience-bound tokens (§7.2). IdP tokens never
  pass through to the client — token passthrough is forbidden by the MCP
  spec, and by this library's design.
- The backend credential is read **once at boot** from the environment into a
  closure, is never logged, audited, placed in token claims, or returned to
  any client, and a missing credential is a **boot failure** (fail-closed,
  §5). Give it a single accessor (`getBackendCredential()`) so the swap to a
  secret-manager fetch later is one function.

## The `/mcp` handler: three shapes

The library gives you the auth surface (metadata routes, register/authorize/
token/revoke via `registerOAuthRoutes`/`createOAuthRouter`/`createOAuthApp`,
and `RequestAuthorizer` for the resource check). The `/mcp` body is yours:

1. **Transparent proxy** (least code, backend tools appear as-is). After
   `authorizer.authorize({...})` accepts the bearer token, forward the
   request to the internal MCP endpoint and relay the response. Rules that
   matter:
   - **The failure path is load-bearing.** `authorize()` *throws* on a
     missing/invalid/expired token — it does not build the response. Your
     handler must catch and answer with the OAuthError's status, a
     `WWW-Authenticate` header from `buildUnauthorizedChallenge(config,
     { scope, error, errorDescription })` (root export), and a JSON-RPC
     error body — exactly as `examples/fastify-sqlite/app.ts`'s `/mcp`
     handler does (contracts §8.2/§9.6). Without the
     `resource_metadata=...` challenge, MCP clients cannot discover the
     protected-resource metadata and **never start the OAuth flow at all**.
   - **Proxy the whole endpoint, not just POST.** The Streamable HTTP
     transport uses `POST` (JSON-RPC), `GET` (server-initiated SSE streams /
     resume), and `DELETE` (session termination). Forward all three with the
     same bearer check and challenge-on-failure; if the backend doesn't use
     the GET/DELETE flows, return an explicit 405 rather than silently
     dropping them.
   - **Never forward the client's `Authorization` header upstream** — replace
     it with the backend credential.
   - Forward `mcp-session-id` and `mcp-protocol-version` in both directions
     if the backend is stateful, and `Last-Event-ID` on GET — the transport
     resumes a broken SSE stream via `GET` + `Last-Event-ID`, so an
     allowlist that omits it silently breaks resumability.
   - Stream SSE responses through; do not buffer them.
2. **Facade** (you own the tool surface). Run your own `McpServer` whose
   tools call the backend API directly. More code, full control: validate
   inputs, expose only the operations users should have, and gate tools by
   the token's scopes (`requireScope`, §8) — e.g. `splunk:read` for search
   tools, `splunk:admin` for the rest.
3. **Proxy + tool gate** (the cheap middle). Proxy as in (1), but when the
   JSON-RPC `method` is `tools/call`, check the tool name against the
   caller's granted scopes before forwarding.

**Scope gates are NOT a per-user entitlement boundary by themselves.** With
the shipped identity ports (Entra, Cloudflare Access, console pairing),
token scopes are whatever the client *requests* from the deployment-wide
`scopeCatalog` and the user consents to — none of the shipped ports supplies
an `allowedScopes` ceiling, so **any** authorized user can request and
approve `splunk:admin` and then pass `requireScope`. Scope gating in (2)/(3)
therefore buys least-privilege hygiene (an agent that only asked for
`splunk:read` cannot call admin tools), not team-level restrictions. To make
scopes an entitlement boundary, an identity must supply the §17.4
`allowedScopes` ceiling (the enforcement engine is shipped): today that
means wrapping a shipped port with your own producer (e.g. derive the
ceiling from your own group lookup); the built-in Entra group→scope producer
is on the roadmap.

Start with (1); move to (2)/(3) when tool-level control matters — and pair
them with an `allowedScopes` producer when the control must be per-user or
per-team rather than per-request.

## Multiple backends: one gateway per MCP

Users usually want `splunk`, `tool4`, … as **separate servers** in their
agent, each added only by the people who need it. The supported topology:

- **One bridge = one `resource` = one audience, by design.** Run one gateway
  deployment per backend, each on its own hostname
  (`splunk-mcp.example.com/mcp`, `tool4-mcp.example.com/mcp`). This is the
  configuration verified live with real MCP clients.
- What that buys you: **audience isolation**. Tokens are minted with
  `aud = resource` and verified fail-closed (§7.2), so a token stolen from
  the Splunk gateway is rejected outright by every other gateway.
- Path-mounted resources (`resource: https://example.com/splunk/mcp`) are
  supported at the metadata level — the adapters register the RFC 9728
  path-inserted PRM route automatically — but hosting several *bridges*
  behind one origin means ingress-routing each bridge's OAuth and well-known
  routes too. Prefer subdomains unless you have a hard single-origin
  requirement.
- Adding backend N+1 is a config change, not a code change: same image, new
  hostname, new resource, new backend credential.

**Never share a store between bridge instances.** Refresh-token acceptance
is entirely store-scoped: the token is an opaque string looked up by hash
and rotated (`rotateRefreshToken`), with a client binding against the
*stored* record — no issuer or resource check, and no signature involved in
acceptance. So two bridges sharing one database let a refresh token issued
by gateway A be redeemed at gateway B, which then mints a token **validly
signed with B's own key for B's audience** — silently defeating the
isolation above. Sharing signing material is *not* required for this break;
store separation is the load-bearing control. One store (file or
database/schema) per bridge. Use separate signing keys per bridge too, as
independent hygiene: it doesn't substitute for store separation, but it
keeps a key compromise contained to one gateway.

*Residual, stated plainly: this isolation is enforced by deployment
discipline, not by the library — store records are not issuer-scoped today.
Issuer-scoped records (closing cross-bridge redemption in code) are a
candidate hardening tracked for a potential multi-resource bridge; until
then, the one-store-per-bridge rule is the control.*

## Kubernetes notes

Each gateway is a small Deployment + Service + Ingress + Secret:

- **Size**: one Node ≥24 process; the hot path is one ES256 verify per `/mcp`
  call. `requests: 100m/128Mi, limits: 500m/256Mi` is comfortable.
- **Secrets**: all three live as Kubernetes Secrets exposed as env vars, but
  they take **two separate paths in code**: the signing JWK and consent
  secret go into `createBridgeConfig`; the backend credential is read and
  validated separately at boot into the `getBackendCredential()` closure and
  **must never be placed in the `createBridgeConfig` input** —
  `BridgeConfig` has no backend-credential field, and extra keys currently
  survive onto the frozen public `bridge.config` object, which is passed
  around the whole app. The quickstart file helper (§17.8) is the *local
  zero-setup* path — do not use it in a pod.
- **Replicas × store**: the sqlite store means **one replica** with the file
  on a PVC — never `emptyDir`: refresh tokens are long-lived sessions, and
  losing the file on a reschedule logs every user out. For ≥2 replicas or
  clean rolling updates, use `/store/mysql` (+ `/rate-limit/redis` so limits
  are shared) — then all replicas share rotation/consent state correctly.
- **Probes**: `GET /.well-known/oauth-authorization-server` — unauthenticated,
  cheap, and because config validation is fail-closed at boot, a
  misconfigured pod never becomes Ready.
- **Shutdown**: handle SIGTERM in *your* entrypoint (close the server, then
  the store) so rolling updates drain in-flight requests.
- **Network**: terminate TLS at the ingress; the pod listens on `0.0.0.0`
  with `issuer`/`resource` set to the public https URL. Add a NetworkPolicy
  so only the gateway can reach the backend — the static credential is then
  useless even to someone who finds the backend's internal address.

## Who is allowed in

Two gates, documented in [`authorization.md`](authorization.md): the primary
gate lives at your IdP (Entra app assignment / Conditional Access, or
Cloudflare Access policy), and `mcp-sso`'s own allowlist
(`subjectAllowlist` / `emailAllowlist`) is defense-in-depth on top. With
`createEntraIdentity`, subjects key on the immutable `oid`. The
`allowedScopes` ceiling engine (§17.4) is shipped; the Entra group→scope
producer that feeds it is on the roadmap.

## Audit

Wire `combineAudit(new JsonlFileAudit(...), new WebhookAudit(...))` into the
Bridge and `RequestAuthorizer` — sinks, delivery trade-offs, and the
fail-open residual are covered in
[`audit-deployment.md`](audit-deployment.md). A webhook sink pointed at your
SIEM's HTTP collector gives the security team the full auth trail (metadata
only — never token values) with no extra moving parts.
