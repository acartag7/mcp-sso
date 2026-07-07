# Gateway deployment — SSO in front of token-only MCP servers

> The most common production shape for `mcp-sso`. An internal MCP server (or
> plain API) only understands a **static credential** — an API key, a bearer
> token — that many people need, and nobody wants to hand out. Put a small
> **gateway** in front: users authenticate through your real IdP (Entra,
> Cloudflare Access, any OIDC); the gateway verifies its own short-lived tokens
> on `/mcp`; the static credential is injected **server-side only** — it never
> reaches an MCP client, a laptop, or a config file.
>
> A runnable worked example lives at
> [`examples/api-key-gateway/`](../examples/api-key-gateway) — mcp-sso as the
> SSO front door for a token-only stub backend, with the credential injected
> server-side and a full proxied round trip covered by
> `test/integration-gateway.test.ts`. This guide documents the pattern rule for
> rule.

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
- The bridge mints its own audience-bound tokens (§7.2). **IdP tokens never pass
  through to the client** — token passthrough is forbidden by the MCP spec and by
  this library's design.
- The backend credential is read **once at boot** from the environment into a
  closure. It is never logged, audited, placed in token claims, or returned to any
  client. A missing credential is a **boot failure** (fail-closed, §5). Give it a
  single accessor (`getBackendCredential()`) so a later swap to a secret-manager
  fetch is one function.

> **Console pairing is not an SSO option here.** It's single-operator by design —
> reading the process stderr *is* the trust boundary, and every pairing mints the
> same `console-operator` subject. In a many-people gateway that gives everyone
> who can see the log the *same* identity, erasing per-user audit + entitlement
> separation. Use it for local/single-operator dev only; for real multi-user
> access use an IdP-backed port.

## The login leg: how the user actually signs in

The shipped `/oauth/authorize` is **header-driven**: it reads one header
(`identityHeader`, default `cf-access-jwt-assertion`) and passes it to your
`IdentityPort.verify`. That is complete **only when a fronting layer has already
done the login and injected the identity assertion**. With no fronting injection
there is no login — `verify` gets nothing and the user gets a **direct 401, not a
sign-in**. Two supported ways to supply that leg:

1. **Assertion-injecting proxy (header model, zero code).** Front the gateway
   with Cloudflare Access (or any reverse proxy that injects a verified id_token
   into `identityHeader`). The shipped authorize does the rest.
2. **The shipped redirect orchestrator (§17.11).** For an OIDC-redirect IdP
   (Entra today; generic OIDC / Google / GitHub are v0.3), build
   `createEntraRedirectIdentity` → pass it to `createUpstreamRedirectFlow` → hand
   the result to the adapter's `upstream` option
   (`registerOAuthRoutes(app, { bridge, upstream })`). It owns the whole dance
   turnkey: per-flow `state`/`nonce`/upstream PKCE, a signed same-browser flow
   cookie carrying the original MCP authorize params, callback validation +
   `exchangeCodeForToken` + `verify` (with the `nonce` bound to the login), then
   `handleAuthorize` with the identity's `allowedScopes` ceiling, consent, and the
   `identity.verify` + `oauth.upstream.callback` audit events. Both examples wire
   it when `ENTRA_TENANT_ID` is set — copy that; do not hand-roll the redirect.

> **If you hand-roll anyway, do NOT finish by re-injecting the id_token into the
> header path.** `resolveIdentity` calls `verify(idToken)` with **no**
> `expectedNonce`, so the header route validates `iss`/`aud`/signature but never
> binds the id_token to the login request — leaving id_token replay/injection
> open. The orchestrator avoids exactly this (it calls
> `verify(idToken, { expectedNonce })` on the callback leg). Prefer it.

## The `/mcp` handler: three shapes

The library gives you the auth surface (metadata routes, register/authorize/
token/revoke, and `RequestAuthorizer` for the resource check). The `/mcp` body is
yours.

**1. Transparent proxy** (least code; backend tools appear as-is). After
`authorizer.authorize({...})` accepts the bearer token, forward to the internal
MCP endpoint and relay the response. (The reference is
[`examples/api-key-gateway/app.ts`](../examples/api-key-gateway/app.ts) — every
rule below is implemented there.)

- **The failure path is load-bearing.** `authorize()` *throws* on a
  missing/invalid/expired token — it does not build the response. Catch it and
  answer with the OAuthError's status, a `WWW-Authenticate` header from
  `buildUnauthorizedChallenge(config, { scope, error, errorDescription })`, and a
  JSON-RPC error body (contracts §8.2/§9.6). **Without the
  `resource_metadata=…` challenge, MCP clients cannot discover the
  protected-resource metadata and never start the OAuth flow at all.**
- **Proxy the whole endpoint, not just POST.** The Streamable HTTP transport uses
  `POST` (JSON-RPC), `GET` (SSE streams / resume), and `DELETE` (session
  termination). Forward all three with the same bearer check and
  challenge-on-failure. If the backend doesn't use GET/DELETE, return an explicit
  405 rather than silently dropping them.
- **Validate `Origin` before anything else.** The spec says servers MUST validate
  `Origin` on every connection and 403 when it is present but not allowlisted
  (DNS-rebinding protection). `RequestAuthorizer` checks the bearer + scopes only
  — the Origin check on your `/mcp` endpoint is yours. Enforce it as a pre-parse,
  method-agnostic hook (Fastify `onRequest` / express middleware before `json()`),
  not inside the POST handler; the SDK's
  `StreamableHTTPServerTransport` options (`enableDnsRebindingProtection`,
  `allowedOrigins`) are off by default.
- **Strip the client `Authorization` before forwarding.** Once `authorize()`
  succeeds, the inbound `Authorization: Bearer …` has done its job — it still
  carries the **bridge-minted per-user token**, which is `aud`-bound to *this*
  gateway. If it rides along to the backend (or into its logs), anyone reading
  them can **replay it against `/mcp` as that user until it expires**. Delete or
  overwrite `Authorization` (and `Cookie`, `Proxy-Authorization`) on the forwarded
  request. Prefer an explicit **allowlist** of forwarded headers over
  pass-through-minus-blocklist — an allowlist fails closed when a new header
  appears.
- **Carry the transport's required headers, or you break interop.** A forward
  allowlist must explicitly include: `MCP-Protocol-Version` (the client MUST send
  it every request after init; drop it and the backend assumes `2025-03-26` and
  can diverge — forward unconditionally), `Accept` (`application/json, text/event-stream`
  on POST, `text/event-stream` on GET — strip it and a strict backend rejects the
  POST or disables SSE), `Content-Type: application/json` on POST,
  `mcp-session-id` (both directions, when the backend is stateful), and
  `Last-Event-ID` on GET (the transport resumes a broken SSE stream via it).
- Stream SSE responses through; do not buffer them.

**2. Facade** (you own the tool surface). Run your own `McpServer` whose tools
call the backend API directly. More code, full control: validate inputs, expose
only the operations users should have, and gate tools by the token's scopes
(`requireScope`, §8).

**3. Proxy + tool gate** (the cheap middle). Proxy as in (1), but when the
JSON-RPC `method` is `tools/call`, check the tool name against the caller's
granted scopes before forwarding.

- **Don't assume the POST body is a single object.** A gate keyed on
  `body.method === "tools/call"` reads `undefined` when the body is a JSON-RPC
  **batch array** and proxies the whole batch **unchecked** — fail-open. The
  current MCP spec (`2025-06-18`) removed batching, so reject a top-level array
  with a JSON-RPC error. If you must serve legacy (`2025-03-26`) batching,
  normalize to an array and gate **every** request, denying the **entire** batch
  on any unauthorized entry — never split and forward the allowed subset.

**Scope gates are not a per-user entitlement boundary by themselves.** Token
scopes are whatever the client requests from the deployment-wide `scopeCatalog`
and the user consents to — any authorized user can request and approve the
highest scope and then pass `requireScope`. Scope gating buys least-privilege
hygiene (an agent that only asked for `read` cannot call admin tools), not
team-level restrictions. To make scopes an entitlement boundary, an identity must
supply the §17.4 `allowedScopes` ceiling: the Entra **group→scope producer is
shipped** (`createEntraIdentity` with `groupAuthorization`), and you can wrap any
port with your own producer (derive the ceiling from your own group lookup).

Start with (1); move to (2)/(3) when tool-level control matters — and pair them
with an `allowedScopes` producer when the control must be per-user/per-team.

## Multiple backends: one gateway per MCP

Users usually want `splunk`, `tool4`, … as **separate servers** in their agent,
each added only by the people who need it.

- **One bridge = one `resource` = one audience, by design.** Run one gateway per
  backend, each on its own hostname (`splunk-mcp.example.com/mcp`). This is the
  shape verified live with real MCP clients.
- **Audience isolation.** Tokens are minted with `aud = resource` and verified
  fail-closed (§7.2), so a token stolen from the Splunk gateway is rejected
  outright by every other gateway.
- **Prefer subdomains over path-mounting.** Path-mounted resources
  (`resource: https://example.com/splunk/mcp`) serve the RFC 9728 path-inserted
  PRM route, but the `WWW-Authenticate` challenge always points clients at the
  origin-**root** PRM URL. With two bridges under one origin, both `/mcp`
  challenges advertise the *same* root route — a client hitting the "other"
  backend discovers the wrong issuer/resource and gets rejected fail-closed.
  Single-origin multi-bridge needs custom per-bridge challenge routing you own;
  one-origin-per-bridge (subdomains) makes the built-in challenge correct.
- Adding backend N+1 is a config change, not a code change: same image, new
  hostname, new resource, new backend credential.

> **Never share a store between bridge instances.** Refresh-token acceptance is
> entirely store-scoped: the token is an opaque string looked up by hash and
> rotated, with client binding against the *stored* record — no issuer/resource
> check, no signature in acceptance. Two bridges sharing one database let a
> refresh token from gateway A be redeemed at gateway B, which then mints a token
> **validly signed with B's key for B's audience** — silently defeating the
> isolation above. Sharing signing material is *not* required for this break;
> **store separation is the load-bearing control.** One store (file or
> database/schema) per bridge. (Issuer-scoped records — closing this in code —
> are candidate hardening; until then the one-store-per-bridge rule is the
> control.)

## Kubernetes notes

Each gateway is a small Deployment + Service + Ingress + Secret.

- **Size**: one Node ≥24 process; the hot path is one ES256 verify per `/mcp`
  call. `requests: 100m/128Mi, limits: 500m/256Mi` is comfortable.
- **Secrets take two separate code paths.** The signing JWK + consent secret go
  into `createBridgeConfig`; the backend credential is read + validated separately
  at boot into the `getBackendCredential()` closure and **must never be placed in
  the `createBridgeConfig` input**. `createBridgeConfig` **rejects unknown keys
  with a boot `AuthConfigError` naming the offending key** (§5) — so a backend
  credential parked on the input fails boot instead of reaching the frozen public
  `bridge.config`. Park it in the closure. The quickstart file helper (§17.8) is
  the *local zero-setup* path — do not use it in a pod.
- **Replicas × store**: sqlite means **one replica** with the file on a PVC —
  never `emptyDir` (refresh tokens are long-lived sessions; losing the file logs
  everyone out). For ≥2 replicas or clean rolling updates, use `/store/mysql` (+
  `/rate-limit/redis` so limits are shared).
- **Stored DCR needs a second shared store.** `/store/mysql` shares the
  `StorePort` (codes, tokens, consent, granted scopes) but **not** dynamic client
  registrations. With `dcr.mode: "stored"`, registrations go to a separate
  `dcr.store` (`ClientStore`) — the shipped stores implement `StorePort` only and
  the reference `ClientStore` is in-memory, so on ≥2 replicas a client that
  registers on pod A is rejected `invalid_client` on pod B. Back the `ClientStore`
  with the same shared DB (a deployer-supplied adapter today), or use
  `dcr.mode: "stateless"` (no per-client state, multi-replica-safe as shipped).
- **Probes**: `GET /.well-known/oauth-authorization-server` — unauthenticated,
  cheap, and config validation is fail-closed at boot, so a misconfigured pod
  never becomes Ready.
- **Shutdown**: handle SIGTERM in *your* entrypoint (close the server, then the
  store) so rolling updates drain in-flight requests.
- **Network**: terminate TLS at the ingress; the pod listens on `0.0.0.0` with
  `issuer`/`resource` set to the public https URL. Add a NetworkPolicy so only the
  gateway can reach the backend — the static credential is then useless even to
  someone who finds the backend's internal address.

## Who is allowed in

Two gates, documented in [`authorization.md`](authorization.md): the primary gate
lives at your IdP (Entra app assignment / Conditional Access, or Cloudflare
Access policy), and `mcp-sso`'s own allowlist (`subjectAllowlist` /
`emailAllowlist`) is defense-in-depth on top. With `createEntraIdentity`,
subjects key on the immutable `oid`. The `allowedScopes` ceiling engine (§17.4)
and the Entra **group→scope producer** both ship.

## Audit

Wire `combineAudit(new JsonlFileAudit(...), new WebhookAudit(...))` into the
Bridge and `RequestAuthorizer` — sinks, delivery trade-offs, and the fail-open
residual are in [`audit-deployment.md`](audit-deployment.md). A webhook sink
pointed at your SIEM's HTTP collector gives the security team the full auth trail
(metadata only — never token values) with no extra moving parts.
