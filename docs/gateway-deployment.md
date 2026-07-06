# Gateway deployment — SSO in front of token-only MCP servers

> The most common production shape for `mcp-sso`: an internal MCP server (or
> plain API) that only understands a **static credential** — an API key, a
> bearer token — needs to be shared with many people, and nobody wants to
> hand that credential out. You put a small **gateway** in front: users
> authenticate through your real IdP (Entra, Cloudflare Access, any OIDC),
> the gateway verifies its own short-lived tokens on `/mcp`, and the static
> credential is injected **server-side only** — it never reaches an MCP
> client, a laptop, or a config file.
>
> **Console pairing is not an SSO option for this shape.** The shipped
> console-pairing port is single-operator by design — reading the process's
> stderr *is* the trust boundary, and every successful pairing mints the same
> `console-operator` subject (`src/identity/console-pairing.ts`). In a
> many-people gateway it gives every user who can see the log the *same*
> identity, erasing per-user audit attribution and entitlement separation.
> Use it for local/single-operator dev only; for real multi-user access use
> an IdP-backed port.
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

> **The browser login leg is not always wired for you — it depends on the
> identity port.** The shipped `/oauth/authorize` handler is *header-driven*:
> it reads one header (`identityHeader`, default `cf-access-jwt-assertion`)
> and passes it to your `IdentityPort.verify`. That is complete **only when a
> fronting layer has already completed the login and injected the identity
> assertion** — the Cloudflare Access model (Access does the browser leg at
> its edge and injects `Cf-Access-Jwt-Assertion`), or any reverse proxy that
> injects an id_token into that header. With `createEntraIdentity` and **no**
> such fronting injection there is no login: `verify` wants a raw `id_token`,
> the header is absent, so `resolveIdentity` fails `entra_id_token_missing`
> and the user gets a **direct 401, not an Entra sign-in**. Driving the Entra
> redirect dance yourself is deployer code — `createEntraIdentity` exposes
> `getAuthorizationUrl` (put a per-request `nonce` on it) and
> `exchangeCodeForToken` for a custom `/oauth/authorize` + callback wrapper.
>
> **Do not finish that wrapper by re-injecting the id_token into the header
> path.** `bridge.resolveIdentity` calls `verify(idToken)` with **no**
> `expectedNonce`, and the Entra port only checks the nonce when the caller
> passes one — so the header route validates `iss`/`aud`/signature but
> **never binds the id_token to the login request**, leaving id_token
> replay/injection open. The wrapper straddles two OAuth legs and must carry
> state across the Entra round-trip. Concretely: (1) at `/oauth/authorize`,
> persist — keyed by the Entra `state` — the **entire original MCP authorize
> query** (`client_id`, `redirect_uri`, `response_type`, `code_challenge`
> (+`_method`), `resource`, `scope`, and the client's own `state`) **plus**
> the `nonce` and the Entra PKCE `code_verifier`, then redirect to
> `getAuthorizationUrl`; (2) on the callback — whose request contains only
> Entra's `code`/`state`, **not** any MCP params — look up that record,
> `exchangeCodeForToken`, and call the concrete
> `entra.verify(idToken, { expectedNonce })` **itself**; (3) only on `ok`,
> **reconstruct** a request whose `query` is the stored MCP authorize params
> and call `bridge.handleAuthorize(reconstructed, { subject, allowedScopes })`
> — `handleAuthorize` reads `client_id`/`redirect_uri`/`code_challenge`/… from
> `req.query` (`bridge.ts`), so handing it the bare callback request yields a
> direct OAuth error, not a consent page. Because this bypasses
> `resolveIdentity`, the wrapper also owns the `identity.verify` **audit
> event** (and any `allowedScopes` ceiling handling) that `resolveIdentity`
> would otherwise emit — don't silently drop it.
>
> Pick one before shipping: front the gateway with an assertion-injecting
> proxy (header model, zero extra code), or compose the redirect wrapper. The
> three `/mcp` shapes below are orthogonal to this choice.

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
   - **Validate `Origin` before anything else.** The MCP Streamable HTTP
     transport says servers MUST validate the `Origin` header on all
     incoming connections and return 403 when it is present but not
     allowlisted (DNS-rebinding protection). `RequestAuthorizer` checks the
     bearer token and scopes only — the Origin check on the deployer-owned
     `/mcp` endpoint is yours. Bearer auth blunts rebinding in practice (a
     rebound browser request carries no token), but the spec requirement is
     unconditional and it is the *only* defense on any surface you later
     expose unauthenticated. The MCP SDK's `StreamableHTTPServerTransport`
     has built-in options for this (`enableDnsRebindingProtection`,
     `allowedOrigins`) — off by default; turn them on or enforce the check
     yourself before proxying.
   - **Strip the client `Authorization` header before forwarding.** Once
     `authorize()` succeeds the inbound `Authorization: Bearer …` has done
     its job; it still carries the **bridge-minted per-user token**. Injecting
     the backend credential is not enough — if you inject it in a *different*
     header (`X-API-Key`, a query param) or merge headers without replacing
     `Authorization`, that per-user token rides along to the backend and into
     its access logs. Those tokens are `aud`-bound to *this* gateway, so a
     backend (or anyone reading its logs) can **replay them against `/mcp` as
     that user until they expire**. Delete or overwrite `Authorization` on the
     forwarded request; never let a client credential reach the backend. Same
     rule for any other client-supplied auth header (`Cookie`,
     `Proxy-Authorization`). Prefer an explicit allowlist of forwarded headers
     over pass-through-minus-blocklist — an allowlist fails closed when a new
     header appears.
   - **Your forward-allowlist must carry the transport's required headers, or
     you break interop.** Stripping client auth (above) means an *allowlist* —
     so it must explicitly include the headers Streamable HTTP requires, not
     just the session/resume ones:
     - `MCP-Protocol-Version` — the client MUST send it on **every** request
       after init, stateful or not; if the gateway drops it the backend
       **assumes `2025-03-26`** and can behave differently than the client
       negotiated. Forward it unconditionally (both directions).
     - `Accept` — the client MUST send `application/json, text/event-stream`
       on POST and `text/event-stream` on GET; strip it and a strict backend
       rejects the POST or disables SSE. Forward it (and `Content-Type:
       application/json` on POST) as request essentials.
     - `mcp-session-id` — forward both directions **when the backend is
       stateful** (it assigns the id at init and expects it echoed).
     - `Last-Event-ID` on GET — the transport resumes a broken SSE stream via
       `GET` + `Last-Event-ID`, so an allowlist that omits it silently breaks
       resumability.
   - Stream SSE responses through; do not buffer them.
2. **Facade** (you own the tool surface). Run your own `McpServer` whose
   tools call the backend API directly. More code, full control: validate
   inputs, expose only the operations users should have, and gate tools by
   the token's scopes (`requireScope`, §8) — e.g. `splunk:read` for search
   tools, `splunk:admin` for the rest.
3. **Proxy + tool gate** (the cheap middle). Proxy as in (1), but when the
   JSON-RPC `method` is `tools/call`, check the tool name against the
   caller's granted scopes before forwarding.
   - **Don't assume the POST body is a single object.** A gate that keys on
     `body.method === "tools/call"` reads `undefined` when the body is a
     JSON-RPC **batch array** and, on the default forward path, proxies the
     whole batch **unchecked** — an admin `tools/call` buried in the array
     slips past the scope gate. This is fail-open, so the client's shape
     decides your enforcement. The current MCP spec (`2025-06-18`, what the
     SDK negotiates) *removed* JSON-RPC batching, so the tightest stance is to
     **reject a top-level array** with a JSON-RPC error before forwarding. If
     you must serve legacy (`2025-03-26`) batching clients, normalize the body
     to an array and gate **every** request in it, denying the **entire**
     batch on any unauthorized entry — never split it and forward the allowed
     subset. Same care for a single `tools/call` with an unexpected shape:
     default to deny, not forward.

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
  served at the metadata level — the adapters register the RFC 9728
  path-inserted PRM route (`/.well-known/oauth-protected-resource/splunk/mcp`)
  automatically — but that route being **served** is not the same as it being
  **advertised**. The `WWW-Authenticate` challenge always points clients at
  the origin-**root** PRM URL (`buildUnauthorizedChallenge` →
  `protectedResourceMetadataUrl`, which drops the resource path,
  `src/challenge.ts`). A client follows `resource_metadata` from the
  challenge, so with two bridges under one origin **both** `/mcp` challenges
  advertise the *same* root metadata route — whichever bridge owns
  `/.well-known/oauth-protected-resource` wins, and a client hitting the other
  backend discovers the **wrong** issuer/resource, then gets its token
  rejected fail-closed at the audience check. Serving the path-inserted route
  and ingress-routing the OAuth/well-known paths is necessary but **not
  sufficient**: single-origin multi-bridge also needs custom challenge
  routing that overrides `resource_metadata` per bridge to point at each
  bridge's path-inserted PRM. **Prefer subdomains** — one origin per bridge
  makes the built-in root challenge correct and is the only multi-bridge shape
  verified live. Reserve single-origin for a hard requirement, and expect to
  own the per-bridge challenge/metadata routing yourself.
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
- **Stored DCR needs a *second* shared store.** `/store/mysql` shares the
  `StorePort` (auth codes, refresh tokens, consent, granted scopes) — but
  **not** dynamic client registrations. With `dcr.mode: "stored"`, registered
  clients are written to a separate `dcr.store` (`ClientStore`) at
  registration and read back at authorize-time (`resolveRedirect`); the
  shipped stores implement `StorePort` only, and the reference `ClientStore`
  is **in-memory**. So on ≥2 replicas with a per-pod `ClientStore`, a client
  that registers on pod A is rejected `invalid_client` when its authorize
  lands on pod B, even though MySQL and Redis are shared. For multi-replica
  stored DCR, back the `ClientStore` with the same shared database too — a
  deployer-supplied adapter today, since no shipped store implements it.
  Otherwise use `dcr.mode: "stateless"`, which keeps no per-client state
  (redirect URIs validated against the global allowlist, no lookup) and is
  multi-replica-safe as shipped.
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
