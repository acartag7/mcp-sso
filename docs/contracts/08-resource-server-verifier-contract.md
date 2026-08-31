# 8. Resource-server verifier contract

**What this protects and why.** What `RequestAuthorizer` checks before your MCP handler runs, and the exact `WWW-Authenticate` challenge it sends when it refuses. This is the half a deployer wires into `/mcp`. It has no unauthenticated mode on purpose.

The RS half. Framework-free. Testable without any HTTP server.

## 8.1 `verifyAccessToken(token, config, clock?) → VerifiedAccessToken`
As §7.2. Throws `OAuthError("invalid_token", …, 401)` on any failure.

The verified result carries the credential kind established from the already verified claims:

```ts
type CredentialKind = "interactive" | "machine";
interface VerifiedAccessToken {
  subject: string;
  clientId: string;
  scopes: string[];
  credentialKind: CredentialKind;
}
```

`credentialKind` is `"machine"` only when all three machine bindings hold: `sub` starts with the reserved `mcc_` namespace, `client_id === sub`, and `gty === "client_credentials"`. Either machine marker, an `mcc_` `sub` or a present `gty` claim, enters this closed classification branch. A partial or conflicting binding, or a `gty` whose value is unknown, non-string, or otherwise not exactly `"client_credentials"`, is `invalid_token`. <a id="8.1.a"></a>It MUST NOT fall back to `"interactive"`. A token with no machine signal is `"interactive"` (authorization-code and refresh tokens). An `mcc_` `client_id` alone is not a machine marker: opaque stateless client IDs are client-selected, and the credential kind is an identity property.

The kind is a verifier result, not a downstream inference. <a id="8.1.b"></a>Consumers MUST use this field rather than decoding the JWT or classifying a subject/client prefix themselves.

## 8.2 `buildUnauthorizedChallenge(config, opts?) → string`  *
Returns the exact `WWW-Authenticate` value for a 401. The source's bug was a bare `Bearer`. The fix emits the RFC 9728 `resource_metadata` URL plus the supported `scope` (and optional `error`/`error_description`):

```
Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource", scope="mcp:read mcp:write", error="invalid_token", error_description="Bearer token is invalid"
```
- `resource_metadata` = the **PRM URL at the resource origin** (root form. The path-inserted form is also served, §9). Quoted per RFC 7235.
- `scope` = space-joined `scopeCatalog` (tells the client what it may request).
- `error`/`error_description` included when the rejection reason is known (`invalid_token`, `invalid_request`, `insufficient_scope`).

## 8.3 `requireScope(auth, required, hierarchy?) → void`  (403 step-up)
Throws `OAuthError("insufficient_scope", …, 403)` if the verified subject lacks the scope. With no explicit hierarchy it uses exact membership. When passed the validated `config.scopeHierarchy`, a granted scope also satisfies every scope reachable through one or more `granted → implies` edges. The adapter emits a 403 whose `WWW-Authenticate` carries the same `resource_metadata` + `scope` + `error="insufficient_scope"` so the client can step up and re-authorize for the missing scope.

## 8.4 `RequestAuthorizer`
```ts
class RequestAuthorizer {
  constructor(deps: { config: BridgeConfig; clock: ClockPort; audit: AuditPort; });
  authorize(input: { authorization?: string | string[]; requiredScope?: string; }): Promise<{
    subject: string;
    clientId: string;
    scopes: string[];
    credentialKind: "interactive" | "machine";
  }>;
}
```
Extracts the bearer token, verifies it, enforces `requiredScope` if given using the exact-resource `config.scopeHierarchy` when present, audits the outcome, and rethrows `OAuthError` on failure. The adapter maps the thrown `OAuthError` to a 401/403 with the challenge from §8.2/§8.3. **No bypass path.** <a id="8.4.a"></a>An array-valued `authorization` input preserves distinct header occurrences: exactly one element is processed as the bearer value, while zero elements or more than one element fail closed as `invalid_token` 401 before any first/last-value selection or token verification. This keeps a one-element array produced by a normalized-header boundary valid without allowing duplicate Authorization input to choose the credential that reaches enforcement. Every shipped `/mcp` composition root (both examples and the generated starter) passes the raw `Authorization` occurrence array into `RequestAuthorizer`. <a id="8.4.b"></a>It must not select Fastify's or Node's normalized first value before this check. The release-stack composition harnesses follow the same rule so their real-socket evidence exercises the shipped boundary rather than a weaker stand-in. Before that bearer call, every shipped Fastify `/mcp` composition root also installs the real `@fastify/rate-limit` plugin through `mcp-sso/fastify/protected-resource-rate-limit`. The route config applies a finite per-IP budget (default **60 requests per 60 seconds**) at `onRequest`. <a id="8.4.c"></a>`skipOnError` is fixed `false`, so a backing-store error fails closed instead of running `RequestAuthorizer` or the protected handler. <a id="8.4.d"></a>The helper snapshots a custom increment result's `current` and `ttl` fields inside its sanitized error boundary and never reads either field more than once. Validation and the value returned to the plugin use only those snapshots. A result is healthy only when the snapshotted `current` is a positive safe integer and `ttl` is a non-negative safe integer. A throwing accessor, malformed snapshot, or a rejected thenable from a custom `incr` (an `async` method that throws before the callback) returns the same fixed 503. The existing foreign- `Origin` gate remains first: rejected cross-origin traffic is 403 without consuming the protected-resource budget. Admitted traffic is rate-limited before body parsing, bearer verification/audit, MCP SDK construction, backend credential access, or proxy fetch. A denial is 429. Fastify's `request.ip` is the key. The two runnable Fastify example factories default to explicit `trustProxy: false`. Their optional `trustedProxies`/`MCP_SSO_TRUSTED_PROXIES` allowlist accepts only validated concrete proxy IP/CIDR entries and is handed to Fastify's proxy-addr chain resolver. <a id="8.4.e"></a>An untrusted socket's `X-Forwarded-For` therefore cannot select a bucket, while a configured trusted socket resolves to the nearest untrusted client address. Malformed proxy trust is a pre-state boot failure. The generated loopback-only starter remains fixed at `trustProxy: false` rather than exposing a forwarded-header escape. The helper's in-memory default is bounded per process and per method route. A multi-replica public deployment supplies a conforming shared store or enforces an aggregate budget at its trusted edge. This is composition-root admission, not a new field on `RequestAuthInput`: the framework-free verifier intentionally has no authority to infer a client IP. `RequestAuthorizer.authorize` returns the `credentialKind` produced by `verifyAccessToken`. `VerifiedAccessToken`, `AuthorizedSubject`, and the `RequestAuthResult` alias all expose the same required field. Per §6.1, `RequestAuthorizer.authorize` takes one canonical clock snapshot before request processing and reuses it for `verifyAccessToken` and `auth.request.occurredAt`. An invalid initial snapshot is `invalid_token` 401 with no fabricated audit timestamp.
