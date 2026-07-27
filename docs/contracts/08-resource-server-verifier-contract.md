# 8. Resource-server verifier contract

The RS half. Framework-free; testable without any HTTP server.

## 8.1 `verifyAccessToken(token, config, clock?) → VerifiedAccessToken`
As §7.2. Throws `OAuthError("invalid_token", …, 401)` on any failure.

## 8.2 `buildUnauthorizedChallenge(config, opts?) → string`  *(fix #1)*
Returns the exact `WWW-Authenticate` value for a 401. The source's bug was a bare
`Bearer`; the fix emits the RFC 9728 `resource_metadata` URL plus the supported
`scope` (and optional `error`/`error_description`):
```
Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource", scope="mcp:read mcp:write", error="invalid_token", error_description="Bearer token is invalid"
```
- `resource_metadata` = the **PRM URL at the resource origin** (root form; the
  path-inserted form is also served — §9). Quoted per RFC 7235.
- `scope` = space-joined `scopeCatalog` (tells the client what it may request).
- `error`/`error_description` included when the rejection reason is known
  (`invalid_token`, `invalid_request`, `insufficient_scope`).

## 8.3 `requireScope(auth, required) → void`  (403 step-up)
Throws `OAuthError("insufficient_scope", …, 403)` if the verified subject lacks
the scope. The adapter emits a 403 whose `WWW-Authenticate` carries the same
`resource_metadata` + `scope` + `error="insufficient_scope"` so the client can
step up and re-authorize for the missing scope.

## 8.4 `RequestAuthorizer`
```ts
class RequestAuthorizer {
  constructor(deps: { config: BridgeConfig; clock: ClockPort; audit: AuditPort; });
  authorize(input: { authorization?: string | string[]; requiredScope?: string; }): Promise<{ subject: string; clientId: string; scopes: string[]; }>;
}
```
Extracts the bearer token, verifies it, enforces `requiredScope` if given, audits
the outcome, and rethrows `OAuthError` on failure. The adapter maps the thrown
`OAuthError` to a 401/403 with the challenge from §8.2/§8.3. **No bypass path.**
