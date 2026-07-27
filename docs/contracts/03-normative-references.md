# 3. Normative references

- **RFC 9728** — OAuth 2.0 Protected Resource Metadata (PRM). Discovery at
  `/.well-known/oauth-protected-resource`; `WWW-Authenticate: Bearer
  resource_metadata="<url>"` (§5).
- **RFC 8414** — OAuth 2.0 Authorization Server Metadata.
- **RFC 7591** — OAuth 2.0 Dynamic Client Registration Protocol (DCR).
- **RFC 7636** — PKCE, `S256` method.
- **RFC 6749** — OAuth 2.0 authorization-code + refresh grants; §4.1.2.1
  **error-redirect semantics** (post-validation errors redirect to
  `redirect_uri?error=…&state=…`; pre-validation errors never do) and §6 refresh
  client-binding.
- **RFC 7009** — Token revocation; the endpoint always returns 200 and treats an
  unknown token as a no-op.
- **RFC 6750** — Bearer token use; `scope`/`error` in `WWW-Authenticate`.
- **RFC 8707** — Resource Indicators; **audience is fail-closed** (a token
  without a matching `aud` is rejected).
- **RFC 8252** — Native apps; loopback redirect any-port rule (§7.3).
- **RFC 9207** — `iss` parameter in the authorization response (RC: also
  advertise `authorization_response_iss_parameter_supported: true`).
- **MCP Authorization 2025-11-25** — the conformance target clients implement.
