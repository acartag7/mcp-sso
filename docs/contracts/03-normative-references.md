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
- **RFC 9207** — `iss` parameter in authorization responses and
  `authorization_response_iss_parameter_supported` metadata.
- **MCP Authorization 2025-11-25** — the current conformance target.
- **MCP Authorization 2026-07-28** — official stable artifact manually checked
  on 2026-08-02. DCR is deprecated but remains a `MAY` compatibility mechanism;
  CIMD remains a `SHOULD` and references
  `draft-ietf-oauth-client-id-metadata-document-00`; MCP clients `MUST` send an
  appropriate DCR `application_type`; authorization servers `SHOULD` include
  RFC 9207 `iss` in success and error authorization responses; and servers
  `MUST` account for scope hierarchies when deciding token sufficiency. The
  final target remains pending on those runtime gaps plus a complete mapping of
  the referenced CIMD draft `-00` requirements.
