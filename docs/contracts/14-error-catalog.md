# 14. Error catalog

All are `OAuthError(code, message, status)`. The 401 rows drive §8.2; the 403 row
drives §8.3.

| code | status | WWW-Authenticate | When |
|---|---|---|---|
| `invalid_token` | 401 | `Bearer resource_metadata=…, scope=…, error="invalid_token"` | missing/bad/expired bearer; bad aud/iss/alg |
| `invalid_request` | 400 | — | malformed/missing parameter |
| `invalid_grant` | 400 | — | bad/expired/replayed code or refresh, wrong refresh resource, legacy refresh row, PKCE fail; consent replay |
| `invalid_scope` | 400 | — | unknown scope requested |
| `invalid_redirect_uri` | 400 | — | redirect fails §10 |
| `invalid_target` | 400 | — | `resource` ≠ configured resource |
| `invalid_origin` | 403 | — | approve CSRF/Origin check failed |
| `access_denied` | 401 (no identity) / redirect (Deny) | context | no/failed identity ⇒ direct 401; user Deny ⇒ redirect (§9.3) |
| `unsupported_response_type` | 400 | — | response_type ≠ code |
| `unsupported_grant_type` | 400 | — | grant_type unsupported |
| `insufficient_scope` | 403 | `Bearer resource_metadata=…, scope=…, error="insufficient_scope"` | missing required scope (step-up) |
| `temporarily_unavailable` | 429 | — | a rate-limit quota denial. Four shipped producers: the Bridge endpoint guards (`bridge.ts`), the upstream-redirect guard for `upstream:<ip>` (`upstream-flow.ts`), `CimdResolver`'s guard for `cimd:<ip>` (`cimd/resolve.ts`), and §17.5's in-process pairing-authorize gate (`pairing-flow.ts`). The **`pairing:<ip>` `RateLimitPort`** key is the one exception: it returns the `pairing_rate_limited` identity failure and re-renders the pairing page instead of this row |
| `temporarily_unavailable` | 503 | — | `RateLimitPort.check` **threw** on `register:<ip>` under `dcr.mode === "stored"` — no quota decision was reached, so it is not 429 (§6.7). Direct channel, never a redirect |
| `server_error` | 500 | — | internal failure (e.g. refresh generation) |
| `internal_error` | 500 | — | unexpected (mapped from non-OAuthError) |

`invalid_consent` (400) is internal to consent verification. `invalid_store_input`
(`StoreInputError`) is thrown by store validation and is a programmer error, not
an OAuth response.

**Redirect vs direct (RFC 6749 §4.1.2.1, see §9.3):** `access_denied` (Deny),
`unsupported_response_type`, `invalid_target`, `invalid_scope`, `invalid_request`
(bad PKCE), and `server_error` are delivered as **302 to `redirect_uri?error=…`**
when they occur after `client_id` + `redirect_uri` validate. `invalid_redirect_uri`,
a missing `client_id`, identity failure, `invalid_origin`, and consent-token
integrity failures are always **direct 4xx**. *(§17.11 extension:* on the
upstream redirect flow, an identity rejection at the **callback** occurs after
the `redirect_uri` was validated and integrity-protected in the signed flow
context, so it redirects as `access_denied`; flow-binding/integrity failures
there — missing/invalid/expired/replayed flow cookie, state mismatch, missing
code — remain direct 4xx.)*
