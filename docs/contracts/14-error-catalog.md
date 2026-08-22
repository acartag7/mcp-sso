# 14. Error catalog

**What this protects and why.** Every error the library emits, with its code, status, and channel. Errors are part of the contract because clients and tests key on them, and because the wrong channel (a redirect where a direct response was required) is itself a vulnerability.

All are `OAuthError(code, message, status)`. The 401 rows drive §8.2. The 403 row drives §8.3.

| code | status | WWW-Authenticate | When |
|---|---|---|---|
| `invalid_token` | 401 | `Bearer resource_metadata=…, scope=…, error="invalid_token"` | missing/bad/expired bearer. Bad aud/iss/alg |
| `invalid_request` | 400 | | malformed/missing parameter |
| `invalid_grant` | 400 | | bad/expired/replayed code or refresh, wrong refresh resource, legacy refresh row, PKCE fail. Consent replay |
| `invalid_scope` | 400 | | unknown scope requested |
| `invalid_redirect_uri` | 400 | | redirect fails §10 |
| `invalid_target` | 400 | | `resource` ≠ configured resource |
| `invalid_origin` | 403 | | approve CSRF/Origin check failed |
| `access_denied` | 400 (claims-only callback) / 401 (no identity) / redirect (Deny) | context | claims-only IdP denial or identity rejection ⇒ direct 400 with one fixed description. No/failed header identity ⇒ direct 401. User Deny ⇒ redirect (§9.3) |
| `unsupported_response_type` | 400 | | response_type ≠ code |
| `unsupported_grant_type` | 400 | | grant_type unsupported |
| `insufficient_scope` | 403 | `Bearer resource_metadata=…, scope=…, error="insufficient_scope"` | missing required scope (step-up) |
| `temporarily_unavailable` | 429 | None | A rate-limit quota denial. Five shipped producer groups return this response: the `Bridge` endpoint guards, the `upstream:<ip>` bridge-completion guard, the `website-login:<ip>` identity-completion guard, the `cimd:<ip>` guard in `CimdResolver`, and the in-process pairing-authorize gate in `handlePairingAuthorize`. Both redirect-completion guards run in `createUpstreamRedirectFlow`. `pairing:<ip>` is different: `createConsolePairingIdentity().verify` returns `pairing_rate_limited`, and `handlePairingAuthorize` handles it as a failed verification. |
| `temporarily_unavailable` | 503 | None | `RateLimitPort.check` threw on `register:<ip>` while `BridgeConfig.dcr.mode === "stored"`. No quota decision was reached, so this is not 429. `Bridge.handleRegister` returns it directly and does not redirect. |
| `server_error` | 500 | | internal failure (e.g. refresh generation) |
| `internal_error` | 500 | | unexpected (mapped from non-OAuthError) |

`invalid_consent` (400) is internal to consent verification (including the adapter's malformed `mcp_idp_consent` cookie percent-decode, §9.3). `invalid_store_input` (`StoreInputError`) is thrown by store validation and is a programmer error, not an OAuth response.

**Redirect vs direct (RFC 6749 §4.1.2.1, see §9.3):** `access_denied` (Deny), `unsupported_response_type`, `invalid_target`, `invalid_scope`, `invalid_request` (bad PKCE), and `server_error` are delivered as **302 to `redirect_uri?error=…`** when they occur after `client_id` + `redirect_uri` validate. `invalid_redirect_uri`, a missing `client_id`, identity failure, `invalid_origin`, and consent-token integrity failures are always **direct 4xx**. *(§17.11 extension:* on the bridge completion, an identity rejection at the **callback** occurs after the `redirect_uri` was validated and integrity-protected in the signed flow context, so it redirects as `access_denied`. The claims-only completion has no validated redirect target. It collapses IdP denial and identity rejection to the same direct 400 `access_denied`, and maps exchange or completion failure to direct 500. Flow-binding and integrity failures, a missing, invalid, expired, or replayed flow cookie, a state mismatch, and a missing code remain direct 4xx in both completions.)*
