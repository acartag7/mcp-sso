// OAuthError — the single error type for the verifier + bridge. Carries an
// optional `redirect` so the authorize flow can deliver post-validation errors
// as RFC 6749 §4.1.2.1 redirects (contracts §9.3). The adapter chooses:
// `error.redirect` set  -> 302 to redirect_uri?error=…&state=…
// `error.redirect` absent -> direct 4xx with oauthErrorBody.

export interface RedirectTarget {
  redirectUri: string;
  state?: string;
}

export class OAuthError extends Error {
  readonly code: string;
  readonly status: number;
  readonly redirect?: RedirectTarget;

  constructor(code: string, message: string, status = 400, redirect?: RedirectTarget) {
    super(message);
    this.name = "OAuthError";
    this.code = code;
    this.status = status;
    this.redirect = redirect;
  }
}

/** RFC 6749 §5.2 / RFC 7591 §3.3 / RFC 7009 §2.2.1 error body for the raw OAuth
 *  endpoints (token / register / revoke / direct-authorize): a top-level ASCII
 *  `error` string + `error_description`. The string form is REQUIRED for
 *  interoperability — the official MCP SDK's OAuthErrorResponseSchema reads
 *  `body.error` as a string to drive recovery (e.g. "invalid_grant" → drop token,
 *  re-authorize), so replay/expiry/PKCE failures must surface as a top-level
 *  string, not the JSON-RPC inner-envelope `{error:{code,message}}` shape. */
export function oauthErrorBody(error: OAuthError): { error: string; error_description: string } {
  return { error: error.code, error_description: error.message };
}

/** Attach a redirect target to an existing OAuthError (used by the authorize flow
 *  to tag post-validation errors so the adapter can 302 them). Returns a new error. */
export function withRedirect(error: OAuthError, redirectUri: string, state?: string): OAuthError {
  return new OAuthError(error.code, error.message, error.status, { redirectUri, state });
}
