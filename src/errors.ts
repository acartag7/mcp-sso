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

export function oauthErrorBody(error: OAuthError): { error: { code: string; message: string } } {
  return { error: { code: error.code, message: error.message } };
}

/** Attach a redirect target to an existing OAuthError (used by the authorize flow
 *  to tag post-validation errors so the adapter can 302 them). Returns a new error. */
export function withRedirect(error: OAuthError, redirectUri: string, state?: string): OAuthError {
  return new OAuthError(error.code, error.message, error.status, { redirectUri, state });
}
