// A pluggable port (StorePort, ClientStore, IdentityPort) is caller-supplied code. Whatever it
// throws is untrusted input on the error channel, exactly like a request body is
// untrusted on the input channel.
//
// The escape this closes: `asOAuth` decides the public response with
// `error instanceof OAuthError ? error : generic`. `OAuthError` is a published
// export, so a store author reaching for it produces a value indistinguishable
// from one the library raised — and its `code`, `message`, and `status` then
// select the response. On `/oauth/revoke` that breaks RFC 7009's always-200 rule
// and turns a store's internal message into an oracle on token existence.
//
// It cannot be fixed inside `asOAuth`: the library's OWN `invalid_grant`,
// `invalid_client`, and `invalid_consent` must reach the client, and provenance
// is not recoverable from the value. So the re-cast happens where the untrusted
// code is invoked, and only there.
//
// `PortFailureError` is deliberately NOT an `OAuthError`. Existing catch blocks
// that audit-then-rethrow keep working unchanged: they already classify a
// non-`OAuthError` as `internal_error`, and `asOAuth` already maps it to the
// generic 500. This adds one boundary; it does not rewire the error paths.

import { OAuthError } from "./errors.ts";

/** Raised in place of anything a pluggable port threw. Carries the original for
 *  local logging ONLY — it must never reach a response body. */
export class PortFailureError extends Error {
  readonly port: string;
  readonly operation: string;
  override readonly cause: unknown;
  readonly causeIsOAuthError: boolean;
  readonly oauthStatusSnapshot: number | undefined;

  constructor(
    port: string,
    operation: string,
    cause: unknown,
    causeIsOAuthError = false,
    oauthStatusSnapshot?: number,
  ) {
    super(`${port}.${operation} failed`);
    this.name = "PortFailureError";
    this.port = port;
    this.operation = operation;
    this.cause = cause;
    this.causeIsOAuthError = causeIsOAuthError;
    this.oauthStatusSnapshot = oauthStatusSnapshot;
  }
}

function snapshotOAuthFailure(error: unknown): {
  causeIsOAuthError: boolean;
  oauthStatusSnapshot: number | undefined;
} {
  let causeIsOAuthError = false;
  try { causeIsOAuthError = error instanceof OAuthError; } catch { /* hostile Proxy */ }
  if (!causeIsOAuthError) return { causeIsOAuthError, oauthStatusSnapshot: undefined };
  try {
    const status = (error as OAuthError).status;
    return {
      causeIsOAuthError,
      oauthStatusSnapshot: typeof status === "number" ? status : undefined,
    };
  } catch {
    return { causeIsOAuthError, oauthStatusSnapshot: undefined };
  }
}

/** Invoke a pluggable-port operation. Any throw becomes a `PortFailureError`, so
 *  a port can never select the public response. A REJECTION is a failure; a
 *  returned value — including a sentinel like `"replayed"` — is control flow and
 *  passes through untouched. Response owners that consume returned object
 *  fields project them inside `invoke`, so accessor failures are covered too. */
export async function callPort<T>(
  port: string,
  operation: string,
  invoke: () => Promise<T>,
): Promise<T> {
  try {
    return await invoke();
  } catch (error) {
    let alreadyWrapped = false;
    try { alreadyWrapped = error instanceof PortFailureError; } catch { /* hostile Proxy */ }
    if (alreadyWrapped) throw error;
    const snapshot = snapshotOAuthFailure(error);
    throw new PortFailureError(
      port, operation, error, snapshot.causeIsOAuthError, snapshot.oauthStatusSnapshot,
    );
  }
}
