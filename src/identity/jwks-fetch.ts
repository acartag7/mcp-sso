// Shared jose remote-JWKS fetch seam (§6.5 / §17.6). Every shipped identity
// port uses this module so the byte cap, cache lifetime, and jose custom-fetch
// wiring cannot drift by provider.

import {
  customFetch,
  type FetchImplementation,
  type RemoteJWKSetOptions,
} from "jose";
import { readCappedText } from "./util.ts";

export const DEFAULT_MAX_JWKS_DOCUMENT_BYTES = 65_536;
const MIN_JWKS_DOCUMENT_BYTES = 1_024;
const MAX_JWKS_DOCUMENT_BYTES = 1_048_576;
const JWKS_CACHE_MAX_AGE_MS = 5 * 60 * 1_000;

/** Resolve the shared JWKS document cap at construction time. */
export function jwksDocumentCap(value: number | undefined): number {
  const resolved = value === undefined ? DEFAULT_MAX_JWKS_DOCUMENT_BYTES : value;
  if (!Number.isInteger(resolved)
    || resolved < MIN_JWKS_DOCUMENT_BYTES
    || resolved > MAX_JWKS_DOCUMENT_BYTES) {
    throw new TypeError(
      `maxJwksDocumentBytes must be an integer in [${MIN_JWKS_DOCUMENT_BYTES}, ${MAX_JWKS_DOCUMENT_BYTES}]`,
    );
  }
  return resolved;
}

/** Fetch a jose-owned JWKS response through the shared streaming byte cap. */
export function createCappedJwksFetch(maxDocumentBytes: number): FetchImplementation {
  return async (url, options) => {
    const response = await fetch(url, options);
    // jose rejects non-200 responses without reading their bodies. Preserve that
    // path so its status/error taxonomy stays exactly as shipped.
    if (response.status !== 200) return response;
    const text = await readCappedText(
      response.body,
      maxDocumentBytes,
      `remote JWKS document exceeded the ${maxDocumentBytes}-byte cap`,
    );
    return new Response(text, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  };
}

/** Build the one jose option shape used by all remote-JWKS call sites. */
export function remoteJwksOptions(value: number | undefined): RemoteJWKSetOptions {
  const maxDocumentBytes = jwksDocumentCap(value);
  return {
    cacheMaxAge: JWKS_CACHE_MAX_AGE_MS,
    [customFetch]: createCappedJwksFetch(maxDocumentBytes),
  };
}
