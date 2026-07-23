import type { importJWK, JWK } from "jose";
import type { IdentityResult } from "../ports/identity.ts";
import type { createValidatedRemoteJWKSet } from "./remote-jwks.ts";
import type {
  GenericOidcIdTokenPayload, GenericOidcValidateOpts,
} from "./generic-oidc-claims.ts";
import type {
  DiscoveryTransport, GenericOidcEndpoints, GenericOidcTokenTransport,
  ResolvedEndpoints, TokenAuthMethod,
} from "./generic-oidc-discovery.ts";

export interface GenericOidcConfig {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  tokenEndpointAuthMethod?: TokenAuthMethod;
  redirectUri: string;
  endpoints: GenericOidcEndpoints;
  scopes?: string;
  subjectAllowlist?: string[];
  allowEmailAllowlist?: boolean;
  allowProviderWithoutPkce?: boolean;
}

export interface GenericOidcAuthorizeRequest {
  state: string;
  nonce: string;
  codeChallenge: string;
  codeChallengeMethod?: "S256";
}

export interface GenericOidcTokenResponse {
  id_token: string;
  access_token: string;
}

export type VerifyKey = Uint8Array | JWK | Awaited<ReturnType<typeof importJWK>>
  | ReturnType<typeof createValidatedRemoteJWKSet>;
export type GenericOidcVerifyKey = Awaited<ReturnType<typeof importJWK>>;

export interface GenericOidcVerifyOpts extends GenericOidcValidateOpts {
  currentDate?: Date;
  allowedAlgs?: string[];
  verifyKey?: VerifyKey;
}

export interface GenericOidcIdentity {
  readonly redirectUri: string;
  getAuthorizationUrl(req: GenericOidcAuthorizeRequest): string;
  exchangeCodeForToken(
    args: { code: string; codeVerifier: string },
    transport?: GenericOidcTokenTransport,
  ): Promise<GenericOidcTokenResponse>;
  verify(input: unknown, opts?: GenericOidcVerifyOpts): Promise<IdentityResult>;
}

export interface GenericOidcIdentityOpts {
  discoveryFetch?: DiscoveryTransport;
  validate?: (
    payload: GenericOidcIdTokenPayload,
    opts: GenericOidcValidateOpts,
  ) => IdentityResult;
}

export type { ResolvedEndpoints };
