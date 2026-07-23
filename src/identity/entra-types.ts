import type { importJWK, JWTPayload } from "jose";
import type { IdentityResult } from "../ports/identity.ts";
import type { GroupAuthorization } from "./entra-groups.ts";

export interface EntraConfig {
  tenantId: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  allowedTenantIds?: string[];
  subjectAllowlist?: string[];
  allowMutableClaims?: boolean;
  groupAuthorization?: GroupAuthorization;
}

export type EntraPayload = JWTPayload & {
  oid?: string; email?: string; preferred_username?: string; tid?: string;
  groups?: unknown; hasgroups?: unknown; _claim_names?: unknown; _claim_sources?: unknown;
};

export interface EntraAuthorizeRequest {
  state: string;
  codeChallenge: string;
  codeChallengeMethod?: "S256";
  scope?: string;
  nonce?: string;
}

export interface EntraTokenTransport {
  postForm(url: string, body: URLSearchParams): Promise<{ status: number; text(): Promise<string> }>;
}

export type EntraVerifyKey = Awaited<ReturnType<typeof importJWK>>;

export interface EntraVerifyOptions {
  currentDate?: Date;
  expectedNonce?: string;
}

export interface EntraIdentity {
  getAuthorizationUrl(req: EntraAuthorizeRequest): string;
  exchangeCodeForToken(
    args: { code: string; codeVerifier: string },
    transport: EntraTokenTransport,
  ): Promise<string>;
  verify(input: unknown, options?: { expectedNonce?: string }): Promise<IdentityResult>;
}
