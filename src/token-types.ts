import type { AuditPort } from "./ports/audit.ts";
import type { ClockPort } from "./ports/clock.ts";
import type { StorePort } from "./ports/store.ts";
import type { BridgeConfig } from "./config.ts";

export interface OAuthTokenDeps {
  config: BridgeConfig;
  store: StorePort;
  clock: ClockPort;
  audit: AuditPort;
}

export interface AuthorizationCodeGrantInput {
  grantType?: string;
  code?: string;
  redirectUri?: string;
  clientId?: string;
  codeVerifier?: string;
}

export interface RefreshGrantInput {
  grantType?: string;
  refreshToken?: string;
  clientId?: string;
}

export interface ClientCredentialsGrantInput {
  grantType?: string;
  authorization?: string;
  clientId?: string;
  clientSecret?: string;
  scope?: string;
  resource?: string;
}

export interface UserTokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
}

export type TokenResponse = UserTokenResponse;

export interface MachineTokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
}
