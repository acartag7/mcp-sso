import type { JWK } from "jose";
import type { ClientStore } from "./ports/client-store.ts";

export type DcrMode = { mode: "stateless" } | { mode: "stored"; store: ClientStore };

export interface DevOptions {
  allowInsecureLocalhost: boolean;
}

export interface ClientCredentialsOptions {
  enabled: boolean;
}

export interface BridgeConfig {
  issuer: string;
  resource: string;
  consentSigningSecret: string;
  signingPrivateJwk: JWK;
  signingKeyId?: string;
  redirectAllowlist: string[];
  scopeCatalog: string[];
  defaultScopes: string[];
  allowedOrigins: string[];
  dcr: DcrMode;
  dev?: DevOptions;
  clientCredentials?: ClientCredentialsOptions;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  consentTokenTtlSeconds: number;
  authorizationCodeTtlSeconds: number;
}
