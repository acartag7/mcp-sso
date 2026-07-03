// ClientStore — required only when BridgeConfig.dcr.mode === "stored" (contracts
// §6.4, fix #4). Persists dynamic client registrations including applicationType,
// which drives the per-client redirect policy (§10.2, RC item (b)). Reference
// adapter: an in-memory map; a persisted adapter is deployment-specific.

export type ApplicationType = "native" | "web";

export interface ClientRegistration {
  clientId: string;
  redirectUris: string[];
  applicationType: ApplicationType;
  issuedAtEpoch: number;
}

export interface ClientStore {
  save(client: ClientRegistration): Promise<void>;
  find(clientId: string): Promise<ClientRegistration | null>;
}
