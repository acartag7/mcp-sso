// ClientStore — required only when BridgeConfig.dcr.mode === "stored" (contracts
// §6.4, fix #4). Persists dynamic client registrations including applicationType,
// which drives the per-client redirect policy (§10.2, RC item (b)). Machine
// clients (§17.2) are provisioned out-of-band into the same store: they carry
// allowedScopes + secrets instead of redirect URIs. Reference adapter: an
// in-memory map plus the user-only SQLite implementation.

/** Discriminant for the two record shapes (contracts §6.4). `"machine"` marks a
 *  secret-bearing client provisioned per §17.2; its `sub` (= clientId) prefix
 *  `mcc_` lets the RS distinguish machine tokens from user tokens
 *  (RFC 9700 §4.15.1). */
export type ApplicationType = "native" | "web" | "machine";

/** A machine-client secret (§17.2). Stored as an UNSALTED SHA-256 hex digest of
 *  the secret string — never the secret itself. RFC 6819 §5.1.4.1.3 conditions
 *  salting/work factors on LOW-entropy credentials (user passwords); for a
 *  256-bit random secret SHA-256 is sufficient and keeps the token-endpoint hot
 *  path cheap (bcrypt there is a DoS lever). `expiresAtEpoch` undefined ⇒ the
 *  secret is live until rotated; set ⇒ the secret stops being accepted at that
 *  UTC second (rotation grace, or a provisioned bounded lifetime). */
export interface ClientSecret {
  hash: string;
  createdAtEpoch: number;
  expiresAtEpoch?: number;
}

export type ActiveClientSecrets = [ClientSecret] | [ClientSecret, ClientSecret];

/** A user client registered via RFC 7591 DCR (§9.2). `redirectUris` is ≥1 and
 *  each entry is validated through §10. `applicationType` selects the §10.2
 *  per-client redirect policy (native ⇒ RFC 8252 loopback any-port,
 *  web ⇒ https exact). */
export interface UserClientRegistration {
  clientId: string;
  redirectUris: string[];
  applicationType: "native" | "web";
  issuedAtEpoch: number;
}

/** Machine row shape published by v0.3.0. It remains public for source
 * compatibility as read-only legacy input. Resource-less rows must be
 * reprovisioned; atomic lifecycle writes use the versioned shapes below. */
export interface MachineClientRegistration {
  clientId: string;
  redirectUris: string[];
  applicationType: "machine";
  issuedAtEpoch: number;
  name?: string;
  allowedScopes: string[];
  secrets: ClientSecret[];
}

interface MachineClientRegistrationBase {
  clientId: string;
  redirectUris: string[];
  applicationType: "machine";
  issuedAtEpoch: number;
  name?: string;
  allowedScopes: string[];
  resource: string;
  version: number;
}

export interface ActiveMachineClientRegistration extends MachineClientRegistrationBase {
  status: "active";
  secrets: ActiveClientSecrets;
}

export interface DisabledMachineClientRegistration extends MachineClientRegistrationBase {
  status: "disabled";
  secrets: [];
  disabledAtEpoch: number;
}

export type VersionedMachineClientRegistration =
  | ActiveMachineClientRegistration
  | DisabledMachineClientRegistration;

export type LegacyMachineClientRegistration = MachineClientRegistration;

export type StoredMachineClientRegistration =
  | MachineClientRegistration
  | VersionedMachineClientRegistration;

/** A stored client record. The legacy member is read-only upgrade input; new
 * machine writes use the status-discriminated versioned union above. */
export type ClientRegistration = UserClientRegistration | StoredMachineClientRegistration;

export interface ClientStore {
  save(client: ClientRegistration): Promise<void>;
  find(clientId: string): Promise<ClientRegistration | null>;
}

/** Durable lifecycle evidence committed atomically with a machine-client row.
 * It is metadata-only: raw secrets and digests are forbidden. */
export interface MachineClientMutationAudit {
  occurredAt: string;
  event: "oauth.client.provision" | "oauth.client.rotate_secret" | "oauth.client.disable";
  clientId: string;
  scopes: string[];
  resource: string;
}

/** Mutation extension required only by the out-of-band machine lifecycle.
 * `false` is a collision/version conflict and MUST commit neither row nor audit.
 * For upgrade compatibility, expectedVersion 0 matches only a v0.3.0 row with
 * both status and version absent. */
export interface MachineClientStore extends ClientStore {
  createMachineClient(
    client: ActiveMachineClientRegistration,
    audit: MachineClientMutationAudit,
  ): Promise<boolean>;
  compareAndSwapMachineClient(
    expectedVersion: number,
    client: VersionedMachineClientRegistration,
    audit: MachineClientMutationAudit,
  ): Promise<boolean>;
}
