// ClientStore — required only when BridgeConfig.dcr.mode === "stored" (contracts
// §6.4, fix #4). Persists dynamic client registrations including applicationType,
// which drives the per-client redirect policy (§10.2, RC item (b)). Machine
// clients (§17.2) are provisioned out-of-band into the same store: they carry
// allowedScopes + secrets instead of redirect URIs. Reference adapter: an
// in-memory map; a persisted adapter is deployment-specific.

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

interface MachineClientRegistrationBase {
  clientId: string;
  redirectUris: string[];
  applicationType: "machine";
  issuedAtEpoch: number;
  name?: string;
  allowedScopes: string[];
  /** Monotonic mutation version used by compare-and-swap lifecycle operations. */
  version: number;
}

/** A live machine client provisioned out-of-band (§17.2). `redirectUris` is
 *  always `[]`; `allowedScopes` is the fixed per-client ceiling; `secrets`
 *  holds one or two stored SHA-256 digests; verification ignores expired grace
 *  entries until a later rotation removes them. */
export interface ActiveMachineClientRegistration extends MachineClientRegistrationBase {
  status: "active";
  secrets: ActiveClientSecrets;
}

/** An auditable tombstone. Disabling clears every stored credential digest;
 *  already-issued access tokens remain valid only until their normal expiry. */
export interface DisabledMachineClientRegistration extends MachineClientRegistrationBase {
  status: "disabled";
  secrets: [];
  disabledAtEpoch: number;
}

export type MachineClientRegistration =
  | ActiveMachineClientRegistration
  | DisabledMachineClientRegistration;

/** A stored client record — a discriminated union on `applicationType` so a
 *  machine record CANNOT exist without its `allowedScopes` + `secrets` (no
 *  optional-field state silently lacks them). Narrow on `applicationType`
 *  before reading machine-only / user-only fields. */
export type ClientRegistration = UserClientRegistration | MachineClientRegistration;

export interface ClientStore {
  save(client: UserClientRegistration): Promise<void>;
  find(clientId: string): Promise<ClientRegistration | null>;
}

/** Metadata-only durable lifecycle audit stored atomically with the matching
 *  machine-client row mutation. It must never contain a raw secret or digest. */
export interface MachineClientMutationAudit {
  occurredAt: string;
  event: "oauth.client.provision" | "oauth.client.rotate_secret" | "oauth.client.disable";
  clientId: string;
  scopes: string[];
}

/** Additional store contract required by out-of-band machine-client mutation.
 *  User DCR stores that do not provision machine clients need only ClientStore.
 *  `false` means the create collided or the CAS version no longer matched. */
export interface MachineClientStore extends ClientStore {
  createMachineClient(
    client: ActiveMachineClientRegistration,
    audit: MachineClientMutationAudit,
  ): Promise<boolean>;
  compareAndSwapMachineClient(
    expectedVersion: number,
    client: MachineClientRegistration,
    audit: MachineClientMutationAudit,
  ): Promise<boolean>;
}
