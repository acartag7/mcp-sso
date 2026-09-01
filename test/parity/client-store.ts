import type { ClientRegistration, ClientStore, UserClientRegistration } from "../../src/ports/client-store.ts";
import { StoreInputError } from "../../src/ports/store.ts";
import { assertRegistrationRedirectPolicy } from "../../src/redirect.ts";

/** The id shape `POST /oauth/register` mints and the only shape the reference
 *  `ClientStore` looks up (`findSqliteClient`). A fixture that pre-registers a
 *  stored-DCR client under any other id is unfindable in both implementations. */
const GENERATED_CLIENT_ID = /^mcpdc_[0-9a-f]{32}$/u;
const MAX_REDIRECT_URIS = 16;

/** The stored-DCR `ClientStore` the parity runner supplies from
 *  `given.state.client_registration` (§19.2). It reads and writes the `clients`
 *  table of the hydrated logical state, so a registration written during a
 *  fixture reaches the snapshot `projectLogicalState` builds afterwards. */
export class FixtureClientStore implements ClientStore {
  readonly #clients: Map<string, ClientRegistration>;
  #closed = false;

  constructor(clients: Map<string, ClientRegistration>) {
    this.#clients = clients;
  }

  /** Validates and copies the registration before the table is touched, so a
   *  rejected registration leaves no row and no caller-owned array behind. */
  async save(client: ClientRegistration): Promise<void> {
    this.#ensureOpen();
    const snapshot = snapshotUserClient(client);
    if (this.#clients.has(snapshot.clientId)) {
      throw new StoreInputError("client id already exists");
    }
    this.#clients.set(snapshot.clientId, snapshot);
  }

  /** Returns a fresh snapshot on every call, so a caller that mutates the
   *  result cannot reach stored state. A stored record that is not a valid user
   *  registration throws instead of being returned. */
  async find(clientId: string): Promise<ClientRegistration | null> {
    this.#ensureOpen();
    if (typeof clientId !== "string" || !GENERATED_CLIENT_ID.test(clientId)) return null;
    const stored = this.#clients.get(clientId);
    return stored === undefined ? null : snapshotUserClient(stored);
  }

  async close(): Promise<void> {
    this.#closed = true;
  }

  #ensureOpen(): void {
    if (this.#closed) throw new Error("Store is closed");
  }
}

/** Parse an untrusted registration into the user shape §19.2 records, with the
 *  field checks, the redirect-count cap, and the per-type redirect policy the
 *  reference `SqliteClientStoreBase` applies. A machine registration has no
 *  `native`/`web` application type, so it is rejected here exactly as the
 *  reference rejects it. */
function snapshotUserClient(value: unknown): UserClientRegistration {
  try {
    if (value === null || typeof value !== "object") throw invalidClient();
    const record = value as Record<string, unknown>;
    const { clientId, applicationType, issuedAtEpoch, redirectUris } = record;
    if (typeof clientId !== "string" || !GENERATED_CLIENT_ID.test(clientId)) throw invalidClient();
    if (applicationType !== "native" && applicationType !== "web") throw invalidClient();
    if (!Number.isSafeInteger(issuedAtEpoch) || (issuedAtEpoch as number) < 0) throw invalidClient();
    if (!Array.isArray(redirectUris)) throw invalidClient();
    const length = redirectUris.length;
    if (!Number.isInteger(length) || length < 1 || length > MAX_REDIRECT_URIS) throw invalidClient();
    const copied = Array.from({ length }, (_, index) => redirectUris[index]);
    for (const redirectUri of copied) assertRegistrationRedirectPolicy(redirectUri, applicationType);
    return {
      clientId,
      redirectUris: copied as string[],
      applicationType,
      issuedAtEpoch: issuedAtEpoch as number,
    };
  } catch (error) {
    if (error instanceof StoreInputError) throw error;
    throw invalidClient();
  }
}

function invalidClient(): StoreInputError {
  return new StoreInputError("client registration is invalid");
}
