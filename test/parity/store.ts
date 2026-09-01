// The fixture store of the parity runner: one StorePort over the hydrated
// logical tables of a fixture's `given.state`. Every operation delegates to the
// landed pure modules, so a fixture exercises the same validation order and the
// same state transitions the store-conformance suite holds the shipped
// adapters to. The consent replay watermark is shared by the code operations,
// so a sweep closes expired JTIs against the approval path in the same store.

import type { ClientRegistration, ClientStore } from "../../src/ports/client-store.ts";
import type { ClockPort } from "../../src/ports/clock.ts";
import { randomBytesFrom, type RandomPort } from "../../src/ports/random.ts";
import type {
  AuthCodeRecord, ConsentApprovalCommitResult, RefreshTokenRecord,
  SaveAuthCodeInput, SaveRefreshTokenInput, StorePort,
} from "../../src/ports/store.ts";
import { assertStoreInstanceId, STORED_DCR_GRANT_GENERATION, STORED_DCR_RESOURCE_BINDING } from "../../src/ports/store.ts";
import { StoreExpiryLifecycle } from "../../src/store/expiry-lifecycle.ts";
import { FixtureClientStore } from "./client-store.ts";
import { FixtureRunnerError } from "./error.ts";
import type { LogicalTables } from "./logical-state.ts";
import { hydrateLogicalState, projectLogicalState } from "./logical-state.ts";
import * as codeOps from "./store-codes.ts";
import type { SweepWatermark } from "./store-codes.ts";
import * as refreshOps from "./store-refresh.ts";
import type { LogicalState } from "./types.ts";

export class FixtureStore implements StorePort, ClientStore {
  readonly storedDcrGrantGeneration = STORED_DCR_GRANT_GENERATION;
  readonly storedDcrResourceBinding = STORED_DCR_RESOURCE_BINDING;
  /** The hydrated state the class operates on. Package-private like the shipped
   *  stores' internals so the shared conformance suite can seed rows that bypass
   *  `StorePort` validation, which is exactly what a fixture's `given.state` can
   *  author. */
  private tables: LogicalTables;
  readonly #random: RandomPort;
  readonly #watermark: SweepWatermark;
  readonly #expiry = new StoreExpiryLifecycle(this, true);
  readonly #clients: FixtureClientStore;
  #instanceId: string;
  #closed = false;

  constructor(state: LogicalState, random: RandomPort) {
    this.#random = random;
    this.tables = hydrateLogicalState(state);
    if (this.tables.instanceId !== undefined) assertStoreInstanceId(this.tables.instanceId);
    this.#instanceId = this.tables.instanceId ?? randomBytesFrom(random, 18).toString("base64url");
    this.#watermark = { sweptThrough: this.tables.sweptThrough };
    this.#clients = new FixtureClientStore(this.tables.clients);
  }

  async getStoreInstanceId(): Promise<string> {
    this.#open();
    return this.#instanceId;
  }

  async rotateStoreInstanceId(): Promise<string> {
    this.#open();
    this.#instanceId = randomBytesFrom(this.#random, 18).toString("base64url");
    return this.#instanceId;
  }

  async commitConsentApproval(
    expectedStoreInstanceId: string,
    jti: string,
    expiresAtIso: string,
    authCode: SaveAuthCodeInput,
  ): Promise<ConsentApprovalCommitResult> {
    this.#open();
    return codeOps.commitConsentApproval(
      this.tables, this.#watermark, this.#instanceId, expectedStoreInstanceId, jti, expiresAtIso, authCode,
    );
  }

  async saveAuthCode(input: SaveAuthCodeInput): Promise<void> {
    this.#open();
    codeOps.saveAuthCode(this.tables, input);
  }

  async consumeAuthCode(
    codeHash: string,
    nowIso: string,
    expectedGrantGeneration?: number,
    expectedResource?: string,
  ): Promise<AuthCodeRecord | null> {
    this.#open();
    return codeOps.consumeAuthCode(this.tables, codeHash, nowIso, expectedGrantGeneration, expectedResource);
  }

  async saveRefreshToken(input: SaveRefreshTokenInput): Promise<void> {
    this.#open();
    refreshOps.saveRefreshToken(this.tables, input);
  }

  async rotateRefreshToken(
    tokenHash: string,
    next: SaveRefreshTokenInput,
    nowIso: string,
    expectedGrantGeneration?: number,
    expectedResource?: string,
  ): Promise<RefreshTokenRecord | null> {
    this.#open();
    return refreshOps.rotateRefreshToken(
      this.tables, tokenHash, next, nowIso, expectedGrantGeneration, expectedResource,
    );
  }

  async revokeRefreshTokenFamily(familyId: string, revokedAtIso: string, expectedResource?: string): Promise<void> {
    this.#open();
    refreshOps.revokeRefreshTokenFamily(this.tables, familyId, revokedAtIso, expectedResource);
  }

  async findRefreshToken(tokenHash: string): Promise<RefreshTokenRecord | null> {
    this.#open();
    return refreshOps.findRefreshToken(this.tables, tokenHash);
  }

  async consumeConsentJti(jti: string, expiresAtIso: string): Promise<boolean> {
    this.#open();
    return codeOps.consumeConsentJti(this.tables, this.#watermark, jti, expiresAtIso);
  }

  async findGrantedScopes(
    subject: string,
    clientId: string,
    nowIso: string,
    expectedGrantGeneration?: number,
    expectedResource?: string,
  ): Promise<string[]> {
    this.#open();
    return refreshOps.findGrantedScopes(
      this.tables, subject, clientId, nowIso, expectedGrantGeneration, expectedResource,
    );
  }

  async sweepExpired(nowIso: string): Promise<void> {
    this.#open();
    codeOps.sweepCodes(this.tables, this.#watermark, nowIso);
    refreshOps.sweepRefresh(this.tables, nowIso);
  }

  startExpiryCollection(clock: ClockPort): void {
    this.#open();
    this.#expiry.start(clock);
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    await this.#expiry.stop();
    await this.#clients.close();
    this.#closed = true;
  }

  async save(client: ClientRegistration): Promise<void> {
    this.#open();
    return this.#clients.save(client);
  }

  async find(clientId: string): Promise<ClientRegistration | null> {
    this.#open();
    return this.#clients.find(clientId);
  }

  snapshot(): Required<LogicalState> {
    return projectLogicalState(this.tables, this.#instanceId);
  }

  #open(): void {
    if (this.#closed) throw new FixtureRunnerError("Store is closed");
  }
}
