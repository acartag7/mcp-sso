export type AdapterKind = "fastify" | "express" | "hono";
type HeaderOccurrence = string | CaptureReference;
export type HeaderValue = HeaderOccurrence | HeaderOccurrence[];
export type HeaderMap = Record<string, HeaderValue>;
export type BodyValue = { absent: true } | { value: unknown };
export type Matcher = string | { absent: true } | { equals: unknown } | { matches: string }
  | { contains: string } | { schema: Record<string, unknown> };

export interface CaptureReference {
  $capture: { fixture: string; name: string; format: "raw" | "bearer" };
}

export interface LogicalState {
  authorization_code?: AuthorizationCodeRow[];
  consent_jti?: ConsentJtiRow[];
  refresh_token?: RefreshTokenRow[];
  revoked_family?: RevokedFamilyRow[];
  client_registration?: ClientRegistrationRow[];
  store_instance?: StoreInstanceRow[];
}

export interface AuthorizationCodeRow {
  code_hash: string; client_id: string; subject: string; redirect_uri: string;
  resource: string; scopes: string[]; code_challenge: string;
  code_challenge_method: "S256"; expires_at: string; grant_generation?: number;
}
export interface ConsentJtiRow { jti: string; expires_at: string }
export interface RefreshTokenRow {
  token_hash: string; family_id: string; previous_token_hash?: string; client_id: string;
  subject: string; resource: string; scopes: string[]; expires_at: string;
  consumed_at?: string; grant_generation?: number;
}
export interface RevokedFamilyRow {
  family_id: string; resource: string; revoked_at: string; grant_generation?: number;
}
export interface ClientRegistrationRow {
  client_id: string; redirect_uris: string[]; application_type: "native" | "web";
  issued_at_epoch: number;
}
export interface StoreInstanceRow { instance_id: string }

export interface HttpExchange {
  request: { method: string; url: string; headers: Record<string, Matcher>; body: Matcher };
  response: { status: number; headers: HeaderMap; body: BodyValue };
}

export interface FixtureGiven {
  config: Record<string, unknown>; clock: string; random: { seed: string };
  keys: { signingPrivate: string; signingPublic?: string }; state: LogicalState;
  http: HttpExchange[]; identity: { checks: IdentityCheck[] };
  rateLimit: { checks: RateLimitCheck[] }; protectedResource: ProtectedResource;
}
export interface BootGiven extends Omit<FixtureGiven, "keys" | "protectedResource" | "config"> {
  config: unknown; entrypoint: "createBridgeConfig" | "Bridge";
  keys: { signingPrivate?: string; signingPublic?: string };
}
export interface ProtectedResource {
  requiredScope: string | null;
  success?: { status: number; headers: HeaderMap; body: BodyValue };
}
type IdentityResult = { ok: true; identity: { subject: string; allowedScopes?: string[]; claims?: Record<string, unknown> } } | { ok: false; reason: string };
type IdentityThrow = { kind: "oauth"; code: string; description: string; status: 401 | 403 } | { kind: "generic" };
type IdentityOutcome = { result: IdentityResult; throw?: never } | { result?: never; throw: IdentityThrow };
export type IdentityCheck = { input: BodyValue } & IdentityOutcome;
export interface RateLimitCheck {
  key: string; outcome: "allow" | "deny" | { throws: string };
}

export interface RequestSpec {
  method: string; path: string; headers?: HeaderMap;
  body?: { json: unknown } | { form: Array<{ name: string; value: string | CaptureReference }> }
    | { text: string | CaptureReference };
}
export interface HttpThen {
  status: number; headers?: Record<string, Matcher>; body?: Matcher;
  audit?: AuditAssertion; state?: StateAssertion; captures?: CaptureSpec[];
  outbound: OutboundCall[];
}
export interface BootThen {
  boot: { outcome: "accepted" } | { outcome: "rejected"; error: {
    code: string; name?: Exclude<Matcher, { absent: true }>; message?: Exclude<Matcher, { absent: true }>;
  } };
  audit?: AuditAssertion; state?: StateAssertion; outbound: OutboundCall[];
}
export interface AuditAssertion {
  events: Array<Record<string, unknown>>; absent: Array<Record<string, unknown>>;
}
export interface StateAssertion {
  mode: "exact" | "contains"; rows: LogicalState;
  absent: Array<{ kind: keyof LogicalState; where: Record<string, unknown> }>;
}
export interface CaptureSpec {
  name: string;
  source: { bodyPointer: string } | { header: string; urlQuery: string };
  jwt?: { key: "signingPublic"; header: Record<string, unknown>; claims: Record<string, unknown> };
}
export interface OutboundCall {
  method: string; url: string; headers: Record<string, Exclude<Matcher, { absent: true }>>; body: Matcher;
}

export interface FixtureReceipt {
  implementation: string; version: string; commit: string; date: string;
}

interface FixtureBaseFields {
  id: string; profile: "portable" | "host";
  contract: { section: string; clause: string; quote: string };
  notes?: string; chain?: { id: string; step: number; previous?: string };
}
interface DraftStatus { status: "draft"; supersededBy?: string; receipt?: FixtureReceipt }
interface FrozenStatus { status: "frozen"; supersededBy?: string; receipt: FixtureReceipt }
interface SupersededStatus { status: "superseded"; supersededBy: string; receipt?: FixtureReceipt }

type WithFixtureStatus<T> = (T & DraftStatus) | (T & FrozenStatus) | (T & SupersededStatus);
type HttpFixtureFields = {
  kind: "fixture"; given: FixtureGiven; when: { request: RequestSpec }; then: HttpThen;
};
type BootFixtureFields = { kind: "boot"; given: BootGiven; then: BootThen };
export type HttpFixture = WithFixtureStatus<FixtureBaseFields & HttpFixtureFields>;
export type BootFixture = WithFixtureStatus<FixtureBaseFields & BootFixtureFields>;
export type ParityFixture = HttpFixture | BootFixture;

export interface ObservedMessage {
  status: number; headers: Record<string, string | string[]>; body: Buffer;
}
export interface ObservedOutbound {
  method: string; url: string; headers: Record<string, string | string[]>; body?: Buffer;
}
export type CaptureValues = Map<string, Map<string, string>>;
