// Flow-JWT sign/verify for the §17.11 upstream redirect leg — the HS256 cookie
// that carries the flow across the IdP redirect. Split out of
// `upstream-flow-internals.ts` to keep both files under the 250-line limit
// (contracts §6); no behavior differs from when this lived there.
//
// The audience is PER FLOW (`flowAudience`), not deployment-wide: see §17.11
// "flow-instance binding". jose is the only import beyond local types.

import { SignJWT, jwtVerify } from "jose";
import { parseCimdRegistrationClaim, type CimdRegistration } from "../cimd/registration.ts";
import { finiteClockSnapshot, type ClockPort } from "../ports/clock.ts";

/** Audience PREFIX for the flow JWT — distinct from `mcp-sso/consent` so a flow
 *  token can never be replayed as a consent token (and vice-versa), even though
 *  both are HS256-signed with the same consent secret (§17.11). */
export const FLOW_AUDIENCE = "mcp-sso/upstream-flow";

/** The per-flow audience — the prefix plus this flow's `callbackPath` (§17.11
 *  "flow-instance binding"; full rationale there). A deployment-wide audience
 *  let every flow built from one signing secret accept every OTHER flow's
 *  cookies, so a cookie minted for the intended IdP could be redeemed through a
 *  different configured one (confused deputy). `callbackPath` is the binding
 *  value because it is already unique per flow and boot-validated by
 *  `assertCallbackPath` into a canonical literal — which also makes the
 *  concatenation unambiguous (it always starts with `/` and cannot contain the
 *  characters that would let two paths collide). A non-matching cookie fails
 *  `jwtVerify` and surfaces as the EXISTING row 3 `flow_cookie_invalid`. */
export function flowAudience(callbackPath: string): string {
  return FLOW_AUDIENCE + callbackPath;
}

export interface FlowClaims {
  jti: string;
  state: string;
  nonce: string;
  codeVerifier: string;
  params: Record<string, string>;
  exp: number;
  /** The validated CIMD registration carried forward under this token's HS256
   *  signature (§17.1.6 decision 1c). Absent for a non-CIMD flow. */
  cimd?: CimdRegistration;
}

function flowSecret(consentSigningSecret: string): Uint8Array {
  return new TextEncoder().encode(consentSigningSecret);
}

export async function signFlowToken(args: {
  secret: string; issuer: string; clock: ClockPort;
  /** This flow's `callbackPath` — binds the token to the flow instance
   *  (§17.11). REQUIRED: defaulting it would silently restore the
   *  deployment-wide audience for any caller that forgot to pass it. */
  callbackPath: string;
  jti: string; state: string; nonce: string; codeVerifier: string;
  params: Record<string, string>; ttlSeconds: number;
  /** EXACTLY a `CimdRegistration` — never a raw `CimdDocument` (decision 1c:
   *  signing the document would carry attacker-controlled members). */
  cimd?: CimdRegistration;
}): Promise<string> {
  const now = Math.floor(finiteClockSnapshot(args.clock, args.ttlSeconds * 1000) / 1000);
  return await new SignJWT({
    jti: args.jti, state: args.state, nonce: args.nonce,
    code_verifier: args.codeVerifier, params: args.params,
    ...(args.cimd === undefined ? {} : {
      cimd: {
        client_id: args.cimd.client_id,
        client_name: args.cimd.client_name,
        redirect_uris: [...args.cimd.redirect_uris],
        ...(args.cimd.application_type === undefined
          ? {} : { application_type: args.cimd.application_type }),
      },
    }),
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(args.issuer)
    .setAudience(flowAudience(args.callbackPath))
    .setIssuedAt(now)
    .setExpirationTime(now + args.ttlSeconds)
    .sign(flowSecret(args.secret));
}

/** Verify signature + iss + aud. Expiry is NOT checked here (currentDate=epoch
 *  disables jose's exp rejection) so the caller can distinguish row 3 (this
 *  throw ⇒ flow_cookie_invalid) from row 4 (manual exp ⇒ flow_expired). A
 *  structurally-malformed payload on a validly-signed token also throws ⇒ row 3. */
export async function verifyFlowToken(token: string, secret: string, issuer: string, callbackPath: string): Promise<FlowClaims> {
  const { payload } = await jwtVerify(token, flowSecret(secret), {
    // §17.11 flow-instance binding: the audience is THIS flow's, so a cookie
    // minted by a sibling flow fails here and reports as row 3 — the same
    // channel as any other cookie-integrity failure (never a distinct code).
    algorithms: ["HS256"], issuer, audience: flowAudience(callbackPath), currentDate: new Date(0),
  });
  const rawParams = payload.params;
  if (typeof rawParams !== "object" || rawParams === null || Array.isArray(rawParams)) {
    throw new Error("flow params missing");
  }
  const params: Record<string, string> = {};
  for (const [k, v] of Object.entries(rawParams)) if (typeof v === "string") params[k] = v;
  return {
    jti: requiredString(payload.jti, "jti"),
    state: requiredString(payload.state, "state"),
    nonce: requiredString(payload.nonce, "nonce"),
    codeVerifier: requiredString(payload.code_verifier, "code_verifier"),
    params,
    // exp is always set by signFlowToken; a signed token missing it (or non-numeric)
    // is structurally malformed ⇒ throw ⇒ row 3 flow_cookie_invalid. Never coerce
    // to 0 (that would silently skip the row-4 expiry check).
    exp: requiredPositiveNumber(payload.exp, "exp"),
    // §17.1.6 decision 1d(i): strict shape parse. A PRESENT-but-malformed claim
    // THROWS here ⇒ row 3 (invalid_request / flow_cookie_invalid), consistent
    // with the other cookie-integrity failures. Unknown members are ignored
    // (named projection, never Object.assign).
    ...(Object.hasOwn(payload, "cimd")
      ? { cimd: parseCimdRegistrationClaim(payload.cimd, params.client_id) }
      : {}),
  };
}

function requiredPositiveNumber(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) throw new Error(`flow token missing ${label}`);
  return value;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || !value) throw new Error(`flow token missing ${label}`);
  return value;
}
