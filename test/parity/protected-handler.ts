import type { IncomingHttpHeaders } from "node:http";
import { buildUnauthorizedChallenge } from "../../src/challenge.ts";
import { originOf, type BridgeConfig } from "../../src/config.ts";
import { headersFromDistinct, readHeader } from "../../src/adapters/http.ts";
import { OAuthError } from "../../src/errors.ts";
import type { RequestAuthorizer } from "../../src/verifier.ts";
import { FixtureRunnerError } from "./error.ts";
import { encodeResponseBody } from "./response-body.ts";
import type { HeaderMap, ProtectedResource } from "./types.ts";

const JSON_RPC_CONTENT_TYPE = "application/json; charset=utf-8";
const JSON_RPC_ERROR_CODE = -32001;
const ORIGIN_REJECTED = "Origin not allowed";
const MISSING_SUCCESS = "protected handler ran without given.protectedResource.success";
const INVALID_HEADER = "protectedResource.success header contains a capture or non-string value";
const INVALID_HEADER_LINE = "protectedResource.success header cannot contain CR or LF";
const NO_HEADER_SOURCE = "protected handler received no request header source";

/** The authorize surface the protected handler consumes. `RequestAuthorizer`
 *  declares TypeScript-private fields, so the class type is nominal and a test
 *  double cannot satisfy it; this pick keeps the real authorizer assignable
 *  while the handler depends only on the call it makes. */
export type ProtectedAuthorizer = Pick<RequestAuthorizer, "authorize">;

export interface HostOutcome {
  status: number;
  headers: Record<string, string | string[]>;
  body: Buffer;
}

export interface ProtectedOutcomeInput {
  /** Node occurrence metadata (`IncomingMessage.headersDistinct`), the header
   *  source a Node-request mount supplies. */
  distinct?: Record<string, string[] | undefined>;
  /** The normalized header map, the only source a Fetch `Request` mount has. */
  normalized?: IncomingHttpHeaders;
  authorizer: ProtectedAuthorizer;
  config: BridgeConfig;
  protectedResource: ProtectedResource;
}

/** Compute the protected `/mcp` handler's status, headers, and body bytes for
 *  one inbound request, with no framework involved (§19.2). A mount supplies its
 *  headers as `distinct`, as `normalized`, or as both, and at least one of the
 *  two is required. The Origin gate runs before authorization, and authorization
 *  runs before the fixture's success response is read. */
export async function protectedOutcome(input: ProtectedOutcomeInput): Promise<HostOutcome> {
  const { authorizer, config, protectedResource } = input;
  const headers = requestHeaders(input);
  if (originRejected(headers, config)) return jsonRpcOutcome(403, ORIGIN_REJECTED);
  try {
    await authorizer.authorize({
      authorization: authorizationInput(input),
      ...protectedResource.requiredScope === null
        ? {}
        : { requiredScope: protectedResource.requiredScope },
    });
  } catch (error) {
    return unauthorizedOutcome(error, config);
  }
  const { success } = protectedResource;
  if (success === undefined) throw new FixtureRunnerError(MISSING_SUCCESS);
  const responseHeaders = explicitHeaders(success.headers);
  return {
    status: success.status,
    headers: responseHeaders,
    body: encodeResponseBody(success.body, responseHeaders),
  };
}

/** §8.4: every shipped composition root passes the raw Authorization
 *  occurrence array into RequestAuthorizer, never a framework's normalized
 *  first value. Deliver that boundary here too: a one-occurrence request
 *  reaches the authorizer as a one-element array, which is the exact input
 *  class the verifier's array rule names, instead of the scalar
 *  headersFromDistinct produces for a single occurrence. */
function authorizationInput(input: ProtectedOutcomeInput): string | string[] | undefined {
  if (input.distinct !== undefined) {
    const values = input.distinct.authorization;
    return values !== undefined && values.length > 0 ? [...values] : undefined;
  }
  const normalized = input.normalized?.authorization;
  if (normalized === undefined) return undefined;
  return Array.isArray(normalized) ? normalized : [normalized];
}

/** Read the mount's headers through the library's own precedence: `distinct`
 *  when it is present, `normalized` only when `distinct` is omitted, and never a
 *  merge of the two. A mount that passes neither is a runner defect rather than
 *  an unauthenticated request, so it fails the fixture instead of reaching the
 *  authorizer as a 401. */
function requestHeaders(input: ProtectedOutcomeInput): Record<string, string | string[] | undefined> {
  try {
    return headersFromDistinct(input.distinct, input.normalized);
  } catch (error) {
    throw new FixtureRunnerError(NO_HEADER_SOURCE, { cause: error });
  }
}

/** MCP Streamable HTTP DNS-rebinding protection: an absent Origin proceeds, an
 *  ambiguous one is refused, and a present one must equal the issuer origin or a
 *  boot-validated `allowedOrigins` entry exactly. */
function originRejected(headers: Record<string, string | string[] | undefined>, config: BridgeConfig): boolean {
  const origin = readHeader(headers, "origin");
  if (origin.ambiguous) return true;
  if (origin.value === undefined) return false;
  return origin.value !== originOf(config.issuer) && !config.allowedOrigins.includes(origin.value);
}

/** Map an authorize rejection onto the JSON-RPC error document plus the §8.2
 *  challenge. A throwable that is not an `OAuthError` carries no client-facing
 *  text and becomes `invalid_token` 401. */
function unauthorizedOutcome(error: unknown, config: BridgeConfig): HostOutcome {
  const oauth = error instanceof OAuthError
    ? error
    : new OAuthError("invalid_token", "Bearer token is invalid", 401);
  const outcome = jsonRpcOutcome(oauth.status, `${oauth.code}: ${oauth.message}`);
  outcome.headers["www-authenticate"] = buildUnauthorizedChallenge(config, {
    scope: config.scopeCatalog, error: oauth.code, errorDescription: oauth.message,
  });
  return outcome;
}

function jsonRpcOutcome(status: number, message: string): HostOutcome {
  const document = { jsonrpc: "2.0", error: { code: JSON_RPC_ERROR_CODE, message }, id: null };
  return {
    status,
    headers: { "content-type": JSON_RPC_CONTENT_TYPE },
    body: Buffer.from(JSON.stringify(document), "utf8"),
  };
}

/** Read the fixture's explicit success header map: one occurrence is a string,
 *  several are an ordered array, and neither a capture reference nor a field
 *  value carrying CR or LF is a response header (sibling of the scripted-response
 *  header reader in `scripted-fetch.ts`). */
function explicitHeaders(source: HeaderMap): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};
  for (const [name, raw] of Object.entries(source)) {
    const values = Array.isArray(raw) ? raw : [raw];
    if (!values.every((value) => typeof value === "string")) {
      throw new FixtureRunnerError(INVALID_HEADER);
    }
    if (values.some((value) => /[\r\n]/u.test(value))) {
      throw new FixtureRunnerError(INVALID_HEADER_LINE);
    }
    defineHeader(result, name, values.length === 1 ? values[0]! : [...values]);
  }
  return result;
}

/** Define header names as written without walking `Object.prototype`; a fixture
 *  may legally name a header `__proto__`. */
function defineHeader(
  target: Record<string, string | string[]>, name: string, value: string | string[],
): void {
  Object.defineProperty(target, name, { value, enumerable: true, configurable: true, writable: true });
}
