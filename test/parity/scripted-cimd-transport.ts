import type { CimdTransport } from "../../src/cimd/transport.ts";
import { FixtureRunnerError } from "./error.ts";
import { encodeResponseBody } from "./response-body.ts";
import type { BodyValue, HeaderMap, HttpExchange, ObservedOutbound } from "./types.ts";

export type ConsumeOutbound = (call: ObservedOutbound) => HttpExchange["response"];

export class ScriptedCimdTransport implements CimdTransport {
  readonly #consume: ConsumeOutbound;

  constructor(consume: ConsumeOutbound) {
    this.#consume = consume;
  }

  async connectAndGet(request: Parameters<CimdTransport["connectAndGet"]>[0]) {
    const url = `https://${request.hostHeader}${request.requestTarget}`;
    const response = this.#consume({
      method: "GET",
      url,
      headers: {
        host: request.hostHeader,
        accept: "application/json",
        "accept-encoding": "identity",
      },
    });
    const headersDistinct = explicitResponseHeaders(response.headers);
    return {
      status: response.status,
      redirected: false,
      finalUrl: url,
      headersDistinct,
      encodedBody: bodyChunks(response.body, headersDistinct),
    };
  }
}

function explicitResponseHeaders(headers: HeaderMap): Record<string, string[]> {
  const result = Object.create(null) as Record<string, string[]>;
  for (const [name, raw] of Object.entries(headers)) {
    const values = Array.isArray(raw) ? [...raw] : [raw];
    if (!values.every((value) => typeof value === "string")) {
      throw new FixtureRunnerError(`outbound response header ${name} contains a capture or non-string value`);
    }
    if (values.some((value) => /[\r\n]/u.test(value))) {
      throw new FixtureRunnerError(`outbound response header ${name} cannot contain CR or LF`);
    }
    result[name] = values;
  }
  return result;
}

async function* bodyChunks(body: BodyValue, headers: Record<string, string[]>): AsyncGenerator<Uint8Array> {
  const encoded = encodeResponseBody(body, headers);
  if (encoded.byteLength > 0) yield Uint8Array.from(encoded);
}
