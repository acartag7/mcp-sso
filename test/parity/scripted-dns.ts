import type { DnsResolver } from "../../src/cimd/transport.ts";
import { FixtureRunnerError } from "./error.ts";

interface ExchangeUrl {
  request: { url: string };
}

const UNDECLARED_HOST = "fixture DNS lookup is not declared by an HTTPS exchange";
const LOOPBACK_ADDRESS = "127.0.0.1";
const PUBLIC_ADDRESS = "93.184.216.34";

export class ScriptedDnsResolver implements DnsResolver {
  readonly #declaredHosts: Set<string>;

  constructor(exchanges: readonly ExchangeUrl[]) {
    this.#declaredHosts = new Set(exchanges.flatMap(({ request }) => {
      const url = new URL(request.url);
      return url.protocol === "https:" ? [url.hostname] : [];
    }));
  }

  async resolve(hostname: string): Promise<Array<{ address: string; family: 4 }>> {
    if (!this.#declaredHosts.has(hostname)) throw new FixtureRunnerError(UNDECLARED_HOST);
    const address = hostname === "localhost" || hostname.endsWith(".localhost")
      ? LOOPBACK_ADDRESS : PUBLIC_ADDRESS;
    return [{ address, family: 4 }];
  }
}
