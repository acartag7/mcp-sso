// Node I/O implementations of the below-guard CIMD seams. Split out of
// `guarded-fetcher.ts` (250-line limit, contracts §6); the guard pipeline —
// URL admission, DNS validation, blocklists, redirect refusal, caps — always
// runs AROUND these, never inside them.

import { Resolver } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import type { CimdTransport, DnsResolver } from "./transport.ts";

export class NodeDnsResolver implements DnsResolver {
  readonly resolver = new Resolver();
  async resolve(hostname: string): Promise<{ address: string; family: 4 | 6 }[]> {
    if (hostname === "localhost" || hostname.endsWith(".localhost")) return [{ address: "127.0.0.1", family: 4 }, { address: "::1", family: 6 }]; // c-ares can't resolve localhost
    const [v4, v6] = await Promise.all([
      resolveFamily(this.resolver.resolve4(hostname), 4),
      resolveFamily(this.resolver.resolve6(hostname), 6),
    ]);
    return [...v4, ...v6];
  }
  /** Cancels only THIS resolver's queries. A fresh instance is constructed per
   *  fetch (guarded-fetcher.ts) so one request's deadline can never cancel
   *  another concurrent request's DNS lookups. */
  cancel(): void { this.resolver.cancel(); }
}

async function resolveFamily(promise: Promise<string[]>, family: 4 | 6) {
  try { return (await promise).map((address) => ({ address, family })); }
  catch (error) {
    const code = typeof error === "object" && error !== null
      ? (error as { code?: unknown }).code : undefined;
    if (code === "ENODATA" || code === "ENOTFOUND") return [];
    throw error;
  }
}

export function nodeConnectAndGet(req: Parameters<CimdTransport["connectAndGet"]>[0]) {
  return new Promise<Awaited<ReturnType<CimdTransport["connectAndGet"]>>>((resolve, reject) => {
    const request = httpsRequest({
      hostname: req.connectIp, family: req.family, port: req.port, servername: req.servername,
      method: "GET", path: req.requestTarget,
      headers: { Host: req.hostHeader, Accept: "application/json", "Accept-Encoding": "identity" },
      agent: false, signal: req.signal, rejectUnauthorized: true, // enforce TLS even under NODE_TLS_REJECT_UNAUTHORIZED=0
    }, (response) => {
      const headersDistinct: Record<string, string[]> = Object.create(null) as Record<string, string[]>;
      for (let index = 0; index < response.rawHeaders.length; index += 2) {
        const name = response.rawHeaders[index]!.toLowerCase();
        (headersDistinct[name] ??= []).push(response.rawHeaders[index + 1]!);
      }
      resolve({ status: response.statusCode ?? 0, redirected: false,
        finalUrl: new URL(`https://${req.hostHeader}${req.requestTarget}`).href,
        headersDistinct, encodedBody: response });
    });
    request.once("error", reject);
    request.end();
  });
}

export const NODE_TRANSPORT: CimdTransport = { connectAndGet: nodeConnectAndGet };
