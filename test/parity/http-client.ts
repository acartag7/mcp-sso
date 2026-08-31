import { Socket } from "node:net";
import type { ObservedMessage } from "./types.ts";
import { FixtureRunnerError } from "./error.ts";

export function sendRealHttp(input: {
  base: string; method: string; path: string; headers: Array<[string, string]>; body?: Buffer;
}): Promise<ObservedMessage> {
  return new Promise((resolve, reject) => {
    const target = new URL(input.path, input.base);
    const socket = new Socket(); const chunks: Buffer[] = [];
    socket.connect(Number(target.port), target.hostname, () => {
      const hasHost = input.headers.some(([name]) => name === "host");
      const hasLength = input.headers.some(([name]) => name === "content-length" || name === "transfer-encoding");
      const lines = [`${input.method} ${target.pathname}${target.search} HTTP/1.1`,
        ...(hasHost ? [] : [`Host: ${target.host}`]),
        ...input.headers.map(([name, value]) => `${name}: ${value}`),
        ...(input.body === undefined || hasLength ? [] : [`Content-Length: ${input.body.byteLength}`]),
        "Connection: close", "", ""];
      socket.write(Buffer.concat([Buffer.from(lines.join("\r\n"), "utf8"), input.body ?? Buffer.alloc(0)]));
    });
    socket.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    socket.on("error", reject);
    socket.on("end", () => {
      try { resolve(parseResponse(Buffer.concat(chunks))); } catch (error) { reject(error); }
    });
    socket.setTimeout(5_000, () => socket.destroy(new Error(`${input.method} ${input.path} timed out`)));
  });
}

function parseResponse(raw: Buffer): ObservedMessage {
  const boundary = raw.indexOf("\r\n\r\n");
  if (boundary < 0) throw new FixtureRunnerError("HTTP response has no header boundary");
  const head = raw.subarray(0, boundary).toString("latin1");
  const lines = head.split("\r\n");
  const status = /^HTTP\/1\.[01] ([0-9]{3})(?: |$)/u.exec(lines[0] ?? "")?.[1];
  if (!status) throw new FixtureRunnerError("HTTP response status line is malformed");
  const values = new Map<string, string[]>();
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(":");
    if (colon <= 0) throw new FixtureRunnerError("HTTP response header line is malformed");
    const name = line.slice(0, colon).toLowerCase(), value = line.slice(colon + 1).trim();
    values.set(name, [...(values.get(name) ?? []), value]);
  }
  const headers = Object.fromEntries([...values].map(([name, occurrences]) => [
    name, occurrences.length === 1 ? occurrences[0]! : occurrences,
  ]));
  const encoded = raw.subarray(boundary + 4);
  const transfer = headers["transfer-encoding"];
  const body = transfer === "chunked" ? decodeChunked(encoded) : contentLengthBody(encoded, headers["content-length"]);
  return { status: Number(status), headers, body };
}

function contentLengthBody(body: Buffer, rawLength: string | string[] | undefined): Buffer {
  if (rawLength === undefined) return body;
  if (typeof rawLength !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(rawLength)) {
    throw new FixtureRunnerError("HTTP response Content-Length is ambiguous or malformed");
  }
  const length = Number(rawLength);
  if (!Number.isSafeInteger(length) || body.byteLength !== length) throw new FixtureRunnerError("HTTP response Content-Length mismatch");
  return body;
}

function decodeChunked(encoded: Buffer): Buffer {
  const chunks: Buffer[] = []; let offset = 0;
  while (true) {
    const lineEnd = encoded.indexOf("\r\n", offset);
    if (lineEnd < 0) throw new FixtureRunnerError("chunked response is truncated");
    const sizeText = encoded.subarray(offset, lineEnd).toString("ascii").split(";", 1)[0]!;
    if (!/^[0-9a-fA-F]+$/u.test(sizeText)) throw new FixtureRunnerError("chunked response size is malformed");
    const size = Number.parseInt(sizeText, 16); offset = lineEnd + 2;
    if (size === 0) return Buffer.concat(chunks);
    if (!Number.isSafeInteger(size) || offset + size + 2 > encoded.byteLength) throw new FixtureRunnerError("chunked response is truncated");
    chunks.push(encoded.subarray(offset, offset + size)); offset += size;
    if (encoded.subarray(offset, offset + 2).toString("ascii") !== "\r\n") throw new FixtureRunnerError("chunk terminator is malformed");
    offset += 2;
  }
}
