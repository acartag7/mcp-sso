import { Socket } from "node:net";
import type { ObservedMessage } from "./types.ts";
import { FixtureRunnerError } from "./error.ts";

export function sendRealHttp(input: {
  base: string; method: string; path: string; headers: Array<[string, string]>; body?: Buffer;
}): Promise<ObservedMessage> {
  if (/[\r\n]/u.test(input.method) || /[\r\n]/u.test(input.path)) {
    throw new FixtureRunnerError("HTTP request method and path cannot contain CR or LF");
  }
  for (const [name, value] of input.headers) {
    if (/[\r\n]/u.test(name) || /[\r\n]/u.test(value)) {
      throw new FixtureRunnerError("HTTP request headers cannot contain CR or LF");
    }
  }
  const base = new URL(input.base);
  const resolved = new URL(input.path, base);
  if (resolved.origin !== base.origin) {
    throw new FixtureRunnerError("HTTP request path cannot leave the mounted host");
  }
  return new Promise((resolve, reject) => {
    const socket = new Socket(); const chunks: Buffer[] = []; let settled = false;
    const fail = (error: unknown): void => {
      if (settled) return;
      settled = true; socket.destroy(); reject(error);
    };
    const finish = (ended: boolean): void => {
      if (settled) return;
      try {
        const response = tryParseResponse(Buffer.concat(chunks), input.method, ended);
        if (!response) return;
        settled = true; socket.setTimeout(0); socket.destroy(); resolve(response);
      } catch (error) { fail(error); }
    };
    socket.connect(Number(base.port), base.hostname, () => {
      const hasHost = input.headers.some(([name]) => name === "host");
      const hasLength = input.headers.some(([name]) => name === "content-length" || name === "transfer-encoding");
      const hasConnection = input.headers.some(([name]) => name === "connection");
      const lines = [`${input.method} ${input.path} HTTP/1.1`,
        ...(hasHost ? [] : [`Host: ${base.host}`]),
        ...input.headers.map(([name, value]) => `${name}: ${value}`),
        ...(input.body === undefined || hasLength ? [] : [`Content-Length: ${input.body.byteLength}`]),
        ...(hasConnection ? [] : ["Connection: close"]), "", ""];
      socket.write(Buffer.concat([Buffer.from(lines.join("\r\n"), "utf8"), input.body ?? Buffer.alloc(0)]));
    });
    socket.on("data", (chunk) => {
      chunks.push(Buffer.from(chunk)); finish(false);
    });
    socket.on("error", fail);
    socket.on("end", () => finish(true));
    socket.setTimeout(5_000, () => fail(new Error(`${input.method} ${input.path} timed out`)));
  });
}

function tryParseResponse(raw: Buffer, method: string, ended: boolean): ObservedMessage | undefined {
  while (true) {
    const boundary = raw.indexOf("\r\n\r\n");
    if (boundary < 0) {
      if (!ended) return undefined;
      throw new FixtureRunnerError("HTTP response has no header boundary");
    }
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
    const statusCode = Number(status);
    if (statusCode >= 100 && statusCode < 200) {
      if (statusCode === 101) throw new FixtureRunnerError("HTTP protocol upgrade responses are unsupported");
      raw = encoded;
      continue;
    }
    return tryParseFinalResponse(statusCode, headers, encoded, method, ended);
  }
}

function tryParseFinalResponse(
  statusCode: number, headers: Record<string, string | string[]>, encoded: Buffer,
  method: string, ended: boolean,
): ObservedMessage | undefined {
  if (method === "HEAD" || statusCode === 204 || statusCode === 205 || statusCode === 304) {
    if (encoded.byteLength > 0) throw new FixtureRunnerError("bodyless HTTP response contained bytes");
    return { status: statusCode, headers, body: Buffer.alloc(0) };
  }
  const transfer = headers["transfer-encoding"];
  if (transfer !== undefined) {
    if (typeof transfer !== "string" || transfer.toLowerCase() !== "chunked") {
      throw new FixtureRunnerError("HTTP response Transfer-Encoding is ambiguous or unsupported");
    }
    const body = decodeChunked(encoded, ended);
    return body ? { status: statusCode, headers, body } : undefined;
  }
  const length = contentLength(headers["content-length"]);
  if (length !== undefined) {
    if (encoded.byteLength < length && !ended) return undefined;
    if (encoded.byteLength !== length) throw new FixtureRunnerError("HTTP response Content-Length mismatch");
    return { status: statusCode, headers, body: encoded };
  }
  if (!ended) return undefined;
  return { status: statusCode, headers, body: encoded };
}

function contentLength(rawLength: string | string[] | undefined): number | undefined {
  if (rawLength === undefined) return undefined;
  if (typeof rawLength !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(rawLength)) {
    throw new FixtureRunnerError("HTTP response Content-Length is ambiguous or malformed");
  }
  const length = Number(rawLength);
  if (!Number.isSafeInteger(length)) throw new FixtureRunnerError("HTTP response Content-Length is ambiguous or malformed");
  return length;
}

function decodeChunked(encoded: Buffer, ended: boolean): Buffer | undefined {
  const chunks: Buffer[] = []; let offset = 0;
  while (true) {
    const lineEnd = encoded.indexOf("\r\n", offset);
    if (lineEnd < 0) {
      if (!ended) return undefined;
      throw new FixtureRunnerError("chunked response is truncated");
    }
    const sizeText = encoded.subarray(offset, lineEnd).toString("ascii").split(";", 1)[0]!;
    if (!/^[0-9a-fA-F]+$/u.test(sizeText)) throw new FixtureRunnerError("chunked response size is malformed");
    const size = Number.parseInt(sizeText, 16); offset = lineEnd + 2;
    if (size === 0) {
      const end = encoded.subarray(offset, offset + 2).toString("ascii") === "\r\n"
        ? offset + 2 : encoded.indexOf("\r\n\r\n", offset) + 4;
      if (end < 4 || end > encoded.byteLength) {
        if (!ended) return undefined;
        throw new FixtureRunnerError("chunked response is truncated");
      }
      if (end !== encoded.byteLength) throw new FixtureRunnerError("chunked response has trailing bytes");
      return Buffer.concat(chunks);
    }
    if (!Number.isSafeInteger(size) || offset + size + 2 > encoded.byteLength) {
      if (!ended) return undefined;
      throw new FixtureRunnerError("chunked response is truncated");
    }
    chunks.push(encoded.subarray(offset, offset + size)); offset += size;
    if (encoded.subarray(offset, offset + 2).toString("ascii") !== "\r\n") throw new FixtureRunnerError("chunk terminator is malformed");
    offset += 2;
  }
}
