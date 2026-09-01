import { FixtureRunnerError } from "./error.ts";
import type { ObservedMessage } from "./types.ts";

const CR = 13;
const LF = 10;
const STATUS_LINE = /^HTTP\/1\.[01] ([0-9]{3})(?: .*)?$/u;
const CONTENT_LENGTH = /^(?:0|[1-9][0-9]*)$/u;
const FIELD_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u;
const CHUNK_SIZE = /^([0-9A-Fa-f]+)(?:;.*)?$/u;

type Headers = Record<string, string | string[]>;
type Framing = { kind: "none" } | { kind: "length"; length: number } | { kind: "chunked" };

/** Parse the bytes received so far into the observed response.
 *  Returns `undefined` only when framing proves more bytes are required and the
 *  socket has not ended; a complete message is returned whether or not it has. */
export function parseHttpResponse(raw: Buffer, method: string, ended: boolean): ObservedMessage | undefined {
  let remaining = raw;
  for (;;) {
    const boundary = remaining.indexOf("\r\n\r\n");
    if (boundary < 0) {
      if (!ended) return undefined;
      throw new FixtureRunnerError("HTTP response has no header boundary");
    }
    const { status, headers } = parseHead(remaining.subarray(0, boundary));
    const encoded = remaining.subarray(boundary + 4);
    if (status >= 100 && status < 200) {
      if (status === 101) throw new FixtureRunnerError("HTTP protocol upgrade responses are unsupported");
      if (framingOf(headers).kind !== "none") {
        throw new FixtureRunnerError("HTTP informational response declared a body");
      }
      remaining = encoded;
      continue;
    }
    return finalMessage(status, headers, encoded, method, ended);
  }
}

function finalMessage(
  status: number, headers: Headers, encoded: Buffer, method: string, ended: boolean,
): ObservedMessage | undefined {
  const framing = framingOf(headers);
  if (method === "HEAD" || status === 204 || status === 205 || status === 304) {
    if (encoded.byteLength > 0) throw new FixtureRunnerError("bodyless HTTP response contained bytes");
    return { status, headers, body: Buffer.alloc(0) };
  }
  if (framing.kind === "chunked") {
    const body = decodeChunked(encoded, ended);
    return body === undefined ? undefined : { status, headers, body };
  }
  if (framing.kind === "length") {
    if (encoded.byteLength < framing.length && !ended) return undefined;
    if (encoded.byteLength !== framing.length) {
      throw new FixtureRunnerError("HTTP response Content-Length mismatch");
    }
    return { status, headers, body: encoded };
  }
  if (!ended) return undefined;
  return { status, headers, body: encoded };
}

/** Every framing decision the parser makes about a header block, taken once and
 *  the same way for informational, bodyless, and ordinary responses. */
function framingOf(headers: Headers): Framing {
  const transfer = headers["transfer-encoding"];
  const declared = headers["content-length"];
  if (transfer !== undefined && declared !== undefined) {
    throw new FixtureRunnerError("HTTP response declared both Transfer-Encoding and Content-Length");
  }
  if (transfer !== undefined) {
    if (typeof transfer !== "string" || transfer.toLowerCase() !== "chunked") {
      throw new FixtureRunnerError("HTTP response Transfer-Encoding is ambiguous or unsupported");
    }
    return { kind: "chunked" };
  }
  if (declared !== undefined) return { kind: "length", length: contentLength(declared) };
  return { kind: "none" };
}

function parseHead(head: Buffer): { status: number; headers: Headers } {
  const lines = head.toString("latin1").split("\r\n");
  const status = STATUS_LINE.exec(lines[0] ?? "")?.[1];
  if (status === undefined) throw new FixtureRunnerError("HTTP response status line is malformed");
  const occurrences = new Map<string, string[]>();
  for (const line of lines.slice(1)) {
    const [name, value] = headerLine(line);
    occurrences.set(name, [...(occurrences.get(name) ?? []), value]);
  }
  const headers = Object.create(null) as Headers;
  for (const [name, values] of occurrences) headers[name] = values.length === 1 ? values[0]! : values;
  return { status: Number(status), headers };
}

function headerLine(line: string): [string, string] {
  if (line.startsWith(" ") || line.startsWith("\t")) {
    throw new FixtureRunnerError("HTTP response header line uses obsolete folding");
  }
  const colon = line.indexOf(":");
  if (colon <= 0) throw new FixtureRunnerError("HTTP response header line is malformed");
  const name = line.slice(0, colon);
  if (!FIELD_NAME.test(name)) throw new FixtureRunnerError("HTTP response header name is not a token");
  return [name.toLowerCase(), trimFieldValue(line.slice(colon + 1))];
}

/** HTTP field values are surrounded by optional whitespace, which RFC 9110 defines
 *  as SP and HTAB only. Any other byte, control or not, is part of the value. */
function trimFieldValue(value: string): string {
  return value.replace(/^[ \t]+/u, "").replace(/[ \t]+$/u, "");
}

function contentLength(value: string | string[]): number {
  if (typeof value !== "string" || !CONTENT_LENGTH.test(value)) {
    throw new FixtureRunnerError("HTTP response Content-Length is ambiguous or malformed");
  }
  const length = Number(value);
  if (!Number.isSafeInteger(length)) {
    throw new FixtureRunnerError("HTTP response Content-Length is ambiguous or malformed");
  }
  return length;
}

function decodeChunked(encoded: Buffer, ended: boolean): Buffer | undefined {
  const chunks: Buffer[] = [];
  let offset = 0;
  for (;;) {
    const lineEnd = encoded.indexOf("\r\n", offset);
    if (lineEnd < 0) return truncated(ended);
    const size = chunkSize(encoded.subarray(offset, lineEnd).toString("latin1"));
    offset = lineEnd + 2;
    if (size === 0) return endOfChunks(encoded, offset, chunks, ended);
    const dataEnd = offset + size;
    if (encoded.byteLength < dataEnd + 2) return truncated(ended);
    if (encoded[dataEnd] !== CR || encoded[dataEnd + 1] !== LF) {
      throw new FixtureRunnerError("HTTP response chunk is not terminated by CRLF");
    }
    chunks.push(encoded.subarray(offset, dataEnd));
    offset = dataEnd + 2;
  }
}

function chunkSize(line: string): number {
  const digits = CHUNK_SIZE.exec(line)?.[1];
  if (digits === undefined) throw new FixtureRunnerError("HTTP response chunk size is malformed");
  const size = Number.parseInt(digits, 16);
  if (!Number.isSafeInteger(size)) throw new FixtureRunnerError("HTTP response chunk size is out of range");
  return size;
}

/** After the zero chunk the message ends with either an empty trailer section or
 *  trailer lines, both closed by CRLF. Searching from the CRLF that ended the zero
 *  chunk line makes the empty section the first match. */
function endOfChunks(encoded: Buffer, offset: number, chunks: Buffer[], ended: boolean): Buffer | undefined {
  const terminator = encoded.indexOf("\r\n\r\n", offset - 2);
  if (terminator < 0) return truncated(ended);
  for (const line of encoded.subarray(offset, terminator + 2).toString("latin1").split("\r\n")) {
    if (line.length > 0) headerLine(line);
  }
  if (terminator + 4 !== encoded.byteLength) {
    throw new FixtureRunnerError("HTTP response contained bytes after the chunked terminator");
  }
  return Buffer.concat(chunks);
}

function truncated(ended: boolean): undefined {
  if (ended) throw new FixtureRunnerError("HTTP response chunked body is truncated");
  return undefined;
}
