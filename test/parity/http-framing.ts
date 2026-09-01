import { FixtureRunnerError } from "./error.ts";
import type { ObservedMessage } from "./types.ts";

const CR = 13;
const LF = 10;
const TOKEN = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
const OWS = "[ \\t]*";
const FIELD_TEXT = "[\\t \\x21-\\x7e\\x80-\\xff]";
const QUOTED = '"(?:[\\t \\x21\\x23-\\x5b\\x5d-\\x7e\\x80-\\xff]|\\\\[\\t \\x21-\\x7e\\x80-\\xff])*"';
const CHUNK_EXT = `(?:${OWS};${OWS}${TOKEN}(?:${OWS}=${OWS}(?:${TOKEN}|${QUOTED}))?)*`;
const STATUS_LINE = new RegExp(`^HTTP/1\\.[01] ([0-9]{3})(?: ${FIELD_TEXT}*)?$`, "u");
const FIELD_NAME = new RegExp(`^${TOKEN}$`, "u");
const FIELD_VALUE = new RegExp(`^${FIELD_TEXT}*$`, "u");
const CHUNK_LINE = new RegExp(`^([0-9A-Fa-f]+)${CHUNK_EXT}$`, "u");
const CONTENT_LENGTH = /^(?:0|[1-9][0-9]*)$/u;
const FORBIDDEN_TRAILERS = new Set(["content-length", "host", "trailer", "transfer-encoding"]);

type Headers = Record<string, string | string[]>;
type Framing = { kind: "none" } | { kind: "length"; length: number } | { kind: "chunked" };

/** Parse the bytes received so far into the observed response.
 *  Returns `undefined` only when framing proves more bytes are required and the
 *  socket has not ended; a complete message is returned whether or not it has.
 *  The caller owns the size and time budgets: this function is pure over the
 *  bytes it is handed and never waits for more. */
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
  if (status === 204 && framing.kind !== "none") {
    throw new FixtureRunnerError("HTTP 204 response declared Content-Length or Transfer-Encoding");
  }
  if (method === "HEAD" || status === 204 || status === 304) {
    if (encoded.byteLength > 0) throw new FixtureRunnerError("bodyless HTTP response contained bytes");
    return { status, headers, body: Buffer.alloc(0) };
  }
  const body = decodeBody(framing, encoded, ended);
  if (body === undefined) return undefined;
  if (status === 205 && body.byteLength > 0) {
    throw new FixtureRunnerError("HTTP 205 response contained a body");
  }
  return { status, headers, body };
}

/** A 205 frames like any other response and only then has to be empty, so a
 *  declared body is decoded before the status rule judges it. */
function decodeBody(framing: Framing, encoded: Buffer, ended: boolean): Buffer | undefined {
  if (framing.kind === "chunked") return decodeChunked(encoded, ended);
  if (framing.kind === "length") {
    if (encoded.byteLength < framing.length && !ended) return undefined;
    if (encoded.byteLength !== framing.length) {
      throw new FixtureRunnerError("HTTP response Content-Length mismatch");
    }
    return encoded;
  }
  return ended ? encoded : undefined;
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
  return [name.toLowerCase(), fieldValue(line.slice(colon + 1))];
}

/** Field values carry optional surrounding whitespace, which RFC 9110 defines as
 *  SP and HTAB only. What survives the trim must be field content: HTAB, SP,
 *  VCHAR, or obs-text. A NUL, a bare CR or LF, VT, FF, or DEL is not a value. */
function fieldValue(raw: string): string {
  const value = raw.replace(/^[ \t]+/u, "").replace(/[ \t]+$/u, "");
  if (!FIELD_VALUE.test(value)) {
    throw new FixtureRunnerError("HTTP response header value contains a disallowed byte");
  }
  return value;
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
  const digits = CHUNK_LINE.exec(line)?.[1];
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
    if (line.length === 0) continue;
    const [name] = headerLine(line);
    if (FORBIDDEN_TRAILERS.has(name)) {
      throw new FixtureRunnerError("HTTP response trailer field is not allowed");
    }
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
