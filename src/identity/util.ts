// Shared identity-port helpers. Currently: the raw `^https://` trust-root check
// (addendum 11, contracts §6.5) hoisted here so every identity port (Entra,
// Cloudflare Access, the §17.6 generic/Google ports) enforces the SAME logic —
// the "sweep for sibling instances" rule. The check runs BEFORE `new URL()`
// because Node's lenient parser normalizes `https:/host` into a valid-looking
// URL, which would let an http JWKS/issuer slip through → a MITM substitutes
// signing keys → total auth bypass.

/** Throw unless `value` starts with the literal `https://`. The label names the
 *  offending field in the thrown message (errors may be logged; the value
 *  itself is never echoed). */
export function assertHttpsRaw(value: string, label: string): void {
  if (!value.startsWith("https://")) {
    throw new Error(`${label} must be an https:// URL (http trust roots allow key substitution)`);
  }
}

/** Stream-read a fetched response body, counting bytes, and reject the moment
 *  the cap is exceeded — WITHOUT materializing the remainder (§17.6 body caps;
 *  the caller owns the taxonomy via `failureMessage`, always a fetch/protocol
 *  failure class, never an identity decision). Chunks are concatenated as
 *  BYTES before the single utf8 decode, so a multi-byte character split across
 *  a chunk boundary still decodes correctly. A null body (204-style empty
 *  response) is an empty string — parsing/validation downstream decides. */
export async function readCappedText(
  body: ReadableStream<Uint8Array> | null,
  maxBytes: number,
  failureMessage: string,
): Promise<string> {
  if (body === null) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxBytes) {
      // Cancel, do NOT drain: the point of the cap is that the remainder is never
      // downloaded or buffered. cancel() itself can fail on an already-dead socket.
      await reader.cancel().catch(() => {});
      throw new Error(failureMessage);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}
