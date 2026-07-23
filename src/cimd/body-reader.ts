import { bindDataMethod, snapshotOwnDataRecord } from "../own-property.ts";
import { CimdError } from "./errors.ts";

export async function readCimdBody(body: unknown, maxBytes: number): Promise<string> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of bodyChunks(body)) {
    if (!(chunk instanceof Uint8Array)) throw new CimdError("fetch_failed");
    total += chunk.byteLength;
    if (total > maxBytes) throw new CimdError("size_exceeded");
    chunks.push(chunk);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new CimdError("document_invalid"); }
}

async function* bodyChunks(body: unknown): AsyncGenerator<unknown> {
  const iteratorFactory = bindDataMethod<() => unknown>(body, Symbol.asyncIterator);
  if (iteratorFactory !== undefined) {
    let iterator: unknown;
    try { iterator = iteratorFactory(); } catch { throw new CimdError("fetch_failed"); }
    yield* readIterator(iterator);
    return;
  }

  const getReader = bindDataMethod<() => unknown>(body, "getReader");
  if (getReader === undefined) throw new CimdError("fetch_failed");
  let reader: unknown;
  try { reader = getReader(); } catch { throw new CimdError("fetch_failed"); }
  yield* readIterator(reader, true);
}

async function* readIterator(iterator: unknown, requireRelease = false): AsyncGenerator<unknown> {
  const next = bindDataMethod<() => Promise<unknown>>(iterator, requireRelease ? "read" : "next");
  const close = bindDataMethod<() => unknown>(iterator, requireRelease ? "releaseLock" : "return");
  if (next === undefined || (requireRelease && close === undefined)) {
    throw new CimdError("fetch_failed");
  }
  let completed = false;
  try {
    while (true) {
      const item = snapshotOwnDataRecord(await next());
      if (item === null || (item.done !== true && item.done !== false)) {
        throw new CimdError("fetch_failed");
      }
      if (item.done) { completed = true; return; }
      yield item.value;
    }
  } finally {
    // AsyncIterator.return is an early-exit hook, not a natural-completion hook.
    // Stream readers always release their lock. Cleanup must never replace the
    // load-bearing timeout/size/body error that caused iteration to stop.
    if (close !== undefined && (requireRelease || !completed)) {
      try { await close(); } catch { /* preserve the primary read/limit outcome */ }
    }
  }
}
