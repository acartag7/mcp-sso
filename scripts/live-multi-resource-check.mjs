#!/usr/bin/env node
// Unauthenticated half of the two-resource live gate
// (docs/live-verification.md checklist E), run against a DEPLOYED origin.
//
//   node scripts/live-multi-resource-check.mjs https://<your-host>
//
// Checks everything that does not need a browser login: per-resource PRM
// discovery, challenge correctness, and metadata isolation. It CANNOT prove the
// cross-resource token rejection — that needs a real grant from a real client,
// which is steps 2-5 of the checklist and stays manual.
//
// Exit code 0 = every automated check passed. Non-zero = a real failure; the
// output names which check and what it saw.

const origin = process.argv[2]?.replace(/\/+$/, "");
if (!origin) {
  console.error("usage: node scripts/live-multi-resource-check.mjs https://<your-host>");
  process.exit(2);
}

const PATHS = ["/grafana/mcp", "/memory/mcp"];
const TIMEOUT_MS = 10_000;

let failures = 0;
const ok = (msg) => console.log(`  PASS  ${msg}`);
const bad = (msg, detail) => { failures++; console.log(`  FAIL  ${msg}\n        ${detail}`); };

async function get(url, init) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: ac.signal, redirect: "manual" });
  } finally {
    clearTimeout(timer);
  }
}

console.log(`\nTwo-resource live check against ${origin}\n`);

// 1. Each resource publishes its own PRM document at the path-inserted URL.
console.log("1. Per-resource PRM discovery (RFC 9728 path insertion)");
const docs = new Map();
for (const path of PATHS) {
  const url = `${origin}/.well-known/oauth-protected-resource${path}`;
  try {
    const res = await get(url);
    if (res.status !== 200) { bad(`${url} -> ${res.status}`, "expected 200"); continue; }
    const doc = await res.json();
    docs.set(path, doc);
    if (doc.resource === `${origin}${path}`) ok(`${path} PRM advertises ${doc.resource}`);
    else bad(`${path} PRM resource mismatch`, `got ${JSON.stringify(doc.resource)}`);
  } catch (error) {
    bad(`${url} unreachable`, error instanceof Error ? error.message : String(error));
  }
}

// 2. Neither document mentions the other resource, and scopes do not leak.
console.log("\n2. Metadata isolation");
for (const path of PATHS) {
  const doc = docs.get(path);
  if (!doc) continue;
  const other = PATHS.find((p) => p !== path);
  const blob = JSON.stringify(doc);
  if (blob.includes(`${origin}${other}`)) bad(`${path} PRM mentions ${other}`, blob.slice(0, 200));
  else ok(`${path} PRM does not mention ${other}`);
}

// 3. An unauthenticated call is challenged, and the challenge points at THIS
//    endpoint's PRM. A client that gets the wrong URL here walks to the wrong
//    authorization server and the isolation story collapses at discovery time.
console.log("\n3. Per-endpoint WWW-Authenticate challenge");
for (const path of PATHS) {
  try {
    const res = await get(`${origin}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1 }),
    });
    if (res.status !== 401) { bad(`${path} -> ${res.status}`, "expected 401 without a token"); continue; }
    const challenge = res.headers.get("www-authenticate") ?? "";
    const expected = `${origin}/.well-known/oauth-protected-resource${path}`;
    const other = PATHS.find((p) => p !== path);
    if (!challenge.includes(expected)) bad(`${path} challenge does not name its own PRM`, challenge || "(no header)");
    else if (challenge.includes(other)) bad(`${path} challenge leaks ${other}`, challenge);
    else ok(`${path} challenged with its own PRM URL`);
  } catch (error) {
    bad(`${path} unreachable`, error instanceof Error ? error.message : String(error));
  }
}

// 4. DNS-rebinding protection: a foreign browser Origin is refused outright.
console.log("\n4. Origin gate (DNS-rebinding protection)");
for (const path of PATHS) {
  try {
    const res = await get(`${origin}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        origin: "https://evil.invalid",
      },
      body: JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1 }),
    });
    if (res.status === 403) ok(`${path} refuses a foreign Origin`);
    else bad(`${path} foreign Origin -> ${res.status}`, "expected 403 before the bearer check");
  } catch (error) {
    bad(`${path} unreachable`, error instanceof Error ? error.message : String(error));
  }
}

// 5. The OAuth surface the MCP clients call server-side must NOT be behind the
//    identity proxy. A login redirect here is the whole-hostname Access mistake.
console.log("\n5. OAuth API paths are public (not gated by the identity proxy)");
const apiPaths = ["/.well-known/oauth-authorization-server"];
// Follow the AS metadata to the real JWKS URL rather than assuming one: the
// path is deployment-defined, and a hard-coded guess reports a false failure.
try {
  const meta = await get(`${origin}/.well-known/oauth-authorization-server`);
  if (meta.status === 200) {
    const { jwks_uri: jwksUri } = await meta.json();
    if (typeof jwksUri === "string" && jwksUri.startsWith(origin)) apiPaths.push(jwksUri.slice(origin.length));
  }
} catch { /* the loop below reports the metadata failure itself */ }

for (const p of apiPaths) {
  try {
    const res = await get(`${origin}${p}`);
    if (res.status === 200) ok(`${p} -> 200`);
    else if (res.status >= 300 && res.status < 400) {
      bad(`${p} -> ${res.status} redirect`, `Location: ${res.headers.get("location") ?? "?"} — the Access app is gating an API path; scope it to /oauth/authorize*`);
    } else bad(`${p} -> ${res.status}`, "expected 200");
  } catch (error) {
    bad(`${p} unreachable`, error instanceof Error ? error.message : String(error));
  }
}

console.log(`\n${failures === 0 ? "All automated checks passed." : `${failures} check(s) FAILED.`}`);
console.log(`
Still manual — these need a real client and a real login:
  - complete a grant at ${origin}${PATHS[0]} and call a tool
  - present that SAME token to ${origin}${PATHS[1]} and confirm it is REFUSED
  - refresh at ${PATHS[0]}, and confirm a refresh naming ${PATHS[1]} is refused
Record client + version per row in docs/live-verification.md.
`);
process.exit(failures === 0 ? 0 : 1);
