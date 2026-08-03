import assert from "node:assert/strict";
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { pkceChallenge } from "../../src/crypto.ts";

export interface GeneratedServer {
  child: ChildProcess;
  origin: string;
  stderr(): string;
  stop(): Promise<void>;
}

export function run(command: string, args: string[], cwd: string, env: NodeJS.ProcessEnv = process.env): Promise<{ code: number | null; output: string }> {
  return new Promise((resolve) => {
    execFile(command, args, { cwd, env, timeout: 120_000, maxBuffer: 20 * 1024 * 1024 },
      (error, stdout, stderr) => resolve({ code: error ? 1 : 0, output: `${stdout}${stderr}` }));
  });
}

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer(); server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") { reject(new Error("could not allocate port")); return; }
      server.close(() => resolve(address.port));
    });
  });
}

function waitFor(child: ChildProcess, stderr: () => string, pattern: RegExp, timeoutMs = 15_000): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setInterval(() => {
      if (pattern.test(stderr())) { clearInterval(timer); clearTimeout(deadline); resolve(); }
      else if (child.exitCode !== null || child.signalCode !== null) { clearInterval(timer); clearTimeout(deadline); reject(new Error(`server exited before ${pattern}:\n${stderr()}`)); }
    }, 25);
    const deadline = setTimeout(() => { clearInterval(timer); reject(new Error(`timed out waiting for ${pattern}:\n${stderr()}`)); }, timeoutMs);
  });
}

export async function startGenerated(project: string, stateDir: string, port: number): Promise<GeneratedServer> {
  let stderr = "";
  const child = spawn(process.execPath, ["server.ts"], { cwd: project,
    env: { ...process.env, MCP_SSO_DIR: stateDir, PORT: String(port), HOST: "127.0.0.1" }, stdio: ["ignore", "pipe", "pipe"] });
  child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
  await waitFor(child, () => stderr, new RegExp(`mcp-sso listening on 127\\.0\\.0\\.1:${port}`));
  return { child, origin: `http://127.0.0.1:${port}`, stderr: () => stderr, async stop() {
    if (child.exitCode !== null || child.signalCode !== null) return;
    child.kill("SIGTERM");
    await Promise.race([
      new Promise<void>((resolve) => child.once("close", () => resolve())),
      new Promise<void>((resolve) => setTimeout(() => { if (child.exitCode === null) child.kill("SIGKILL"); resolve(); }, 5_000)),
    ]);
  } };
}

export async function fetchBounded(url: string, init: RequestInit = {}): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(10_000) });
}

function hidden(html: string, name: string): string {
  const value = new RegExp(`name="${name}" value="([^"]+)"`).exec(html)?.[1];
  assert.ok(value, `missing hidden field ${name}`); return value;
}

function newestPairingCode(stderr: string): string {
  const matches = [...stderr.matchAll(/Console pairing code: ([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})/g)];
  const code = matches.at(-1)?.[1]; assert.ok(code, "installed generated server printed a pairing code"); return code;
}

async function prepareConsent(server: GeneratedServer, clientId: string, verifier: string): Promise<{
  consentToken: string; pairingCode: string; redirect: string;
}> {
  const redirect = "http://localhost:4321/callback";
  const query = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirect,
    code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read", state: `s-${Date.now()}` });
  const pairingPage = await fetchBounded(`${server.origin}/oauth/authorize?${query}`);
  assert.equal(pairingPage.status, 200);
  const pairingNonce = hidden(await pairingPage.text(), "pairing_nonce");
  const pairingCode = newestPairingCode(server.stderr());
  const consent = await fetchBounded(`${server.origin}/oauth/authorize`, { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ...Object.fromEntries(query), pairing_code: pairingCode, pairing_nonce: pairingNonce }).toString() });
  assert.equal(consent.status, 200);
  const consentToken = hidden(await consent.text(), "consent_token");
  return { consentToken, pairingCode, redirect };
}

export async function denyAuthorization(server: GeneratedServer, clientId: string, verifier: string): Promise<string> {
  const { consentToken } = await prepareConsent(server, clientId, verifier);
  const deny = await fetchBounded(`${server.origin}/oauth/authorize/approve`, { method: "POST", redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded", origin: server.origin },
    body: new URLSearchParams({ consent_token: consentToken, approved: "false" }).toString() });
  assert.equal(deny.status, 302);
  assert.equal(new URL(deny.headers.get("location") ?? "").searchParams.get("error"), "access_denied");
  return consentToken;
}

export async function authorize(server: GeneratedServer, clientId: string, verifier: string): Promise<{
  accessToken: string; refreshToken: string; authCode: string; pairingCode: string; consentToken: string;
}> {
  const { consentToken, pairingCode, redirect } = await prepareConsent(server, clientId, verifier);
  const approve = await fetchBounded(`${server.origin}/oauth/authorize/approve`, { method: "POST", redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded", origin: server.origin },
    body: new URLSearchParams({ consent_token: consentToken, approved: "true" }).toString() });
  assert.equal(approve.status, 302);
  const authCode = new URL(approve.headers.get("location") ?? "").searchParams.get("code"); assert.ok(authCode);
  const token = await postForm(server.origin, "/oauth/token", { grant_type: "authorization_code", code: authCode,
    redirect_uri: redirect, client_id: clientId, code_verifier: verifier });
  assert.equal(token.status, 200);
  const body = await token.json() as { access_token: string; refresh_token: string };
  assert.ok(body.access_token); assert.ok(body.refresh_token);
  return { accessToken: body.access_token, refreshToken: body.refresh_token, authCode, pairingCode, consentToken };
}

export function postForm(origin: string, path: string, body: Record<string, string>): Promise<Response> {
  return fetchBounded(`${origin}${path}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString() });
}

export async function sdkPing(origin: string, accessToken: string): Promise<string> {
  const transport = new StreamableHTTPClientTransport(new URL(`${origin}/mcp`), { requestInit: { headers: { authorization: `Bearer ${accessToken}` } } });
  const client = new Client({ name: "release-packed", version: "1" }, { capabilities: {} });
  try {
    await client.connect(transport);
    const result = await client.callTool({ name: "ping", arguments: {} });
    const text = (result.content as Array<{ type: string; text?: string }>).find((part) => part.type === "text")?.text;
    assert.equal(text, "pong: console-operator", "installed generated server returned visible value");
    return text;
  } finally { await client.close(); await transport.close(); }
}
