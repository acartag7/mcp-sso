// A real OAuth client against a SERVED leg on its public hostname: dynamic
// registration, an authorization the headless driver completes through the
// real provider pages as a provisioned test user, the code exchange, an
// official MCP SDK tool call, and one refresh; or, for a deny fixture, the
// exact access_denied the client sees and the exact reason the audit records.
// Runs as a run.sh entry (kind client): it receives the public origin, the
// probe callback, the test users and their password, the Cloudflare login
// method, and the served leg's audit file. No application credential.
//
//   run.sh scripts/live/probe-client.mjs entra --user nogroups --expect entra_no_groups
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { pkceChallenge } from "../../src/crypto.ts";
import { driveAuthorize, openBrowser } from "./drive-identity-browser.mjs";
import { ARMABLE_OUTCOMES, ProbeRefusal } from "./drive-identity-support.mjs";
import { assertProbeClientRedirect } from "./probe-redirect-support.mjs";
import { form, sdkPing } from "./probe-e2e-support.mjs";
import {
  approvedFlowOrder, auditLeaks, deniedFlowHolds, eventsSince, expectedDescription, inOrder, parseClientArgs,
} from "./probe-client-support.mjs";

const out = [];
const ok = (label, condition, detail = "") => {
  out.push(`${condition ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  return condition;
};
const requireEnv = (name) => {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} is required`);
  return value;
};
const readAudit = () => {
  try {
    return readFileSync(auditFile, "utf8");
  } catch {
    return "";
  }
};
const countLines = (text) => text.split("\n").filter((line) => line.trim() !== "").length;

const options = parseClientArgs(process.argv.slice(2));
const leg = requireEnv("MCP_SSO_LEG");
const origin = requireEnv("OAUTH_ISSUER");
const callback = assertProbeClientRedirect(requireEnv("PROBE_APP_CALLBACK"));
const auditFile = requireEnv("MCP_SSO_AUDIT_FILE");
const users = JSON.parse(requireEnv("IDP_TEST_USERS_JSON"));
const password = requireEnv("IDP_TEST_USER_PASSWORD");
const user = users[options.user];
if (typeof user !== "string" || user.length === 0) throw new Error("the requested test user is not provisioned");
const idpName = leg === "cloudflare_access" ? requireEnv("CF_ACCESS_IDP_NAME") : undefined;

let failures = 0;
let opened;
let refusal;
const trace = [];
const secrets = [];
// No browser is a runner-level refusal, reported the way run.sh reports one, so
// the rehearsal records BLOCKED browser_unavailable and not a failed check.
opened = await openBrowser();
if (opened === undefined) {
  process.stderr.write("probe-client: browser is unavailable; install Chrome or set MCP_SSO_BROWSER_CDP_URL\n");
  process.exitCode = 1;
} else try {
  const metadata = await fetch(`${origin}/.well-known/oauth-protected-resource`, { signal: AbortSignal.timeout(15_000) });
  const metadataJson = metadata.ok ? await metadata.json() : {};
  if (!ok("protected resource metadata is served on the public origin",
    metadata.status === 200 && Array.isArray(metadataJson.authorization_servers) && metadataJson.authorization_servers.includes(origin),
    `HTTP ${metadata.status}`)) failures++;
  const before = countLines(readAudit());

  const registration = await fetch(`${origin}/oauth/register`, {
    method: "POST", headers: { "content-type": "application/json" }, signal: AbortSignal.timeout(15_000),
    body: JSON.stringify({ redirect_uris: [callback], application_type: "web" }),
  });
  const registrationJson = registration.status === 201 ? await registration.json() : {};
  const clientId = typeof registrationJson.client_id === "string" ? registrationJson.client_id : undefined;
  if (!ok("dynamic registration issues a client on the public origin", registration.status === 201 && clientId !== undefined,
    `HTTP ${registration.status}`)) failures++;

  const verifier = randomBytes(32).toString("base64url");
  const state = randomBytes(16).toString("base64url");
  const query = new URLSearchParams({
    response_type: "code", client_id: clientId ?? "registration-failed", redirect_uri: callback, state,
    code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read",
  });
  const authorizeUrl = `${origin}/oauth/authorize?${query}`;

  const result = await driveAuthorize({ context: opened.context, origin, authorizeUrl, callback, user, password, idpName, trace });
  // An outcome the operator must arm (the tenant asking this test user to
  // register MFA) is a runner-level refusal, not a failed check: the flow was
  // never attempted, so the rehearsal records BLOCKED with that reason instead
  // of reporting the product as broken. The same shape as no browser above.
  if (ARMABLE_OUTCOMES.has(result.outcome)) throw new ProbeRefusal(result.outcome);
  out.push(`NOTE  trace ${trace.join(" > ")}`);

  if (options.expect === "approved") {
    const redirect = result.outcome === "approved" ? new URL(result.redirectUrl) : undefined;
    const code = redirect?.searchParams.get("code") ?? undefined;
    if (code) secrets.push(code);
    if (!ok("provider sign-in reaches consent and the callback carries a code bound to the state",
      redirect !== undefined && typeof code === "string" && redirect.searchParams.get("state") === state
        && redirect.searchParams.get("iss") === origin, result.outcome)) failures++;
    const token = await fetch(`${origin}/oauth/token`, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, signal: AbortSignal.timeout(15_000),
      body: form({ grant_type: "authorization_code", code: code ?? "missing", redirect_uri: callback, client_id: clientId ?? "", code_verifier: verifier }),
    });
    const tokens = token.status === 200 ? await token.json() : {};
    if (tokens.access_token) secrets.push(tokens.access_token);
    if (tokens.refresh_token) secrets.push(tokens.refresh_token);
    if (!ok("the authorization code exchanges for an access token and a refresh token",
      token.status === 200 && typeof tokens.access_token === "string" && typeof tokens.refresh_token === "string", `HTTP ${token.status}`)) failures++;
    const pong = await sdkPing(origin, tokens.access_token ?? "");
    if (!ok("the official MCP SDK client completes a tool call on the public origin", typeof pong === "string" && pong.length > 0)) failures++;
    const refresh = await fetch(`${origin}/oauth/token`, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, signal: AbortSignal.timeout(15_000),
      body: form({ grant_type: "refresh_token", refresh_token: tokens.refresh_token ?? "missing", client_id: clientId ?? "" }),
    });
    const rotated = refresh.status === 200 ? await refresh.json() : {};
    if (rotated.access_token) secrets.push(rotated.access_token);
    if (rotated.refresh_token) secrets.push(rotated.refresh_token);
    if (!ok("the refresh token rotates", refresh.status === 200 && typeof rotated.refresh_token === "string"
      && rotated.refresh_token !== tokens.refresh_token, `HTTP ${refresh.status}`)) failures++;
    const audit = readAudit();
    const events = eventsSince(audit, before);
    if (!ok("the served leg's audit records the whole flow in order", inOrder(events, approvedFlowOrder(leg)), `${events.length} events added`)) failures++;
    // Five values are searched for (the code, two access tokens, two refresh
    // tokens); fewer means the flow did not mint them and the check fails.
    if (!ok("the audit holds no code or token from this flow", secrets.length === 5 && !auditLeaks(audit, secrets), `${secrets.length} values`)) failures++;
  } else {
    if (!ok("the client receives access_denied with the documented description for this fixture",
      result.outcome === "denied_at_gateway" && result.error === "access_denied" && result.state === state
        && result.errorDescription === expectedDescription(options.expect), result.outcome)) failures++;
    const events = eventsSince(readAudit(), before);
    if (!ok("the served leg's audit records the exact rejection reason and mints nothing", deniedFlowHolds(events, options.expect),
      `${events.length} events added`)) failures++;
  }
} catch (error) {
  failures++;
  if (error instanceof ProbeRefusal) refusal = error.outcome;
  else out.push("FAIL  probe aborted before completion");
} finally {
  try { await opened?.browser.close(); } catch { /* nothing left to release */ }
  if (refusal !== undefined) {
    process.stderr.write(`probe-client: ${refusal}\n`);
  } else {
    console.log(out.join("\n"));
    console.log(`\n${out.filter((line) => line.startsWith("PASS")).length}/${out.filter((line) => !line.startsWith("NOTE")).length} checks passed`);
  }
  process.exitCode = failures > 0 ? 1 : 0;
}
