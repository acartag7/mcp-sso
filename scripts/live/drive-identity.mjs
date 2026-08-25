// The headless identity driver. Signs a provisioned test user in through the
// real provider pages so a live leg can run with no one at a browser. Runs as a
// run.sh entry, so its inputs arrive through the runner's allowlisted
// environment: OAUTH_ISSUER (the leg origin), IDP_TEST_USERS_JSON and
// IDP_TEST_USER_PASSWORD (the Entra stack's test users), and for the Cloudflare
// leg CF_ACCESS_IDP_NAME (the login method to choose).
//
//   run.sh scripts/live/drive-identity.mjs cloudflare_access cloudflare-assertion --out <file> [--user member]
//
// Writes {"task","user","outcome","trace"[, "assertion"]} to --out at mode
// 0600 and prints exactly one `outcome: <name>` line. The trace is the class
// of page seen at each step (leg, access, microsoft, blank) and what the
// driver made of it; never a host, a URL, or a page's text. The password is
// typed only on login.microsoftonline.com; any other host is
// `unexpected_host` before a keystroke.
import { closeSync, constants, openSync, writeSync } from "node:fs";
import { cloudflareAssertion, openBrowser } from "./drive-identity-browser.mjs";
import { parseDriverArgs } from "./drive-identity-support.mjs";

function requireEnv(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

function writePrivate(path, text) {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    writeSync(fd, text);
  } finally {
    closeSync(fd);
  }
}

const options = parseDriverArgs(process.argv.slice(2));
const origin = requireEnv("OAUTH_ISSUER");
const users = JSON.parse(requireEnv("IDP_TEST_USERS_JSON"));
const password = requireEnv("IDP_TEST_USER_PASSWORD");
const user = users[options.user];
if (typeof user !== "string" || user.length === 0) throw new Error("the requested test user is not provisioned");
const trace = [];
let result = { outcome: "browser_unavailable" };
let opened;
try {
  opened = await openBrowser();
  if (opened !== undefined) {
    result = await cloudflareAssertion({ context: opened.context, origin, idpName: requireEnv("CF_ACCESS_IDP_NAME"), user, password, trace });
  }
} catch (error) {
  const timedOut = /Timeout/i.test(error?.name ?? "") || /timeout/i.test(error?.message ?? "");
  result = { outcome: timedOut ? "timeout" : "unexpected_host" };
  trace.push(timedOut ? "step:timeout" : "step:error");
} finally {
  try { await opened?.browser.close(); } catch { /* nothing left to release */ }
}
writePrivate(options.out, `${JSON.stringify({ task: options.task, user: options.user, ...result, trace })}\n`);
process.stdout.write(`outcome: ${result.outcome}\n`);
process.exitCode = result.outcome === "approved" || result.outcome === "denied_at_provider" ? 0 : 2;
