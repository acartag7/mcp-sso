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
import { chromium } from "playwright-core";
import {
  classifyAccessPage, classifyMicrosoftPage, extractAssertionCookie, hostPolicy, parseDriverArgs,
} from "./drive-identity-support.mjs";

const STEP_TIMEOUT_MS = 30_000;
const SETTLE_ROUNDS = 12;

function requireEnv(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

async function openBrowser() {
  const cdp = process.env.MCP_SSO_BROWSER_CDP_URL;
  try {
    if (typeof cdp === "string" && cdp.length > 0) {
      const browser = await chromium.connectOverCDP(cdp);
      return { browser, context: browser.contexts()[0] ?? await browser.newContext() };
    }
    const browser = await chromium.launch({ channel: "chrome", headless: true });
    return { browser, context: await browser.newContext() };
  } catch {
    return undefined;
  }
}

const bodyText = (page) => page.locator("body").innerText({ timeout: 5_000 }).catch(() => "");

/** Complete the Microsoft sign-in pages. Resolves to an outcome only when the
 *  sign-in did not lead away from the login host; `undefined` means it did. */
async function signInMicrosoft(page, policy, user, password, trace) {
  await page.waitForURL((url) => policy.classify(url.toString()) === "microsoft", { timeout: STEP_TIMEOUT_MS });
  if (!policy.mayTypeCredential(page.url())) return "unexpected_host";
  await page.locator('input[name="loginfmt"]').fill(user, { timeout: STEP_TIMEOUT_MS });
  trace.push("microsoft:login:typed");
  await page.locator('input[type="submit"]').click();
  await page.locator('input[name="passwd"]').waitFor({ state: "visible", timeout: STEP_TIMEOUT_MS });
  if (!policy.mayTypeCredential(page.url())) return "unexpected_host";
  await page.locator('input[name="passwd"]').fill(password);
  trace.push("microsoft:password:typed");
  await page.locator('input[type="submit"]').click();
  for (let round = 0; round < SETTLE_ROUNDS; round++) {
    await page.waitForLoadState("domcontentloaded", { timeout: STEP_TIMEOUT_MS }).catch(() => {});
    const url = page.url();
    if (!policy.allowed(url)) return "unexpected_host";
    const kind = classifyMicrosoftPage({ url, text: await bodyText(page) });
    trace.push(`${policy.classify(url)}:${kind}`);
    if (kind === "elsewhere") return undefined;
    if (kind === "kmsi") { await page.locator("#idBtn_Back").click({ timeout: STEP_TIMEOUT_MS }).catch(() => {}); continue; }
    if (kind === "mfa_interstitial") return "blocked_mfa_interstitial";
    if (kind === "error") return "denied_at_provider";
    await page.waitForTimeout(1_000);
  }
  return "timeout";
}

async function cloudflareAssertion({ context, origin, idpName, user, password, trace }) {
  const policy = hostPolicy(origin);
  const page = await context.newPage();
  page.setDefaultTimeout(STEP_TIMEOUT_MS);
  await page.goto(`${origin}/oauth/authorize`, { waitUntil: "domcontentloaded" });
  trace.push(`${policy.classify(page.url())}:start`);
  if (!policy.allowed(page.url())) return { outcome: "unexpected_host" };
  if (policy.classify(page.url()) === "access") {
    await page.getByText(idpName, { exact: false }).first().click();
    trace.push("access:idp-chosen");
    const signIn = await signInMicrosoft(page, policy, user, password, trace);
    if (signIn !== undefined) return { outcome: signIn };
  }
  for (let round = 0; round < SETTLE_ROUNDS; round++) {
    await page.waitForLoadState("domcontentloaded", { timeout: STEP_TIMEOUT_MS }).catch(() => {});
    const url = page.url();
    if (!policy.allowed(url)) return { outcome: "unexpected_host" };
    const kind = classifyAccessPage({ url, text: await bodyText(page) });
    trace.push(`${policy.classify(url)}:${kind}`);
    if (kind === "denied") return { outcome: "denied_at_provider" };
    const assertion = extractAssertionCookie(await context.cookies(origin), origin);
    if (assertion !== undefined) return { outcome: "approved", assertion };
    await page.waitForTimeout(1_000);
  }
  return { outcome: "timeout" };
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
