// The browser half of the identity driver: open a browser, sign a test user
// in on the Microsoft pages, and either capture the Cloudflare Access
// assertion or complete an mcp-sso authorization all the way to the client
// callback. Shared by drive-identity.mjs and probe-client.mjs. Every step
// records a page class in `trace`, never a host, a URL, or a page's text; the
// password is typed only where hostPolicy.mayTypeCredential says so.
import { chromium } from "playwright-core";
import {
  classifyAccessPage, classifyLegPage, classifyMicrosoftPage, extractAssertionCookie, hostPolicy,
} from "./drive-identity-support.mjs";

export const STEP_TIMEOUT_MS = 30_000;
const SETTLE_ROUNDS = 12;
const AUTHORIZE_ROUNDS = 40;

/** The machine's Chrome headless, or the remote browser MCP_SSO_BROWSER_CDP_URL
 *  names. `undefined` when neither can be opened: the caller reports
 *  `browser_unavailable`. */
export async function openBrowser(env = process.env) {
  const cdp = env.MCP_SSO_BROWSER_CDP_URL;
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

export const bodyText = (page) => page.locator("body").innerText({ timeout: 5_000 }).catch(() => "");

/** Complete the Microsoft sign-in pages. Resolves to an outcome only when the
 *  sign-in did not lead away from the login host; `undefined` means it did. */
export async function signInMicrosoft(page, policy, user, password, trace) {
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
    if (kind === "error") return "denied_at_login";
    await page.waitForTimeout(1_000);
  }
  return "timeout";
}

/** Sign in through the Access login page of the leg's authorize route and
 *  capture the assertion cookie, or record the edge's denial. */
export async function cloudflareAssertion({ context, origin, idpName, user, password, trace }) {
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
    if (kind === "denied") return { outcome: "denied_at_access_edge" };
    const assertion = extractAssertionCookie(await context.cookies(origin), origin);
    if (assertion !== undefined) return { outcome: "approved", assertion };
    await page.waitForTimeout(1_000);
  }
  return { outcome: "timeout" };
}

const CONSENT_APPROVE = 'form[action="/oauth/authorize/approve"] button[name="approved"][value="true"]';

/** Drive one mcp-sso authorization from its authorize URL to the client
 *  callback: Access login when the leg is behind it, the Microsoft sign-in,
 *  the consent page, and the redirect back. The callback is a registered
 *  https URL on the leg's own origin that the example does not serve, so the
 *  browser lands on it with the code or the error in the query and the page
 *  URL is the capture. (Playwright does not route redirected requests, so a
 *  route handler on the callback would never see the 302 that carries it.) */
export async function driveAuthorize({ context, origin, authorizeUrl, callback, user, password, idpName, trace, loopbackCallback }) {
  const policy = hostPolicy(origin, { loopbackCallback });
  const page = await context.newPage();
  page.setDefaultTimeout(STEP_TIMEOUT_MS);
  const response = await page.goto(authorizeUrl, { waitUntil: "domcontentloaded" });
  trace.push(`${policy.classify(page.url())}:start:${Number.isInteger(response?.status()) ? response.status() : "none"}`);
  let idpChosen = false;
  let signedIn = false;
  let approved = false;
  for (let round = 0; round < AUTHORIZE_ROUNDS; round++) {
    const url = page.url();
    if (url === callback || url.startsWith(`${callback}?`) || policy.classify(url) === "callback") {
      const params = new URL(url).searchParams;
      const error = params.get("error");
      trace.push(error === null ? "callback:code" : "callback:error");
      if (error !== null) return { outcome: "denied_at_gateway", error, errorDescription: params.get("error_description") ?? "", state: params.get("state") ?? "" };
      return { outcome: "approved", redirectUrl: url };
    }
    if (!policy.allowed(url)) return { outcome: "unexpected_host" };
    const cls = policy.classify(url);
    if (cls === "access") {
      const kind = classifyAccessPage({ url, text: await bodyText(page) });
      trace.push(`access:${kind}`);
      if (kind === "denied") return { outcome: "denied_at_access_edge" };
      if (!idpChosen) {
        await page.getByText(idpName, { exact: false }).first().click();
        idpChosen = true;
        trace.push("access:idp-chosen");
        const signIn = await signInMicrosoft(page, policy, user, password, trace);
        signedIn = true;
        if (signIn !== undefined) return { outcome: signIn };
        continue;
      }
    } else if (cls === "microsoft" && !signedIn) {
      const signIn = await signInMicrosoft(page, policy, user, password, trace);
      signedIn = true;
      if (signIn !== undefined) return { outcome: signIn };
      continue;
    } else if (cls === "leg" && !approved) {
      const approve = page.locator(CONSENT_APPROVE);
      const kind = classifyLegPage({ hasConsentForm: await approve.count() > 0, text: await bodyText(page) });
      if (kind === "consent") {
        await approve.first().click();
        approved = true;
        trace.push("leg:consent:approved");
        continue;
      }
      if (kind !== "other") {
        // The gateway answered the authorize request with a direct error page
        // (an untrusted redirect_uri is never used as an error channel).
        trace.push(`leg:${kind}`);
        return { outcome: "denied_at_gateway", error: kind.split(":")[0], errorDescription: "", state: "" };
      }
    }
    await page.waitForTimeout(500);
  }
  return { outcome: "timeout" };
}
