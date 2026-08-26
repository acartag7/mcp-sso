// The one seam of the identity driver that opens a browser. Everything the
// driver then does to a page lives in drive-identity-pages.mjs, which imports
// no browser, so the tests exercise the page logic without Playwright and this
// file stays the only place `playwright-core` is loaded.
import { chromium } from "playwright-core";

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

// The page-driving functions live in drive-identity-pages.mjs, which imports no
// browser; they are re-exported here so every caller has one import.
export {
  bodyText, clearSessionCookies, cloudflareAssertion, driveAuthorize, signInMicrosoft, STEP_TIMEOUT_MS,
} from "./drive-identity-pages.mjs";
