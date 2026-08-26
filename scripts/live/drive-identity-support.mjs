// Pure support for scripts/live/drive-identity.mjs: argument parsing, the
// navigation host policy, page classification, and cookie extraction. Nothing
// here touches a browser, so every decision the driver makes is testable.

export const TASKS = Object.freeze(["cloudflare-assertion"]);
/** The driver's whole vocabulary. A denial names WHERE it happened: at the
 *  Access edge (the policy refused a signed-in account, which is what the
 *  edge-denial row proves) or at the Microsoft login (a wrong password, a
 *  disabled fixture), because a broken test account must never read as proof
 *  that Cloudflare Access stopped it. */
export const OUTCOMES = Object.freeze([
  "approved", "denied_at_access_edge", "denied_at_login", "denied_at_gateway", "blocked_mfa_interstitial", "browser_unavailable",
  "unexpected_host", "timeout", "driver_error",
]);
/** Outcomes the driver exits 0 for: it did what it was asked and observed a definite answer. */
export const DEFINITE_OUTCOMES = Object.freeze(["approved", "denied_at_access_edge", "denied_at_login", "denied_at_gateway"]);
/** The one host a password may be typed on. Anything else is refused before a keystroke. */
export const CREDENTIAL_HOST = "login.microsoftonline.com";
const ROLE = /^[a-z]+$/;

export function parseDriverArgs(argv) {
  const options = { task: undefined, out: undefined, user: "member" };
  const [task, ...rest] = argv;
  if (!TASKS.includes(task)) throw new Error(`usage: drive-identity.mjs <${TASKS.join("|")}> --out <file> [--user <role>]`);
  options.task = task;
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === "--out" && rest[i + 1]) options.out = rest[++i];
    else if (rest[i] === "--user" && rest[i + 1] && ROLE.test(rest[i + 1])) options.user = rest[++i];
    else throw new Error("unknown or malformed driver argument");
  }
  if (options.out === undefined) throw new Error("--out is required");
  return options;
}

export const hostOf = (url) => {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
};

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Which hosts the main frame may land on for a leg. The leg's own origin,
 *  Cloudflare Access, and the Microsoft login host; nothing else, unless a
 *  `loopbackCallback` is named: the plain-http loopback URL a CLI client
 *  listens on, which the browser may reach only as the final redirect. */
export function hostPolicy(legOrigin, { loopbackCallback } = {}) {
  const legHost = hostOf(legOrigin);
  if (legHost === "") throw new Error("leg origin is not a URL");
  let loopback;
  if (loopbackCallback !== undefined) {
    const parsed = new URL(loopbackCallback);
    if (parsed.protocol !== "http:" || !LOOPBACK_HOSTS.has(parsed.hostname)) throw new Error("a loopback callback must be plain http on a loopback host");
    loopback = parsed.origin;
  }
  const secure = (url) => {
    try {
      return new URL(url).protocol === "https:";
    } catch {
      return false;
    }
  };
  return Object.freeze({
    legHost,
    /** Which class of page a URL is, for the trace; never the host itself. */
    classify(url) {
      const host = hostOf(url);
      if (url === "about:blank") return "blank";
      if (loopback !== undefined && url.startsWith(`${loopback}/`)) return "callback";
      if (!secure(url)) return "other";
      if (host === legHost) return "leg";
      if (host === CREDENTIAL_HOST) return "microsoft";
      if (host.endsWith(".cloudflareaccess.com")) return "access";
      return "other";
    },
    allowed(url) {
      return this.classify(url) !== "other";
    },
    mayTypeCredential(url) {
      return secure(url) && hostOf(url) === CREDENTIAL_HOST;
    },
  });
}

/** What a page on the Microsoft login host is asking for. Markers are the
 *  stable texts of those pages; an AADSTS code is a provider error. */
export function classifyMicrosoftPage({ url, text }) {
  if (hostOf(url) !== CREDENTIAL_HOST) return "elsewhere";
  const body = typeof text === "string" ? text : "";
  if (/AADSTS\d{5,}/.test(body)) return "error";
  if (/Stay signed in\?/i.test(body)) return "kmsi";
  if (/More information required|Action Required|Help us protect your account|Set up your account to keep it secure/i.test(body)) {
    return "mfa_interstitial";
  }
  if (/account or password is incorrect|That Microsoft account doesn't exist|We couldn't find an account/i.test(body)) return "error";
  if (/Enter password/i.test(body)) return "password";
  if (/Sign in/i.test(body)) return "login";
  return "other";
}

/** What a page on Cloudflare Access is showing. */
export function classifyAccessPage({ url, text }) {
  if (!hostOf(url).endsWith(".cloudflareaccess.com")) return "elsewhere";
  const body = typeof text === "string" ? text : "";
  if (/does not have access|not allowed|Access denied|forbidden|is not permitted/i.test(body)) return "denied";
  return "login";
}

const OAUTH_ERROR_CODES = /\b(invalid_request|invalid_client|invalid_redirect_uri|unauthorized_client|access_denied|unsupported_response_type|invalid_scope|server_error|temporarily_unavailable|invalid_target)\b/;

/** What a page on the leg's own origin is: the consent form, a direct OAuth
 *  error the gateway rendered (named by its fixed error code, never by its
 *  description), or something else. */
export function classifyLegPage({ hasConsentForm, text }) {
  if (hasConsentForm === true) return "consent";
  const body = typeof text === "string" ? text : "";
  const code = body.match(OAUTH_ERROR_CODES);
  if (code === null) return "other";
  const cause = /too large/i.test(body) ? ":too_large" : /duplicate request parameters/i.test(body) ? ":duplicate" : /is required/i.test(body) ? ":required" : "";
  return code[1] + cause;
}

/** The Access assertion for the leg, from the browser's cookie jar. */
export function extractAssertionCookie(cookies, legOrigin) {
  const legHost = hostOf(legOrigin);
  const hit = (Array.isArray(cookies) ? cookies : []).find((cookie) => cookie?.name === "CF_Authorization"
    && typeof cookie.domain === "string" && (cookie.domain.replace(/^\./, "") === legHost || legHost.endsWith(`.${cookie.domain.replace(/^\./, "")}`)));
  const value = hit?.value;
  return typeof value === "string" && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value) ? value : undefined;
}
