// Behavioural coverage for the identity driver's decisions (scripts/live/
// drive-identity-support.mjs) and the runner support it relies on. The browser
// itself is exercised only by a live run; everything it decides on is here.
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  CREDENTIAL_HOST, DEFINITE_OUTCOMES, OUTCOMES, classifyAccessPage, classifyLegPage, classifyMicrosoftPage, extractAssertionCookie, hostPolicy,
  parseDriverArgs,
} from "../scripts/live/drive-identity-support.mjs";
import { clearSessionCookies, signInMicrosoft } from "../scripts/live/drive-identity-pages.mjs";
import { readAssertionFile, testUsersJson } from "../scripts/live/run-support.mjs";

const JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln";

test("BEHAVIOUR driver args: one task, an output file, an optional provisioned role", () => {
  assert.deepEqual(parseDriverArgs(["cloudflare-assertion", "--out", "/tmp/x.json"]), { task: "cloudflare-assertion", out: "/tmp/x.json", user: "member" });
  assert.deepEqual(parseDriverArgs(["cloudflare-assertion", "--user", "nogroups", "--out", "x"]).user, "nogroups");
  for (const argv of [[], ["authorize", "--out", "x"], ["cloudflare-assertion"], ["cloudflare-assertion", "--out"],
    ["cloudflare-assertion", "--out", "x", "--user", "No Groups"], ["cloudflare-assertion", "--out", "x", "--url", "y"]]) {
    assert.throws(() => parseDriverArgs(argv), argv.join(" "));
  }
});

test("BEHAVIOUR host policy: the password may be typed on exactly one host, navigation on three", () => {
  const policy = hostPolicy("https://leg.example");
  assert.equal(policy.legHost, "leg.example");
  for (const url of ["https://leg.example/oauth/authorize", "https://team.cloudflareaccess.com/cdn-cgi/access/login/x",
    `https://${CREDENTIAL_HOST}/common/oauth2/v2.0/authorize`, "about:blank"]) {
    assert.equal(policy.allowed(url), true, url);
  }
  for (const url of ["https://evil.example/", "https://leg.example.evil.example/", "https://cloudflareaccess.com.evil.example/",
    "https://login.microsoftonline.com.evil.example/", "http://leg.example/", "not a url"]) {
    assert.equal(policy.allowed(url), false, url);
  }
  assert.equal(policy.mayTypeCredential(`https://${CREDENTIAL_HOST}/x`), true);
  assert.equal(policy.mayTypeCredential(`http://${CREDENTIAL_HOST}/x`), false, "never over plain http");
  assert.equal(policy.mayTypeCredential("https://leg.example/"), false, "the leg itself never sees the password");
  assert.equal(policy.mayTypeCredential("https://team.cloudflareaccess.com/"), false);
  assert.deepEqual(["https://leg.example/a", "https://x.cloudflareaccess.com/", `https://${CREDENTIAL_HOST}/`, "about:blank", "https://evil.example/"].map((u) => policy.classify(u)),
    ["leg", "access", "microsoft", "blank", "other"], "the trace names a class, never a host");
  assert.throws(() => hostPolicy("leg.example"), /not a URL/);
});

test("BEHAVIOUR driver vocabulary: every outcome is named, and a definite one names where a denial happened", () => {
  for (const outcome of ["approved", "denied_at_access_edge", "denied_at_login", "denied_at_gateway", "blocked_mfa_interstitial",
    "browser_unavailable", "unexpected_host", "timeout", "driver_error"]) {
    assert.ok(OUTCOMES.includes(outcome), outcome);
  }
  assert.ok(!OUTCOMES.includes("denied_at_provider"), "an undifferentiated provider denial is not a vocabulary word");
  assert.ok(DEFINITE_OUTCOMES.every((outcome) => OUTCOMES.includes(outcome)));
  assert.ok(!DEFINITE_OUTCOMES.includes("timeout") && !DEFINITE_OUTCOMES.includes("driver_error") && !DEFINITE_OUTCOMES.includes("browser_unavailable"));
});

/** A page-like object that scripts the Microsoft sign-in: `urls` are the URLs
 *  the page reports in turn, `texts` the body texts. Records every fill. */
function fakePage({ urls, texts = [] }) {
  let step = 0;
  const fills = [];
  const locator = (selector) => ({
    fill: async (value) => { fills.push({ selector, value }); },
    click: async () => { step += 1; },
    waitFor: async () => {},
    innerText: async () => texts[Math.min(step, texts.length - 1)] ?? "",
  });
  return {
    fills,
    url: () => urls[Math.min(step, urls.length - 1)],
    waitForURL: async () => {},
    waitForLoadState: async () => {},
    waitForTimeout: async () => { step += 1; },
    locator,
  };
}

test("BEHAVIOUR sign-in: the password is typed only when the page is on the credential host", async () => {
  const policy = hostPolicy("https://leg.example");
  const ms = `https://${CREDENTIAL_HOST}/common/oauth2/v2.0/authorize`;
  // The login field is on the credential host; by the time the password field
  // is reached the page has moved to a lookalike. Nothing is typed there.
  const hijacked = fakePage({ urls: [ms, "https://login.microsoftonline.com.evil.example/passwd"] });
  const trace = [];
  assert.equal(await signInMicrosoft(hijacked, policy, "user@fixture.example", "s3cret-password", trace), "unexpected_host");
  assert.deepEqual(hijacked.fills.map((fill) => fill.value), ["user@fixture.example"], "the login name was typed, the password was not");
  assert.deepEqual(trace, ["microsoft:login:typed"]);
  const plainHttp = fakePage({ urls: [`http://${CREDENTIAL_HOST}/x`] });
  assert.equal(await signInMicrosoft(plainHttp, policy, "user@fixture.example", "s3cret-password", []), "unexpected_host");
  assert.deepEqual(plainHttp.fills, [], "nothing is typed over plain http");
  // The happy path: both fields on the credential host, then the page leaves.
  const good = fakePage({ urls: [ms, ms, ms, "https://leg.example/oauth/callback?code=x"], texts: ["Sign in", "Enter password", "", ""] });
  const goodTrace = [];
  assert.equal(await signInMicrosoft(good, policy, "user@fixture.example", "s3cret-password", goodTrace), undefined, "leaving the login host means the sign-in went through");
  assert.deepEqual(good.fills.map((fill) => fill.value), ["user@fixture.example", "s3cret-password"]);
  assert.ok(goodTrace.includes("microsoft:password:typed"));
  // A wrong password is a denial at the login, never at the edge.
  const wrong = fakePage({ urls: [ms, ms, ms, ms], texts: ["Sign in", "Enter password", "Enter password\nYour account or password is incorrect.", "Enter password\nYour account or password is incorrect."] });
  assert.equal(await signInMicrosoft(wrong, policy, "user@fixture.example", "s3cret-password", []), "denied_at_login");
  const mfa = fakePage({ urls: [ms, ms, ms, ms], texts: ["Sign in", "Enter password", "More information required", "More information required"] });
  assert.equal(await signInMicrosoft(mfa, policy, "user@fixture.example", "s3cret-password", []), "blocked_mfa_interstitial");
});

test("BEHAVIOUR page classification: the stable markers of the Microsoft and Access pages", () => {
  const ms = (text) => classifyMicrosoftPage({ url: `https://${CREDENTIAL_HOST}/x`, text });
  assert.equal(ms("Sign in\nEmail, phone, or Skype"), "login");
  assert.equal(ms("Enter password\nPassword"), "password");
  assert.equal(ms("Stay signed in?\nDo this to reduce the number of times you are asked to sign in."), "kmsi");
  assert.equal(ms("More information required\nYour organization needs more information to keep your account secure"), "mfa_interstitial");
  assert.equal(ms("Action Required\nSet up your account to keep it secure"), "mfa_interstitial");
  assert.equal(ms("Sign in\nAADSTS50126: Error validating credentials due to invalid username or password."), "error");
  assert.equal(ms("Enter password\nYour account or password is incorrect."), "error");
  assert.equal(ms(""), "other");
  assert.equal(classifyMicrosoftPage({ url: "https://leg.example/", text: "Sign in" }), "elsewhere");
  const cf = (text) => classifyAccessPage({ url: "https://team.cloudflareaccess.com/cdn-cgi/access/x", text });
  assert.equal(cf("Sign in with\nOne-time PIN\nmcp-sso test tenant"), "login");
  assert.equal(cf("That account does not have access."), "denied");
  assert.equal(cf("Forbidden"), "denied");
  assert.equal(classifyAccessPage({ url: "https://leg.example/", text: "does not have access" }), "elsewhere");
  // A page on the leg is the consent form, a direct OAuth error named by its
  // fixed code and cause, or something else; a description never leaks.
  assert.equal(classifyLegPage({ hasConsentForm: true, text: "invalid_request" }), "consent");
  assert.equal(classifyLegPage({ hasConsentForm: false, text: "Error: invalid_request\nduplicate request parameters" }), "invalid_request:duplicate");
  assert.equal(classifyLegPage({ hasConsentForm: false, text: "invalid_request: request parameters too large" }), "invalid_request:too_large");
  assert.equal(classifyLegPage({ hasConsentForm: false, text: "invalid_request: client_id is required" }), "invalid_request:required");
  assert.equal(classifyLegPage({ hasConsentForm: false, text: "invalid_client: The client could not be verified for user@leak.example" }), "invalid_client");
  assert.equal(classifyLegPage({ hasConsentForm: false, text: "Signing you in" }), "other");
  assert.equal(classifyLegPage({ hasConsentForm: false, text: undefined }), "other");
});

test("BEHAVIOUR clearSessionCookies: a reused browser starts each task with no session for the leg or the sign-in hosts", async () => {
  const cleared = [];
  const context = {
    cookies: async () => [
      { name: "CF_Authorization", domain: ".leg.example" },
      { name: "s", domain: "leg.example" },
      { name: "CF_AppSession", domain: "team.cloudflareaccess.com" },
      { name: "ESTSAUTH", domain: ".login.microsoftonline.com" },
      { name: "buc", domain: "login.microsoftonline.com" },
      { name: "keep", domain: "accounts.google.com" },
      { name: "keep2", domain: "example.invalid" },
      { name: "odd", domain: 42 },
      null,
    ],
    clearCookies: async (filter) => { cleared.push(filter.domain); },
  };
  const count = await clearSessionCookies(context, "https://leg.example");
  assert.deepEqual(cleared.sort(), [".leg.example", "leg.example", "team.cloudflareaccess.com", ".login.microsoftonline.com", "login.microsoftonline.com"].sort(),
    "every cookie is cleared by the domain it is stored under, leading dot and all, or Playwright's filter misses it");
  assert.equal(count, 5);
  assert.equal(cleared.some((domain) => domain.replace(/^\./, "") === "accounts.google.com"), false, "a hosted profile's other sign-ins survive");
  const empty = { cookies: async () => { throw new Error("not supported"); }, clearCookies: async () => { throw new Error("unreachable"); } };
  assert.equal(await clearSessionCookies(empty, "https://leg.example"), 0, "a context that cannot list cookies clears nothing and does not throw");
});

test("BEHAVIOUR assertion cookie: the Access JWT for the leg host, from the jar", () => {
  const cookies = [
    { name: "CF_Authorization", domain: ".other.example", value: JWT },
    { name: "CF_Authorization", domain: "leg.example", value: JWT.replace("sig", "leg") },
    { name: "session", domain: "leg.example", value: "x" },
  ];
  assert.equal(extractAssertionCookie(cookies, "https://leg.example"), JWT.replace("sig", "leg"));
  assert.equal(extractAssertionCookie([{ name: "CF_Authorization", domain: ".example", value: JWT }], "https://leg.example"), JWT, "a parent-domain cookie counts");
  assert.equal(extractAssertionCookie([{ name: "CF_Authorization", domain: "leg.example", value: "not a jwt" }], "https://leg.example"), undefined);
  assert.equal(extractAssertionCookie([], "https://leg.example"), undefined);
  assert.equal(extractAssertionCookie(undefined, "https://leg.example"), undefined);
});

test("BEHAVIOUR run-support: test users and the driver's result file are validated as data", () => {
  const users = { member: "member@fixture.example", nogroups: "nogroups@fixture.example" };
  assert.deepEqual(JSON.parse(testUsersJson(JSON.stringify(users))), users);
  for (const raw of ["{}", "[]", JSON.stringify({ member: "not an address" }), JSON.stringify({ "Bad Role": "a@b.example" }),
    JSON.stringify({ member: `${"x".repeat(320)}@b.example` }), "nope"]) {
    assert.throws(() => testUsersJson(raw), raw.slice(0, 30));
  }
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-assertion-"));
  try {
    const file = join(dir, "result.json");
    const write = (text, mode = 0o600) => { writeFileSync(file, text, { mode }); chmodSync(file, mode); };
    write(JSON.stringify({ task: "cloudflare-assertion", user: "member", outcome: "approved", assertion: JWT }));
    assert.equal(readAssertionFile(file), JWT);
    write(JSON.stringify({ outcome: "denied_at_access_edge" }));
    assert.throws(() => readAssertionFile(file), /not an approved/, "a denial never yields an assertion");
    write(JSON.stringify({ outcome: "approved", assertion: "not.a" }));
    assert.throws(() => readAssertionFile(file), /compact JWT/);
    write(JSON.stringify({ outcome: "approved" }));
    assert.throws(() => readAssertionFile(file), /compact JWT/);
    write("[]");
    assert.throws(() => readAssertionFile(file), /not an object/);
    write(JSON.stringify({ outcome: "approved", assertion: JWT }), 0o644);
    assert.throws(() => readAssertionFile(file), /group or other/);
    write(JSON.stringify({ outcome: "approved", assertion: JWT }));
    symlinkSync(file, join(dir, "link.json"));
    assert.throws(() => readAssertionFile(join(dir, "link.json")), /symlink/);
    assert.throws(() => readAssertionFile(file, 424242), /owned/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
