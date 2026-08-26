// Pure support for scripts/live/probe-client.mjs: argument parsing, the
// expected client-facing text per rejection reason (from the shipped mapping,
// never a copy), and the audit assertions over the events one flow added.
import { identityRejectionDescription } from "../../src/adapters/bridge-internals.ts";

export const EXPECTATIONS = Object.freeze([
  "approved", "entra_no_groups", "entra_no_mapped_groups", "entra_groups_overage", "entra_bad_tid", "entra_subject_not_allowed",
]);
const ROLE = /^[a-z]+$/;

export function parseClientArgs(argv) {
  const options = { user: "member", expect: "approved" };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--user" && argv[i + 1] && ROLE.test(argv[i + 1])) options.user = argv[++i];
    else if (argv[i] === "--expect" && EXPECTATIONS.includes(argv[i + 1])) options.expect = argv[++i];
    else throw new Error(`usage: probe-client.mjs [--user <role>] [--expect <${EXPECTATIONS.join("|")}>]`);
  }
  return options;
}

/** The error_description a denied client must see for a reason. */
export const expectedDescription = (reason) => identityRejectionDescription(reason);

/** Parse the audit lines a flow added: everything after `before` lines. */
export function eventsSince(text, before) {
  const lines = (typeof text === "string" ? text : "").split("\n").filter((line) => line.trim() !== "");
  return lines.slice(before).map((line) => JSON.parse(line));
}

const kinds = (events) => events.map((event) => `${event.event}:${event.status}`);

/** The events an approved flow must have added, in order. The identity is
 *  verified before the authorization is prepared on every leg: a header leg
 *  (Cloudflare Access) verifies the assertion at authorize, and a redirect leg
 *  (Entra, Google) verifies the exchanged token at the callback and then
 *  prepares the consent, recording the callback's success after it. Every
 *  named event must appear in this relative order; unrelated events between
 *  them are allowed because a served leg is shared by the rest of the run. */
export function approvedFlowOrder(leg) {
  const upstream = leg === "cloudflare_access" ? [] : ["oauth.upstream.callback:success"];
  return [
    "oauth.register:success", "identity.verify:success", "oauth.authorize.prepare:success", ...upstream,
    "oauth.authorize.approve:success", "oauth.token.authorization_code:success", "auth.request:success", "oauth.token.refresh:success",
  ];
}

export function inOrder(events, expected) {
  const seen = kinds(events);
  let cursor = 0;
  for (const name of expected) {
    const at = seen.indexOf(name, cursor);
    if (at < 0) return false;
    cursor = at + 1;
  }
  return true;
}

/** A denied flow: identity.verify failed with exactly the expected reason,
 *  the callback recorded identity_rejected, and nothing was approved or minted. */
export function deniedFlowHolds(events, reason) {
  const verify = events.find((event) => event.event === "identity.verify" && event.status === "failure");
  const callback = events.find((event) => event.event === "oauth.upstream.callback" && event.status === "failure");
  const minted = events.some((event) => ["oauth.authorize.approve", "oauth.token.authorization_code", "oauth.token.refresh"].includes(event.event)
    && event.status === "success");
  return verify?.reason === reason && callback?.reason === "identity_rejected" && !minted;
}

/** True when any of the values appears in the audit text. Fails closed: no
 *  audit text to search, or nothing to search for, counts as a leak, so the
 *  check can never pass by having compared nothing. */
export function auditLeaks(text, values) {
  if (typeof text !== "string" || text.length === 0) return true;
  if (!Array.isArray(values) || values.length === 0) return true;
  return values.some((value) => typeof value !== "string" || value.length === 0 || text.includes(value));
}
