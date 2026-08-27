// The rows `render-evidence.mjs` writes into docs/client-compatibility.md, in
// one place because two readers need the same answer: the renderer, which
// writes them, and the release gate, which has to know which recorded rows the
// harness produced. Those rows and an operator's own live client runs have
// different lifecycles — a harness change re-proves the first set and cannot
// reach the second — so the gate ages them separately.
/** The provider rows a receipt can prove, each gated on the rehearsal rows it
 *  needs. Subjects (provider, client, flow) are what the parser dedupes on. */
export const PROVIDER_ROWS = Object.freeze([
  {
    needs: ["client-entra:member"],
    provider: "Entra ID", client: "Official MCP SDK client, driven by the rehearsal",
    flow: "DCR → authorization → Entra identity through the headless driver as the member test user → consent → token → `/mcp` → refresh",
    status: "Verified", limits: "",
  },
  {
    needs: ["client-entra:nogroups", "client-entra:wronggroup", "client-entra:overage", "client-entra:wrong-tenant", "client-entra:not-allowlisted"],
    provider: "Entra ID", client: "Rehearsal deny fixtures",
    flow: "No-group, no-mapped-group, group-overage, wrong-tenant, and subject-allowlist denials",
    status: "Verified",
    limits: "Each fixture produced its audit reason once (`entra_no_groups`, `entra_no_mapped_groups`, `entra_groups_overage`, `entra_bad_tid`, `entra_subject_not_allowed`) and the client received `access_denied` with the documented description.",
  },
  {
    needs: ["client-cloudflare:member", "access-login", "access-edge-denial", "probe-cloudflare"],
    provider: "Cloudflare Access", client: "Official MCP SDK client, driven by the rehearsal",
    flow: "DCR → Access login through the Entra login method as the member test user → consent → token → `/mcp` → refresh; a non-admitted test user stopped at the Access edge",
    status: "Verified", limits: "",
  },
  {
    needs: ["claude-code:entra", "claude-code:cloudflare"], version: "claude",
    provider: "Cloudflare Access and Entra ID", client: "Claude Code, driven by the rehearsal",
    flow: "CIMD `client_id` → `claude mcp login --no-browser` → provider identity through the headless driver as the member test user → consent → the CLI's loopback callback → token → connection check on `/mcp`",
    status: "Verified", limits: "",
  },
  {
    needs: ["codex-cli:entra", "codex-cli:cloudflare"], version: "codex",
    provider: "Cloudflare Access and Entra ID", client: "Codex CLI, driven by the rehearsal",
    flow: "`codex mcp add` → the client identity Codex chose, CIMD document or dynamic registration → provider identity through the headless driver as the member test user → consent → the CLI's loopback callback → token",
    status: "Verified with limit", limits: "Limit: a tool call runs only when the client-keys file supplies `OPENAI_API_KEY`.",
  },
  {
    needs: ["probe-google"],
    provider: "Google", client: "Provider probe, driven by the rehearsal",
    flow: "Discovery through the shipped resolver, the JWKS, and the authorize redirect",
    status: "Verified with limit", limits: "Limit: the Google sign-in was not driven.",
  },
]);


/** One cell of a subject, as the table compares it. */
export function renderedSubjectCell(value) {
  return value.replace(/`([^`\r\n]+)`/g, "$1").replace(/\s+/gu, " ").trim();
}

/** The (provider, client, flow) subject the compatibility table dedupes on. */
export const subjectOf = (cells) => JSON.stringify(cells.slice(0, 3).map(renderedSubjectCell));

/** Whether a recorded provider row is one the harness renders. Anything else
 *  was recorded by a person driving a real client against a served leg. */
export function isRenderedRow(provider, client, flow) {
  const subject = subjectOf([provider, client, flow]);
  return PROVIDER_ROWS.some((row) => subjectOf([row.provider, row.client, row.flow]) === subject);
}
