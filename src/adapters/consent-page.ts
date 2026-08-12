// Consent page HTML (fix #5). The GET /oauth/authorize success body. Shows the
// resource, the requested scopes (marking which are new vs already granted — the
// scope-accumulation delta, RC item c), and BOTH Approve and Deny buttons. Deny
// POSTs approved=false, which the core redirects as access_denied (§9.3).
// CSP hardens the page; all interpolated values are HTML-escaped.
//
// For a CIMD client (§17.1.4 / §17.1.6 decision 1c) the page additionally MUST
// show the client_id host and the redirect host as the primary identity anchors,
// then renders `client_name` as HTML-escaped SELF-REPORTED / UNVERIFIED text
// (threat-model row 17 XSS + impersonation). It SHOULD warn when every
// registered redirect is loopback.

import type { BridgeConfig } from "../config.ts";
import type { PreparedConsent } from "../authorize.ts";

const esc = (v: string): string => v.replace(/[<>&"']/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#39;" })[c] ?? c);

function cimdBlock(prepared: PreparedConsent): string {
  const cimd = prepared.cimd;
  if (cimd === undefined) return "";
  const loopbackWarning = cimd.allRedirectsLoopback
    ? `<p class="warn">Every registered redirect for this client is a local (loopback) address. Any program on this machine could be impersonating it.</p>`
    : "";
  return `<div class="client">
<p class="client-label">Client ID host</p>
<p class="client-host"><code>${esc(cimd.clientIdHost)}</code></p>
<p class="client-label">Redirect destination host</p>
<p class="client-host"><code>${esc(cimd.redirectHost)}</code></p>
<p class="client-name">Self-reported name: <strong>${esc(cimd.clientName)}</strong> <span class="trust-note">(unverified)</span></p>
<p class="client-help">Check the two hosts above before approving.</p>
${loopbackWarning}</div>`;
}

function redirectBlock(prepared: PreparedConsent): string {
  return `<div class="redirect">
<p class="client-label">Authorization code destination</p>
<p class="redirect-uri"><code>${esc(prepared.redirectUri)}</code></p>
</div>`;
}

export function renderConsentPage(_config: BridgeConfig, prepared: PreparedConsent): string {
  const scopeItems = [...prepared.scopes].map((s) => {
    const prior = prepared.priorScopes.includes(s);
    const tag = prior ? ' <span class="tag">(already granted)</span>' : ' <span class="tag new">(new)</span>';
    return `<div class="scope">${esc(s)}${tag}</div>`;
  }).join("");
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize</title>
<style>body{font-family:system-ui,sans-serif;max-width:480px;margin:60px auto;padding:0 20px;color:#1a1a1a}h1{font-size:1.3rem}.scope{background:#f4f4f4;padding:8px 12px;border-radius:6px;font-family:monospace;font-size:.85rem;margin:4px 0}.tag{font-family:system-ui;font-size:.75rem;color:#666}.tag.new{color:#2563eb;font-weight:600}.client,.redirect{background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:10px 12px;margin:10px 0}.client p,.redirect p{margin:4px 0}.client-label{color:#555;font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.03em}.client p.client-host{font-size:1rem;font-weight:700;margin-bottom:10px}.redirect-uri{font-size:.9rem;font-weight:700;overflow-wrap:anywhere}.client-name,.client-help{font-size:.85rem}.trust-note{color:#666}.client-help{color:#444}.warn{color:#b45309;font-size:.85rem;font-weight:600}form{margin-top:24px;display:flex;gap:12px}.approve{margin-left:auto}button{padding:10px 24px;font-size:1rem;border:none;border-radius:6px;cursor:pointer}.approve{background:#2563eb;color:#fff}.deny{background:#e5e7eb;color:#1a1a1a}</style>
</head><body>
<h1>Authorize access</h1>
<p>An application requests access to <strong>${esc(prepared.resource)}</strong>.</p>
${cimdBlock(prepared)}
${redirectBlock(prepared)}
<p>Requested scopes:</p>
${scopeItems}
<form method="POST" action="/oauth/authorize/approve">
<input type="hidden" name="consent_token" value="${esc(prepared.consentToken)}">
<button type="submit" class="deny" name="approved" value="false">Deny</button>
<button type="submit" class="approve" name="approved" value="true">Approve</button>
</form>
</body></html>`;
}
