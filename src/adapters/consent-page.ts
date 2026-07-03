// Consent page HTML (fix #5). The GET /oauth/authorize success body. Shows the
// resource, the requested scopes (marking which are new vs already granted — the
// scope-accumulation delta, RC item c), and BOTH Approve and Deny buttons. Deny
// POSTs approved=false, which the core redirects as access_denied (§9.3).
// CSP hardens the page; all interpolated values are HTML-escaped.

import type { BridgeConfig } from "../config.ts";
import type { PreparedConsent } from "../authorize.ts";

export function renderConsentPage(_config: BridgeConfig, prepared: PreparedConsent): string {
  const esc = (v: string): string => v.replace(/[<>&"']/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
  const scopeItems = [...prepared.scopes].map((s) => {
    const prior = prepared.priorScopes.includes(s);
    const tag = prior ? ' <span class="tag">(already granted)</span>' : ' <span class="tag new">(new)</span>';
    return `<div class="scope">${esc(s)}${tag}</div>`;
  }).join("");
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize</title>
<style>body{font-family:system-ui,sans-serif;max-width:480px;margin:60px auto;padding:0 20px;color:#1a1a1a}h1{font-size:1.3rem}.scope{background:#f4f4f4;padding:8px 12px;border-radius:6px;font-family:monospace;font-size:.85rem;margin:4px 0}.tag{font-family:system-ui;font-size:.75rem;color:#666}.tag.new{color:#2563eb;font-weight:600}form{margin-top:24px;display:flex;gap:12px}.approve{margin-left:auto}button{padding:10px 24px;font-size:1rem;border:none;border-radius:6px;cursor:pointer}.approve{background:#2563eb;color:#fff}.deny{background:#e5e7eb;color:#1a1a1a}</style>
</head><body>
<h1>Authorize access</h1>
<p>An application requests access to <strong>${esc(prepared.resource)}</strong>.</p>
<p>Requested scopes:</p>
${scopeItems}
<form method="POST" action="/oauth/authorize/approve">
<input type="hidden" name="consent_token" value="${esc(prepared.consentToken)}">
<button type="submit" class="deny" name="approved" value="false">Deny</button>
<button type="submit" class="approve" name="approved" value="true">Approve</button>
</form>
</body></html>`;
}
