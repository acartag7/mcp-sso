// Pairing entry page HTML (contracts §17.5) — the GET /oauth/authorize body when
// console pairing is wired and no code has been submitted yet. Parallel to
// consent-page.ts: CSP-hardened, every interpolated value HTML-escaped, a visible
// code input, the session nonce + all round-tripped OAuth params as hidden fields
// so the operator's paste flows back into the authorize handler verbatim.
//
// The page itself never contains the pairing code (the code is on stderr); it is
// the surface where the operator pastes it. The nonce binds the submission to the
// session that triggered the code's printing (§17.5 session binding).

export interface PairingPageInput {
  /** Session nonce issued by beginSession(); submitted back as pairing_nonce. */
  nonce: string;
  /** ISO expiry of the active code, shown so the operator knows the window. */
  expiresAt: string;
  /** Round-tripped OAuth authorize params (client_id, redirect_uri, ...). */
  oauthParams: Record<string, string>;
  /** Optional failure message from a rejected previous submission. */
  error?: string;
}

const esc = (v: string): string =>
  v.replace(/[<>&"']/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#39;" })[c] ?? c);

export function renderPairingPage(input: PairingPageInput): string {
  const hidden = Object.entries(input.oauthParams)
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
    .join("");
  const resource = input.oauthParams.resource;
  const errorBlock = input.error
    ? `<p class="error" role="alert">${esc(input.error)}</p>`
    : `<p class="hint">A one-time code has been printed to the server console. Paste it to continue.</p>`;
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pair</title>
<style>body{font-family:system-ui,sans-serif;max-width:480px;margin:60px auto;padding:0 20px;color:#1a1a1a}h1{font-size:1.3rem}label{display:block;font-weight:600;margin-top:16px}#pairing_code{width:100%;padding:10px;font-size:1.1rem;font-family:monospace;letter-spacing:.1em;border:1px solid #ccc;border-radius:6px;box-sizing:border-box}button{margin-top:16px;padding:10px 24px;font-size:1rem;border:none;border-radius:6px;background:#2563eb;color:#fff;cursor:pointer}.hint{color:#666;font-size:.9rem}.error{color:#b91c1c;font-size:.9rem}.meta{color:#666;font-size:.8rem;margin-top:24px}</style>
</head><body>
<h1>Pair this device</h1>
${errorBlock}
${resource ? `<p class="meta">Authorizing access to <strong>${esc(resource)}</strong>.</p>` : ""}
<form method="POST" action="/oauth/authorize" autocomplete="off">
<label for="pairing_code">Pairing code</label>
<input id="pairing_code" name="pairing_code" inputmode="text" autocapitalize="characters" spellcheck="false" autofocus required>
<input type="hidden" name="pairing_nonce" value="${esc(input.nonce)}">
${hidden}
<button type="submit">Continue</button>
</form>
<p class="meta">Code expires ${esc(input.expiresAt)}.</p>
</body></html>`;
}
