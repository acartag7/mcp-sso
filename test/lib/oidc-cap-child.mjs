// Child leg for the §17.6 body-cap tests. The parent spawns this process with
// NODE_EXTRA_CA_CERTS pointing at the local server's self-signed certificate,
// so the library runs with FULL TLS verification against a cert Node trusts —
// no NODE_TLS_REJECT_UNAUTHORIZED anywhere (CodeQL: js/disabling-cert-validation).
// Args: <discovery|token> <port>. Prints one JSON line with the outcome.
const [, , mode, portArg] = process.argv;
const port = Number(portArg);
const base = `https://127.0.0.1:${port}`;

try {
  if (mode === "discovery") {
    const { createGenericOidcIdentity } = await import("../../src/identity/generic-oidc.ts");
    await createGenericOidcIdentity({ issuer: base, clientId: "cid", clientSecret: "s", redirectUri: `${base}/cb`, endpoints: "discover" });
    console.log(JSON.stringify({ unexpected: "identity-created" }));
  } else if (mode === "token") {
    const { createGenericOidcRedirectIdentity } = await import("../../src/identity/generic-oidc.ts");
    const identity = await createGenericOidcRedirectIdentity({
      issuer: base, clientId: "cid",
      redirectUri: `${base}/cb`,
      endpoints: {
        authorizationEndpoint: `${base}/auth`, tokenEndpoint: `${base}/token`, jwksUri: `${base}/jwks`,
      },
    });
    const result = await identity.exchangeAndVerify({ code: "c", codeVerifier: "v", nonce: "n" });
    console.log(JSON.stringify({ ok: result.ok, kind: result.ok ? undefined : result.kind, reason: result.ok ? undefined : result.reason }));
  } else {
    console.log(JSON.stringify({ badMode: mode }));
  }
} catch (error) {
  console.log(JSON.stringify({ threw: String(error?.message ?? error) }));
}
