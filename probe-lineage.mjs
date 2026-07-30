import { generateKeyPairSync, createHash } from 'node:crypto';
import { decodeJwt } from 'jose';
import { createBridgeConfig } from './src/config.ts';
import { MemoryStore } from './src/store/memory.ts';
import { Bridge } from './src/adapters/bridge.ts';
import { OAuthTokenUseCase } from './src/token.ts';
import { sha256Hex, generateRefreshToken, parseRefreshFamilyId } from './src/crypto.ts';
import { resourceParam, queryString, oauthErrorResponse } from './src/adapters/http.ts';
import { OAuthError } from './src/errors.ts';

const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const signingPrivateJwk = { ...privateKey.export({ format: 'jwk' }), alg: 'ES256', kid: 'k1' };
const A = 'https://a.example/mcp';
const B = 'https://b.example/mcp';
const REDIR = 'https://client.example/cb';
const clock = { nowMs: () => Date.now() };
const audit = { writeAuthEvent: async () => {} };
const s256 = (v) => createHash('sha256').update(v).digest('base64url');

function multi() {
  return createBridgeConfig({
    issuer: 'https://as.example',
    consentSigningSecret: 'x'.repeat(40),
    signingPrivateJwk, signingKeyId: 'k1',
    redirectAllowlist: [REDIR],
    allowedOrigins: ['https://as.example'],
    dcr: { mode: 'stateless' },
    accessTokenTtlSeconds: 300, refreshTokenTtlSeconds: 3600,
    authorizationCodeTtlSeconds: 300, consentTokenTtlSeconds: 300,
    resources: [
      { resource: A, scopeCatalog: ['mcp:read','mcp:write'], defaultScopes: ['mcp:read'] },
      { resource: B, scopeCatalog: ['mcp:read','mcp:admin'], defaultScopes: ['mcp:read'] },
    ],
  });
}
function single(resource=A, extra={}) {
  return createBridgeConfig({
    issuer: 'https://as.example',
    consentSigningSecret: 'x'.repeat(40),
    signingPrivateJwk, signingKeyId: 'k1',
    redirectAllowlist: [REDIR],
    allowedOrigins: ['https://as.example'],
    dcr: { mode: 'stateless' },
    accessTokenTtlSeconds: 300, refreshTokenTtlSeconds: 3600,
    authorizationCodeTtlSeconds: 300, consentTokenTtlSeconds: 300,
    resource, scopeCatalog: ['mcp:read'], defaultScopes: ['mcp:read'],
    ...extra,
  });
}

const cfg = multi();
const store = new MemoryStore();
const tokenUC = new OAuthTokenUseCase({ config: cfg, store, clock, audit });

async function seedRT(resource) {
  const rt = generateRefreshToken();
  await store.saveRefreshToken({
    tokenHash: sha256Hex(rt), familyId: parseRefreshFamilyId(rt), previousTokenHash: null,
    clientId: 'client-1', subject: 'user-1', scopes: ['mcp:read'],
    expiresAt: new Date(clock.nowMs() + 3600_000).toISOString(),
    resource,
  });
  return rt;
}

console.log('=== refresh resource guard with REAL token ===');
let rt = await seedRT(A);
try {
  const r = await tokenUC.refresh({ grantType: 'refresh_token', refreshToken: rt, clientId: 'client-1', resource: A });
  console.log('resource=A OK aud=', decodeJwt(r.access_token).aud);
} catch (e) { console.log('resource=A REJ', e.code, e.message); }

rt = await seedRT(A);
try {
  const r = await tokenUC.refresh({ grantType: 'refresh_token', refreshToken: rt, clientId: 'client-1', resource: B });
  console.log('resource=B on A-token OK aud=', decodeJwt(r.access_token).aud);
} catch (e) { console.log('resource=B on A-token REJ', e.code, e.message); }

rt = await seedRT(A);
try {
  const r = await tokenUC.refresh({ grantType: 'refresh_token', refreshToken: rt, clientId: 'client-1', resource: '' });
  console.log('resource="" OK', decodeJwt(r.access_token).aud);
} catch (e) { console.log('resource="" REJ', e.code, e.message); }

rt = await seedRT(A);
try {
  const r = await tokenUC.refresh({ grantType: 'refresh_token', refreshToken: rt, clientId: 'client-1' });
  console.log('resource omitted multi OK', decodeJwt(r.access_token).aud);
} catch (e) { console.log('resource omitted multi REJ', e.code, e.message); }

rt = await seedRT(A);
try {
  const r = await tokenUC.refresh({ grantType: 'refresh_token', refreshToken: rt, clientId: 'client-1', resource: resourceParam([A,B]) });
  console.log('resource array-as-invalid OK', decodeJwt(r.access_token).aud);
} catch (e) { console.log('resource array-as-invalid REJ', e.code, e.message); }

console.log('\n=== code exchange resource mismatch ===');
const cv = 'correct-horse-battery-staple-0123456789abcdef0123';
const ch = s256(cv);
async function seedCode(resource) {
  const code = 'code-' + Math.random().toString(16).slice(2);
  await store.saveAuthCode({
    codeHash: sha256Hex(code), clientId: 'client-1', redirectUri: REDIR,
    subject: 'user-1', scopes: ['mcp:read'], codeChallenge: ch,
    expiresAt: new Date(clock.nowMs() + 300_000).toISOString(),
    resource,
  });
  return code;
}
let code = await seedCode(A);
try {
  const r = await tokenUC.exchangeAuthorizationCode({
    grantType: 'authorization_code', code, redirectUri: REDIR,
    clientId: 'client-1', codeVerifier: cv, resource: B,
  });
  console.log('code A + resource B OK', decodeJwt(r.access_token).aud);
} catch (e) { console.log('code A + resource B REJ', e.code, e.message); }

code = await seedCode(A);
try {
  const r = await tokenUC.exchangeAuthorizationCode({
    grantType: 'authorization_code', code, redirectUri: REDIR,
    clientId: 'client-1', codeVerifier: cv, resource: A,
  });
  console.log('code A + resource A OK', decodeJwt(r.access_token).aud);
} catch (e) { console.log('code A + resource A REJ', e.code, e.message); }

code = await seedCode(A);
try {
  const r = await tokenUC.exchangeAuthorizationCode({
    grantType: 'authorization_code', code, redirectUri: REDIR,
    clientId: 'client-1', codeVerifier: cv,
  });
  console.log('code A omit multi OK', decodeJwt(r.access_token).aud);
} catch (e) { console.log('code A omit multi REJ', e.code, e.message); }

code = await seedCode(A);
try {
  const r = await tokenUC.exchangeAuthorizationCode({
    grantType: 'authorization_code', code, redirectUri: REDIR,
    clientId: 'client-1', codeVerifier: cv, resource: resourceParam(''),
  });
  console.log('code A empty OK', decodeJwt(r.access_token).aud);
} catch (e) { console.log('code A empty REJ', e.code, e.message); }

console.log('\n=== Bridge handleToken real refresh + resourceParam ===');
const store2 = new MemoryStore();
const bridge = new Bridge({ config: cfg, store: store2, clock, audit });
for (const [label, resource] of [
  ['A', A], ['B', B], ['empty', ''], ['array', [A,B]], ['omit', undefined],
]) {
  const rtX = generateRefreshToken();
  await store2.saveRefreshToken({
    tokenHash: sha256Hex(rtX), familyId: parseRefreshFamilyId(rtX), previousTokenHash: null,
    clientId: 'client-1', subject: 'user-1', scopes: ['mcp:read'],
    expiresAt: new Date(clock.nowMs() + 3600_000).toISOString(), resource: A,
  });
  const body = { grant_type: 'refresh_token', refresh_token: rtX, client_id: 'client-1' };
  if (resource !== undefined) body.resource = resource;
  const res = await bridge.handleToken({ query: {}, body, headers: {} });
  console.log('bridge refresh', label, res.status, res.body?.error || ('aud='+decodeJwt(res.body.access_token).aud), res.body?.error_description || '');
}

console.log('\n=== pairing-flow resource first-wins ===');
const q = { resource: [B, A] };
console.log('queryString resource array', queryString(q, 'resource'));
console.log('resourceParam raw array', resourceParam(q.resource));
console.log('pairing gathered then resourceParam', resourceParam(queryString(q, 'resource')));

console.log('\n=== oauthErrorResponse challenge on multi without resource ===');
try {
  const err = new OAuthError('invalid_token', 'nope', 401);
  const resp = oauthErrorResponse(err, { config: cfg, scope: ['mcp:read'] });
  console.log('challenge resp', resp.status, resp.headers, resp.body);
} catch (e) {
  console.log('challenge threw', e.code || e.name, e.message);
}

console.log('\n=== legacy singleton rebind on refresh without attestation ===');
const cfgL = single(B);
const storeL = new MemoryStore();
const tokenL = new OAuthTokenUseCase({ config: cfgL, store: storeL, clock, audit });
const rtL = generateRefreshToken();
await storeL.saveRefreshToken({
  tokenHash: sha256Hex(rtL), familyId: parseRefreshFamilyId(rtL), previousTokenHash: null,
  clientId: 'client-1', subject: 'user-1', scopes: ['mcp:read'],
  expiresAt: new Date(clock.nowMs() + 3600_000).toISOString(),
  resource: null,
});
try {
  const r = await tokenL.refresh({ grantType: 'refresh_token', refreshToken: rtL, clientId: 'client-1' });
  console.log('null lineage without attestation OK aud=', decodeJwt(r.access_token).aud);
} catch (e) { console.log('null lineage without attestation REJ', e.code, e.message); }

const cfgL2 = single(B, { legacySingletonResource: B });
const storeL2 = new MemoryStore();
const tokenL2 = new OAuthTokenUseCase({ config: cfgL2, store: storeL2, clock, audit });
const rtL2 = generateRefreshToken();
await storeL2.saveRefreshToken({
  tokenHash: sha256Hex(rtL2), familyId: parseRefreshFamilyId(rtL2), previousTokenHash: null,
  clientId: 'client-1', subject: 'user-1', scopes: ['mcp:read'],
  expiresAt: new Date(clock.nowMs() + 3600_000).toISOString(),
  resource: null,
});
try {
  const r = await tokenL2.refresh({ grantType: 'refresh_token', refreshToken: rtL2, clientId: 'client-1' });
  console.log('null lineage WITH attestation OK aud=', decodeJwt(r.access_token).aud);
} catch (e) { console.log('null lineage WITH attestation REJ', e.code, e.message); }

const storeL3 = new MemoryStore();
const tokenL3 = new OAuthTokenUseCase({ config: cfgL, store: storeL3, clock, audit });
const rtL3 = generateRefreshToken();
await storeL3.saveRefreshToken({
  tokenHash: sha256Hex(rtL3), familyId: parseRefreshFamilyId(rtL3), previousTokenHash: null,
  clientId: 'client-1', subject: 'user-1', scopes: ['mcp:read'],
  expiresAt: new Date(clock.nowMs() + 3600_000).toISOString(),
  resource: A,
});
try {
  const r = await tokenL3.refresh({ grantType: 'refresh_token', refreshToken: rtL3, clientId: 'client-1' });
  console.log('A-bound under singleton B OK aud=', decodeJwt(r.access_token).aud);
} catch (e) { console.log('A-bound under singleton B REJ', e.code, e.message); }

console.log('\n=== findGrantedScopes isolation ===');
const storeG = new MemoryStore();
const nowIso = new Date(clock.nowMs()).toISOString();
const rtG = generateRefreshToken();
await storeG.saveRefreshToken({
  tokenHash: sha256Hex(rtG), familyId: parseRefreshFamilyId(rtG), previousTokenHash: null,
  clientId: 'client-1', subject: 'user-1', scopes: ['mcp:read', 'mcp:extra'],
  expiresAt: new Date(clock.nowMs() + 3600_000).toISOString(),
  resource: null,
});
console.log('legacy allow=true', await storeG.findGrantedScopes('user-1','client-1',nowIso,undefined,{resource:B,allowLegacySingletonBinding:true}));
console.log('legacy allow=false', await storeG.findGrantedScopes('user-1','client-1',nowIso,undefined,{resource:B,allowLegacySingletonBinding:false}));
const rtGA = generateRefreshToken();
await storeG.saveRefreshToken({
  tokenHash: sha256Hex(rtGA), familyId: parseRefreshFamilyId(rtGA), previousTokenHash: null,
  clientId: 'client-1', subject: 'user-1', scopes: ['mcp:admin'],
  expiresAt: new Date(clock.nowMs() + 3600_000).toISOString(),
  resource: A,
});
console.log('scopes for B', await storeG.findGrantedScopes('user-1','client-1',nowIso,undefined,{resource:B,allowLegacySingletonBinding:false}));
console.log('scopes for A', await storeG.findGrantedScopes('user-1','client-1',nowIso,undefined,{resource:A,allowLegacySingletonBinding:false}));
