import { generateKeyPairSync } from 'node:crypto';
import { SignJWT, importJWK, decodeJwt } from 'jose';
import { createBridgeConfig } from './src/config.ts';
import { signAccessToken, verifyAccessToken } from './src/access-token.ts';
import { createRequestAuthorizer } from './src/verifier.ts';
import { planProtectedResourceRoutes } from './src/adapters/protected-resource-routes.ts';
import { protectedResourceMetadata } from './src/metadata.ts';
import { buildUnauthorizedChallenge } from './src/challenge.ts';
import { resourceParam, INVALID_RESOURCE } from './src/adapters/http.ts';
import { MemoryStore } from './src/store/memory.ts';
import { Bridge } from './src/adapters/bridge.ts';

const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const signingPrivateJwk = { ...privateKey.export({ format: 'jwk' }), alg: 'ES256', kid: 'k1' };
const A = 'https://a.example/mcp';
const B = 'https://b.example/mcp';
const clock = { nowMs: () => Date.now() };
const audit = { writeAuthEvent: async () => {} };

function common() {
  return {
    issuer: 'https://as.example',
    consentSigningSecret: 'x'.repeat(40),
    signingPrivateJwk,
    signingKeyId: 'k1',
    redirectAllowlist: ['https://client.example/cb'],
    allowedOrigins: ['https://as.example'],
    dcr: { mode: 'stateless' },
    accessTokenTtlSeconds: 300,
    refreshTokenTtlSeconds: 3600,
    authorizationCodeTtlSeconds: 60,
    consentTokenTtlSeconds: 300,
  };
}

function multiConfig(resources, extra={}) {
  return createBridgeConfig({ ...common(), resources, ...extra });
}

console.log('=== resourceParam boundary ===');
for (const v of [undefined, null, '', 'https://x', 0, false, ['https://a','https://b'], {x:1}, INVALID_RESOURCE]) {
  console.log(JSON.stringify(v), '=>', JSON.stringify(resourceParam(v)));
}

const cfg = multiConfig([
  { resource: A, scopeCatalog: ['mcp:read', 'mcp:write'], defaultScopes: ['mcp:read'] },
  { resource: B, scopeCatalog: ['mcp:read', 'mcp:admin'], defaultScopes: ['mcp:read'] },
]);

console.log('\n=== multi-value aud attack ===');
const tokenA = await signAccessToken({ subject: 'u1', clientId: 'c1', scopes: ['mcp:read'], resource: A }, cfg, clock);
console.log('tokenA aud=', decodeJwt(tokenA).aud);
const now = Math.floor(Date.now()/1000);
const key = await importJWK(signingPrivateJwk, 'ES256');
const multiAud = await new SignJWT({ client_id: 'c1', scope: 'mcp:read' })
  .setProtectedHeader({ alg: 'ES256', kid: 'k1', typ: 'JWT' })
  .setIssuer(cfg.issuer).setSubject('u1')
  .setAudience([A, B])
  .setIssuedAt(now).setExpirationTime(now+300)
  .sign(key);
const emptyAud = await new SignJWT({ client_id: 'c1', scope: 'mcp:read' })
  .setProtectedHeader({ alg: 'ES256', kid: 'k1', typ: 'JWT' })
  .setIssuer(cfg.issuer).setSubject('u1')
  .setAudience([])
  .setIssuedAt(now).setExpirationTime(now+300)
  .sign(key);
const oneArr = await new SignJWT({ client_id: 'c1', scope: 'mcp:read' })
  .setProtectedHeader({ alg: 'ES256', kid: 'k1', typ: 'JWT' })
  .setIssuer(cfg.issuer).setSubject('u1')
  .setAudience([A])
  .setIssuedAt(now).setExpirationTime(now+300)
  .sign(key);
const tokenB = await signAccessToken({ subject: 'u1', clientId: 'c1', scopes: ['mcp:read'], resource: B }, cfg, clock);

for (const [label, token, res] of [
  ['legit A@A', tokenA, A],
  ['legit A@B', tokenA, B],
  ['legit B@A', tokenB, A],
  ['multiAud@A', multiAud, A],
  ['multiAud@B', multiAud, B],
  ['oneArr@A', oneArr, A],
  ['emptyAud@A', emptyAud, A],
  ['legit A omit', tokenA, undefined],
]) {
  try {
    const v = await verifyAccessToken(token, cfg, clock, res);
    console.log(`VERIFY OK ${label} => resource=${v.resource}`);
  } catch (e) {
    console.log(`VERIFY REJ ${label} => ${e.code}: ${e.message}`);
  }
}

console.log('\n=== authorizer pin ===');
const authA = createRequestAuthorizer({ config: cfg, clock, audit, resource: A });
const authB = createRequestAuthorizer({ config: cfg, clock, audit, resource: B });
console.log('pins', authA.resource, authB.resource);
console.log('A@A', (await authA.authorize({ authorization: `Bearer ${tokenA}` })).resource);
try { await authB.authorize({ authorization: `Bearer ${tokenA}` }); console.log('FAIL A@B'); }
catch (e) { console.log('A@B rej', e.code); }
try { createRequestAuthorizer({ config: cfg, clock, audit }); console.log('FAIL multi no pin'); }
catch (e) { console.log('multi no pin', e.message); }
const desc = Object.getOwnPropertyDescriptor(authA, 'resource');
console.log('resource descriptor writable?', desc?.writable, 'configurable?', desc?.configurable);
authA.resource = B;
console.log('after plain assign', authA.resource);
try {
  const r = await authA.authorize({ authorization: `Bearer ${tokenA}` });
  console.log('after assign A-token result resource', r.resource, 'auth.resource', authA.resource);
} catch (e) {
  console.log('after assign use', e.code, e.message);
}

console.log('\n=== PRM route planning ===');
const routeCases = [
  ['normal multi', [A, B]],
  ['slash variants', ['https://example.com/mcp', 'https://example.com/mcp/']],
  ['case path', ['https://example.com/mcp', 'https://example.com/MCP']],
  ['percent', ['https://example.com/mcp', 'https://example.com/%6dcp']],
  ['metachar colon', ['https://example.com/mcp:id']],
  ['metachar star', ['https://example.com/mcp*x']],
  ['metachar brace', ['https://example.com/mcp{x}']],
  ['origin + path', ['https://example.com', 'https://example.com/mcp']],
  ['dot-seg vs plain', ['https://example.com/a/../mcp', 'https://example.com/mcp']],
];
for (const [label, resources] of routeCases) {
  try {
    const c = multiConfig(resources.map(r => ({ resource: r, scopeCatalog: ['mcp:read'], defaultScopes: [] })));
    const plan = planProtectedResourceRoutes(c);
    console.log(`OK plan ${label}:`, plan.routes.map(r => `${r.pathname}->${r.resource.resource}`), 'fallback=', plan.rootFallback?.resource);
  } catch (e) {
    console.log(`REJ plan ${label}: ${e.message}`);
  }
}

console.log('\n=== challenge / metadata ===');
const chA = buildUnauthorizedChallenge(cfg, { resource: A, error: 'invalid_token' });
const chB = buildUnauthorizedChallenge(cfg, { resource: B, error: 'invalid_token' });
console.log('chA', chA);
console.log('chB', chB);
console.log('mdA', protectedResourceMetadata(cfg, A));
console.log('mdB', protectedResourceMetadata(cfg, B));
try { console.log('md omit', protectedResourceMetadata(cfg)); }
catch (e) { console.log('md omit REJ', e.code, e.message); }

console.log('\n=== percent path as distinct resources + token cross ===');
try {
  const p1 = 'https://example.com/mcp';
  const p2 = 'https://example.com/%6dcp';
  const pcfg = multiConfig([
    { resource: p1, scopeCatalog: ['mcp:read'], defaultScopes: ['mcp:read'] },
    { resource: p2, scopeCatalog: ['mcp:write'], defaultScopes: ['mcp:write'] },
  ]);
  console.log('catalog entries', pcfg.resources.map(r=>r.resource));
  const plan = planProtectedResourceRoutes(pcfg);
  console.log('plan pathnames', plan.routes.map(r=>r.pathname));
  const t1 = await signAccessToken({ subject:'u', clientId:'c', scopes:['mcp:read'], resource: p1 }, pcfg, clock);
  const t2 = await signAccessToken({ subject:'u', clientId:'c', scopes:['mcp:write'], resource: p2 }, pcfg, clock);
  console.log('t1 aud', decodeJwt(t1).aud);
  console.log('t2 aud', decodeJwt(t2).aud);
  for (const [lab, tok, res] of [['t1@p1',t1,p1],['t1@p2',t1,p2],['t2@p1',t2,p1],['t2@p2',t2,p2]]) {
    try { console.log(lab, (await verifyAccessToken(tok, pcfg, clock, res)).resource); }
    catch (e) { console.log(lab, 'REJ', e.code); }
  }
} catch (e) {
  console.log('percent multi failed', e.message);
}

console.log('\n=== slash-trailing distinct resources ===');
try {
  const s1 = 'https://example.com/mcp';
  const s2 = 'https://example.com/mcp/';
  const scfg = multiConfig([
    { resource: s1, scopeCatalog: ['mcp:read'], defaultScopes: ['mcp:read'] },
    { resource: s2, scopeCatalog: ['mcp:write'], defaultScopes: ['mcp:write'] },
  ]);
  const plan = planProtectedResourceRoutes(scfg);
  console.log('slash plan', plan.routes.map(r=>r.pathname));
  const t = await signAccessToken({ subject:'u', clientId:'c', scopes:['mcp:read'], resource: s1 }, scfg, clock);
  try { console.log('s1@s2', (await verifyAccessToken(t, scfg, clock, s2)).resource); }
  catch (e) { console.log('s1@s2 REJ', e.code); }
} catch (e) {
  console.log('slash multi failed', e.message);
}

console.log('\n=== Bridge HTTP boundary: invalid resource does not collapse ===');
const store = new MemoryStore();
const bridge = new Bridge({ config: cfg, store, clock, audit });
const badRes = await bridge.handleAuthorize({
  query: { client_id: 'https://client.example', redirect_uri: 'https://client.example/cb', response_type: 'code',
    code_challenge: 'x'.repeat(43), code_challenge_method: 'S256', resource: '' },
  body: undefined, headers: {},
}, { subject: 'u1' });
console.log('empty resource authorize', badRes.status, badRes.body);

const arrRes = await bridge.handleAuthorize({
  query: { client_id: 'c', redirect_uri: 'https://client.example/cb', response_type: 'code',
    code_challenge: 'x'.repeat(43), code_challenge_method: 'S256', resource: ['https://a.example/mcp','https://b.example/mcp'] },
  body: undefined, headers: {},
}, { subject: 'u1' });
console.log('array resource authorize', arrRes.status, JSON.stringify(arrRes.body));

const tokBad = await bridge.handleToken({
  query: {},
  body: { grant_type: 'refresh_token', refresh_token: 'rt_x.y', client_id: 'c', resource: '' },
  headers: {},
});
console.log('empty resource refresh', tokBad.status, tokBad.body);

const tokArr = await bridge.handleToken({
  query: {},
  body: { grant_type: 'refresh_token', refresh_token: 'rt_x.y', client_id: 'c', resource: [A,B] },
  headers: {},
});
console.log('array resource refresh', tokArr.status, tokArr.body);

const tokOmitMulti = await bridge.handleToken({
  query: {},
  body: { grant_type: 'refresh_token', refresh_token: 'rt_x.y', client_id: 'c' },
  headers: {},
});
console.log('omit resource refresh multi', tokOmitMulti.status, tokOmitMulti.body);

// Direct formField-like path: does formField collapse empty while resourceParam does not?
import { formField, queryString } from './src/adapters/http.ts';
console.log('formField empty', formField({resource:''}, 'resource'));
console.log('queryString empty', queryString({resource:''}, 'resource'));
console.log('queryString array first', queryString({resource:[A,B]}, 'resource'));
console.log('resourceParam array', resourceParam([A,B]));
