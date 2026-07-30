import {
  canonicalResource,
  buildResourceCatalog,
  resolveResource,
} from './src/resource.ts';
import { AuthConfigError } from './src/config.ts';
import { OAuthError } from './src/errors.ts';

const opt = { allowInsecureLocalhost: true };
const optProd = { allowInsecureLocalhost: false };

function tryCanon(label, value, o = opt) {
  try {
    const c = canonicalResource(value, o);
    console.log(`OK  ${label.padEnd(50)} => ${JSON.stringify(c)}`);
  } catch (e) {
    console.log(`REJ ${label.padEnd(50)} => ${e.message}`);
  }
}

console.log('=== canonicalization ===');
const cases = [
  ['basic', 'https://example.com/mcp'],
  ['trailing slash path', 'https://example.com/mcp/'],
  ['origin only', 'https://example.com'],
  ['origin slash', 'https://example.com/'],
  ['default port 443', 'https://example.com:443/mcp'],
  ['upper host', 'https://EXAMPLE.COM/mcp'],
  ['upper path', 'https://example.com/MCP'],
  ['dot segments', 'https://example.com/a/../mcp'],
  ['dot segments keep', 'https://example.com/mcp/./x'],
  ['percent mcp', 'https://example.com/%6dcp'],
  ['percent slash', 'https://example.com/mcp%2Fextra'],
  ['double encode', 'https://example.com/%256dcp'],
  ['trailing host dot', 'https://example.com./mcp'],
  ['userinfo', 'https://user:pass@example.com/mcp'],
  ['query', 'https://example.com/mcp?x=1'],
  ['fragment', 'https://example.com/mcp#x'],
  ['backslash', 'https://example.com\\mcp'],
  ['space', 'https://example.com/m cp'],
  ['tab', 'https://example.com/m\tcp'],
  ['null byte', 'https://example.com/m\x00cp'],
  ['http non-loopback', 'http://example.com/mcp'],
  ['http loopback', 'http://127.0.0.1:3000/mcp'],
  ['http localhost', 'http://localhost/mcp'],
  ['empty', ''],
  ['malformed pct', 'https://example.com/%zz'],
  ['empty authority', 'https:///mcp'],
  ['empty port', 'https://example.com:/mcp'],
  ['ipv6', 'https://[::1]/mcp'],
  ['idna raw', 'https://bücher.example/mcp'],
  ['idna puny', 'https://xn--bcher-kva.example/mcp'],
  ['unicode path', 'https://example.com/mKcp'], // K
  ['nfkc path', 'https://example.com/ﬁ'], // ﬁ ligature
  ['oversize', 'https://example.com/' + 'a'.repeat(3000)],
  ['exactly 2048', (() => {
    const prefix = 'https://example.com/';
    const need = 2048 - Buffer.byteLength(prefix);
    return prefix + 'a'.repeat(need);
  })()],
  ['2049 bytes', (() => {
    const prefix = 'https://example.com/';
    const need = 2049 - Buffer.byteLength(prefix);
    return prefix + 'a'.repeat(need);
  })()],
];
for (const [l,v] of cases) tryCanon(l, v);

console.log('\n=== collision pairs after canonicalization ===');
const pairs = [
  ['https://example.com/mcp', 'https://EXAMPLE.COM/mcp'],
  ['https://example.com/mcp', 'https://example.com:443/mcp'],
  ['https://example.com/mcp', 'https://example.com/%6dcp'],
  ['https://example.com/mcp', 'https://example.com/mcp/'],
  ['https://example.com', 'https://example.com/'],
  ['https://bücher.example/mcp', 'https://xn--bcher-kva.example/mcp'],
  ['https://example.com./mcp', 'https://example.com/mcp'],
  ['https://example.com/a/../mcp', 'https://example.com/mcp'],
  ['http://127.0.0.1/mcp', 'http://localhost/mcp'],
];
for (const [a,b] of pairs) {
  try {
    const ca = canonicalResource(a, opt);
    const cb = canonicalResource(b, opt);
    console.log(`${ca === cb ? 'COLLIDE' : 'distinct'} ${JSON.stringify(a)} vs ${JSON.stringify(b)} => ${JSON.stringify(ca)} / ${JSON.stringify(cb)}`);
  } catch (e) {
    console.log(`error pair ${a} / ${b}: ${e.message}`);
  }
}

console.log('\n=== catalog duplicate rejection ===');
try {
  buildResourceCatalog({
    resources: [
      { resource: 'https://example.com/mcp', scopeCatalog: ['a'], defaultScopes: [] },
      { resource: 'https://EXAMPLE.COM/mcp', scopeCatalog: ['b'], defaultScopes: [] },
    ],
  }, opt);
  console.log('FAIL: allowed case-variant duplicates');
} catch (e) {
  console.log('OK reject case-variant:', e.message);
}
try {
  buildResourceCatalog({
    resources: [
      { resource: 'https://example.com/mcp', scopeCatalog: ['a'], defaultScopes: [] },
      { resource: 'https://example.com/%6dcp', scopeCatalog: ['b'], defaultScopes: [] },
    ],
  }, opt);
  console.log('FAIL: allowed percent duplicates');
} catch (e) {
  console.log('OK reject percent-dup:', e.message);
}

console.log('\n=== resolveResource invalid collapse ===');
const cat = buildResourceCatalog({
  resources: [
    { resource: 'https://a.example/mcp', scopeCatalog: ['read'], defaultScopes: ['read'] },
    { resource: 'https://b.example/mcp', scopeCatalog: ['write'], defaultScopes: ['write'] },
  ],
}, opt);
for (const req of [undefined, '', 'https://a.example/mcp', 'https://b.example/mcp', 'https://c.example/mcp', 'not-a-url', 'https://a.example/mcp?x=1', '\x00invalid-resource']) {
  try {
    const r = resolveResource(cat, req);
    console.log(`resolve ${JSON.stringify(req)} => ${r.resource}`);
  } catch (e) {
    console.log(`resolve ${JSON.stringify(req)} => ${e.code || e.name}: ${e.message}`);
  }
}

const single = buildResourceCatalog({
  resource: 'https://a.example/mcp', scopeCatalog: ['read'], defaultScopes: ['read'],
}, opt);
for (const req of [undefined, '', 'https://a.example/mcp', 'https://b.example/mcp', '\x00invalid-resource']) {
  try {
    const r = resolveResource(single, req);
    console.log(`single resolve ${JSON.stringify(req)} => ${r.resource}`);
  } catch (e) {
    console.log(`single resolve ${JSON.stringify(req)} => ${e.code || e.name}: ${e.message}`);
  }
}
