#!/usr/bin/env node
'use strict';
/* tools/test.mjs — headless checks. Run: node tools/test.mjs
   Stubs browser globals, loads the inline script from index.html, and
   unit-tests parsers + grade engine + license verification (via node crypto,
   mirroring verify.js logic against a signed demo key). No network calls. */
import fs from 'node:fs';
import vm from 'node:vm';
import crypto from 'node:crypto';

let pass = 0, fail = 0;
const t = (name, cond) => { cond ? pass++ : (fail++, console.error('FAIL:', name)); };

// ---- extract inline script from index.html ----
const html = fs.readFileSync('index.html', 'utf8');
const m = html.match(/<script>\n('use strict';[\s\S]*?)<\/script>/);
if (!m) { console.error('could not extract inline script'); process.exit(1); }
const src = m[1];

// ---- stubbed browser environment ----
const elStub = () => new Proxy({ classList: { add(){}, remove(){}, toggle(){} }, style: {},
  addEventListener(){}, insertAdjacentHTML(){}, focus(){}, click(){}, dataset: {},
  innerHTML: '', textContent: '', value: '', open: false, disabled: false },
  { get: (o, k) => k in o ? o[k] : (o[k] = ''), set: (o, k, v) => (o[k] = v, true) });
const sandbox = {
  window: {}, console,
  document: { getElementById: elStub, createElement: () => ({ ...elStub(), getContext: () => null }),
    addEventListener(){}, },
  localStorage: { setItem(){}, getItem(){ return null; }, removeItem(){} },
  location: { search: '?__test=1', origin: 'https://x.test', pathname: '/', host: 'x.test' },
  history: { replaceState(){} },
  URL, URLSearchParams, fetch: async () => { throw new Error('no network in tests'); },
  AbortController, setTimeout, clearTimeout, Map, Set, Promise, JSON, Date,
  navigator: { clipboard: { writeText: async () => {} } },
  alert(){},
};
sandbox.window = sandbox;
sandbox.window.inboxproofVerifyLicense = async () => ({ valid: false });
vm.createContext(sandbox);
try { vm.runInContext(src, sandbox); }
catch (e) { console.error('script eval failed:', e); process.exit(1); }
const IP = sandbox.window.IP;
t('IP test surface exported', !!IP && typeof IP.parseSpfRecord === 'function');

// ---- SPF parser ----
let p = IP.parseSpfRecord('v=spf1 include:_spf.google.com ip4:1.2.3.4 -all');
t('spf: -all detected', p.allQual === '-');
t('spf: include captured', p.includes[0] === '_spf.google.com');
t('spf: lookup count (include only)', p.localLookups === 1);
p = IP.parseSpfRecord('v=spf1 a mx include:x.com include:y.com redirect=z.com');
t('spf: a+mx+2incl+redirect = 5 lookups', p.localLookups === 5);
t('spf: redirect captured', p.redirect === 'z.com');
p = IP.parseSpfRecord('v=spf1 +all');
t('spf: +all detected', p.allQual === '+');
p = IP.parseSpfRecord('v=spf1 include:%{d}.spf.example.com ~all');
t('spf: macro flagged', p.hasMacro === true);
t('spf: macro include NOT recursed', p.includes.length === 0);
p = IP.parseSpfRecord('v=spf1 ip4:1.2.3.0/24 ?all');
t('spf: ?all neutral', p.allQual === '?');
t('spf: ip4 costs no lookup', p.localLookups === 0);

// ---- DMARC parser ----
let d = IP.parseDmarc('v=DMARC1; p=reject; rua=mailto:a@b.c; pct=100');
t('dmarc: p=reject', d.p === 'reject');
t('dmarc: rua parsed', d.rua === 'mailto:a@b.c');
d = IP.parseDmarc('v=DMARC1;p = none');
t('dmarc: whitespace tolerant', d.p === 'none');

// ---- org domain heuristic ----
t('orgDomain: plain', IP.orgDomain('mail.acme.com') === 'acme.com');
t('orgDomain: co.uk', IP.orgDomain('mail.acme.co.uk') === 'acme.co.uk');
t('orgDomain: bare stays', IP.orgDomain('acme.com') === 'acme.com');

// ---- TXT joining ----
const joined = IP.txtStrings({ answers: [{ type: 16, data: '"v=spf1 ip4:1.1.1.1 " "-all"' }] });
t('txt: split strings joined', joined[0] === 'v=spf1 ip4:1.1.1.1 -all');

// ---- grade engine ----
const mk = (dp, spfQ, spfSt, dkimSt, mxSt, spfRecs = ['x']) => ({
  dmarc: { policy: dp }, spf: { allQual: spfQ, status: spfSt, records: spfRecs },
  dkim: { status: dkimSt }, mx: { status: mxSt }, bimi: { status: 'info' } });
t('grade: full stack = A/A+', ['A', 'A+'].includes(IP.computeGrade(mk('reject', '-', 'pass', 'pass', 'pass')).letter));
t('grade: no DMARC capped at D', ['D', 'F'].includes(IP.computeGrade(mk(null, '-', 'pass', 'pass', 'pass')).letter));
t('grade: +all forces F', IP.computeGrade(mk('reject', '+', 'fail', 'pass', 'pass')).letter === 'F');
t('grade: multiple SPF forces F', IP.computeGrade(mk('reject', null, 'fail', 'pass', 'pass', ['a', 'b'])).letter === 'F');
t('grade: p=none is midtier', ['C', 'D'].includes(IP.computeGrade(mk('none', '~', 'pass', 'warn', 'pass')).letter));

// ---- domain normalization (IDN/punycode via URL API) ----
const nd = sandbox.normalizeDomain;
t('norm: bare domain', nd('Acme.COM ') === 'acme.com');
t('norm: strips url', nd('https://acme.com/x?y') === 'acme.com');
t('norm: IDN → punycode', nd('bücher.de') === 'xn--bcher-kva.de');
t('norm: garbage rejected', nd('not a domain') === null);
t('norm: empty rejected', nd('') === null);

// ---- license verify (node-side mirror of verify.js) ----
const vsrc = fs.readFileSync('verify.js', 'utf8');
const pub = vsrc.match(/PUBLIC_KEY_B64URL = '([^']+)'/)[1];
const demo = process.env.DEMO_LICENSE || '';
if (demo) {
  const [, pl, sg] = demo.split('.');
  const pubDer = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(pub, 'base64url')]);
  const key = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' });
  t('license: demo key verifies', crypto.verify(null, Buffer.from(pl, 'base64url'), key, Buffer.from(sg, 'base64url')));
  const bad = Buffer.from(sg, 'base64url'); bad[0] ^= 0xff;
  t('license: tampered sig rejected', !crypto.verify(null, Buffer.from(pl, 'base64url'), key, bad));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
