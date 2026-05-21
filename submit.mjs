#!/usr/bin/env node
// Same read-tap as before, but inject checkpoint markers and drive an actual
// submit on the /i/flow/login form. Partition reads into:
//   [pre-pageload]  →  [pageload → submit]  →  [submit → end]
// to see what (if anything) Castle re-collects on the auth-event submit.

import fs from 'fs';
import { chromium } from 'playwright';

const TARGET_URL = 'https://x.com/i/flow/login';

const INSTRUMENT = `
(() => {
  if (window.__readtap) return;
  window.__readtap = true;
  window.__reads = [];
  window.__btoaCalls = [];
  window.__mark = (label) => {
    try {
      window.__reads.push({ ts: performance.now(), ord: window.__reads.length, ch: '__marker', what: label, value: null });
      window.__btoaCalls.push({ ts: performance.now(), ord: window.__btoaCalls.length, callsite: -1, len: -1, marker: label });
    } catch (e) {}
  };

  const CASTLE_RE = /ondemand\\.castle\\./;
  const truncate = (v) => (typeof v === 'string' && v.length > 600) ? v.slice(0, 600) + '…+' + (v.length - 600) : v;
  const stringify = (v) => {
    if (v === null) return null;
    if (v === undefined) return undefined;
    const t = typeof v;
    if (t === 'function') return '[fn]';
    if (t === 'string' || t === 'number' || t === 'boolean') return v;
    if (Array.isArray(v)) return v.slice(0, 10).map(stringify);
    if (t === 'object') {
      try { if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return '[BinaryView len=' + (v.byteLength||v.length) + ']'; } catch(e){}
      const out = {}; let n = 0;
      for (const k of Object.keys(v)) { if (n++ > 12) { out['…'] = '+' + (Object.keys(v).length - n) + ' more'; break; } try { out[k] = stringify(v[k]); } catch(e){ out[k] = '[err]'; } }
      return out;
    }
    return String(v).slice(0, 200);
  };
  const isCastle = () => { try { return CASTLE_RE.test(new Error().stack || ''); } catch (e) { return false; } };
  const recordRead = (channel, what, value, extra) => {
    if (!isCastle()) return;
    try { window.__reads.push({ ts: performance.now(), ord: window.__reads.length, ch: channel, what, value: truncate(stringify(value)), ...(extra || {}) }); } catch (e) {}
  };

  // wrap btoa to track encoding events (lets us see whether a token actually built post-submit)
  const realBtoa = window.btoa.bind(window);
  window.btoa = function (s) {
    try {
      if (CASTLE_RE.test(new Error().stack || '')) {
        window.__btoaCalls.push({ ts: performance.now(), ord: window.__btoaCalls.length, len: typeof s === 'string' ? s.length : -1, marker: null });
      }
    } catch (e) {}
    return realBtoa(s);
  };

  const wrapGetter = (proto, prop, channel) => {
    try {
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || !desc.get) return;
      const origGet = desc.get;
      Object.defineProperty(proto, prop, { configurable: true, enumerable: desc.enumerable, get() { const v = origGet.call(this); recordRead(channel, prop, v); return v; } });
    } catch (e) {}
  };
  const wrapMethod = (proto, method, channel, argFmt) => {
    try {
      const orig = proto[method];
      if (typeof orig !== 'function') return;
      proto[method] = function (...args) { const r = orig.apply(this, args); recordRead(channel, method, argFmt ? argFmt(args, r) : { args: args.map(stringify), result: stringify(r) }); return r; };
    } catch (e) {}
  };

  for (const p of ['userAgent','appVersion','platform','vendor','vendorSub','product','productSub','language','languages','hardwareConcurrency','deviceMemory','maxTouchPoints','cookieEnabled','doNotTrack','webdriver','pdfViewerEnabled','plugins','mimeTypes','userAgentData','oscpu','buildID','onLine','connection']) wrapGetter(Navigator.prototype, p, 'navigator');
  if (window.navigator.userAgentData) wrapMethod(Object.getPrototypeOf(window.navigator.userAgentData), 'getHighEntropyValues', 'uaData');
  if (navigator.permissions) wrapMethod(Object.getPrototypeOf(navigator.permissions), 'query', 'permissions');
  for (const p of ['width','height','availWidth','availHeight','colorDepth','pixelDepth','orientation']) wrapGetter(Screen.prototype, p, 'screen');
  for (const p of ['innerWidth','innerHeight','outerWidth','outerHeight','devicePixelRatio','screenX','screenY']) {
    try { const desc = Object.getOwnPropertyDescriptor(window, p); if (desc && desc.get) { const orig = desc.get; Object.defineProperty(window, p, { configurable: true, get() { const v = orig.call(this); recordRead('window', p, v); return v; } }); } } catch (e) {}
  }
  wrapGetter(Document.prototype, 'cookie', 'document');
  wrapGetter(Document.prototype, 'referrer', 'document');
  wrapGetter(Document.prototype, 'title', 'document');
  for (const p of ['hostname','host','port','pathname','protocol','href','origin','search']) {
    try { const desc = Object.getOwnPropertyDescriptor(Location.prototype, p); if (desc && desc.get) { const orig = desc.get; Object.defineProperty(Location.prototype, p, { configurable: true, get() { const v = orig.call(this); recordRead('location', p, v); return v; } }); } } catch (e) {}
  }
  wrapMethod(Date.prototype, 'getTimezoneOffset', 'date');
  wrapMethod(Date.prototype, 'toLocaleString', 'date');
  wrapMethod(Date.prototype, 'toString', 'date');
  wrapMethod(Date.prototype, 'getTime', 'date');
  const origDateNow = Date.now;
  Date.now = function () { const v = origDateNow.call(this); recordRead('date', 'Date.now', v); return v; };
  if (typeof performance !== 'undefined') {
    wrapGetter(Performance.prototype, 'timeOrigin', 'performance');
    wrapMethod(Performance.prototype, 'getEntriesByType', 'performance');
    wrapMethod(Performance.prototype, 'getEntries', 'performance');
    // NOTE: performance.now() wrap omitted — x.com's React calls it millions of
    // times and the per-call stack-walk in recordRead destroys page load.
    // We already documented Castle reads it ~2313× per token in the prior run.
    try { const desc = Object.getOwnPropertyDescriptor(Performance.prototype, 'memory'); if (desc && desc.get) { const orig = desc.get; Object.defineProperty(Performance.prototype, 'memory', { configurable: true, get() { const v = orig.call(this); recordRead('performance', 'memory', v); return v; } }); } } catch (e) {}
  }
  if (window.matchMedia) { const origMM = window.matchMedia.bind(window); window.matchMedia = function (q) { const m = origMM(q); recordRead('matchMedia', q, m && m.matches); return m; }; }
  function wrapWebGL(proto, label) {
    if (!proto) return;
    const origGP = proto.getParameter; if (origGP) proto.getParameter = function (p) { const v = origGP.call(this, p); recordRead('webgl', label + '.getParameter', v, { param: p }); return v; };
    const origGE = proto.getExtension; if (origGE) proto.getExtension = function (name) { const v = origGE.call(this, name); recordRead('webgl', label + '.getExtension', name); return v; };
    const origGSP = proto.getShaderPrecisionFormat; if (origGSP) proto.getShaderPrecisionFormat = function (st, t) { const v = origGSP.call(this, st, t); recordRead('webgl', label + '.getShaderPrecisionFormat', { shaderType: st, precisionType: t }); return v; };
  }
  if (typeof WebGLRenderingContext !== 'undefined') wrapWebGL(WebGLRenderingContext.prototype, 'WebGL1');
  if (typeof WebGL2RenderingContext !== 'undefined') wrapWebGL(WebGL2RenderingContext.prototype, 'WebGL2');
  if (typeof CanvasRenderingContext2D !== 'undefined') {
    const proto = CanvasRenderingContext2D.prototype;
    wrapMethod(proto, 'measureText', 'canvas', (args, r) => ({ text: args[0], width: r && r.width }));
    wrapMethod(proto, 'fillText', 'canvas', (args) => ({ text: args[0], x: args[1], y: args[2] }));
    wrapMethod(proto, 'strokeText', 'canvas', (args) => ({ text: args[0] }));
    wrapMethod(proto, 'getImageData', 'canvas', (args, r) => ({ x: args[0], y: args[1], w: args[2], h: args[3], sampleHash: r && r.data ? r.data.slice(0, 16).join(',') : null }));
  }
  if (typeof HTMLCanvasElement !== 'undefined') wrapMethod(HTMLCanvasElement.prototype, 'toDataURL', 'canvas', (args, r) => ({ args, len: r && r.length, head: r && r.slice(0, 80) }));
  if (typeof OfflineAudioContext !== 'undefined') { const orig = OfflineAudioContext.prototype.startRendering; if (orig) OfflineAudioContext.prototype.startRendering = function () { recordRead('audio', 'startRendering', null); return orig.call(this); }; }
  if (typeof RTCPeerConnection !== 'undefined') { const orig = RTCPeerConnection.prototype.createDataChannel; if (orig) RTCPeerConnection.prototype.createDataChannel = function (...a) { recordRead('rtc', 'createDataChannel', a); return orig.apply(this, a); }; }
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) { const orig = crypto.getRandomValues.bind(crypto); crypto.getRandomValues = function (a) { recordRead('crypto', 'getRandomValues', { len: a && a.length, type: a && a.constructor.name }); return orig(a); }; }
  for (const s of ['localStorage','sessionStorage']) { try { const obj = window[s]; if (obj) { const origGet = obj.getItem.bind(obj); obj.getItem = function (k) { const v = origGet(k); recordRead('storage', s + '.getItem', { key: k, value: v }); return v; }; } } catch (e) {} }
  try { if (indexedDB && indexedDB.open) { const orig = indexedDB.open.bind(indexedDB); indexedDB.open = function (...a) { recordRead('storage', 'indexedDB.open', a); return orig(...a); }; } } catch (e) {}

  console.log('[readtap+submit] hooks installed');
})();
`;

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  viewport: { width: 1280, height: 800 },
});
await ctx.addInitScript(INSTRUMENT);

const page = await ctx.newPage();
page.on('pageerror', (e) => console.log(`  [pageerror] ${e.message.slice(0, 200)}`));
const apiHits = [];
page.on('request', (req) => {
  const url = req.url();
  if (/x\.com\/i\/api\/|api\.x\.com|onboarding|sso/i.test(url)) {
    apiHits.push({ ts: Date.now(), method: req.method(), url: url.slice(0, 140), hasCastleHdr: !!req.headers()['x-client-transaction-id'] || /castle/i.test(JSON.stringify(req.headers())) });
  }
});

console.log(`navigate → ${TARGET_URL}`);
await page.goto(TARGET_URL, { waitUntil: 'domcontentloaded', timeout: 45_000 });
console.log('settle 25s for SDK + auto-fire (and React render of login form)');
await new Promise((r) => setTimeout(r, 25_000));

// Checkpoint: pageload-fire complete
await page.evaluate(() => window.__mark('PAGELOAD_FIRE_DONE'));
const postLoadStats = await page.evaluate(() => ({ reads: window.__reads.length, btoa: window.__btoaCalls.length }));
console.log(`  pageload fire: ${postLoadStats.reads} reads, ${postLoadStats.btoa} btoa calls`);

// --- find & fill the email/username input, click Next ---
console.log('\nlocating username input + Next button...');
let submitted = false;
let submitErr = null;
try {
  // x.com's flow uses <input autocomplete="username"> for the email field
  const input = await page.waitForSelector('input[autocomplete="username"], input[name="text"]', { timeout: 20_000 });
  await input.fill('test_account_' + Date.now() + '@example.com');
  console.log('  filled email field');

  await page.evaluate(() => window.__mark('BEFORE_NEXT_CLICK'));

  // Find Next button — x.com uses a role=button div with the text "Next"
  const nextBtn = await page.waitForSelector('button:has-text("Next"), [role="button"]:has-text("Next"), button[data-testid="LoginForm_Login_Button"]', { timeout: 10_000 });
  await nextBtn.click();
  console.log('  clicked Next');
  submitted = true;
  await page.evaluate(() => window.__mark('AFTER_NEXT_CLICK'));
} catch (e) {
  submitErr = e.message.slice(0, 200);
  console.log(`  submit failed: ${submitErr}`);
}

console.log('settle 15s for post-submit Castle fire');
await new Promise((r) => setTimeout(r, 15_000));
await page.evaluate(() => window.__mark('END_OF_RUN'));

const reads = await page.evaluate(() => window.__reads);
const btoaCalls = await page.evaluate(() => window.__btoaCalls);

await browser.close();

// ---- partition by markers ----
const markers = reads.filter(r => r.ch === '__marker').map(r => ({ ord: r.ord, label: r.what, ts: r.ts }));
console.log(`\n=== markers ===`);
for (const m of markers) console.log(`  ord=${m.ord} t=${m.ts.toFixed(0)}ms  ${m.label}`);

function bucket(ord) {
  let label = 'PRE';
  for (const m of markers) {
    if (ord >= m.ord) label = m.label;
  }
  return label;
}
const byBucket = new Map();
for (const r of reads) {
  if (r.ch === '__marker') continue;
  const b = bucket(r.ord);
  if (!byBucket.has(b)) byBucket.set(b, []);
  byBucket.get(b).push(r);
}
console.log(`\n=== reads per bucket ===`);
for (const [b, rs] of byBucket) console.log(`  ${b.padEnd(24)} ${rs.length}`);

console.log(`\n=== btoa calls per bucket (token rebuild marker) ===`);
const btoaByBucket = new Map();
const btoaMarkers = btoaCalls.filter(c => c.marker).map(c => ({ ord: c.ord, label: c.marker }));
function btoaBucket(ord) {
  let label = 'PRE';
  for (const m of btoaMarkers) if (ord >= m.ord) label = m.label;
  return label;
}
for (const c of btoaCalls) {
  if (c.marker) continue;
  const b = btoaBucket(c.ord);
  if (!btoaByBucket.has(b)) btoaByBucket.set(b, []);
  btoaByBucket.get(b).push(c);
}
for (const [b, cs] of btoaByBucket) console.log(`  ${b.padEnd(24)} ${cs.length}  (largest=${cs.reduce((m,c)=>Math.max(m,c.len),0)})`);

// Diff: what signals appear in AFTER_NEXT_CLICK that weren't in BEFORE_NEXT_CLICK
const sigKey = (r) => r.ch + ':' + r.what;
function uniqSet(rs) { const s = new Map(); for (const r of rs) { const k = sigKey(r); s.set(k, (s.get(k) || 0) + 1); } return s; }
const preBucket = byBucket.get('PAGELOAD_FIRE_DONE') || [];
const postBucket = byBucket.get('AFTER_NEXT_CLICK') || [];
const preSet = uniqSet(preBucket);
const postSet = uniqSet(postBucket);

console.log(`\n=== signals BEFORE submit (pageload bucket) ===`);
console.log(`  unique signals: ${preSet.size}`);
console.log(`  total reads:    ${preBucket.length}`);

console.log(`\n=== signals AFTER submit (post-click bucket) ===`);
console.log(`  unique signals: ${postSet.size}`);
console.log(`  total reads:    ${postBucket.length}`);

console.log(`\n=== signals NEW in post-submit (not in pageload bucket) ===`);
const newSignals = [...postSet.entries()].filter(([k]) => !preSet.has(k));
if (newSignals.length === 0) console.log('  (none)');
else for (const [k, n] of newSignals) console.log(`  +${n}× ${k}`);

console.log(`\n=== signals re-read MORE often post-submit (≥3× more) ===`);
for (const [k, n] of postSet.entries()) {
  const preN = preSet.get(k) || 0;
  if (preN > 0 && n >= 3 * preN) console.log(`  ${preN} → ${n}  ${k}`);
}

console.log(`\n=== x.com API requests captured ===`);
for (const r of apiHits.slice(0, 12)) console.log(`  ${r.method} ${r.url}`);

fs.writeFileSync('./results/submit.json', JSON.stringify({
  submitted, submitErr,
  markers,
  bucketCounts: Object.fromEntries([...byBucket.entries()].map(([k,v]) => [k, v.length])),
  btoaBucketCounts: Object.fromEntries([...btoaByBucket.entries()].map(([k,v]) => [k, v.length])),
  preSet: Object.fromEntries(preSet),
  postSet: Object.fromEntries(postSet),
  newSignals: Object.fromEntries(newSignals),
  apiHits,
  reads,
}, null, 2));
console.log('\nwrote ./results/submit.json');
