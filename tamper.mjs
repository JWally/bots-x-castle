#!/usr/bin/env node
// Demonstrate value tampering on x.com Castle: patch the prototype getters
// Castle reads from, BEFORE the bundle loads, then run readtap to verify
// Castle saw the lies. Castle ciphers the spoofed values into its own
// otherwise-valid token. No cipher reversal needed.
//
// Run order:
//   1. Baseline: readtap only, no lies. Capture what Castle reads on
//      headless+Linux+SwiftShader.
//   2. Tampered: chrome-win-style lies + Function.prototype.toString
//      forgery + readtap. Capture what Castle reads when we lie to it.
//
// Diff produces: signal → (baseline value, tampered value). The lies
// should appear in __reads as the value Castle saw.

import fs from 'fs';
import { chromium } from 'playwright';

const TARGET_URL = 'https://x.com/i/flow/login';

// ---- LIE PROFILE: chrome-win-ish spoof, plus Function.prototype.toString lying ----
// Installed BEFORE any page script. Order matters: lies first, then readtap
// wraps over them so __reads captures what Castle actually saw post-lie.
const LIES = `
(() => {
  if (window.__lies_applied) return;
  window.__lies_applied = true;

  // ---- Function.prototype.toString forgery (Castle.md §4.7) ----
  const lyingToStringMap = new WeakMap();
  const _origFnToString = Function.prototype.toString;
  Function.prototype.toString = function () {
    if (lyingToStringMap.has(this)) return lyingToStringMap.get(this);
    return _origFnToString.call(this);
  };
  // also lie about the wrapped Function.prototype.toString itself
  lyingToStringMap.set(Function.prototype.toString, 'function toString() { [native code] }');

  const lieAsNative = (fn, name) => {
    lyingToStringMap.set(fn, 'function ' + (name || 'get') + '() { [native code] }');
    return fn;
  };

  // Patch on prototype so both navigator.X and OGOPD(Navigator.prototype, 'X').get.call(navigator) hit it.
  const defineNativeGetter = (host, prop, value) => {
    try {
      const getter = lieAsNative(function () { return value; }, 'get ' + prop);
      Object.defineProperty(host, prop, { get: getter, configurable: true });
    } catch (e) {}
  };

  const UA_WIN = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
  const APP_VER_WIN = '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

  // ---- navigator ----
  defineNativeGetter(Navigator.prototype, 'webdriver', undefined);   // huge bot tell — Linux headless reports true
  defineNativeGetter(Navigator.prototype, 'userAgent', UA_WIN);
  defineNativeGetter(Navigator.prototype, 'appVersion', APP_VER_WIN);
  defineNativeGetter(Navigator.prototype, 'platform', 'Win32');
  defineNativeGetter(Navigator.prototype, 'vendor', 'Google Inc.');
  defineNativeGetter(Navigator.prototype, 'productSub', '20030107');
  defineNativeGetter(Navigator.prototype, 'oscpu', undefined);
  defineNativeGetter(Navigator.prototype, 'language', 'en-US');
  defineNativeGetter(Navigator.prototype, 'languages', Object.freeze(['en-US', 'en']));
  defineNativeGetter(Navigator.prototype, 'cookieEnabled', true);
  defineNativeGetter(Navigator.prototype, 'doNotTrack', null);
  defineNativeGetter(Navigator.prototype, 'hardwareConcurrency', 8);   // change from real 12
  defineNativeGetter(Navigator.prototype, 'deviceMemory', 16);         // change from real 8
  defineNativeGetter(Navigator.prototype, 'maxTouchPoints', 0);
  defineNativeGetter(Navigator.prototype, 'pdfViewerEnabled', true);

  // ---- userAgentData (Chrome UA-CH) ----
  const fakeUaData = {
    brands: [
      { brand: 'Not_A Brand', version: '8' },
      { brand: 'Chromium', version: '131' },
      { brand: 'Google Chrome', version: '131' },
    ],
    mobile: false,
    platform: 'Windows',
    getHighEntropyValues: lieAsNative(function (hints) {
      return Promise.resolve({
        architecture: 'x86', bitness: '64',
        brands: this.brands, fullVersionList: this.brands,
        mobile: false, model: '', platform: 'Windows',
        platformVersion: '15.0.0', uaFullVersion: '131.0.6778.205', wow64: false,
      });
    }, 'getHighEntropyValues'),
    toJSON: lieAsNative(function () { return { brands: this.brands, mobile: this.mobile, platform: this.platform }; }, 'toJSON'),
  };
  defineNativeGetter(Navigator.prototype, 'userAgentData', fakeUaData);

  // ---- plugins / mimeTypes (real Chrome has these) ----
  function fakePlugin(name, description, filename) {
    return { name, description, filename, length: 0, item: () => null, namedItem: () => null };
  }
  const fakePlugins = [
    fakePlugin('PDF Viewer', 'Portable Document Format', 'internal-pdf-viewer'),
    fakePlugin('Chrome PDF Viewer', 'Portable Document Format', 'internal-pdf-viewer'),
    fakePlugin('Chromium PDF Viewer', 'Portable Document Format', 'internal-pdf-viewer'),
    fakePlugin('Microsoft Edge PDF Viewer', 'Portable Document Format', 'internal-pdf-viewer'),
    fakePlugin('WebKit built-in PDF', 'Portable Document Format', 'internal-pdf-viewer'),
  ];
  fakePlugins.item = function (i) { return this[i] || null; };
  fakePlugins.namedItem = function (n) { return this.find(p => p.name === n) || null; };
  fakePlugins.refresh = function () {};
  defineNativeGetter(Navigator.prototype, 'plugins', fakePlugins);

  const fakeMimeTypes = [
    { type: 'application/pdf', description: '', suffixes: 'pdf', enabledPlugin: fakePlugins[0] },
    { type: 'text/pdf', description: '', suffixes: 'pdf', enabledPlugin: fakePlugins[0] },
  ];
  fakeMimeTypes.item = function (i) { return this[i] || null; };
  fakeMimeTypes.namedItem = function (n) { return this.find(m => m.type === n) || null; };
  defineNativeGetter(Navigator.prototype, 'mimeTypes', fakeMimeTypes);

  // ---- WebGL (Castle reads via getParameter after getExtension WEBGL_debug_renderer_info) ----
  const FAKE_RENDERER        = 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)';
  const FAKE_VENDOR          = 'Google Inc. (NVIDIA)';
  const FAKE_MASKED_RENDERER = 'WebKit WebGL';
  const FAKE_MASKED_VENDOR   = 'WebKit';
  function wrapGetParameter(proto) {
    if (!proto || !proto.getParameter) return;
    const orig = proto.getParameter;
    const wrapped = function (param) {
      if (param === 37446) return FAKE_RENDERER;          // UNMASKED_RENDERER_WEBGL
      if (param === 37445) return FAKE_VENDOR;            // UNMASKED_VENDOR_WEBGL
      if (param === 7937)  return FAKE_MASKED_RENDERER;
      if (param === 7936)  return FAKE_MASKED_VENDOR;
      return orig.call(this, param);
    };
    lieAsNative(wrapped, 'getParameter');
    proto.getParameter = wrapped;
  }
  if (typeof WebGLRenderingContext  !== 'undefined') wrapGetParameter(WebGLRenderingContext.prototype);
  if (typeof WebGL2RenderingContext !== 'undefined') wrapGetParameter(WebGL2RenderingContext.prototype);

  // ---- screen / window (consistent with claimed UA) ----
  defineNativeGetter(Screen.prototype, 'width',  1920);
  defineNativeGetter(Screen.prototype, 'height', 1080);
  defineNativeGetter(Screen.prototype, 'availWidth',  1920);
  defineNativeGetter(Screen.prototype, 'availHeight', 1040);

  // ---- Castle.md §3.3: matchMedia cross-validates screen via DPI binary search + device-width queries ----
  // Defeat by intercepting (max-resolution: Xdpi) and (device-width: Ypx) queries.
  // We claim devicePixelRatio=1, screen 1920×1080. matchMedia must return consistent answers.
  const origMM = window.matchMedia.bind(window);
  const matchMediaLie = function (q) {
    // DPI binary search — claim 96dpi (standard desktop)
    let m;
    if ((m = /\\(max-resolution:\\s*(\\d+)dpi\\)/.exec(q))) {
      const dpi = parseInt(m[1], 10);
      const fakeMatches = dpi >= 96;
      return { matches: fakeMatches, media: q, addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {}, onchange: null, dispatchEvent: () => true };
    }
    if ((m = /\\(min-resolution:\\s*(\\d+)dpi\\)/.exec(q))) {
      const dpi = parseInt(m[1], 10);
      const fakeMatches = dpi <= 96;
      return { matches: fakeMatches, media: q, addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {}, onchange: null, dispatchEvent: () => true };
    }
    if ((m = /\\(resolution:\\s*(\\d+(?:\\.\\d+)?)dppx\\)/.exec(q))) {
      const dppx = parseFloat(m[1]);
      const fakeMatches = Math.abs(dppx - 1) < 1e-6;
      return { matches: fakeMatches, media: q, addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {}, onchange: null, dispatchEvent: () => true };
    }
    if ((m = /\\(device-width:\\s*(\\d+)px\\)/.exec(q))) {
      const w = parseInt(m[1], 10);
      const fakeMatches = w === 1920;
      const result = { matches: fakeMatches, media: q, addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {}, onchange: null, dispatchEvent: () => true };
      return result;
    }
    if ((m = /\\(device-height:\\s*(\\d+)px\\)/.exec(q))) {
      const h = parseInt(m[1], 10);
      return { matches: h === 1080, media: q, addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {}, onchange: null, dispatchEvent: () => true };
    }
    // composite queries (device-width AND device-height)
    if (/device-width:\\s*1920.*device-height:\\s*1080|device-height:\\s*1080.*device-width:\\s*1920/.test(q)) {
      return { matches: true, media: q, addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {}, onchange: null, dispatchEvent: () => true };
    }
    // pass-through for color-scheme etc
    return origMM(q);
  };
  lieAsNative(matchMediaLie, 'matchMedia');
  window.matchMedia = matchMediaLie;

  // devicePixelRatio = 1
  try {
    const desc = Object.getOwnPropertyDescriptor(window, 'devicePixelRatio');
    if (desc && desc.get) {
      Object.defineProperty(window, 'devicePixelRatio', { configurable: true, get: lieAsNative(function () { return 1; }, 'get devicePixelRatio') });
    }
  } catch (e) {}

  // ---- WEBGL_debug_renderer_info extension still returns the constants (don't nullify; Castle then reads via getParameter) ----
  // No change needed here — Castle.md showed Castle uses getExtension to get the constants, then getParameter(37446/37445).
  // Our getParameter override handles both.

  // Tally what we lied about for output
  window.__lies = {
    'navigator.webdriver': { lied: 'undefined' },
    'navigator.userAgent': { lied: UA_WIN.slice(0, 80) + '…' },
    'navigator.appVersion': { lied: APP_VER_WIN.slice(0, 80) + '…' },
    'navigator.platform': { lied: 'Win32' },
    'navigator.hardwareConcurrency': { lied: 8 },
    'navigator.deviceMemory': { lied: 16 },
    'navigator.userAgentData.platform': { lied: 'Windows' },
    'navigator.plugins.length': { lied: 5 },
    'navigator.mimeTypes.length': { lied: 2 },
    'WebGL.getParameter(37446)': { lied: FAKE_RENDERER },
    'WebGL.getParameter(37445)': { lied: FAKE_VENDOR },
    'screen.width':  { lied: 1920 },
    'screen.height': { lied: 1080 },
    'devicePixelRatio': { lied: 1 },
    'matchMedia(device-width:1920)': { lied: true },
    'matchMedia(device-height:1080)': { lied: true },
    'matchMedia(max-resolution:96dpi)': { lied: true },
  };

  console.log('[lies] installed');
})();
`;

// ---- READ TAP: log Castle's reads (after lies are applied, so this captures what Castle saw) ----
const READTAP = `
(() => {
  if (window.__readtap) return;
  window.__readtap = true;
  window.__reads = [];
  window.__btoaCalls = [];

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

  // btoa counter (so we can verify tokens still build)
  const realBtoa = window.btoa.bind(window);
  window.btoa = function (s) {
    try {
      if (CASTLE_RE.test(new Error().stack || '')) {
        window.__btoaCalls.push({ ts: performance.now(), ord: window.__btoaCalls.length, len: typeof s === 'string' ? s.length : -1 });
      }
    } catch (e) {}
    return realBtoa(s);
  };

  // -- Stack a NEW wrapper around the (possibly-already-wrapped) getter so we log what Castle actually saw --
  const wrapGetter = (proto, prop, channel) => {
    try {
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || !desc.get) return;
      const origGet = desc.get;
      Object.defineProperty(proto, prop, {
        configurable: true, enumerable: desc.enumerable,
        get() { const v = origGet.call(this); recordRead(channel, prop, v); return v; }
      });
    } catch (e) {}
  };
  const wrapMethod = (proto, method, channel, argFmt) => {
    try {
      const orig = proto[method];
      if (typeof orig !== 'function') return;
      proto[method] = function (...args) { const r = orig.apply(this, args); recordRead(channel, method, argFmt ? argFmt(args, r) : { args: args.map(stringify), result: stringify(r) }); return r; };
    } catch (e) {}
  };

  for (const p of ['userAgent','appVersion','platform','vendor','productSub','language','languages',
                   'hardwareConcurrency','deviceMemory','maxTouchPoints','cookieEnabled','doNotTrack',
                   'webdriver','pdfViewerEnabled','plugins','mimeTypes','userAgentData','oscpu']) {
    wrapGetter(Navigator.prototype, p, 'navigator');
  }
  for (const p of ['width','height','availWidth','availHeight','colorDepth','pixelDepth']) wrapGetter(Screen.prototype, p, 'screen');
  for (const p of ['innerWidth','innerHeight','outerWidth','outerHeight','devicePixelRatio']) {
    try {
      const desc = Object.getOwnPropertyDescriptor(window, p);
      if (desc && desc.get) {
        const orig = desc.get;
        Object.defineProperty(window, p, { configurable: true, get() { const v = orig.call(this); recordRead('window', p, v); return v; } });
      }
    } catch (e) {}
  }
  wrapGetter(Document.prototype, 'cookie', 'document');

  // matchMedia — wrap our own lie wrapper to log
  const realMM = window.matchMedia.bind(window);
  window.matchMedia = function (q) {
    const r = realMM(q);
    recordRead('matchMedia', q, r && r.matches);
    return r;
  };

  // WebGL
  function wrapWebGL(proto, label) {
    if (!proto) return;
    const origGP = proto.getParameter;
    if (origGP) {
      proto.getParameter = function (p) { const v = origGP.call(this, p); recordRead('webgl', label + '.getParameter', v, { param: p }); return v; };
    }
    const origGE = proto.getExtension;
    if (origGE) {
      proto.getExtension = function (name) { const v = origGE.call(this, name); recordRead('webgl', label + '.getExtension', name); return v; };
    }
  }
  if (typeof WebGLRenderingContext !== 'undefined') wrapWebGL(WebGLRenderingContext.prototype, 'WebGL1');
  if (typeof WebGL2RenderingContext !== 'undefined') wrapWebGL(WebGL2RenderingContext.prototype, 'WebGL2');

  // canvas (don't fake, just count)
  if (typeof CanvasRenderingContext2D !== 'undefined') {
    wrapMethod(CanvasRenderingContext2D.prototype, 'measureText', 'canvas', (args, r) => ({ text: args[0], width: r && r.width }));
    wrapMethod(CanvasRenderingContext2D.prototype, 'fillText', 'canvas', (args) => ({ text: args[0], x: args[1], y: args[2] }));
    wrapMethod(CanvasRenderingContext2D.prototype, 'getImageData', 'canvas', (args) => ({ x: args[0], y: args[1], w: args[2], h: args[3] }));
  }
  if (typeof HTMLCanvasElement !== 'undefined') wrapMethod(HTMLCanvasElement.prototype, 'toDataURL', 'canvas', (args, r) => ({ len: r && r.length }));

  // storage
  for (const s of ['localStorage','sessionStorage']) {
    try { const obj = window[s]; if (obj) { const origGet = obj.getItem.bind(obj); obj.getItem = function (k) { const v = origGet(k); recordRead('storage', s + '.getItem', { key: k, value: v }); return v; }; } } catch (e) {}
  }

  // userAgentData methods
  if (window.navigator.userAgentData) {
    wrapMethod(Object.getPrototypeOf(window.navigator.userAgentData), 'getHighEntropyValues', 'uaData');
  }

  console.log('[readtap] installed');
})();
`;

const apiHits = [];

async function runOne(label, applyLies) {
  console.log(`\n========== RUN: ${label} (lies=${applyLies}) ==========`);
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    viewport: { width: 1280, height: 800 },
  });

  // Lies FIRST, then readtap over them.
  if (applyLies) await ctx.addInitScript(LIES);
  await ctx.addInitScript(READTAP);

  const page = await ctx.newPage();
  page.on('console', (m) => { if (/lies|readtap|castle/i.test(m.text())) console.log(`  [browser] ${m.text().slice(0,200)}`); });
  page.on('pageerror', (e) => console.log(`  [pageerror] ${e.message.slice(0, 200)}`));

  const localApiHits = [];
  page.on('request', async (req) => {
    const url = req.url();
    if (!/x\.com\/(i\/api|1\.1\/onboarding|1\.1\/jot|1\.1\/graphql|1\.1\/guest)|api\.x\.com\/(1\.1\/onboarding|1\.1\/jot|1\.1\/graphql|1\.1\/guest)/.test(url)) return;
    let bodyInfo = null;
    try {
      const post = req.postData();
      if (post) {
        const long = post.match(/[A-Za-z0-9_\-+/=]{300,}/g) || [];
        bodyInfo = { len: post.length, longBase64Lens: long.map(s => s.length) };
      }
    } catch (e) {}
    localApiHits.push({ method: req.method(), url: url.slice(0, 110), bodyInfo });
  });

  console.log(`navigate → ${TARGET_URL}`);
  await page.goto(TARGET_URL, { waitUntil: 'domcontentloaded', timeout: 45_000 });

  console.log('settle 25s for SDK + page-load fire');
  await new Promise((r) => setTimeout(r, 25_000));

  let submitted = false;
  let submitErr = null;
  try {
    const input = await page.waitForSelector('input[autocomplete="username"], input[name="text"]', { timeout: 15_000 });
    await input.fill('test_account_' + Date.now() + '@example.com');
    const nextBtn = await page.waitForSelector('button:has-text("Next"), [role="button"]:has-text("Next")', { timeout: 8_000 });
    await nextBtn.click();
    console.log('  clicked Next');
    submitted = true;
  } catch (e) {
    submitErr = e.message.slice(0, 200);
    console.log(`  submit failed: ${submitErr}`);
  }

  console.log('settle 12s for post-submit fires');
  await new Promise((r) => setTimeout(r, 12_000));

  const reads = await page.evaluate(() => window.__reads);
  const btoaCalls = await page.evaluate(() => window.__btoaCalls);
  const lies = await page.evaluate(() => window.__lies || null);
  await browser.close();

  // unique signal summary
  const sigMap = new Map();
  for (const r of reads) {
    const k = r.ch + ':' + r.what;
    if (!sigMap.has(k)) sigMap.set(k, { count: 0, samples: [] });
    const e = sigMap.get(k);
    e.count++;
    if (e.samples.length < 1) e.samples.push(r.value);
  }
  return { label, applyLies, reads, btoaCalls, lies, apiHits: localApiHits, sigMap: Object.fromEntries(sigMap), submitted, submitErr };
}

// ---- run both sequentially ----
const baseline = await runOne('baseline', false);
const tampered = await runOne('tampered', true);

// ---- diff what Castle saw ----
function getSig(run, ch, what) {
  const key = ch + ':' + what;
  const e = run.sigMap[key];
  return e ? { count: e.count, value: e.samples[0] } : null;
}

const interesting = [
  ['navigator', 'webdriver'],
  ['navigator', 'userAgent'],
  ['navigator', 'platform'],
  ['navigator', 'vendor'],
  ['navigator', 'hardwareConcurrency'],
  ['navigator', 'deviceMemory'],
  ['navigator', 'languages'],
  ['navigator', 'language'],
  ['navigator', 'plugins'],
  ['navigator', 'mimeTypes'],
  ['navigator', 'userAgentData'],
  ['screen', 'width'],
  ['screen', 'height'],
  ['screen', 'availWidth'],
  ['window', 'devicePixelRatio'],
  ['webgl', 'WebGL1.getParameter'],
  ['matchMedia', '(device-width:1920px) and (device-height:1080px)'],
  ['matchMedia', '(max-resolution: 96dpi)'],
  ['matchMedia', '(resolution: 1dppx)'],
];

console.log('\n\n========== DIFF: what Castle read ==========\n');
console.log('signal'.padEnd(40), 'baseline'.padEnd(48), 'tampered');
console.log('-'.repeat(120));
const safeJSON = (v) => { const s = JSON.stringify(v); return s === undefined ? 'undefined' : s; };
for (const [ch, what] of interesting) {
  const b = getSig(baseline, ch, what);
  const t = getSig(tampered, ch, what);
  const bStr = b ? `${b.count}× ${safeJSON(b.value).slice(0, 44)}` : '(not read)';
  const tStr = t ? `${t.count}× ${safeJSON(t.value).slice(0, 44)}` : '(not read)';
  const flag = (b && t && safeJSON(b.value) !== safeJSON(t.value)) ? ' ← LIE LANDED' : '';
  console.log((ch + ':' + what).padEnd(40), bStr.padEnd(48), tStr + flag);
}

// ---- token submission survived? ----
function tokenStats(run) {
  const big = run.apiHits.find(h => h.bodyInfo && h.bodyInfo.longBase64Lens.some(l => l > 5000));
  const med = run.apiHits.find(h => h.bodyInfo && h.bodyInfo.longBase64Lens.some(l => l > 200 && l < 5000));
  return {
    bigTokenLen: big ? Math.max(...big.bodyInfo.longBase64Lens) : 0,
    medTokenLen: med ? Math.max(...med.bodyInfo.longBase64Lens) : 0,
    submitOk: run.submitted,
    btoaCalls: run.btoaCalls.length,
    largestBtoa: run.btoaCalls.reduce((m, c) => Math.max(m, c.len), 0),
  };
}
console.log('\n========== Token build survived? ==========');
console.log(`baseline: ${JSON.stringify(tokenStats(baseline))}`);
console.log(`tampered: ${JSON.stringify(tokenStats(tampered))}`);

// ---- save ----
const out = {
  ts: new Date().toISOString(),
  baseline: { sigMap: baseline.sigMap, btoaCount: baseline.btoaCalls.length, apiHits: baseline.apiHits, submitted: baseline.submitted, submitErr: baseline.submitErr },
  tampered: { sigMap: tampered.sigMap, btoaCount: tampered.btoaCalls.length, apiHits: tampered.apiHits, submitted: tampered.submitted, submitErr: tampered.submitErr, lies: tampered.lies },
};
fs.writeFileSync('./results/tamper.json', JSON.stringify(out, null, 2));
console.log('\nwrote ./results/tamper.json');
