#!/usr/bin/env node
// Hook every fingerprint-relevant property getter and method, log only the calls
// originating from Castle's ondemand chunk. This recovers what Castle collects
// — i.e. the plaintext payload before per-field encryption.

import fs from 'fs';
import { chromium } from 'playwright';

const TARGET_URL = 'https://x.com/i/flow/login';

const INSTRUMENT = `
(() => {
  if (window.__readtap) return;
  window.__readtap = true;
  window.__reads = [];

  const CASTLE_RE = /ondemand\\.castle\\./;
  // truncate so JSON dump doesn't explode on canvas dataURLs etc.
  const truncate = (v) => {
    if (typeof v === 'string' && v.length > 600) return v.slice(0, 600) + '…+' + (v.length - 600);
    if (v && typeof v === 'object' && v.length > 100) return '[len=' + v.length + ']';
    return v;
  };
  const stringify = (v) => {
    if (v === null) return null;
    if (v === undefined) return undefined;
    const t = typeof v;
    if (t === 'function') return '[fn]';
    if (t === 'string' || t === 'number' || t === 'boolean') return v;
    if (Array.isArray(v)) return v.slice(0, 10).map(stringify);
    if (t === 'object') {
      try {
        if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return '[BinaryView len=' + (v.byteLength||v.length) + ']';
      } catch(e){}
      const out = {};
      let n = 0;
      for (const k of Object.keys(v)) {
        if (n++ > 12) { out['…'] = '+' + (Object.keys(v).length - n) + ' more'; break; }
        try { out[k] = stringify(v[k]); } catch(e){ out[k] = '[err]'; }
      }
      return out;
    }
    return String(v).slice(0, 200);
  };

  const isCastle = () => {
    try {
      const s = new Error().stack || '';
      return CASTLE_RE.test(s);
    } catch (e) { return false; }
  };

  const recordRead = (channel, what, value, extra) => {
    if (!isCastle()) return;
    try {
      window.__reads.push({
        ts: performance.now(),
        ord: window.__reads.length,
        ch: channel,
        what,
        value: truncate(stringify(value)),
        ...(extra || {})
      });
    } catch (e) {}
  };

  // ---- property-getter wrapper helpers ----
  const wrapGetter = (proto, prop, channel) => {
    try {
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || !desc.get) return;
      const origGet = desc.get;
      Object.defineProperty(proto, prop, {
        configurable: true,
        enumerable: desc.enumerable,
        get() {
          const v = origGet.call(this);
          recordRead(channel, prop, v);
          return v;
        }
      });
    } catch (e) {}
  };
  const wrapMethod = (proto, method, channel, argFmt) => {
    try {
      const orig = proto[method];
      if (typeof orig !== 'function') return;
      proto[method] = function (...args) {
        const r = orig.apply(this, args);
        recordRead(channel, method, argFmt ? argFmt(args, r) : { args: args.map(stringify), result: stringify(r) });
        return r;
      };
    } catch (e) {}
  };

  // ---- navigator ----
  for (const p of ['userAgent','appVersion','platform','vendor','vendorSub','product','productSub',
                   'language','languages','hardwareConcurrency','deviceMemory','maxTouchPoints',
                   'cookieEnabled','doNotTrack','webdriver','pdfViewerEnabled',
                   'plugins','mimeTypes','userAgentData','oscpu','buildID','onLine',
                   'connection']) {
    wrapGetter(Navigator.prototype, p, 'navigator');
  }
  // userAgentData methods
  if (window.navigator.userAgentData) {
    const proto = Object.getPrototypeOf(window.navigator.userAgentData);
    wrapMethod(proto, 'getHighEntropyValues', 'uaData');
  }
  // permissions (Castle probes this)
  if (navigator.permissions) {
    wrapMethod(Object.getPrototypeOf(navigator.permissions), 'query', 'permissions');
  }

  // ---- screen ----
  for (const p of ['width','height','availWidth','availHeight','colorDepth','pixelDepth',
                   'orientation']) {
    wrapGetter(Screen.prototype, p, 'screen');
  }

  // ---- window ----
  for (const p of ['innerWidth','innerHeight','outerWidth','outerHeight','devicePixelRatio',
                   'screenX','screenY']) {
    try {
      const desc = Object.getOwnPropertyDescriptor(window, p);
      if (desc && desc.get) {
        const orig = desc.get;
        Object.defineProperty(window, p, {
          configurable: true, get() { const v = orig.call(this); recordRead('window', p, v); return v; }
        });
      }
    } catch (e) {}
  }

  // ---- document ----
  wrapGetter(Document.prototype, 'cookie', 'document');
  wrapGetter(Document.prototype, 'referrer', 'document');
  wrapGetter(Document.prototype, 'title', 'document');
  wrapGetter(HTMLDocument.prototype, 'cookie', 'document');

  // ---- location ----
  for (const p of ['hostname','host','port','pathname','protocol','href','origin','search']) {
    try {
      const desc = Object.getOwnPropertyDescriptor(Location.prototype, p);
      if (desc && desc.get) {
        const orig = desc.get;
        Object.defineProperty(Location.prototype, p, {
          configurable: true, get() { const v = orig.call(this); recordRead('location', p, v); return v; }
        });
      }
    } catch (e) {}
  }

  // ---- Date ----
  wrapMethod(Date.prototype, 'getTimezoneOffset', 'date');
  wrapMethod(Date.prototype, 'toLocaleString', 'date');
  wrapMethod(Date.prototype, 'toString', 'date');
  wrapMethod(Date.prototype, 'getTime', 'date');
  const origDateNow = Date.now;
  Date.now = function () { const v = origDateNow.call(this); recordRead('date', 'Date.now', v); return v; };

  // ---- Intl ----
  if (typeof Intl !== 'undefined' && Intl.DateTimeFormat) {
    const origDTF = Intl.DateTimeFormat;
    function DTF(...args) {
      const inst = new origDTF(...args);
      const origResolve = inst.resolvedOptions;
      inst.resolvedOptions = function () { const v = origResolve.call(this); recordRead('intl', 'resolvedOptions', v); return v; };
      return inst;
    }
    DTF.prototype = origDTF.prototype;
    // can't easily replace Intl.DateTimeFormat constructor safely; just leave alone
  }

  // ---- performance ----
  if (typeof performance !== 'undefined') {
    wrapGetter(Performance.prototype, 'timeOrigin', 'performance');
    wrapMethod(Performance.prototype, 'getEntriesByType', 'performance');
    wrapMethod(Performance.prototype, 'getEntries', 'performance');
    wrapMethod(Performance.prototype, 'now', 'performance');
    // performance.memory (chromium-only)
    try {
      const desc = Object.getOwnPropertyDescriptor(Performance.prototype, 'memory');
      if (desc && desc.get) {
        const orig = desc.get;
        Object.defineProperty(Performance.prototype, 'memory', {
          configurable: true, get() { const v = orig.call(this); recordRead('performance', 'memory', v); return v; }
        });
      }
    } catch (e) {}
  }

  // ---- matchMedia ----
  if (window.matchMedia) {
    const origMM = window.matchMedia.bind(window);
    window.matchMedia = function (q) { const m = origMM(q); recordRead('matchMedia', q, m && m.matches); return m; };
  }

  // ---- WebGL ----
  function wrapWebGL(proto, label) {
    if (!proto) return;
    const origGP = proto.getParameter;
    if (origGP) {
      proto.getParameter = function (p) {
        const v = origGP.call(this, p);
        recordRead('webgl', label + '.getParameter', v, { param: p });
        return v;
      };
    }
    const origGE = proto.getExtension;
    if (origGE) {
      proto.getExtension = function (name) {
        const v = origGE.call(this, name);
        recordRead('webgl', label + '.getExtension', name);
        return v;
      };
    }
    const origGSP = proto.getShaderPrecisionFormat;
    if (origGSP) {
      proto.getShaderPrecisionFormat = function (st, t) {
        const v = origGSP.call(this, st, t);
        recordRead('webgl', label + '.getShaderPrecisionFormat', { shaderType: st, precisionType: t, result: v && {p:v.precision,rmin:v.rangeMin,rmax:v.rangeMax} });
        return v;
      };
    }
  }
  if (typeof WebGLRenderingContext !== 'undefined') wrapWebGL(WebGLRenderingContext.prototype, 'WebGL1');
  if (typeof WebGL2RenderingContext !== 'undefined') wrapWebGL(WebGL2RenderingContext.prototype, 'WebGL2');

  // ---- Canvas ----
  if (typeof CanvasRenderingContext2D !== 'undefined') {
    const proto = CanvasRenderingContext2D.prototype;
    wrapMethod(proto, 'measureText', 'canvas', (args, r) => ({ text: args[0], width: r && r.width }));
    wrapMethod(proto, 'fillText', 'canvas', (args) => ({ text: args[0], x: args[1], y: args[2] }));
    wrapMethod(proto, 'strokeText', 'canvas', (args) => ({ text: args[0] }));
    wrapMethod(proto, 'getImageData', 'canvas', (args, r) => ({
      x: args[0], y: args[1], w: args[2], h: args[3], sampleHash: r && r.data ? r.data.slice(0, 16).join(',') : null
    }));
  }
  if (typeof HTMLCanvasElement !== 'undefined') {
    wrapMethod(HTMLCanvasElement.prototype, 'toDataURL', 'canvas', (args, r) => ({ args, len: r && r.length, head: r && r.slice(0, 80) }));
  }

  // ---- Audio ----
  if (typeof OfflineAudioContext !== 'undefined') {
    const orig = OfflineAudioContext.prototype.startRendering;
    if (orig) {
      OfflineAudioContext.prototype.startRendering = function () { recordRead('audio', 'startRendering', null); return orig.call(this); };
    }
  }

  // ---- WebRTC (just count) ----
  if (typeof RTCPeerConnection !== 'undefined') {
    const orig = RTCPeerConnection.prototype.createDataChannel;
    if (orig) {
      RTCPeerConnection.prototype.createDataChannel = function (...a) { recordRead('rtc', 'createDataChannel', a); return orig.apply(this, a); };
    }
  }

  // ---- Crypto ----
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const orig = crypto.getRandomValues.bind(crypto);
    crypto.getRandomValues = function (a) { recordRead('crypto', 'getRandomValues', { len: a && a.length, type: a && a.constructor.name }); return orig(a); };
  }

  // ---- Storage ----
  for (const s of ['localStorage','sessionStorage']) {
    try {
      const obj = window[s];
      if (obj) {
        const origGet = obj.getItem.bind(obj);
        obj.getItem = function (k) { const v = origGet(k); recordRead('storage', s + '.getItem', { key: k, value: v }); return v; };
      }
    } catch (e) {}
  }
  try {
    if (indexedDB && indexedDB.open) {
      const orig = indexedDB.open.bind(indexedDB);
      indexedDB.open = function (...a) { recordRead('storage', 'indexedDB.open', a); return orig(...a); };
    }
  } catch (e) {}

  // ---- error dialect probes ----
  // wrap Object.assign/Object.create with __proto__ would be invasive; instead
  // just catch any Error constructor call with cyclic-proto messages.
  // skip — caught in the byte tap

  console.log('[readtap] hooks installed');
})();
`;

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  viewport: { width: 1280, height: 800 },
});
await ctx.addInitScript(INSTRUMENT);

const page = await ctx.newPage();
page.on('console', (m) => { if (/readtap|castle/i.test(m.text())) console.log(`  [browser] ${m.text().slice(0,200)}`); });
page.on('pageerror', (e) => console.log(`  [pageerror] ${e.message.slice(0, 200)}`));

console.log(`navigate → ${TARGET_URL}`);
await page.goto(TARGET_URL, { waitUntil: 'domcontentloaded', timeout: 45_000 });

console.log('settle 18s for SDK + auto-fire');
await new Promise((r) => setTimeout(r, 18_000));

const reads = await page.evaluate(() => window.__reads || []);
console.log(`\ntotal Castle-attributed reads: ${reads.length}`);

await browser.close();

// ---- analysis ----
const byChannel = new Map();
for (const r of reads) {
  if (!byChannel.has(r.ch)) byChannel.set(r.ch, []);
  byChannel.get(r.ch).push(r);
}
console.log(`\n=== reads grouped by channel ===`);
for (const [ch, rs] of [...byChannel.entries()].sort((a,b)=>b[1].length-a[1].length)) {
  console.log(`  ${ch}: ${rs.length} reads`);
}

// Show unique (channel, what) tuples with sample values
const uniq = new Map();
for (const r of reads) {
  const k = r.ch + ':' + r.what;
  if (!uniq.has(k)) uniq.set(k, { count: 0, samples: [] });
  const e = uniq.get(k);
  e.count++;
  if (e.samples.length < 3) e.samples.push(r.value);
}
console.log(`\n=== unique (channel, signal) reads with sample values — sorted by call count ===`);
const ranked = [...uniq.entries()].sort((a,b) => b[1].count - a[1].count);
for (const [k, e] of ranked) {
  const sampStr = JSON.stringify(e.samples[0]).slice(0, 140);
  console.log(`  ${e.count.toString().padStart(4)}× ${k.padEnd(40)} ${sampStr}`);
}

fs.writeFileSync('./results/readtap.json', JSON.stringify({
  totalReads: reads.length,
  byChannel: Object.fromEntries([...byChannel.entries()].map(([k,v])=>[k,v.length])),
  uniqueSignals: Object.fromEntries(ranked.map(([k,e])=>[k,{count:e.count, samples:e.samples}])),
  reads,
}, null, 2));
console.log('\nwrote ./results/readtap.json');
