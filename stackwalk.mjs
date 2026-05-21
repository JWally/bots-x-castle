#!/usr/bin/env node
// Runtime instrumentation of x.com's Castle bundle:
//   - Wrap btoa BEFORE any script loads — every call records caller stack + input
//   - Wrap Uint8Array constructor — every alloc records stack
//   - Wrap Function.prototype.toString — every probe is logged (Castle's tamper check)
//   - Navigate to x.com/i/flow/login; wait for SDK init (requestIdleCallback, 5s)
//   - Hunt the webpack module cache for the Castle module exports; force-fire createRequestToken
//   - Dump everything; classify call stacks
//
// Goal: answer "is the new build's encoder still a single chokepoint, just better hidden,
// or has it been distributed across many sites?"

import fs from 'fs';
import { chromium } from 'playwright';

const INSTRUMENT = `
(() => {
  if (window.__instrumented) return;
  window.__instrumented = true;
  window.__btoaCalls = [];
  window.__uaCalls = [];
  window.__fnTsCalls = [];

  // ---- wrap btoa ----
  const realBtoa = window.btoa.bind(window);
  window.btoa = function (s) {
    let stack = '';
    try { stack = new Error().stack || ''; } catch (e) {}
    try {
      const head = typeof s === 'string' ? s.slice(0, 64) : '[non-string]';
      window.__btoaCalls.push({
        ts: performance.now(),
        len: typeof s === 'string' ? s.length : -1,
        head_hex: typeof s === 'string'
          ? Array.from(s.slice(0, 32)).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
          : '',
        // strip Error: prefix and first frame (our wrapper); keep top 8
        stack_top: stack.split('\\n').slice(2, 10).map(l => l.trim()).join(' | '),
      });
    } catch (e) {}
    return realBtoa(s);
  };

  // ---- wrap Uint8Array constructor ----
  const RealUA = window.Uint8Array;
  function WrappedUA(...args) {
    try {
      let stack = '';
      try { stack = new Error().stack || ''; } catch (e) {}
      const lenArg = args[0];
      window.__uaCalls.push({
        ts: performance.now(),
        arg_type: typeof lenArg,
        arg_len: (lenArg && lenArg.length) || (typeof lenArg === 'number' ? lenArg : -1),
        stack_top: stack.split('\\n').slice(2, 8).map(l => l.trim()).join(' | '),
      });
    } catch (e) {}
    return new RealUA(...args);
  }
  WrappedUA.prototype = RealUA.prototype;
  WrappedUA.BYTES_PER_ELEMENT = RealUA.BYTES_PER_ELEMENT;
  // Use a Proxy so existing identity checks pass
  window.Uint8Array = new Proxy(RealUA, {
    construct(target, args) {
      try {
        let stack = '';
        try { stack = new Error().stack || ''; } catch (e) {}
        const lenArg = args[0];
        window.__uaCalls.push({
          ts: performance.now(),
          arg_type: typeof lenArg,
          arg_len: (lenArg && lenArg.length) || (typeof lenArg === 'number' ? lenArg : -1),
          stack_top: stack.split('\\n').slice(2, 8).map(l => l.trim()).join(' | '),
        });
      } catch (e) {}
      return Reflect.construct(target, args);
    }
  });

  // ---- wrap Function.prototype.toString (count, don't lie) ----
  const realFnTs = Function.prototype.toString;
  Function.prototype.toString = function () {
    try {
      let stack = '';
      try { stack = new Error().stack || ''; } catch (e) {}
      const top = stack.split('\\n').slice(2, 5).map(l => l.trim()).join(' | ');
      if (window.__fnTsCalls.length < 5000) {
        window.__fnTsCalls.push({
          target: (this && this.name) || '<anon>',
          stack_top: top,
        });
      }
    } catch (e) {}
    return realFnTs.call(this);
  };

  // Anchor a hunting helper for after-load discovery
  window.__hunt = () => {
    // 1. Find webpack runtime globals
    const found = { chunkArrays: [], moduleCacheCandidates: [] };
    for (const k of Object.keys(window)) {
      if (/^webpackChunk/i.test(k) && Array.isArray(window[k])) {
        found.chunkArrays.push({ name: k, length: window[k].length });
      }
    }
    // 2. Iterate registered modules to find anything with createRequestToken
    const seen = new Set();
    const sdkCandidates = [];
    for (const arrName of found.chunkArrays.map(c => c.name)) {
      try {
        for (const entry of window[arrName]) {
          if (!Array.isArray(entry) || entry.length < 2) continue;
          const modules = entry[1];
          if (!modules || typeof modules !== 'object') continue;
          for (const id of Object.keys(modules)) {
            if (seen.has(id)) continue;
            seen.add(id);
            const fnSrc = String(modules[id]).slice(0, 4000);
            if (/createRequestToken/.test(fnSrc) && /configure/.test(fnSrc)) {
              sdkCandidates.push({ id, src_head: fnSrc.slice(0, 300) });
            }
          }
        }
      } catch (e) {}
    }
    found.sdkCandidates = sdkCandidates;
    found.sdkModuleCount = sdkCandidates.length;
    return found;
  };

  console.log('[instrument] btoa, Uint8Array, Function.prototype.toString wrapped');
})();
`;

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  viewport: { width: 1280, height: 800 },
});
await ctx.addInitScript(INSTRUMENT);

const page = await ctx.newPage();
page.on('console', (m) => {
  const t = m.text();
  if (/instrument|hunt|castle/i.test(t)) console.log(`  [browser] ${t.slice(0, 200)}`);
});
page.on('pageerror', (e) => console.log(`  [pageerror] ${e.message.slice(0, 200)}`));

console.log('navigate → x.com/i/flow/login');
await page.goto('https://x.com/i/flow/login', { waitUntil: 'domcontentloaded', timeout: 45_000 });

// wait for Castle SDK lazy chunk + idle-callback init
console.log('settle 12s for SDK lazy load + requestIdleCallback init');
await new Promise((r) => setTimeout(r, 12_000));

// Take pre-fire snapshots
const preFire = await page.evaluate(() => ({
  btoa: window.__btoaCalls.length,
  ua: window.__uaCalls.length,
  fnTs: window.__fnTsCalls.length,
}));
console.log(`pre-fire counters: btoa=${preFire.btoa} ua=${preFire.ua} fnTs=${preFire.fnTs}`);

// Hunt for SDK in webpack cache
const hunt = await page.evaluate(() => window.__hunt());
console.log(`webpack chunk arrays: ${JSON.stringify(hunt.chunkArrays)}`);
console.log(`SDK candidate modules: ${hunt.sdkModuleCount}`);
for (const c of hunt.sdkCandidates) {
  console.log(`  module #${c.id}: ${c.src_head.slice(0, 160)}...`);
}

// Force-fire createRequestToken via the discovered module
const fired = await page.evaluate(async () => {
  // Try to call configure + createRequestToken on each candidate
  for (const arrName of Object.keys(window)) {
    if (!/^webpackChunk/i.test(arrName) || !Array.isArray(window[arrName])) continue;
    for (const entry of window[arrName]) {
      if (!Array.isArray(entry) || entry.length < 2) continue;
      const modules = entry[1];
      if (!modules || typeof modules !== 'object') continue;
      for (const id of Object.keys(modules)) {
        const fnSrc = String(modules[id]).slice(0, 4000);
        if (!/createRequestToken/.test(fnSrc) || !/configure/.test(fnSrc)) continue;
        // try to invoke this module via webpack require if it's loaded
        try {
          // webpack exposes its require via the chunk runtime; try common globals
          const wpReq = window.__webpack_require__ || (window.webpackChunk_twitter_responsive_web && window.webpackChunk_twitter_responsive_web.r);
          if (typeof wpReq === 'function') {
            const mod = wpReq(id);
            if (mod && typeof mod.configure === 'function') {
              const scoped = mod.configure({ pk: 'pk_FqZjowm5oV2YzpB6yrz81HSAznzyE6x3' });
              const token = await scoped.createRequestToken();
              return { ok: true, source: 'wpReq', module_id: id, token_len: token.length, token_head: token.slice(0, 60) };
            }
          }
        } catch (e) {
          // fall through and try next
        }
      }
    }
  }
  // Fallback: hunt for an object on window with both configure + createRequestToken
  function deepHunt(obj, depth, path) {
    if (!obj || depth > 4) return null;
    if (typeof obj.configure === 'function' && typeof obj.createRequestToken === 'function') {
      return { obj, path };
    }
    try {
      for (const k of Object.keys(obj)) {
        const v = obj[k];
        if (v && typeof v === 'object') {
          const hit = deepHunt(v, depth + 1, path + '.' + k);
          if (hit) return hit;
        }
      }
    } catch (e) {}
    return null;
  }
  const hit = deepHunt(window, 0, 'window');
  if (hit) {
    try {
      const scoped = hit.obj.configure({ pk: 'pk_FqZjowm5oV2YzpB6yrz81HSAznzyE6x3' });
      const token = await scoped.createRequestToken();
      return { ok: true, source: 'deepHunt', path: hit.path, token_len: token.length, token_head: token.slice(0, 60) };
    } catch (e) {
      return { ok: false, error: 'deepHunt-call: ' + e.message };
    }
  }
  return { ok: false, error: 'no SDK found' };
});
console.log(`force-fire: ${JSON.stringify(fired).slice(0, 200)}`);

// Settle for any deferred btoa calls
await new Promise((r) => setTimeout(r, 3000));

const result = await page.evaluate(() => ({
  btoaCalls: window.__btoaCalls,
  uaCalls: window.__uaCalls,
  fnTsSample: window.__fnTsCalls.slice(0, 200),
  fnTsCount: window.__fnTsCalls.length,
}));

await browser.close();

console.log(`\n=== final counters ===`);
console.log(`btoa calls:  ${result.btoaCalls.length}`);
console.log(`uint8a:      ${result.uaCalls.length}`);
console.log(`fnTs:        ${result.fnTsCount}`);

// Classify btoa call stacks: count distinct top-frame functions
const btoaStackTops = new Map();
for (const c of result.btoaCalls) {
  const top = (c.stack_top.split(' | ')[0] || '<unknown>').slice(0, 120);
  btoaStackTops.set(top, (btoaStackTops.get(top) || 0) + 1);
}
console.log(`\n=== btoa call sites (distinct top frames) ===`);
for (const [k, v] of [...btoaStackTops.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20)) {
  console.log(`  ${v}× ${k}`);
}

// Show large-input btoa calls (likely the token cipher output)
const big = result.btoaCalls.filter(c => c.len > 500).sort((a, b) => b.len - a.len);
console.log(`\n=== large btoa calls (>500 bytes input — likely token cipher) ===`);
for (const c of big.slice(0, 10)) {
  console.log(`  len=${c.len} head=${c.head_hex.slice(0, 32)}…`);
  console.log(`    stack: ${c.stack_top.slice(0, 240)}`);
}

fs.writeFileSync('./results/stackwalk.json', JSON.stringify({
  preFire,
  hunt,
  fired,
  btoaCalls: result.btoaCalls,
  uaCallCount: result.uaCalls.length,
  uaCallsSample: result.uaCalls.slice(0, 50),
  fnTsCount: result.fnTsCount,
  btoaStackTops: Object.fromEntries(btoaStackTops),
}, null, 2));
console.log('\nwrote ./results/stackwalk.json');
