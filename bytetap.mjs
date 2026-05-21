#!/usr/bin/env node
// Wrap every btoa(EXPR) call in the Castle chunk with __btoaTap(EXPR, idx).
// Captures full input bytes per call, plus call order and a stable callsite id.
// Then dumps and parses each blob looking for ASCII, TLV-shaped records, etc.

import fs from 'fs';
import { chromium } from 'playwright';

const TARGET_URL = 'https://x.com/i/flow/login';
const CASTLE_CHUNK_RE = /ondemand\.castle\.[a-f0-9]+\.js$/;

// Walk balanced parens to find the end of `btoa(EXPR)`. Returns end index after ')'.
function findBalancedClose(src, openIdx) {
  // openIdx points at the '(' after 'btoa'
  let depth = 0;
  let i = openIdx;
  let inStr = null;
  while (i < src.length) {
    const c = src[i];
    if (inStr) {
      if (c === '\\') { i += 2; continue; }
      if (c === inStr) inStr = null;
      i++; continue;
    }
    if (c === '"' || c === "'" || c === '`') { inStr = c; i++; continue; }
    if (c === '(') depth++;
    else if (c === ')') {
      depth--;
      if (depth === 0) return i + 1;
    }
    i++;
  }
  return -1;
}

function patchBundle(src) {
  // Find every `btoa(` not preceded by identifier chars (so we hit window.btoa or bare btoa)
  // Replace with `(window.__btoaTap?window.__btoaTap(EXPR,IDX):btoa(EXPR))`
  // — but keep it simple: just `__btoaTap(EXPR,IDX)` assuming the tap is installed.
  const out = [];
  let last = 0;
  let idx = 0;
  const re = /(^|[^A-Za-z0-9_$.])btoa\(/g;
  let m;
  const callsites = [];
  while ((m = re.exec(src)) !== null) {
    const openIdx = m.index + m[0].length - 1; // position of '('
    const closeIdx = findBalancedClose(src, openIdx);
    if (closeIdx < 0) continue;
    const expr = src.slice(openIdx + 1, closeIdx - 1);
    // emit unchanged prefix
    out.push(src.slice(last, m.index + m[1].length));
    out.push(`__btoaTap(${expr},${idx})`);
    callsites.push({ idx, srcOffset: m.index + m[1].length });
    last = closeIdx;
    re.lastIndex = closeIdx;
    idx++;
  }
  out.push(src.slice(last));
  return { patched: out.join(''), count: idx, callsites };
}

const PRELUDE = `
;(function(){
  if (window.__btoaTap) return;
  window.__btoaCalls = [];
  var realBtoa = window.btoa.bind(window);
  window.__btoaTap = function(s, idx) {
    try {
      var stack = '';
      try { stack = new Error().stack || ''; } catch(e){}
      var sStr = (typeof s === 'string') ? s : String(s);
      // hex-encode full input (these are binary strings — each char is 0..255)
      var hex = '';
      for (var i = 0; i < sStr.length; i++) {
        var b = sStr.charCodeAt(i) & 0xff;
        hex += (b < 16 ? '0' : '') + b.toString(16);
      }
      window.__btoaCalls.push({
        ord: window.__btoaCalls.length,
        callsite: idx,
        len: sStr.length,
        hex: hex,
        // also keep raw chars (ASCII slice) to spot text fields quickly
        asciiPreview: sStr.slice(0, 200).replace(/[^\\x20-\\x7e]/g, '.'),
        stack: stack.split('\\n').slice(2, 6).map(function(l){return l.trim();}).join(' | ')
      });
    } catch (e) {}
    return realBtoa(s);
  };
})();
`;

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  viewport: { width: 1280, height: 800 },
});
await ctx.addInitScript(PRELUDE);

let patchedInfo = null;
await ctx.route('**/*', async (route) => {
  const req = route.request();
  const url = req.url();
  if (!CASTLE_CHUNK_RE.test(url)) return route.continue();
  try {
    const resp = await route.fetch();
    const body = await resp.text();
    const { patched, count, callsites } = patchBundle(body);
    patchedInfo = { url, origSize: body.length, patchedSize: patched.length, btoaCount: count };
    console.log(`  patched chunk: ${url}`);
    console.log(`    btoa() call sites wrapped: ${count}`);
    const headers = { ...resp.headers() };
    for (const h of Object.keys(headers)) {
      if (h.toLowerCase().startsWith('content-security-policy')) delete headers[h];
    }
    return route.fulfill({ status: resp.status(), headers, body: patched });
  } catch (e) {
    console.log(`  route err: ${e.message}`);
    return route.continue();
  }
});

const page = await ctx.newPage();
page.on('pageerror', (e) => console.log(`  [pageerror] ${e.message.slice(0, 200)}`));

console.log(`navigate → ${TARGET_URL}`);
await page.goto(TARGET_URL, { waitUntil: 'domcontentloaded', timeout: 45_000 });

console.log('settle 15s for Castle SDK + auto-fire');
await new Promise((r) => setTimeout(r, 15_000));

const result = await page.evaluate(() => window.__btoaCalls || []);
console.log(`\ntotal btoa calls captured: ${result.length}`);

await browser.close();

// ---- Analysis ----
// Categorize by callsite & by size
const bySite = new Map();
for (const c of result) {
  if (!bySite.has(c.callsite)) bySite.set(c.callsite, []);
  bySite.get(c.callsite).push(c);
}
console.log(`\n=== btoa calls grouped by callsite (top 20 by call-count) ===`);
const siteRanked = [...bySite.entries()].sort((a, b) => b[1].length - a[1].length).slice(0, 20);
for (const [site, calls] of siteRanked) {
  const sizes = calls.map(c => c.len).sort((a, b) => a - b);
  const avg = (sizes.reduce((s, n) => s + n, 0) / sizes.length).toFixed(1);
  console.log(`  callsite ${site}: ${calls.length} calls, sizes min=${sizes[0]} avg=${avg} max=${sizes[sizes.length-1]}`);
}

// Show large blobs (likely the cipher output)
const big = [...result].sort((a, b) => b.len - a.len).slice(0, 5);
console.log(`\n=== 5 largest btoa inputs (likely cipher outputs / final encoding) ===`);
for (const c of big) {
  console.log(`  ord=${c.ord} site=${c.callsite} len=${c.len}`);
  console.log(`    hex[0..96]:  ${c.hex.slice(0, 96)}…`);
  console.log(`    ascii[..80]: ${c.asciiPreview.slice(0, 80)}`);
  console.log(`    stack: ${c.stack.slice(0, 200)}`);
}

// Find any blob with substantial ASCII text — those are likely pre-cipher with strings intact
const asciish = result.filter(c => {
  // count printable ASCII chars in preview
  const printable = (c.asciiPreview.match(/[A-Za-z]{4,}/g) || []).join(' ');
  return printable.length > 4;
}).slice(0, 30);
console.log(`\n=== blobs with ASCII strings inline (plaintext candidates) — top 30 ===`);
for (const c of asciish) {
  console.log(`  ord=${c.ord} site=${c.callsite} len=${c.len}: ${c.asciiPreview.slice(0, 160)}`);
}

fs.writeFileSync('./results/bytetap.json', JSON.stringify({
  patchedInfo,
  callCount: result.length,
  bySiteCounts: Object.fromEntries([...bySite.entries()].map(([k, v]) => [k, v.length])),
  calls: result,
}, null, 2));
console.log('\nwrote ./results/bytetap.json');
