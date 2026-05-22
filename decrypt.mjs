#!/usr/bin/env node
// decrypt — capture one live Castle token from x.com and decrypt it with tv().
//
// Demonstrates that the cipher pair (tt, tv) from the bundle is fully reversed:
// the bundle ships its own inverse function for build-time string deobfuscation,
// and that same function inverts the runtime token cipher byte-for-byte.
//
// Output goes to results/decrypt.json.

import { chromium } from 'playwright';
import fs from 'fs';
import { tv } from './castle-cipher.mjs';

const HOOK = `
(() => {
  if (window.__decryptHooked) return;
  window.__decryptHooked = true;
  window.__bigToken = null;
  const realBtoa = window.btoa.bind(window);
  window.btoa = function(s) {
    const result = realBtoa(s);
    try {
      // Only the tt() function is invertible via tv() — other byte-emitters
      // (f4, tN, lb) in the chunk use different ciphers. Filter by stack frame.
      const stack = new Error().stack || '';
      if (typeof s === 'string' && s.length > 100
          && /at tt \\(/.test(stack)
          && /ondemand\\.castle\\./.test(stack)) {
        if (!window.__bigToken || s.length > window.__bigToken.binaryLen) {
          window.__bigToken = { binaryLen: s.length, b64Len: result.length, b64: result };
        }
      }
    } catch (e) {}
    return result;
  };
})();
`;

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  viewport: { width: 1280, height: 800 },
});
await ctx.addInitScript(HOOK);

const page = await ctx.newPage();
console.log('navigate → x.com/i/flow/login');
await page.goto('https://x.com/i/flow/login', { waitUntil: 'domcontentloaded', timeout: 45_000 });
console.log('settle 22s for Castle auto-fire');
await new Promise((r) => setTimeout(r, 22_000));

const captured = await page.evaluate(() => window.__bigToken);
await browser.close();

if (!captured) {
  console.error('NO TOKEN CAPTURED — Castle may not have fired. Retry, or extend settle.');
  process.exit(1);
}

console.log(`\n=== captured token ===`);
console.log(`  base64 length: ${captured.b64Len} chars`);
console.log(`  token head:    ${captured.b64.slice(0, 80)}…`);

console.log(`\n=== tv() decrypt ===`);
const decrypted = tv(captured.b64);
console.log(`  decrypted length: ${decrypted.length} chars`);

// Render output
const codes = Array.from(decrypted).map(c => c.charCodeAt(0));
const ascii = codes.map(c => {
  const lo = c & 0xFF;
  const hi = (c >> 8) & 0xFF;
  if (hi === 0 && lo >= 32 && lo <= 126) return String.fromCharCode(lo);
  if (hi === 0 && lo === 0) return '\\0';
  if (hi === 0) return `\\x${lo.toString(16).padStart(2,'0')}`;
  return `\\u${c.toString(16).padStart(4,'0')}`;
}).join('');

console.log(`\n=== plaintext preview (first 600 chars, ASCII-rendered) ===`);
console.log(ascii.slice(0, 600));

// Look for ASCII runs (likely strings, base64s, numbers)
const runs = ascii.match(/[A-Za-z0-9+/=,.\-_]{5,}/g) || [];
console.log(`\n=== ASCII runs found in decrypted plaintext: ${runs.length} ===`);
for (const r of runs.slice(0, 30)) {
  console.log(`  "${r}"`);
}

// Find embedded base64 substrings (likely nested tt() outputs)
const b64Subs = [...ascii.matchAll(/[A-Za-z0-9+/]{12,}={0,2}/g)].slice(0, 10);
console.log(`\n=== embedded base64 candidates (showing first 10): ===`);
for (const m of b64Subs) {
  try {
    const dec = tv(m[0]);
    const decAscii = Array.from(dec).map(c => {
      const cc = c.charCodeAt(0);
      return (cc >= 32 && cc <= 126) ? c : '.';
    }).join('').slice(0, 60);
    console.log(`  "${m[0].slice(0, 40)}${m[0].length>40?'…':''}" → tv → "${decAscii}"`);
  } catch (e) {}
}

fs.writeFileSync('./results/decrypt.json', JSON.stringify({
  captured,
  decryptedLength: decrypted.length,
  asciiPreview: ascii.slice(0, 2000),
  asciiRuns: runs.slice(0, 100),
  hex: codes.slice(0, 500).map(c => c.toString(16).padStart(4,'0')).join(' '),
}, null, 2));
console.log('\nwrote ./results/decrypt.json');
