// Patch tt() in the Castle chunk to log its INPUT (n) and OUTPUT (the
// returned base64 string). Then we can directly test:
//   tv(tt_output) == tt_input ?
// If yes → tv works, tt's input is the next ciphertext layer.
// If no → there's a different cipher path producing the token.

import { chromium } from 'playwright';
import fs from 'fs';
import { tv } from './castle-cipher.mjs';

const TT_LITERAL = 'function tt(n){var r=[];r[0]=[],r[1]=n;';
const TT_PATCH = `function tt(n){window.__ttCalls=window.__ttCalls||[];var __ttIdx=window.__ttCalls.length;window.__ttCalls.push({i:__ttIdx,inputLen:typeof n==='string'?n.length:-1,inputHexHead:typeof n==='string'?Array.from(n.slice(0,32)).map(c=>c.charCodeAt(0).toString(16).padStart(4,'0')).join(' '):''});var __ttResult=(function(){var r=[];r[0]=[],r[1]=n;`;
// We need to ALSO wrap the return. Replace `return btoa(r[2])}` to capture result.

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  viewport: { width: 1280, height: 800 },
});

let patchedBytes = 0;
await ctx.route('**/*', async (route) => {
  const req = route.request();
  const url = req.url();
  if (!/ondemand\.castle\..*\.js$/.test(url)) return route.continue();

  const resp = await route.fetch();
  const body = await resp.text();

  // Count how many times the tt literal appears
  const count = (body.match(new RegExp(TT_LITERAL.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length;
  console.log(`  patching tt() — literal appears ${count} time(s)`);

  // Replace each tt definition: capture input on entry, capture output on return
  // Pattern: function tt(n){var r=[];r[0]=[],r[1]=n;...return btoa(r[2])}
  // We rewrite to record entry, run original body, record output, return.
  const patched = body.replace(
    /function tt\(n\)\{var r=\[\];r\[0\]=\[\],r\[1\]=n;([\s\S]+?)return btoa\(r\[2\]\)\}/g,
    (match, mid) => {
      patchedBytes += match.length;
      return `function tt(n){
        window.__ttCalls = window.__ttCalls || [];
        var __ttIdx = window.__ttCalls.length;
        var __ttInputCopy = (typeof n === 'string') ? n : '';
        var __r = (function(){ var r=[]; r[0]=[], r[1]=n; ${mid} return btoa(r[2]); })();
        try {
          window.__ttCalls.push({
            i: __ttIdx,
            inputLen: __ttInputCopy.length,
            // Save the FULL char codes for every call (not just first 500)
            inputCharCodes: Array.from(__ttInputCopy).map(c => c.charCodeAt(0)),
            outputLen: __r.length,
            outputFull: __r
          });
        } catch(e) { window.__ttPatchErr = e.message; }
        return __r;
      }`;
    }
  );

  console.log(`  patched ${patchedBytes} bytes of tt() bodies`);
  const headers = { ...resp.headers() };
  for (const h of Object.keys(headers)) {
    if (h.toLowerCase().startsWith('content-security-policy')) delete headers[h];
  }
  return route.fulfill({ status: resp.status(), headers, body: patched });
});

const page = await ctx.newPage();
page.on('pageerror', (e) => console.log(`  [pageerror] ${e.message.slice(0, 200)}`));
console.log('navigate → x.com/i/flow/login');
await page.goto('https://x.com/i/flow/login', { waitUntil: 'domcontentloaded', timeout: 45_000 });
console.log('settle 22s');
await new Promise((r) => setTimeout(r, 22_000));

const ttCalls = await page.evaluate(() => window.__ttCalls || []);
const patchErr = await page.evaluate(() => window.__ttPatchErr || null);
await browser.close();

console.log(`\n=== tt() call summary ===`);
console.log(`  total tt() calls captured: ${ttCalls.length}`);
if (patchErr) console.log(`  patch threw on at least one call: ${patchErr}`);

if (ttCalls.length === 0) {
  console.log('NO TT CALLS CAPTURED. Patch may have broken bundle parsing.');
  process.exit(1);
}

// Show size distribution
const sizes = ttCalls.map(c => c.inputLen).sort((a, b) => a - b);
console.log(`  input sizes: min=${sizes[0]} med=${sizes[Math.floor(sizes.length/2)]} max=${sizes[sizes.length-1]}`);
console.log(`  output sizes: ${ttCalls.map(c => c.outputLen).join(', ')}`);

// The BIG one is the token. Decrypt and compare.
const big = [...ttCalls].sort((a, b) => b.outputLen - a.outputLen)[0];
console.log(`\n=== biggest tt() call (the token) ===`);
console.log(`  input chars: ${big.inputLen}`);
console.log(`  output base64: ${big.outputLen} chars`);
console.log(`  output head:   ${big.outputFull.slice(0, 80)}...`);
console.log(`  input hex (first 60 chars): ${big.inputCharCodes.slice(0, 30).map(c=>c.toString(16).padStart(4,'0')).join(' ')}`);

const decrypted = tv(big.outputFull);
console.log(`\n=== decrypt via tv() ===`);
console.log(`  decrypted length: ${decrypted.length}`);

// Compare first 30 chars
const expectedHex = big.inputCharCodes.slice(0, 30).map(c => c.toString(16).padStart(4, '0')).join(' ');
const decryptedHex = Array.from(decrypted.slice(0, 30)).map(c => c.charCodeAt(0).toString(16).padStart(4, '0')).join(' ');
const match = expectedHex === decryptedHex;
console.log(`  expected (first 30): ${expectedHex}`);
console.log(`  decrypted (first 30): ${decryptedHex}`);
console.log(`  match? ${match ? 'YES — tv is the correct inverse, tt input is the next layer' : 'NO — tt is a different cipher or has different constants in this scope'}`);

// (Match check above already covered.)

fs.writeFileSync('./results/tt-instrument.json', JSON.stringify({
  callCount: ttCalls.length,
  patchErr,
  // Full data per call: input char codes + output base64
  calls: ttCalls,
}, null, 2));
console.log('\nwrote ./results/tt-instrument.json');

// ---- recursive decrypt: for each tt() call, render its input as ASCII to find plaintext ----
console.log('\n========== Per-call input plaintext ==========');
for (const c of ttCalls) {
  if (c.inputLen === 0) continue;
  const codes = c.inputCharCodes;
  // Try interpreting as low-byte ASCII string (high byte = 0 expected for ASCII-range data)
  const asAscii = codes.map(cc => {
    const lo = cc & 0xFF;
    const hi = (cc >> 8) & 0xFF;
    if (hi === 0 && lo >= 32 && lo <= 126) return String.fromCharCode(lo);
    if (hi === 0) return `\\x${lo.toString(16).padStart(2,'0')}`;
    return `\\u${cc.toString(16).padStart(4,'0')}`;
  }).join('');
  console.log(`\n  call #${c.i} (${c.inputLen} chars input → ${c.outputLen} b64):`);
  console.log(`    ascii:  "${asAscii.slice(0, 200)}"`);
  // Hex view too
  console.log(`    hex16:  ${codes.slice(0, 24).map(cc => cc.toString(16).padStart(4,'0')).join(' ')}`);
}
