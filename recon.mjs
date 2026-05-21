#!/usr/bin/env node
// Recon: visit x.com flows, log every JS response, flag any that look Castle-shaped.
// "Castle-shaped" = contains createRequestToken / castle.io / wS[Hg]-style encoder regex.

import fs from 'fs';
import { chromium } from 'playwright';

const TARGETS = [
  'https://x.com/i/flow/login',
  'https://x.com/i/flow/signup',
  'https://x.com/login',
  'https://x.com/',
];

const HG_PATTERN = /((\w+)\[\w+\]=function\(n,r,i,t\)\{)(return \2\[\w+\]\(\2\[\w+\]\(\(n&)/;
const CASTLE_HINTS = [
  /createRequestToken/,
  /castle\.io/i,
  /\bm\.castle\b/i,
  /\bcastleio\b/i,
  /Castle[A-Z][a-zA-Z]*Token/,
];

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  viewport: { width: 1280, height: 800 },
});

const findings = [];

for (const target of TARGETS) {
  console.log(`\n=== ${target} ===`);
  const seen = [];
  const page = await ctx.newPage();
  page.on('response', async (resp) => {
    const url = resp.url();
    const ct = (resp.headers()['content-type'] || '').toLowerCase();
    const looksJs = ct.includes('javascript') || /\.js(\?|$)/.test(url) || /\/client\//.test(url);
    if (!looksJs) return;
    try {
      const body = await resp.text();
      const hints = CASTLE_HINTS.filter((rx) => rx.test(body)).map((rx) => rx.toString());
      const hgMatch = HG_PATTERN.test(body);
      if (hints.length || hgMatch) {
        seen.push({ url, size: body.length, hints, hgMatch });
      }
    } catch (_) {}
  });
  page.on('pageerror', (e) => console.log(`  [pageerror] ${e.message.slice(0, 160)}`));
  try {
    await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 30_000 });
  } catch (e) {
    console.log(`  goto failed: ${e.message.slice(0, 120)}`);
  }
  await new Promise((r) => setTimeout(r, 15_000));
  console.log(`  Castle-shaped chunks: ${seen.length}`);
  for (const s of seen) {
    console.log(`    ${s.url.slice(0, 110)}  size=${s.size}  hg=${s.hgMatch}  hints=${s.hints.join('|')}`);
  }
  findings.push({ target, chunks: seen });
  await page.close();
}

await browser.close();
fs.writeFileSync('./results/recon.json', JSON.stringify(findings, null, 2));
console.log(`\nwrote ./results/recon.json`);
