#!/usr/bin/env node
// Capture full request headers + body shape on x.com auth endpoints to find
// where Castle's token is forwarded. Castle tokens are URL-safe base64,
// typically 2000+ chars, very high entropy.

import fs from 'fs';
import { chromium } from 'playwright';

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  viewport: { width: 1280, height: 800 },
});
const page = await ctx.newPage();

const captures = [];
page.on('request', async (req) => {
  const url = req.url();
  // narrow to x.com auth / onboarding endpoints
  if (!/x\.com\/(i\/api|1\.1\/onboarding|1\.1\/jot|1\.1\/graphql|1\.1\/guest)|api\.x\.com\/(1\.1\/onboarding|1\.1\/jot|1\.1\/graphql|1\.1\/guest)/.test(url)) return;
  const headers = req.headers();
  // find long high-entropy header values (likely tokens)
  const tokeny = {};
  for (const [k, v] of Object.entries(headers)) {
    if (typeof v === 'string' && v.length > 100) {
      // sample base64-ness: ratio of [A-Za-z0-9_-+/=]
      const safe = (v.match(/[A-Za-z0-9_\-+/=]/g) || []).length / v.length;
      tokeny[k] = { len: v.length, base64ish: safe > 0.95, head: v.slice(0, 40) };
    }
  }
  let body = null;
  try {
    const post = req.postData();
    if (post) {
      // base64-shape substring search in body
      const long = post.match(/[A-Za-z0-9_\-+/=]{300,}/g) || [];
      body = { contentType: headers['content-type'], len: post.length, bodyPreview: post.slice(0, 200), longBase64Tokens: long.length, longBase64Heads: long.slice(0, 3).map(s => ({ len: s.length, head: s.slice(0, 40) })) };
    }
  } catch (e) {}
  captures.push({ ts: Date.now(), method: req.method(), url: url.slice(0, 110), tokenyHeaders: tokeny, body });
});

console.log('navigate → x.com/i/flow/login');
await page.goto('https://x.com/i/flow/login', { waitUntil: 'domcontentloaded', timeout: 45_000 });
await new Promise((r) => setTimeout(r, 20_000));

console.log('fill email + click Next');
try {
  const input = await page.waitForSelector('input[autocomplete="username"], input[name="text"]', { timeout: 15_000 });
  await input.fill('test_account_' + Date.now() + '@example.com');
  const nextBtn = await page.waitForSelector('button:has-text("Next"), [role="button"]:has-text("Next")', { timeout: 8_000 });
  await nextBtn.click();
  console.log('clicked Next');
} catch (e) {
  console.log('submit failed: ' + e.message.slice(0, 120));
}
await new Promise((r) => setTimeout(r, 8_000));
await browser.close();

console.log(`\n=== auth requests captured: ${captures.length} ===\n`);
for (const c of captures) {
  console.log(`${c.method} ${c.url}`);
  if (c.body) {
    console.log(`  body: ${c.body.contentType} len=${c.body.len}  longBase64=${c.body.longBase64Tokens}`);
    for (const t of c.body.longBase64Heads) console.log(`    body-token len=${t.len} head=${t.head}…`);
    if (c.body.longBase64Tokens === 0) console.log(`    bodyPreview: ${c.body.bodyPreview}`);
  }
  for (const [k, info] of Object.entries(c.tokenyHeaders)) {
    console.log(`  hdr ${k}: len=${info.len} b64ish=${info.base64ish}  head=${info.head}…`);
  }
  console.log();
}

fs.writeFileSync('./results/headers.json', JSON.stringify(captures, null, 2));
console.log('wrote ./results/headers.json');
