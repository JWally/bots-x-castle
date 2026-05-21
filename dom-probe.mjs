#!/usr/bin/env node
import { chromium } from 'playwright';

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  viewport: { width: 1280, height: 800 },
});
const page = await ctx.newPage();
await page.goto('https://x.com/i/flow/login', { waitUntil: 'domcontentloaded', timeout: 45_000 });
console.log('settle 20s');
await new Promise((r) => setTimeout(r, 20_000));

// dump all inputs
const inputs = await page.evaluate(() => {
  const out = [];
  for (const el of document.querySelectorAll('input, textarea')) {
    const cs = el.getBoundingClientRect();
    out.push({
      tag: el.tagName, type: el.type, name: el.name, autocomplete: el.autocomplete,
      placeholder: el.placeholder, ariaLabel: el.getAttribute('aria-label'),
      visible: cs.width > 0 && cs.height > 0
    });
  }
  return out;
});
console.log(`inputs found: ${inputs.length}`);
for (const i of inputs) console.log(`  ${JSON.stringify(i)}`);

const buttons = await page.evaluate(() => {
  const out = [];
  for (const el of document.querySelectorAll('button, [role="button"]')) {
    const cs = el.getBoundingClientRect();
    const txt = (el.innerText || el.textContent || '').slice(0, 60).trim();
    if (cs.width > 0) out.push({ tag: el.tagName, role: el.getAttribute('role'), testid: el.getAttribute('data-testid'), text: txt });
  }
  return out;
});
console.log(`\nvisible buttons: ${buttons.length}`);
for (const b of buttons.slice(0, 15)) console.log(`  ${JSON.stringify(b)}`);

const title = await page.title();
console.log(`\ntitle: ${title}`);
console.log(`url:   ${page.url()}`);
const html = await page.content();
console.log(`html size: ${html.length}`);

await browser.close();
