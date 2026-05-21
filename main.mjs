#!/usr/bin/env node
// Interactive launcher for x-castle-attack-bot.
// Arrow-key menu over all scripts; descriptions render below the list.
// Children inherit stdio so live output streams through.

import prompts from 'prompts';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const SCRIPTS = [
  {
    file: 'tamper.mjs',
    title: '★ tamper       — value tampering demo (THE HEADLINER)',
    desc:
      'Two consecutive runs: (1) baseline — readtap only, no lies; ' +
      '(2) tampered — chrome-win-style prototype overrides + ' +
      'Function.prototype.toString countermeasure + readtap stacked on top. ' +
      'Prints side-by-side diff of what Castle saw. Confirms 13 spoofed ' +
      'signals (incl. webdriver=true→undefined, SwiftShader→NVIDIA RTX 3060) ' +
      'land in Castle\'s token, which still builds and submits to ' +
      'POST /1.1/onboarding/task.json. ~3 min.',
  },
  {
    file: 'recon.mjs',
    title: '  recon        — find Castle chunk on x.com',
    desc:
      'Loads x.com\'s auth pages with Playwright, logs every JS response, ' +
      'flags chunks containing createRequestToken / castle.io / the old ' +
      'wS[Hg] regex. Run first to confirm Castle is still deployed and ' +
      'find the current bundle URL. ~1 min.',
  },
  {
    file: 'stackwalk.mjs',
    title: '  stackwalk    — locate chokepoint offsets at runtime',
    desc:
      'Wraps btoa, Uint8Array constructor, and Function.prototype.toString ' +
      'before bundle load; captures call-stack tops for every call. ' +
      'Reveals the chokepoint function offsets (tt, f4, Array.tN, lb) ' +
      'inside the minified bundle. Re-run after a bundle hash drift. ~1 min.',
  },
  {
    file: 'bytetap.mjs',
    title: '  bytetap      — patch every btoa() call site',
    desc:
      'In-flight bundle patch: rewrites every btoa(EXPR) call site to ' +
      '__btoaTap(EXPR, callsite_idx) and captures full input bytes per call. ' +
      'Confirms the per-field cipher claim — every blob arriving at btoa ' +
      'is high-entropy, so no plaintext is recoverable at the encoder ' +
      'output layer. Exploratory tool. ~1 min.',
  },
  {
    file: 'readtap.mjs',
    title: '  readtap      — full plaintext signal inventory',
    desc:
      'Prototype-getter / method instrumentation on Navigator, Screen, ' +
      'WebGL, Canvas, Date, Document, Location, Performance, matchMedia, ' +
      'storage, crypto. Stack-filtered to ondemand.castle.*. Produces the ' +
      'canonical "what does Castle read" capture — 47 unique signals per ' +
      'page-load fire. ~1 min.',
  },
  {
    file: 'submit.mjs',
    title: '  submit       — readtap + drive login form',
    desc:
      'Same as readtap, plus marker checkpoints (PAGELOAD_FIRE_DONE, ' +
      'BEFORE_NEXT_CLICK, AFTER_NEXT_CLICK, END_OF_RUN) and an actual ' +
      'Playwright-driven input.fill + Next click on the login form. ' +
      'Partitions reads into per-fire buckets — shows Castle fires 3× ' +
      'per interaction with tokens growing ~50-150 bytes per fire. ~2 min.',
  },
  {
    file: 'headers.mjs',
    title: '  headers      — find where the token rides on the wire',
    desc:
      'Captures full request headers + POST bodies on x.com\'s auth ' +
      'endpoints (onboarding, jot, graphql, guest). Flags high-entropy ' +
      'long-base64 fragments. Localizes Castle\'s token to the body of ' +
      'POST /1.1/onboarding/task.json (14760 base64 chars on submit). ~1 min.',
  },
  {
    file: 'dom-probe.mjs',
    title: '  dom-probe    — DOM dump diagnostic',
    desc:
      'Tiny diagnostic tool — lists all visible inputs and buttons on ' +
      'x.com\'s login flow page. Run when tamper.mjs or submit.mjs\'s form ' +
      'selector starts failing because x.com changed their DOM. ~30 sec.',
  },
];

function runScript(file) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(__dirname, file)], {
      stdio: 'inherit',
      cwd: __dirname,
    });
    const onSig = () => child.kill('SIGINT');
    process.on('SIGINT', onSig);
    child.on('exit', (code, signal) => {
      process.removeListener('SIGINT', onSig);
      resolve({ code, signal });
    });
  });
}

async function main() {
  console.clear();
  console.log();
  console.log('\x1b[1mx-castle-attack-bot\x1b[0m  —  Castle.io reverse-engineering harness for x.com');
  console.log('\x1b[2mSee README.md for context · X.Castle.md for the full writeup\x1b[0m');
  console.log();

  while (true) {
    const { choice } = await prompts({
      type: 'select',
      name: 'choice',
      message: 'pick a script',
      hint: 'arrow keys to navigate · enter to run · esc/ctrl-c to quit',
      choices: [
        ...SCRIPTS.map((s) => ({ title: s.title, description: s.desc, value: s })),
        { title: '  quit', description: 'Exit the launcher.', value: '__quit' },
      ],
      initial: 0,
    });

    if (!choice || choice === '__quit') {
      console.log('\nbye.');
      process.exit(0);
    }

    console.log();
    console.log(`\x1b[36m─── running ${choice.file} ───\x1b[0m\n`);
    const { code, signal } = await runScript(choice.file);
    const status = signal ? `signal ${signal}` : `exit code ${code}`;
    console.log();
    console.log(`\x1b[36m─── ${choice.file} finished (${status}) ───\x1b[0m\n`);

    const { again } = await prompts({
      type: 'confirm',
      name: 'again',
      message: 'back to menu?',
      initial: true,
    });
    if (!again) {
      console.log('bye.');
      process.exit(0);
    }
  }
}

main().catch((e) => {
  console.error('\nlauncher error:', e);
  process.exit(1);
});
