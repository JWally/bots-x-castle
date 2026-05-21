# x-castle-attack-bot

Reverse-engineering harness for [Castle.io](https://castle.io)'s
fingerprinting bundle as deployed on **x.com** (2026-05-21).
Demonstrates input-side value tampering that produces cryptographically
valid live tokens, without reversing Castle's cipher or wire format.

Companion writeup: **[X.Castle.md](X.Castle.md)** — full methodology,
diff vs. the May-15 vanilla-npm analysis, what we did and didn't beat.
The original [Castle.md](https://github.com/...) (not included here)
covers the May-15 vanilla Castle 2.8.4 baseline.

> **Scope.** Defensive / red-team research. Demonstrates a bot
> producing a fingerprinted device profile of our choosing on a single
> auth-flow load of a public x.com page. Does not submit credentials,
> does not attempt to break into accounts, does not exfiltrate any
> user data. Intended audience: Castle's own research team, and
> argus / fingerprinting practitioners studying production hardening.

---

## Quick start

```bash
git clone <this-repo> x-castle-attack-bot
cd x-castle-attack-bot
npm install                # installs playwright + downloads Chromium
npm start                  # interactive menu — pick a script with arrow keys
```

You'll see an arrow-key menu of all 8 scripts with descriptions
below the highlighted item:

```
x-castle-attack-bot  —  Castle.io reverse-engineering harness for x.com
See README.md for context · X.Castle.md for the full writeup

? pick a script › arrow keys to navigate · enter to run · esc/ctrl-c to quit
❯ ★ tamper       — value tampering demo (THE HEADLINER)
    recon        — find Castle chunk on x.com
    stackwalk    — locate chokepoint offsets at runtime
    bytetap      — patch every btoa() call site
    readtap      — full plaintext signal inventory
    submit       — readtap + drive login form
    headers      — find where the token rides on the wire
    dom-probe    — DOM dump diagnostic
    quit
```

Pick **tamper** for the headline demo (~3 min). After each script
finishes you're returned to the menu.

Open `results/tamper.json` after the run. You should see two captures
(`baseline` and `tampered`) with a `sigMap` showing exactly what
Castle's bundle read in each. The 13-row diff in
[X.Castle.md §9.2](X.Castle.md) tells you which signals to compare.

### Power-user shortcuts

If you don't want the menu, every script also has a direct npm-run
shortcut:

```bash
npm run tamper       # same as picking tamper from the menu
npm run recon        # etc.
```

If `npm install` skips the Chromium download, run it manually:

```bash
npx playwright install chromium
```

---

## What each script does

All scripts are standalone — run any in any order. They all save JSON
to `results/<name>.json` and most print a short summary to stdout.

| Script | What it does | When to run |
|---|---|---|
| `npm run recon` | Loads x.com's auth pages with Playwright, logs every JS response, flags any chunk containing `createRequestToken` / `castle.io` / the old `wS[Hg]` regex. Discovery tool — finds the current Castle chunk URL even after content-hash drift. | First. Confirms Castle is still deployed and tells you the chunk URL to download. |
| `npm run stackwalk` | Wraps `btoa`, `Uint8Array` ctor, and `Function.prototype.toString` before bundle load, navigates to `/i/flow/login`, captures call-stack tops for every call. Reveals the chokepoint function offsets in the minified bundle (`tt`, `f4`, `Array.tN`, `lb` on c42626ea). | When the chunk hash changes — re-locate the chokepoints. |
| `npm run bytetap` | Patches every `btoa(EXPR)` call site in the chunk in-flight with `__btoaTap(EXPR, callsite_idx)`. Captures full input bytes per call. Useful for confirming the per-field cipher claim (every blob arriving at btoa is high-entropy → no plaintext to extract at this layer). | Exploratory — when you suspect plaintext might be visible at some btoa boundary. Spoiler: it isn't. |
| `npm run readtap` | Prototype-getter / method instrumentation on Navigator, Screen, WebGL, Canvas, Date, Document, Location, Performance, matchMedia, storage, crypto. Stack-filtered to `ondemand.castle.*`. Produces the full plaintext signal inventory. | When you want the canonical "what does Castle read" answer. |
| `npm run submit` | Same as `readtap` but adds marker checkpoints (`PAGELOAD_FIRE_DONE`, `BEFORE_NEXT_CLICK`, `AFTER_NEXT_CLICK`, `END_OF_RUN`) and drives a real Playwright `input.fill` + click on the login form. Partitions reads into per-fire buckets. | When you want to see how Castle behaves across multiple fires per interaction. |
| `npm run headers` | Captures full request headers + POST bodies on x.com's auth endpoints, flags high-entropy long-base64 fragments. Localizes where Castle's token rides on the wire (it's in the body of `POST /1.1/onboarding/task.json`). | When you want to confirm where the token ends up. |
| **`npm run tamper`** | **The headline demo.** Two consecutive Playwright runs: (1) `baseline` — readtap only, no lies; (2) `tampered` — chrome-win-style prototype getter overrides + `Function.prototype.toString` countermeasure + readtap stacked over the lies. Prints a side-by-side diff and saves both `sigMap`s plus the actual API hits to `results/tamper.json`. | The main thing. Run this. |
| `npm run dom-probe` | Tiny DOM dump tool — used when the submit-form selector fails. Lists all visible inputs and buttons on the page. | Diagnostic only. |

---

## What success looks like

After `npm run tamper`, you'll see something like:

```
========== DIFF: what Castle read ==========

signal                                   baseline                  tampered
------------------------------------------------------------------------------
navigator:webdriver                      2× true                   3× undefined ← LIE LANDED
navigator:platform                       5× "Linux x86_64"         5× "Win32" ← LIE LANDED
navigator:hardwareConcurrency            3× 12                     4× 8 ← LIE LANDED
navigator:deviceMemory                   3× 8                      4× 16 ← LIE LANDED
navigator:userAgentData                  4× {}                     5× {"brands":[{"brand":"Not_A Brand"... ← LIE LANDED
screen:width                             3× 1280                   3× 1920 ← LIE LANDED
screen:height                            3× 800                    3× 1080 ← LIE LANDED
webgl:WebGL1.getParameter                8× "ANGLE (Google,        8× "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060... ← LIE LANDED
... (8 more rows)

========== Token build survived? ==========
baseline: {"bigTokenLen":14544,"medTokenLen":352,"submitOk":true,"largestBtoa":10953}
tampered: {"bigTokenLen":14308,"medTokenLen":352,"submitOk":true,"largestBtoa":10772}
```

Reference output for comparison: [`examples/tamper-sample-2026-05-21.json`](examples/tamper-sample-2026-05-21.json).

What this means: 13 distinct signals — including the two biggest bot
tells (`navigator.webdriver = true` and the SwiftShader WebGL renderer
string) — were replaced with values of our choice. Castle's bundle
encrypted the spoofed values through its own per-field cipher and
shipped them as a valid token to `api.x.com/1.1/onboarding/task.json`.
We did this without reversing the cipher, the wire format, or any
internal Castle protocol. The only attack surface was the JS-engine
prototype layer that the bundle has to read from. Full analysis:
[X.Castle.md §9](X.Castle.md).

---

## Verification (don't trust, test)

Three checks you can run before believing anything in this repo:

**1. The Castle bundle on x.com is what we say it is.**

```bash
curl -sSI 'https://abs.twimg.com/responsive-web/client-web/ondemand.castle.c42626ea.js' | head -5
# Expect: HTTP/2 200, content-type: application/javascript, x-tw-cdn: CF

curl -sSL 'https://abs.twimg.com/responsive-web/client-web/ondemand.castle.c42626ea.js' | sha256sum
# Expected (as of 2026-05-21): 056647a122d2c0a1f45b345c95f0b5895118f1df238d9d67a94bca9d9e6b391b
```

Bundle content-hash will drift on re-deploy; `npm run recon` finds the
current chunk regardless.

**2. The structural claims (encoder distribution, no TLV bit-pack, native-API aliasing) hold.**

```bash
curl -sSL 'https://abs.twimg.com/responsive-web/client-web/ondemand.castle.c42626ea.js' > /tmp/cur.js
python3 -c "
import re
d = open('/tmp/cur.js').read()
print('bundle size:                ', len(d))
print('<<3 (TLV header pack):      ', len(re.findall(r'<<3', d)),    '  (expect 0)')
print('&7/15/31/63/127/255 masks:  ', len(re.findall(r'&(7|15|31|63|127|255)\b', d)), '  (expect 0)')
print('literal String.fromCharCode:', len(re.findall(r'String\.fromCharCode', d)), '  (expect 0)')
print('>>> ops:                    ', len(re.findall(r'>>>', d)),    '  (expect ~745)')
print('createRequestToken refs:    ', len(re.findall(r'createRequestToken', d)), '  (expect 1)')
"
```

**3. The tamper script does what it says.**

```bash
npm install && npm run tamper
cat results/tamper.json | jq '.tampered.sigMap["navigator:webdriver"]'
# Expect: { "count": 3, "samples": [null] }   (JSON serializes undefined as null)
cat results/tamper.json | jq '.baseline.sigMap["navigator:webdriver"]'
# Expect: { "count": 2, "samples": [true] }
```

---

## What's in the repo

```
.
├── README.md                                  this file
├── X.Castle.md                                full analysis writeup
├── package.json                               playwright + prompts deps, npm-run scripts
├── .gitignore                                 node_modules, results/
├── main.mjs                                   interactive arrow-key launcher (npm start)
├── recon.mjs                                  discovery: find Castle chunk
├── stackwalk.mjs                              find chokepoint function offsets
├── bytetap.mjs                                patch every btoa() in the chunk
├── readtap.mjs                                input-side instrumentation
├── submit.mjs                                 readtap + drive login form
├── headers.mjs                                find where token rides on the wire
├── tamper.mjs                                 the demo: baseline vs spoofed
├── dom-probe.mjs                              diagnostic DOM dumper
├── results/                                   each script's JSON output (gitignored)
└── examples/
    └── tamper-sample-2026-05-21.json          reference output for tamper.mjs
```

---

## Known limitations

- **Headless leaks unrelated to Castle.** The runs in `examples/` were
  done on a headless Linux host with no GPU (so WebGL =
  `SwiftShader`, `webdriver = true`, etc.) — Castle's bundle sees a
  textbook bot. The `tamper.mjs` lies the navigator/screen/WebGL
  surface but does not touch canvas font fingerprint, the
  `performance.now` × 2,313 timing side-channel, or the `__cuid`
  localStorage probe. Castle's score (which we can't see — see below)
  still reflects those un-spoofed signals.
- **No risk-score visibility.** Castle's response from `/v1/filter` is
  only readable with the merchant's secret key. We can confirm the
  lies *reach* Castle but not that they *change the risk
  classification*. To prove score movement, point the SDK at your own
  Castle merchant pk/secret (set `--pk` in tamper.mjs or wherever
  configure() is called) and read the `/v1/filter` response.
- **Bundle hash drifts.** `c42626ea` is current as of 2026-05-21.
  When x.com re-deploys, the hash changes; `npm run recon` finds the
  new chunk. The runtime scripts (`readtap.mjs`, `tamper.mjs`) work
  unchanged on any newer Castle bundle because they hook at the JS
  prototype layer, not at specific bundle offsets. `stackwalk.mjs`
  needs to be re-run to find the new chokepoint offsets if you care
  about those.
- **x.com's anti-bot may evolve.** If x.com starts requiring a
  captcha or refuses to render the form for headless Chromium with the
  spoofed UA, the `submit.mjs`/`tamper.mjs` form drivers will fail.
  The `readtap.mjs` capture works regardless (Castle fires
  auto-magically on page load — no submit needed).
- **Per-field cipher kept the format opaque.** We never decoded the
  new wire format or reversed Castle's `tt()` bit-mix cipher. So we
  can't independently verify the encrypted token contains exactly
  what we lied about. The indirect evidence is strong (Castle's
  bundle observably read the lies, token size shrank by 236 bytes
  consistent with shorter spoofed values, no crashes / integrity
  errors) but it isn't byte-level proof. To get byte-level proof,
  reverse `tt()` per X.Castle.md §10.5.
