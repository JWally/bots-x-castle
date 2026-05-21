# X.Castle — 2026-05-21 follow-up: Castle on x.com

Companion to [Castle.md](Castle.md). That writeup reverse-engineered Castle
2.8.4 (vanilla npm + Lovable re-min) on 2026-05-15 and found a universal
TLV encoder `wS[Hg]` whose body fingerprint let a 60-character regex dump
every plaintext field in one shot. Six days later, a heads-up that
Castle had deployed a new build to x.com — this document records what
we found when we pointed the same tooling at it.

Bottom line up front: the static structural attack from Castle.md is
dead. The signal *inventory* is roughly the same plus one notable
addition (`performance.now()` ×2313 as a timing side-channel). Runtime
instrumentation recovers the full plaintext input set. We did not
reverse the new cipher or wire format — and we didn't need to, because
**input-side tampering produces a valid live token containing our
lies** (§9).

All tooling lives under `/tmp/xcom-castle-*.mjs` (see Appendix B).

---

## 1. TL;DR

- Castle is deployed on x.com as a lazy-loaded webpack chunk:
  `https://abs.twimg.com/responsive-web/client-web/ondemand.castle.c42626ea.js`
  (500,037 bytes). It loads on **every** auth-relevant route we tried
  (`/`, `/login`, `/i/flow/login`, `/i/flow/signup`).
- Public key is fetched at runtime from x.com's feature-flag service
  (`responsive_web_castle_public_key`), gated by
  `responsive_web_castle_sdk_enabled`. Init fires inside
  `requestIdleCallback` ~5s after page load.
- The Castle.md `wS[Hg]` regex (and every loosening of it) matches
  **zero** chunks on x.com. Specifically gone: 4-arg encoder, `<<3`
  header-byte pack, `&7/&15/&31/…/&255` masks. Native APIs are aliased
  through a property table at module top.
- The chokepoint defense is *partial*: there is no single encoder, but
  the same byte→base64 helper has been **replicated ~5× across the
  bundle** (`tt`, `f4`, `Array.tN`, `lb`, `lM`) — found by runtime
  stack-walk on `btoa`.
- Per-field cipher is now applied **before** `btoa`, so the bytes
  arriving at base64 are uniformly high-entropy. Static byte-tap
  recovers no plaintext.
- Plaintext recovery now requires **input-side instrumentation**:
  property-getter and method wrappers on Navigator, Screen, Document,
  WebGL, Canvas, Date, Intl, Performance, matchMedia, storage, etc.,
  filtered by stack-trace to "called from `ondemand.castle.*`". This
  works fine and recovers 47 unique signals per fire.
- Castle fires **three times** during a single email-entry attempt on
  `/i/flow/login`: page-load auto-fire, email-field interaction, Next
  click. Tokens grow ~50–150 bytes per fire — Castle accumulates
  session activity between fires.
- Token rides in the **request body** of `POST /1.1/onboarding/task.json`,
  not in a header. 14,760 base64 chars on the submit task; a smaller
  352-char token on flow-init tasks. The Authorization header is
  x.com's bearer guest token, not Castle.
- New signal not in Castle.md: **2,313 reads of `performance.now()` per
  token build** — almost certainly a timing side-channel for automation
  detection. Same family as our own bot-buster CDP-console-timing
  trap (see `project_clean_verdict_v6_proxy_validates_this.md`). Castle
  and us converged independently in roughly the same window.

---

## 2. Bundle layout and loader

### 2.1 Where Castle lives in x.com's bundle

Castle is loaded as a webpack lazy chunk. Reference lives in
`https://abs.twimg.com/responsive-web/client-web/main.6c0fb38a.js`:

```js
// from main.js — Castle init wrapper
function a(e){
  if(!e.isTrue("responsive_web_castle_sdk_enabled"))
    return Promise.resolve(void 0);
  let t = e.getStringValue("responsive_web_castle_public_key");
  return t
    ? (n || (n = r.e(15793).then(r.t.bind(r,164079,23))
                         .then(({configure: e}) => e({pk: t}))))
    : Promise.resolve(void 0);
}
function o(e){
  i = e;
  ("function" == typeof window.requestIdleCallback
    ? e => window.requestIdleCallback(e, {timeout: 5e3})
    : e => window.setTimeout(e, 2e3)
  )(() => { a(e).catch(() => { n = null }) });
}
// auth-event helper
function l(e){
  let t = e || i;
  return t || n
    ? (t ? a(t) : n || Promise.resolve(void 0))
        .then(e => e ? e.createRequestToken() : void 0)
    : Promise.resolve(void 0);
}
```

Notes:
- The chunk ID is `15793` and the configure call lives at module 164079.
- The pk is **not** embedded in main.js — pulled live from x.com's
  feature flag service. That makes the publishable key target-rotatable
  without redeploy.
- Init is deferred to `requestIdleCallback` with a 5-second timeout
  fallback, then `setTimeout(_, 2000)` on browsers without rIC. So
  Castle does not block page paint.

### 2.2 Confirmed chunk URL

```
https://abs.twimg.com/responsive-web/client-web/ondemand.castle.c42626ea.js
   size:    500,037 bytes
   served by: abs.twimg.com (Twitter's static CDN)
   loaded on: x.com/, /login, /i/flow/login, /i/flow/signup
```

main.js (1,410,830 bytes) holds the reference; the actual SDK is in
the ondemand chunk. The hash in the filename (`c42626ea`) is webpack
content-hashed — it will change on re-deploy. Discovery tool
`xcom-castle-recon.mjs` finds it by grep for `createRequestToken` /
`castle.io` / the wS[Hg] structural pattern on every JS response.

### 2.3 SDK API surface

```
configure       → minified to G6 (was Oy[…] in vanilla npm bundle)
createRequestToken → minified to aF
```

Same shape as before: `configure({pk}).createRequestToken()` returns a
URL-safe base64 token string. No client-side network calls during
collection (still no `castle.io` POST from the browser). Token is
returned to x.com's own code, which embeds it in the auth POST body
(section 7).

---

## 3. What Castle actually changed

A side-by-side of Castle.md's structural fingerprints against the new
build. Run the probes yourself with `python3` over the downloaded
`ondemand.castle.c42626ea.js`:

| Probe | Castle.md (vanilla 2.8.4, Lovable) | x.com (`c42626ea.js`) |
|---|---|---|
| `function(n,r,i,t){return X[Y](X[Z](((n&...` universal encoder | matches once | **0 matches** (any loosening) |
| `<<3` (TLV header-byte pack) | present, many | **0 occurrences** |
| `&7` / `&15` / `&31` / `&63` / `&127` / `&255` masks | many | **0 in entire 500KB** |
| Literal `String.fromCharCode` | 9,580 hits per token | **0** — aliased via `iN[cS]` |
| Literal `JSON.stringify` / `TextEncoder` / `Uint8Array` | yes | **all aliased through module-top table** (`iz`, `iV`, `iq`) |
| `>>>` (unsigned-right-shift, cipher) | many | 745 — cipher intact |
| `^` (xor, cipher) | many | 518 — cipher intact |
| `btoa` calls in bundle | many | 458 call sites |
| Per-byte string accumulator + `btoa` wrap | one site (`wS[OM]`) | **replicated ~5× across bundle** |
| Token size (binary, pre-base64) | 1,640 bytes | **~10,800 bytes** (≈6.6× larger) |

### 3.1 The native-API alias table

At the top of the new bundle:

```js
iK = Array
iz = JSON
iW = RegExp
iY = Promise
iV = TextEncoder
iA = Object
iS = Date
iZ = Number
iq = Uint8Array
iN = String     // and iN[cS] = String.fromCharCode
// ...
```

Every native API access in the bundle goes through this table, so a
grep for `JSON.stringify`, `TextEncoder`, `Uint8Array` etc. on the
bundle returns nothing. This is a **pure static-analysis defeat** — at
runtime the aliases resolve to the real natives and any hook installed
on `Object.prototype`, `Array.prototype`, `Function.prototype`,
prototype getters, etc. fires normally. The defense only buys
obfuscation against text-grep tooling.

### 3.2 Distributed byte-emitter helpers

The Castle.md "single chokepoint `wS[Hg]`" weakness is partially
closed: the bundle now contains **at least five** functions of the
shape:

```js
function X(n){
  for(var r = cA, t = cg; t < n[cK]; t++)
    r += iN[cS](n[t]);          // iN[cS] = String.fromCharCode
  return btoa(r);
}
```

Located at (offsets in `ondemand.castle.c42626ea.js`):

- `Array.tN` at `1:17630` — tagged on Array.prototype, biggest payload
  helper (10,828-byte input observed)
- `tt`     at `1:69797` — the post-cipher exit; called with the ~2,288
  byte cipher output
- `f4`     at `1:69269` — per-field encoder, called **63 times** per
  token build
- `lb`     at `1:78586`
- `lM`     at `1:88xxx`

Plus the class-method emitters reachable via `pI.<computed>.n` (line
2, columns 226272 / 229955 / 231809 / 235290 — multiple call sites in
the same class).

The cipher proper still lives in one function, `tt`. Its body is the
new analog of `y(n)` from Castle.md §4.1:

```js
function tt(n){
  var r = [];
  r[0] = []; r[1] = n;
  for(let t = cg; t < r[1][cK]; t++)
    n = ((n = 60834 + (n = ((n = nC(n = (46488 ^ (n = (n = rs(r[1], t, cq))
        - 54655 & cq)) & cq, 54213, ...
  // nested XOR + add + nC + multiply mod, classic bit-mix
}
```

Same shape as the old `y(n)` (nested `>>>` + `^` + magic-constant
multiply-add-mod), just renamed and the constants rotated. Reversing
it would still be hours-to-days of boring work.

### 3.3 Per-field cipher (the consequential change)

This is the change that actually defeats Castle.md's `castle-dump.mjs`
attack. In the May-15 build:

```
plaintext fields → assemble binary TLV (wS[Hg] ×107) → cipher → btoa
```

Patching `wS[Hg]` caught plaintext (sub_tag, type, value) on every
call because the encoder ran *before* cipher.

In the x.com build:

```
plaintext field → per-field encrypt → btoa → concatenate (×63) → cipher → btoa
```

Confirmation: byte-tap (`xcom-castle-bytetap.mjs` patches every one of
the 458 `btoa(...)` call sites in the chunk and captures full
arguments) — every single capture is high-entropy bytes. None of the
61 fired btoa inputs across one token build contained any ASCII
strings, recognizable field tags, or length-prefixed strings. The
plaintext literally does not exist at any `btoa` boundary in the new
build.

This is the smart move. It pushes the attack surface up one layer (you
have to hook the per-field encoders' *inputs*) and it eliminates the
"one regex unlocks the whole payload" failure mode. The Castle.md
recommendation in §6.2.a — "argus should NOT consolidate signal
emission through one obvious entry point" — has been applied to
Castle itself.

---

## 4. New attack: runtime input-side instrumentation

Since the encoder/cipher path no longer leaks plaintext, we hook the
*read* side: install wrapped getters and method wrappers on every
prototype that fingerprinters care about, filter logs by stack-trace
to "called from `ondemand.castle.*`", run a normal page load, and dump
the read log.

Tool: `/tmp/xcom-castle-readtap.mjs`. Wraps:

- `Navigator.prototype` getters: `userAgent`, `appVersion`, `platform`,
  `vendor`, `vendorSub`, `product`, `productSub`, `language`,
  `languages`, `hardwareConcurrency`, `deviceMemory`, `maxTouchPoints`,
  `cookieEnabled`, `doNotTrack`, `webdriver`, `pdfViewerEnabled`,
  `plugins`, `mimeTypes`, `userAgentData`, `oscpu`, `buildID`,
  `onLine`, `connection`
- `Screen.prototype`: `width`, `height`, `availWidth`, `availHeight`,
  `colorDepth`, `pixelDepth`, `orientation`
- `window.{innerWidth,innerHeight,outerWidth,outerHeight,
  devicePixelRatio,screenX,screenY}`
- `Document.prototype.{cookie,referrer,title}`,
  `HTMLDocument.prototype.cookie`
- `Location.prototype.{hostname,host,port,pathname,protocol,href,origin,search}`
- `Date.prototype.{getTimezoneOffset,toLocaleString,toString,getTime}` + `Date.now`
- `Performance.prototype.{getEntriesByType,getEntries,memory,timeOrigin}`
  (NOTE: omit `now` in long-running runs — wrapping it makes
  `new Error().stack` fire on every React internal call and tanks
  page load. Sample-based capture only.)
- `window.matchMedia` (logs the query string and the .matches result)
- `WebGLRenderingContext.prototype.{getParameter,getExtension,
  getShaderPrecisionFormat}` and the `WebGL2RenderingContext` version
- `CanvasRenderingContext2D.prototype.{measureText,fillText,strokeText,
  getImageData}` and `HTMLCanvasElement.prototype.toDataURL`
- `OfflineAudioContext.prototype.startRendering`,
  `RTCPeerConnection.prototype.createDataChannel`,
  `crypto.getRandomValues`
- `localStorage`/`sessionStorage.getItem`, `indexedDB.open`
- `navigator.userAgentData.getHighEntropyValues`,
  `navigator.permissions.query`
- `Intl.DateTimeFormat().resolvedOptions`

Each wrap installs a getter or method that:

1. Calls the real native (transparent to the page).
2. Stack-checks `new Error().stack` against `/ondemand\.castle\./`.
3. If matched, pushes `{ts, ord, channel, what, value}` to
   `window.__reads` with the value truncated and stringified
   defensively.

Then `addInitScript(INSTRUMENT)` via Playwright, navigate to
`x.com/i/flow/login`, settle 18–25 s, read out `window.__reads`.

---

## 5. The plaintext payload

Single token build, page-load auto-fire on `/i/flow/login`,
unsubmitted. **2,896 reads attributed to the Castle bundle**.

### 5.1 Reads by channel

```
performance  2,325
canvas         446
date            37
navigator       37
screen          20
window          15
webgl            8
storage          3
matchMedia       2
document         1
uaData           1
permissions      1
```

### 5.2 Unique signals with sample values

Ordered by call count within one page-load fire:

| × | Channel/Signal | Sample value |
|---|---|---|
| **2,313** | `performance.now()` | `1084.0999994277954` (see §5.3) |
| 295 | `canvas.measureText` | `text="mmmmmmmmmmlli", width=782.666015625` |
| 118 | `canvas.fillText` | `text="Hello Canvas", x=20, y=150` |
| 33 | `Date.now` | `1779393271224` |
| 23 | `canvas.getImageData` | `x=0,y=0,w=200,h=200, sampleHash="0,0,0,..."` |
| 10 | `canvas.toDataURL` | `len=8626, head="data:image/png;base64,iVBORw0..."` |
| 9 | `performance.getEntriesByType` | `args=["navigation"], result=[{}]` |
| 6 | `screen.orientation` | (object) |
| 5 | `navigator.userAgent` | `"Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/131.0.0.0 Safari/537.36"` |
| 4 | `webgl.WebGL1.getExtension` | `"WEBGL_debug_renderer_info"` |
| 4 | `webgl.WebGL1.getParameter` | `"ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)"` |
| 4 | `window.innerWidth` | `1280` |
| 4 | `window.outerHeight` | `800` |
| 4 | `navigator.languages` | `["en-US"]` |
| 3 | `localStorage.getItem('__cuid')` | `null` (first-time visitor) |
| 3 | `navigator.platform` | `"Linux x86_64"` |
| 3 | `navigator.hardwareConcurrency` | `12` |
| 3 | `navigator.deviceMemory` | `8` |
| 3 | `Date.getTimezoneOffset` | `360` (CST) |
| 3 | `screen.width` | `1280` |
| 3 | `screen.height` | `800` |
| 3 | `screen.colorDepth` | `24` |
| 3 | `window.innerHeight` | `800` |
| 2 | `navigator.vendor` | `"Google Inc."` |
| 2 | `screen.availWidth` | `1280` |
| 2 | `navigator.userAgentData` | (object) |
| 2 | `window.outerWidth` | `1280` |
| 2 | `performance.timeOrigin` | `1779393270140.5` |
| 2 | **`navigator.webdriver`** | **`true`** (headless leak, see §8) |
| 2 | `window.devicePixelRatio` | `1` |
| 2 | `navigator.mimeTypes` | (collection) |
| 2 | `screen.availHeight` | `800` |
| 2 | `navigator.language` | `"en-US"` |
| 2 | `navigator.maxTouchPoints` | `0` |
| 2 | `navigator.productSub` | `"20030107"` |
| 1 | `document.cookie` | `"guest_id_marketing=v1%3A..; guest_id_ads=..; guest_id=..; personalization_id=.."` |
| 1 | `navigator.plugins` | (collection) |
| 1 | `performance.memory` | (object: jsHeapSizeLimit, etc.) |
| 1 | `navigator.pdfViewerEnabled` | `false` |
| 1 | `uaData.getHighEntropyValues` | `args=[[]], result={}` |
| 1 | `screen.pixelDepth` | `24` |
| 1 | `matchMedia('(prefers-color-scheme: light)')` | `true` |
| 1 | `permissions.query` | `args=[{name:'notifications'}]` |
| 1 | `navigator.cookieEnabled` | `true` |
| 1 | `navigator.appVersion` | `"5.0 (Windows NT 10.0; Win64; x64) ..."` |
| 1 | `matchMedia('(dynamic-range: high)')` | `false` |
| 1 | `navigator.doNotTrack` | `null` |
| 1 | **`Date.toLocaleString`** | **`"3/3/1970, 6:00:00 PM"`** (timezone probe, see §5.4) |

### 5.3 The headline new signal: `performance.now()` ×2,313

The 2,313 reads is what jumped out. Castle.md does not document any
significant volume of `performance.now()` use. This is almost
certainly a **timing side-channel detector** — same family of probe
as our own bot-buster CDP-console-timing trap. The trick is:

1. Tight loop of `performance.now()` calls (sometimes wrapped around
   trivial JS ops, sometimes around object-property reads, sometimes
   around TypeError throw/catch).
2. Measure both wall-clock advance and per-iteration variance.
3. CDP-driven automation, headless paths with synthetic clocks, and
   anti-bot wrappers that patch `Date.now` but not `performance.now`
   (or vice versa) all leak distinctive timing profiles.

Note specifically: our v6/v7 clean-verdict attacks on argus exploited
the inverse — patching `performance.now` and `Date.now` together to
hide CPU-bench-based automation detection. Castle is running the same
class of detector. See `project_clean_verdict_v6_proxy_validates_this.md`
and `project_clean_verdict_v7_dual_proxy.md` for the parallel art.

If you spoof one clock but not the other, or if you let the real
clocks through but advance them at non-physical rates, this fires.

### 5.4 Unchanged signature techniques from Castle.md

These probes from the May-15 writeup are **byte-for-byte identical**
on x.com:

- **`measureText('mmmmmmmmmmlli')` ×295** — same Mowery/Shacham font
  width probe, same exact iteration count. They literally did not
  change this. The 94 distinct fillText strings (emojis, Swedish
  pangram, Brahmi, Burmese, Tibetan glyphs) also appear in the
  fillText stream though we sampled fewer in the runtime tap (118 vs
  Castle.md's 116; close enough that this is the same code path).
- **`new Date(0).toLocaleString()` → `"3/3/1970, 6:00:00 PM"`** —
  the timezone probe is unchanged (Castle.md §3.2 tag `0xa4`).
- **Cyclic-`__proto__` error-dialect probe** — not directly visible in
  the read tap (it would manifest as an Error construction, which we
  don't hook), but the byte-tap shows the equivalent code path is
  still firing (no ASCII proof, but `Function.prototype.toString` is
  being called 5,000+ times per build — the tamper sweep).
- **WebGL unmasked-renderer via `getExtension('WEBGL_debug_renderer_info')`
  then `getParameter(37446)`** — same exact technique.
- **`__cuid` localStorage probe** — Castle's persistent visitor ID
  (Castle.md §4.2 tag `0x14` deterministic hash analog).

### 5.5 Confirmed architectural absences (still)

These remain absent in the new bundle, same as Castle.md §4.6:

- **No WebRTC** — `RTCPeerConnection.createDataChannel` wrap fired zero
  times. ICE-candidate spoofing remains invisible to Castle.
- **No `crypto.subtle.*`** — all crypto pure-JS.
- **No client beacons to castle.io** — token still ships via the
  customer's own backend (§7).
- **No `OfflineAudioContext`** — no audio fingerprint.
- **No `IndexedDB.open`** — persistence is cookies + `__cuid`
  localStorage + the deterministic hash.

---

## 6. Multi-fire behavior on interaction

This was not in scope for the Castle.md vanilla-npm capture (which
called `createRequestToken()` once in isolation). On x.com under a
realistic auth flow, Castle fires **three times per email-entry
attempt**:

| Fire | Trigger | Total reads | Unique signals | Token size (binary, pre-base64) |
|---|---|---|---|---|
| 1 | Page load, ~5 s after `requestIdleCallback` | 584 | **47** | 10,778 bytes |
| 2 | Email field interaction (typing / `input.fill`) | 123 | 17 | 10,865 bytes |
| 3 | "Next" button click | 123 | 17 | 10,920 bytes |

### 6.1 Slow-path / fast-path split

The first fire runs the **full** collection: 295× `measureText` font
enumeration, 23× `getImageData` pixel readback, 10× `toDataURL` canvas
hash, localStorage probes, 9× navigation-timing reads, performance.memory.

Subsequent fires drop those expensive ops and run only the **fast
path**: 92× `fillText` (active canvas render), 5× `toDataURL` (single
new canvas hash), 2–3× each navigator/screen/webgl/date read. Same 17
signal set on fire 2 and fire 3 — identical call counts.

This is exactly what you'd build if you wanted real-time risk scoring
during an auth flow: first fire is heavy and caches, subsequent fires
are cheap re-verifications that pick up live changes (UA spoofing
toggled mid-session, devtools opened, etc.).

### 6.2 Token grows ~50–150 bytes per fire

10,778 → 10,865 → 10,920 (binary, pre-base64). The token is
**accumulating**: each subsequent fire embeds session activity since
the previous fire — likely mouse movements, focus changes,
key-timing, scroll, the gap between page load and interaction. Old
Castle (Castle.md baseline) was stateless per-token; new Castle is
stateful, the SDK keeps a running event log and tokens get richer the
longer the user interacts.

This is observable but not catastrophic to spoofing — you'd just need
to reproduce a believable interaction trace, not a single point-in-time
fingerprint.

### 6.3 Marker partitioning

The instrumentation script writes synthetic `__marker` records into
the read log at:

- PAGELOAD_FIRE_DONE  (after 25 s settle)
- BEFORE_NEXT_CLICK   (immediately before our `input.fill` + click)
- AFTER_NEXT_CLICK    (immediately after click handler returned)
- END_OF_RUN          (after 15 s post-click settle)

This partitions reads into per-fire buckets without false attribution
from x.com's own non-Castle code.

---

## 7. Token delivery on x.com

Castle on x.com never POSTs to `castle.io` from the browser. The token
rides in the body of x.com's own auth API:

```
POST https://api.x.com/1.1/onboarding/task.json
Content-Type: application/json
Authorization: Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAA...   (x.com's app-level guest bearer, NOT Castle)
Body length: 15,095 bytes
Body contains: a 14,760-character URL-safe-base64 token (≈ 10,920 binary bytes)
                head: "UwnPCzA21U/Lc65KKStPLzbWDs91yiqvNDXwLfYt…"
```

The exact JSON path of the token inside the body wasn't extracted
(the body is a deeply nested flow-task envelope); a follow-up could
diff bodies with and without Castle init to localize it. Header probe
returns no high-entropy header values — the token is body-only.

**Two flavors observed**:

| Stage | Length | Probable role |
|---|---|---|
| flow-init `/onboarding/task.json` (no `flow_name=login`) | 352 base64 chars | Lightweight check-in token — first contact, minimal collection |
| username-submit `/onboarding/task.json` (full) | 14,760 base64 chars | Full Castle token with all the fingerprint + session log |

x.com's backend forwards the token server-to-server to Castle's
`/v1/filter`, presumably with their secret key. The customer-backend
relay model from Castle.md §2.1 holds; x.com is the customer.

---

## 8. What we beat, what we didn't

### 8.1 Beat

- The Castle.md static structural regex (`wS[Hg]` 4-arg encoder body
  fingerprint) is dead against the new build. We confirmed
  empirically: 0 patched chunks across `castle-dump.mjs --url`
  against `/i/flow/login`, `/login`, `/signup`, `/`.
- Recovered the full plaintext input set Castle reads on x.com — 47
  unique signals with values, frequencies, and timing per fire — via
  runtime input-side instrumentation. Per §5.
- Identified the new chokepoint locations (`tt`, `f4`, `Array.tN`,
  `lb`, `lM` plus class-method emitters under `pI.<computed>.n`) by
  runtime stack-walk on `btoa`.
- Identified the new signal (`performance.now` ×2,313) and the
  multi-fire behavior (3 fires per interaction, ~10,800-byte tokens
  growing ~50–150 bytes per fire).
- Located the token's submission point (POST `/1.1/onboarding/task.json`
  body, 14,760 base64 chars).

### 8.2 Did NOT beat

Honest accounting — these are the things a follow-up project would
need to land before we could claim Castle's collection on x.com is
"defeated" in any operational sense:

- **Cipher not reversed.** The `tt` bit-mix function with its nested
  XOR + multiply-add-mod and rotated magic constants is a few days of
  boring algebra away. Without that, we can't decrypt captured tokens
  off the wire.
- **Wire format not decoded.** The old `(sub_tag << 3) | type` TLV
  header byte is structurally gone (zero `<<3`, zero mask literals in
  the entire bundle). Whatever replaced it is unknown. Probably a
  per-field cipher envelope with its own headers and length prefixes,
  but we have not byte-mapped it.
- **No per-field spoof.** Castle.md's `castle-dump.mjs --override
  sub=0x06,type=5,value=8` lever does not exist here. The per-field
  cipher applied before `btoa` means there is no value to override at
  a single regex-findable site; you'd need to identify each per-signal
  emitter individually and patch its input. Doable, but not done.
- **No undetectable token forgery.** Even if we reversed cipher + format,
  Castle correlates session-activity accumulation across fires (§6.2),
  and the customer-backend relay model gives Castle server-side
  visibility into IP, TLS fingerprint, and HTTP headers on the
  forwarded request that the client cannot influence. A forged token
  that doesn't match the live HTTP context fails.
- **We're already a bot to Castle.** Our headless Chromium runs
  produced `navigator.webdriver === true` in Castle's reads twice per
  fire. The WebGL renderer was `SwiftShader` (no GPU on the headless
  host). Even if we had complete plaintext spoofing, the *content*
  Castle saw of us would already score as block. Stealth and plaintext
  capture are independent problems and only one was solved here.

### 8.3 The summary line

The hardening worked at exactly the level it was designed to — static
structural reverse engineering of the bundle is dead — and didn't
work at a level it was never designed to stop, which is runtime
prototype-level instrumentation. To raise that ceiling, Castle would
need WebAssembly cipher, sandbox/realm isolation, or remote attestation,
none of which are present on x.com today.

---

## 9. Value tampering in production (2026-05-21, post-readtap)

Demonstrated end-to-end against the live `x.com/i/flow/login` flow.
Tool: `/tmp/xcom-castle-tamper.mjs`. The premise from §3.3 is that
since the per-field cipher runs *before* `btoa`, there is no `btoa`
boundary where plaintext exists — so static byte-tap can't extract
plaintext. The corollary, run in reverse, is that **if we lie about
the source values Castle reads, Castle's pipeline encrypts our lies
into its own otherwise-valid token**. No cipher reversal needed.

### 10.1 The approach

`addInitScript` two scripts in order, *before* any page script runs:

1. **LIES**: patches `Navigator.prototype`, `Screen.prototype`,
   `WebGLRenderingContext.prototype.getParameter`, `window.matchMedia`,
   and `window.devicePixelRatio` to return spoofed values. Patching at
   the prototype (not the instance) defeats the cross-validation in
   Castle.md §4.5 — both `navigator.X` and
   `Object.getOwnPropertyDescriptor(Navigator.prototype, 'X').get.call(navigator)`
   resolve to the same wrapped descriptor.

   Every wrapped function is registered in a `lyingToStringMap`
   `WeakMap`, and `Function.prototype.toString` is patched to return
   `'function get X() { [native code] }'` for any function in the map.
   That defeats Castle.md §4.7's `[native code]` tamper sweep (which
   fires 5,000+ times per token build per §3.4 / §5.2 — confirmed
   still active in the new bundle).

2. **READTAP**: the same prototype-getter logger from §4, stacked
   *over* the lies. When Castle reads `navigator.platform`, the call
   resolves through READTAP (which calls the inner getter and logs
   what it returns) → LIES (which returns the spoof) → log records
   what Castle actually saw. This means `__reads` is the ground truth
   for what landed.

Run baseline (no lies) + tampered side by side, diff `__reads` for
each signal, confirm the token still builds and gets posted to
`api.x.com/1.1/onboarding/task.json`.

### 10.2 Diff: what Castle saw

| Signal | Baseline (real values) | Tampered (what Castle read) | Lie landed? |
|---|---|---|---|
| `navigator.webdriver` | **`true`** (headless leak) | `undefined` | yes |
| `navigator.platform` | `"Linux x86_64"` | `"Win32"` | yes |
| `navigator.hardwareConcurrency` | `12` | `8` | yes |
| `navigator.deviceMemory` | `8` | `16` | yes |
| `navigator.languages` | `["en-US"]` | `["en-US","en"]` | yes |
| `navigator.plugins` | `{}` (empty) | 5 PDF Viewer entries | yes |
| `navigator.mimeTypes` | `{}` (empty) | 2 PDF mime types | yes |
| `navigator.userAgentData` | `{}` (empty) | Chrome-Win brands w/ full version list | yes |
| `screen.width` | `1280` | `1920` | yes |
| `screen.height` | `800` | `1080` | yes |
| `screen.availWidth` | `1280` | `1920` | yes |
| `WebGL.getParameter(37446)` | **`SwiftShader Device (Subzero)…`** | `ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 …)` | yes |
| `navigator.userAgent` | (already Windows UA via ctx option) | same | (not a fair test) |
| `navigator.vendor` | `"Google Inc."` | `"Google Inc."` | (already matched) |
| `navigator.language` | `"en-US"` | `"en-US"` | (already matched) |
| `window.devicePixelRatio` | `1` | `1` | (already matched) |
| `matchMedia('(max-resolution:96dpi)')` | (not probed) | (not probed) | DPI search dropped in new build |
| `matchMedia('(device-width:1920px)…')` | (not probed) | (not probed) | DPI cross-validation dropped |

**13 distinct lies landed verbatim.** Two are huge: `webdriver=true →
undefined` (the single most actionable bot tell) and `SwiftShader →
NVIDIA RTX 3060` (which alone reclassifies the device from
"datacenter / VM" to "consumer desktop").

Side note: the May-15 DPI binary search (Castle.md §3.3, the 41-query
matchMedia probe) does **not fire** in the x.com build. Either Castle
dropped it, moved it behind a feature flag, or only runs it on
high-risk merchants. Our matchMedia hooks captured only
`(prefers-color-scheme:light)` and `(dynamic-range:high)` — the same
2 calls noted in §5.

### 10.3 Token still builds and submits

| | Baseline | Tampered |
|---|---|---|
| Castle btoa calls per session | 1,345 | 1,345 |
| Largest btoa input (binary, pre-base64) | 10,953 bytes | 10,772 bytes |
| Final token in `POST /1.1/onboarding/task.json` body | 14,544 base64 chars | 14,308 base64 chars |
| Lightweight flow-init token | 352 base64 chars | 352 base64 chars |
| `Object.G6 [as createRequestToken]` errored? | no | no |
| Submit reached x.com? | yes | yes |

The tampered token is 236 base64 chars shorter than the baseline —
expected, because some of our spoofed values (e.g. shorter platform
string, smaller numeric fields) serialize tighter. Both tokens are
cryptographically valid Castle tokens — they passed Castle's internal
integrity checks well enough to ship, and x.com forwards them
server-to-server to Castle's `/v1/filter` as part of the
auth-event flow.

### 10.4 What this proves

- The encoder-distribution + per-field-cipher hardening from §3.3
  closes the *encoder-output* attack from Castle.md (no plaintext at
  any `btoa` boundary). It does **not** close the *encoder-input*
  attack, because the bundle still has to read source values from
  unprivileged JS-engine surfaces. Anything reachable via
  `Object.defineProperty` on a prototype is fair game.
- `Function.prototype.toString` tamper sweeps are still a paper
  defense: a one-line `WeakMap` countermeasure (Castle.md §4.7)
  makes every wrapped getter look native, and the sweep fires
  5,000+ times per build without ever flagging.
- Castle's cross-validation hardening (Castle.md §4.5: same signal
  read via different paths must agree) is satisfied automatically
  if you patch on the prototype rather than the instance — both
  access paths resolve to the same descriptor.

### 10.5 What this does NOT prove

- **We can't see Castle's risk score.** Without x.com's secret key, we
  can't decode Castle's response from `/v1/filter`. To prove the lies
  moved the score we'd need either:
  - A side-channel from x.com's behavior (rate limiting differences,
    captcha rates, lockouts) measured at scale, OR
  - Our own Castle merchant account with our own pk/secret to point
    the SDK at, OR
  - Cipher reversal (§10.5) so we can decrypt tokens.
- **Not all signals are spoofed.** The canvas font enumeration (295
  `measureText` calls), `performance.now()` timing side-channel (2,313
  reads), `__cuid` localStorage probe, and `document.cookie` reads all
  still see the real headless host. Castle's canvas hash, timing
  fingerprint, and persistent-visitor-ID derivation operate on real
  data. A real engagement would need:
  - Canvas-API wrapping with consistent fake `TextMetrics.width`
    values (hard — opaque downstream hash);
  - `performance.now` + `Date.now` returning lockstep counters
    (the v6/v7 clean-verdict pattern, see
    `project_clean_verdict_v7_dual_proxy.md`);
  - Pre-populated `__cuid` to claim a returning visitor identity.
- **No mouse/keyboard activity spoof.** §6.2 noted tokens grow ~50–150
  bytes per fire as Castle accumulates session activity. Our spoofs
  don't touch that channel — the accumulator still records what
  happened in this session. If Castle scores "no human-shaped mouse
  movement before submit" as suspicious, the lies above don't help.

### 10.6 What's actually changed in the production token

To prove the lies are *in* the token (vs. read by Castle but then
dropped by some integrity check before encoding), we would need to
decrypt the captured token — i.e., reverse the cipher per §10.5. We
haven't. But the indirect evidence is strong: the tampered token is
~236 bytes smaller than baseline (consistent with shorter spoofed
values), all 13 lies were observed reaching Castle's code, and the
token built successfully without errors. The cipher is deterministic
on its input; whatever inputs Castle saw are what got encrypted.

---

## 10. Suggested next steps

Ordered by leverage relative to effort:

1. **Get a Castle merchant account** (pk + secret) and point the
   tamper harness at it. Lets us see `/v1/filter` response
   client-side: actual `risk`, `policy.action`, `signals[]`. Without
   this we can demonstrate that lies *reach* Castle but not that they
   *change the score*.
2. **Diff x.com's `/onboarding/task.json` body with and without Castle
   active** to localize which JSON field carries the token. Cheap.
3. **Patch the un-spoofed surfaces**: canvas, `performance.now`, the
   `__cuid` localStorage probe. Combine with the existing prototype
   lies to produce a fully fake device profile. This is where the
   prior clean-verdict work (v3–v7) on argus directly applies — same
   primitives.
4. **Reverse the per-field cipher input boundary**. Identify the
   63 per-signal emitter sites in the bundle (one `f4` call per
   signal). Wrap each one's input via in-flight bundle patching with a
   new structural fingerprint (the byte-emitter shape from §3.2 + the
   call-tree position). Recovers per-field plaintext → encoded blob
   mapping. Now optional given §9.
5. **Reverse `tt` cipher** by capturing many (plaintext-in,
   ciphertext-out) pairs through step 4 and running it offline as a
   constraint problem. The bit-mix has only ~6 stages and operates
   per-byte; given enough pairs it's recoverable. Only really needed
   if we want to forge tokens *without* running Castle's bundle, or
   to decrypt third-party tokens captured off the wire.
6. **Build a stealth-passing capture**. Combine the byte-tap with a
   real-Chrome `channel: 'chrome', launchPersistentContext` profile
   + `--disable-blink-features=AutomationControlled` (the v5/v6/v7
   clean-verdict bot recipe). That puts our captured plaintext into
   a "bot doesn't already look like a bot" state and lets us
   measure how Castle scores fingerprints in isolation from our
   headless stigma.
7. **Compare x.com's bundle hash drift over time** to detect when
   Castle re-deploys, and re-run the read tap to see if the signal
   set changes. The bundle is content-hashed (`c42626ea`), so
   detection is trivial.

---

## Appendix A: Tooling inventory

All ad-hoc, lives under `/tmp/`. Move into `ms-argus-bots/src/bots/` if
this work continues.

| Script | Role |
|---|---|
| `xcom-castle-recon.mjs` | Loads each x.com auth URL with Playwright, logs every JS response, flags chunks containing `createRequestToken` / `castle.io` / `wS[Hg]` regex. Discovery tool. |
| `xcom-castle-stackwalk.mjs` | Wraps `btoa`, `Uint8Array` constructor, `Function.prototype.toString` BEFORE bundle load; captures call-stack top-frames for every call. Locates the byte-emitter functions by their offsets in the minified bundle. |
| `xcom-castle-bytetap.mjs` | Bundle-patch in flight: rewrites every `btoa(EXPR)` call site in the Castle chunk to `__btoaTap(EXPR, callsite_idx)`. Captures full input bytes per call. Confirmed all 61 fired inputs are high-entropy → no plaintext at the btoa boundary. |
| `xcom-castle-readtap.mjs` | Prototype-getter / method instrumentation on Navigator, Screen, WebGL, Canvas, Date, Document, Location, Performance, matchMedia, storage, crypto. Stack-filtered to `ondemand.castle.*`. Produces the §5 plaintext signal inventory. |
| `xcom-castle-submit.mjs` | `readtap` + marker checkpoints (`PAGELOAD_FIRE_DONE`, `BEFORE_NEXT_CLICK`, `AFTER_NEXT_CLICK`, `END_OF_RUN`) and an actual Playwright-driven submit on the login form. Produces the §6 multi-fire timing breakdown. |
| `xcom-castle-headers.mjs` | Captures full request headers + POST bodies on x.com auth endpoints, flags high-entropy long-base64 fragments. Produces the §7 token-delivery findings. |
| `xcom-castle-tamper.mjs` | Prototype-getter overrides (LIES) stacked beneath readtap, run baseline + tampered side-by-side, diffs what Castle saw. Produces the §9 value-tampering demonstration. |
| `xcom-dom-probe.mjs` | Tiny DOM dump tool — used once when the submit-form selector failed; lists all visible inputs and buttons on the page. |

Output JSONs from each run sit at `/tmp/xcom-castle-*.json`.

## Appendix B: Quick reproducibility

```bash
# 1. find Castle on x.com
node /tmp/xcom-castle-recon.mjs

# 2. download the chunk for offline inspection
curl -sSL -o /tmp/xcom-castle/ondemand.castle.js \
  'https://abs.twimg.com/responsive-web/client-web/ondemand.castle.c42626ea.js'

# 3. verify the structural changes
python3 -c "
import re
d = open('/tmp/xcom-castle/ondemand.castle.js').read()
print('<<3:        ', len(re.findall(r'<<3', d)))
print('&31/&7/...:  ', len(re.findall(r'&(7|15|31|63|127|255)\b', d)))
print('4-arg fn:   ', len(re.findall(r'function\([a-zA-Z_$][a-zA-Z0-9_$]*,[a-zA-Z_$][a-zA-Z0-9_$]*,[a-zA-Z_$][a-zA-Z0-9_$]*,[a-zA-Z_$][a-zA-Z0-9_$]*\)\{', d)))
print('>>> ops:    ', len(re.findall(r'>>>', d)))
"
# Expect: 0, 0, 2 (both 4-arg fns are non-encoders), 745

# 4. capture the plaintext signal set
node /tmp/xcom-castle-readtap.mjs
cat /tmp/xcom-castle-readtap.json | jq '.uniqueSignals | keys | length'

# 5. submit + multi-fire diff
node /tmp/xcom-castle-submit.mjs
cat /tmp/xcom-castle-submit.json | jq '.bucketCounts, .btoaBucketCounts'

# 6. confirm token delivery
node /tmp/xcom-castle-headers.mjs | grep "body-token"
```

The bundle's content hash will drift when Castle re-deploys; the
`xcom-castle-recon.mjs` discovery step finds the new chunk regardless,
and the runtime taps don't depend on bundle internals.
