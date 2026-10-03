# EnvCloak motion spec

**Version 1, 3 October 2026.** For the M3 macOS app (SwiftUI) and for envcloak.com.

The motion set has four moments: the logo reveal, the loaders, the redaction line and the approval pulse. Every number in this file was generated from the same timeline source that compiled the CSS keyframes in the SVGs. The web and the app therefore share one source and cannot drift apart. A SwiftUI reference implementation is in `swiftui/EnvCloakMotion.swift`. It type-checks against the macOS 26 SDK, and its timelines match the CSS at 1,202 samples taken 5 ms apart.

Paths are relative to `assets/brand/motion/`. The brand guide is [`docs/BRAND.md`](../../../docs/BRAND.md).

---

## The rules

1. **The `=` is drawn once, in the logo reveal.** After that, only the block moves.
2. **The block keeps time on the caret clock:** 530 ms on and 530 ms off, with hard cuts. It never fades when it blinks. The one exception is reduced motion (see below).
3. **Every sequence signs off the same way: two blinks, then still.** The block goes off for 530 ms, on for 530, off for 530, then stays on. The sign-off lasts 2120 ms.
4. **The block never prints a character.** At rest it is always 3:5. It is wider only while it covers a value in the redaction moment, and that lasts 600 ms.
5. **Amber only sits on Ink.** On a light surface, the approval mark brings its own Ink plate.
6. **Stay calm.** There is no bounce, overshoot, glow or shake. The only scale change is the single approval pulse to 1.10.
7. **Reduced motion means no movement and no hard flashing.** Each moment shows its resting state. Colour changes stay, and the loaders breathe slowly instead of blinking.

## Tokens

| Token | Value | CSS | SwiftUI |
|---|---|---|---|
| Caret | 530 ms on, 530 ms off | keyframes 530 ms apart with `steps(1, end)` | `TimelineView(.periodic(from: start, by: 0.53))`, or `MoveKeyframe` cuts |
| Draw | Used for the `=` being drawn: a firm start and a long, soft landing | `cubic-bezier(0.5, 0, 0, 1)` | `UnitCurve.bezier(startControlPoint: UnitPoint(x: 0.5, y: 0), endControlPoint: UnitPoint(x: 0, y: 1))`, or `.timingCurve(0.5, 0, 0, 1, duration:)` |
| Settle | Used for arrivals and collapses: fast, then exact | `cubic-bezier(0.2, 0, 0, 1)` | `UnitCurve.bezier(startControlPoint: UnitPoint(x: 0.2, y: 0), endControlPoint: UnitPoint(x: 0, y: 1))`, or `.timingCurve(0.2, 0, 0, 1, duration:)` |
| Breathe | Used for the pulse return and the reduced-motion fades: a symmetric ease in and out | `cubic-bezier(0.45, 0, 0.55, 1)` | `UnitCurve.bezier(startControlPoint: UnitPoint(x: 0.45, y: 0), endControlPoint: UnitPoint(x: 0.55, y: 1))`, or `.timingCurve(0.45, 0, 0.55, 1, duration:)` |
| Ghost | The empty block in loaders | `opacity: 0.2` | `.opacity(0.2)` |
| Sign-off | Two blinks, then still | 2120 ms | `ECMotion.signOffVisible(_:from:)` |

**Colours**

| Name | Hex | Use in motion |
|---|---|---|
| Ink | `#111110` | The text and block on Paper, and the plate under any Amber |
| Paper | `#F3F0E8` | The `=`, text and block on Ink, and the approval block at rest |
| Amber Phosphor | `#FFB000` | The block on Ink: the brand reveal, the hero line and a waiting approval. Never on Paper. |
| Dark tile | `#0B0B0A` | The approval plate in the dark appearance |
| Dark `=` | `#DCD8CE` | The approval `=` in the dark appearance |

All colour transitions interpolate in sRGB, as CSS does for hex colours. The tables below give the hex value per frame.

**Curve samples.** Each row gives eased progress y at input progress x. Use these to unit-test a native curve.

| x | 0.0 | 0.1 | 0.2 | 0.3 | 0.4 | 0.5 | 0.6 | 0.7 | 0.8 | 0.9 | 1.0 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| draw | 0.000 | 0.017 | 0.104 | 0.447 | 0.729 | 0.851 | 0.919 | 0.960 | 0.984 | 0.996 | 1.000 |
| settle | 0.000 | 0.156 | 0.500 | 0.688 | 0.802 | 0.878 | 0.929 | 0.963 | 0.985 | 0.996 | 1.000 |
| breathe | 0.000 | 0.018 | 0.075 | 0.177 | 0.324 | 0.500 | 0.676 | 0.823 | 0.925 | 0.982 | 1.000 |

---

## 1. Logo reveal

**Files:**
- `reveal/reveal-ink.svg` for Paper backgrounds.
- `reveal/reveal-paper.svg` for dark backgrounds.
- `reveal/reveal-amber-on-ink.svg` carries its own Ink field with clear space, and shows a Paper `=` with an Amber block.

Each file plays once on load and rests. Set `--ec-iter: infinite` on an ancestor to loop it, as the demo page does.

**What happens:**
- The `=` draws in from the left, top bar first.
- The block lands with a hard cut, as a caret appears in a terminal.
- The block blinks twice, then holds still.

The whole entrance takes 900 ms, and the logo is at rest after 3020 ms.

**Construction:**
- Each bar is revealed by a mask anchored at its left edge. The mask's width goes from 0 to 3s, so the bar's own rounded corners never distort.
- Nothing scales.
- In SwiftUI, use `.mask(alignment: .leading) { Rectangle().frame(width: 3 * s * progress) }`.

| t (ms) | Top bar | Low bar | Block |
|---|---|---|---|
| 0 | wipe starts (draw, 540 ms) | hidden | hidden |
| 180 | | wipe starts (draw, 540 ms) | |
| 540 | full | | |
| 720 | | full | |
| 900 | | | **on** (cut) |
| 1430 | | | off |
| 1960 | | | on |
| 2490 | | | off |
| 3020 | | | **on, rests** |

**Wipe width per frame**, as a share of the bar's 3s width, sampled every 60 ms:

| t (ms) | Top bar width | Low bar width |
|---|---|---|
| 0 | 0.0 % | 0.0 % |
| 60 | 2.2 % | 0.0 % |
| 120 | 14.6 % | 0.0 % |
| 180 | 57.4 % | 0.0 % |
| 240 | 79.3 % | 2.2 % |
| 300 | 89.3 % | 14.6 % |
| 360 | 94.9 % | 57.4 % |
| 420 | 98.0 % | 79.3 % |
| 480 | 99.5 % | 89.3 % |
| 540 | 100.0 % | 94.9 % |
| 600 | 100.0 % | 98.0 % |
| 660 | 100.0 % | 99.5 % |
| 720 | 100.0 % | 100.0 % |

**Colour per frame.** Colours hold constant through the reveal. Choose them by surface:

| Surface | `=` | Block |
|---|---|---|
| Ink (brand moments, splash, About window) | Paper `#F3F0E8` | Amber `#FFB000` |
| Paper | Ink `#111110` | Ink `#111110` |
| Other dark UI | Paper `#F3F0E8` | Paper `#F3F0E8` |

**SwiftUI:** see `ECReveal` and `RevealTimeline`. The core is:

```swift
let f = RevealTimeline.frame(at: elapsed)          // pure function of time
ECSymbol(module: s, equalsColor: eq, blockColor: block,
         topBar: f.top, lowBar: f.low, blockOpacity: f.block ? 1 : 0)
// f.top = ECMotion.segment(t, 0.000, 0.540, ECMotion.draw)
// f.low = ECMotion.segment(t, 0.180, 0.720, ECMotion.draw)
// f.block = t >= 0.900 && ECMotion.signOffVisible(t, from: 0.900)
```

Drive it with `TimelineView(.animation(paused: finished || reduceMotion))`. Pause the timeline once it rests, so it does not tick forever.

---

## 2. Loaders

**Files:**
- `loader/loader-blink-{16,24,48}-{ink,paper,mono}.svg`
- `loader/loader-fill-{16,24,48}-{ink,paper,mono}.svg`

`ink` is for light surfaces and `paper` for dark ones. `mono` uses `currentColor`, so it follows the text colour when inlined. Loaders are UI, so they never use Amber.

Each size is hand-hinted so every edge lands on a whole pixel. When the margin is odd, the spare pixel goes to the right and the bottom.

| Size | Module s | Mark origin (x, y) | Corner radius | Block | Fill steps | Files |
|---|---|---|---|---|---|---|
| 16 px | 2 px | (1, 3) | square | 6 x 10 px | 10 (1 px each) | `loader-blink-16-*.svg`, `loader-fill-16-*.svg` |
| 24 px | 3 px | (1, 4) | 0.75 | 9 x 15 px | 15 (1 px each) | `loader-blink-24-*.svg`, `loader-fill-24-*.svg` |
| 48 px | 6 px | (3, 9) | 1.5 | 18 x 30 px | 30 (1 px each) | `loader-blink-48-*.svg`, `loader-fill-48-*.svg` |

### Busy (indeterminate)

- The block blinks like a caret over a ghost of itself at 0.2 opacity. The ghost keeps the loader's footprint steady and keeps it reading as the mark when the block is off.
- Block opacity is 1 from 0 ms, cuts to 0 at 530 ms, and the cycle loops at 1060 ms.
- The `=` never moves.

### Progress (determinate)

- The block fills bottom-up: `level = floor(p * steps) / steps`. Each step is one pixel of block height, so the edge of the level is always crisp.
- The level is a mask anchored at the bottom of the block. Its top edge is flat and its bottom corners follow the block.
- Each change of level animates over 240 ms with settle.
- At `p = 1` the block is whole, which makes it the logo, and it signs off with two blinks. After that the caller can keep it or swap in the static symbol.
- **Switching from busy to progress:** switch on an on-beat, so the block never jumps from the ghost straight to a partial level.

**On the web:**
1. Inline the `mono` file.
2. Remove the `ec-demo` class.
3. Set `style="--p: 0.42"` on the `<svg>`.

The file already contains the 240 ms transition and the whole-pixel `round()`, and falls back to unrounded values in browsers without `round()`.

The standalone files play a demo loop when they have the `ec-demo` class:

| t (ms) | Level at 16 px | at 24 px | at 48 px | Curve |
|---|---|---|---|---|
| 0 | 0 | 0 | 0 | hold |
| 300 to 540 | 0.200 | 0.200 | 0.200 | settle |
| 900 to 1140 | 0.300 | 0.267 | 0.300 | settle |
| 1500 to 1740 | 0.600 | 0.600 | 0.600 | settle |
| 2100 to 2340 | 0.900 | 0.867 | 0.900 | settle |
| 2600 to 2840 | 1.000 | 1.000 | 1.000 | settle |
| 2840 | full | full | full | sign-off: off at 3370, on 3900, off 4430, on 4960 |
| 5600 | loop | | | |

**SwiftUI:** `ECBusy(size:color:)` and `ECProgress(progress:size:color:)`. The steps are 10, 15 and 30 at 16, 24 and 48 pt, and are computed as `5 * module`.

---

## 3. Redaction

**Files:**
- `redaction/redaction-amber-on-ink.svg` is the hero version, with Paper text and an Amber block on its own Ink field.
- `redaction/redaction-ink.svg` is for Paper backgrounds.
- `redaction/redaction-paper.svg` is for other dark backgrounds.

The glyphs are Martian Mono outlines, so no font is needed. The value `sk-demo-xxxx` is an obviously fake demo string. Never put anything key-shaped in its place. Each file plays once and rests on `OPENAI_API_KEY=█`. Set `--ec-iter: infinite` on an ancestor to loop it.

**Geometry, in em** (font size = 1 em, baseline at 0, y up):

| Part | Value |
|---|---|
| Face | Martian Mono, weight 400, width 87.5 (the wordmark's width, a calmer weight) |
| Cell (advance) | 0.65 em; the line is 27 cells plus one for the caret |
| Block | 0.5088 x 0.848 em (3:5), sitting on the baseline. Its top is level with the `l` and `k`, as in the lockup |
| Block side bearing | 0.0706 em each side, so the block is centred in its cell |
| Block radius | 0.0424 em (s/4, with s = block height / 5) |
| Line box | 1.25 em: 1.0 em above the baseline and 0.25 em below |

**Phases:**

| Phase | Start (ms) | End (ms) | What happens | Curve |
|---|---|---|---|---|
| Ready | 0 | 1060 | The caret waits in cell 0. It is on for 530 ms, then off. | cut |
| Type the key | 1060 | 1830 | `OPENAI_API_KEY=` types in, one character every 55 ms. The caret rides one cell ahead. | cut |
| Beat | 1830 | 2050 | A 220 ms pause after the `=` | |
| Type the value | 2050 | 2655 | `sk-demo-xxxx`, one character every 55 ms | cut |
| Hold | 2655 | 3185 | The caret stays solid after the value for one caret beat. | |
| Cover | 3185 | 3425 | The block's left edge slides back to the first value cell and covers the value. The value glyphs are removed when it ends. | settle, 240 ms |
| Collapse | 3425 | 3785 | The right edge slides back until one 3:5 block remains after the `=`. | settle, 360 ms |
| Sign-off | 3785 | 5905 | Two blinks: off 4315, on 4845, off 5375, on 5905 | cut |
| Rest | 5905 | | `OPENAI_API_KEY=█` | |

**Character schedule:**
- For the key, `T(i) = 1060 + 55 i` for i = 0 to 14.
- For the value, `T(i) = 2050 + 55 (i - 15)` for i = 15 to 26.

At `T(i)`, character i appears and the caret cuts to cell i + 1.

| i | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 | 26 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| char | `O` | `P` | `E` | `N` | `A` | `I` | `_` | `A` | `P` | `I` | `_` | `K` | `E` | `Y` | `=` | `s` | `k` | `-` | `d` | `e` | `m` | `o` | `-` | `x` | `x` | `x` | `x` |
| t (ms) | 1060 | 1115 | 1170 | 1225 | 1280 | 1335 | 1390 | 1445 | 1500 | 1555 | 1610 | 1665 | 1720 | 1775 | 1830 | 2050 | 2105 | 2160 | 2215 | 2270 | 2325 | 2380 | 2435 | 2490 | 2545 | 2600 | 2655 |

**Block edges per frame** during the cover and the collapse, in cells. Cell 15 is the first value cell and cell 27 is the caret cell. The block's x extent is `left * cell + side bearing` to `right * cell + side bearing + block width`.

| t (ms) | Phase | Left edge (cell) | Right edge (cell) | Width (cells) |
|---|---|---|---|---|
| 3185 | cover | 27.00 | 27.00 | 1.00 |
| 3225 | cover | 22.12 | 27.00 | 5.88 |
| 3265 | cover | 18.22 | 27.00 | 9.78 |
| 3305 | cover | 16.47 | 27.00 | 11.53 |
| 3345 | cover | 15.56 | 27.00 | 12.44 |
| 3385 | cover | 15.12 | 27.00 | 12.88 |
| 3425 | cover | 15.00 | 27.00 | 13.00 |
| 3465 | collapse | 15.00 | 24.61 | 10.61 |
| 3505 | collapse | 15.00 | 20.38 | 6.38 |
| 3545 | collapse | 15.00 | 18.22 | 4.22 |
| 3585 | collapse | 15.00 | 16.93 | 2.93 |
| 3625 | collapse | 15.00 | 16.10 | 2.10 |
| 3665 | collapse | 15.00 | 15.56 | 1.56 |
| 3705 | collapse | 15.00 | 15.23 | 1.23 |
| 3745 | collapse | 15.00 | 15.05 | 1.05 |
| 3785 | collapse | 15.00 | 15.00 | 1.00 |

**Colour per frame.** Colours hold constant through the sequence:

| Surface | Text | Block |
|---|---|---|
| Ink (hero) | Paper `#F3F0E8` | Amber `#FFB000` |
| Paper | Ink `#111110` | Ink `#111110` |
| Other dark UI | Paper `#F3F0E8` | Paper `#F3F0E8` |

**Notes:**
- On the web, the SVGs carry the accessible name "OPENAI_API_KEY equals a hidden value".
- The files are built from two block caps and a square-cornered span, moved only with transforms. The rounded ends stay exact while the block stretches, and nothing depends on browser support for `clip-path` on SVG elements.
- In SwiftUI there is no such constraint: draw one rounded rectangle from `left` to `right`, as `ECRedaction` does in a `Canvas`.

**SwiftUI:** `ECRedaction(fontSize:textColor:blockColor:)` and `RedactionTimeline.frame(at:)`. Bundle Martian Mono and select the instance with `ECFont.martianMono(size:weight:width:)`, which sets the `wght` and `wdth` variation axes.

---

## 4. Approval

**Files:**
- `approval/approval-plate.svg` sits on its own Ink plate (the macOS icon tile shape), so it can go on any surface.
- `approval/approval-bare.svg` is for Ink `#111110` or the dark tile `#0B0B0A` only.

Each file plays a 4800 ms demo once: idle, then a request at 600 ms, a wait, approval at 3000 ms, and idle again. Set `--ec-iter: infinite` on an ancestor to loop it, as the demo page does.

**States:**

| State | `=` | Block | Motion |
|---|---|---|---|
| Idle | Paper | Paper | none |
| Request arrives | Paper | Paper to Amber in 120 ms, linear | One pulse: scale 1 to 1.10 in 180 ms (settle), then back to 1 in 420 ms (breathe). The pivot is the block's centre. |
| Waiting for Touch ID | Paper | Amber | Still. There is no looping pulse and no blinking: the system's Touch ID prompt is the call to action. |
| Approved, denied or timed out | Paper | Amber to Paper in 240 ms, settle | No pulse. Every outcome releases the same calm way, with no red. |

**Colour per frame**, Paper to Amber when the request arrives (linear):

| t (ms) | Progress | Block colour |
|---|---|---|
| 0 | 0.000 | `#F3F0E8` |
| 20 | 0.167 | `#F5E5C1` |
| 40 | 0.333 | `#F7DB9B` |
| 60 | 0.500 | `#F9D074` |
| 80 | 0.667 | `#FBC54D` |
| 100 | 0.833 | `#FDBB27` |
| 120 | 1.000 | `#FFB000` |

**Colour per frame**, Amber to Paper on release (settle):

| t (ms) | Progress | Block colour |
|---|---|---|
| 0 | 0.000 | `#FFB000` |
| 40 | 0.406 | `#FACA5E` |
| 80 | 0.732 | `#F6DFAA` |
| 120 | 0.878 | `#F4E8CC` |
| 160 | 0.953 | `#F4EDDD` |
| 200 | 0.990 | `#F3EFE6` |
| 240 | 1.000 | `#F3F0E8` |

**Block scale per frame**, from the moment the request arrives:

| t (ms) | Scale | Curve |
|---|---|---|
| 0 | 1.0000 | settle |
| 30 | 1.0406 | settle |
| 60 | 1.0732 | settle |
| 90 | 1.0878 | settle |
| 120 | 1.0953 | settle |
| 150 | 1.0990 | settle |
| 180 | 1.1000 | settle |
| 210 | 1.0991 | breathe |
| 240 | 1.0963 | breathe |
| 270 | 1.0913 | breathe |
| 300 | 1.0840 | breathe |
| 330 | 1.0744 | breathe |
| 360 | 1.0628 | breathe |
| 390 | 1.0500 | breathe |
| 420 | 1.0372 | breathe |
| 450 | 1.0256 | breathe |
| 480 | 1.0160 | breathe |
| 510 | 1.0087 | breathe |
| 540 | 1.0037 | breathe |
| 570 | 1.0009 | breathe |
| 600 | 1.0000 | breathe |

**Placement:**
- The mark is 60 % of the plate's width and moved left by s/4, as on the app icon.
- The plate's corner radius is 22.5 % of its side, continuous.
- In the dark appearance, the plate is `#0B0B0A` and the `=` is `#DCD8CE`, matching the icon's dark appearance.
- **Menu bar:** the status item is a template image, which cannot carry Amber and must stay legible on any menu bar. While a request waits, blink the template block on the caret clock, and do not pulse it.

**SwiftUI:** `ECApprovalMark(waiting:module:)`. The pulse is a `KeyframeAnimator` triggered by a counter that goes up each time `waiting` becomes true:

```swift
KeyframeAnimator(initialValue: 1.0, trigger: pulses) { scale in
    ECSymbol(module: s, equalsColor: eq, blockColor: waiting ? amber : paper, blockScale: scale)
} keyframes: { _ in
    LinearKeyframe(1.1, duration: 0.180, timingCurve: ECMotion.settle)
    LinearKeyframe(1.0, duration: 0.420, timingCurve: ECMotion.breathe)
}
.animation(waiting ? .linear(duration: 0.120) : .timingCurve(0.2, 0, 0, 1, duration: 0.240), value: waiting)
```

---

## Reduced motion

Every SVG honours `prefers-reduced-motion: reduce` on its own. When the demo page's preview switch is on, an `.ec-reduced` class on any ancestor does the same. In SwiftUI, read `@Environment(\.accessibilityReduceMotion)`.

| Moment | Reduced behaviour |
|---|---|
| Logo reveal | Shows the resting logo at once. |
| Busy loader | Shows no hard blink. The block breathes between full and the ghost, 1060 ms each way, with the breathe curve. |
| Progress loader | Level changes jump with no tween. There is no sign-off blink. |
| Redaction | Shows the resting line `OPENAI_API_KEY=█` at once. |
| Approval | Keeps the colour turn, because colour is not movement. Drops the pulse. |

## Files

| Path | What |
|---|---|
| `index.html` | A demo page that plays every moment on Ink and on Paper, on a loop, with a reduced-motion preview switch. It is self-contained, with the SVGs and a Martian Mono subset inlined. |
| `reveal/*.svg` | The logo reveal in 3 colourways. |
| `loader/*.svg` | Busy and progress loaders: 2 kinds x 3 sizes x 3 colourways. |
| `redaction/*.svg` | The redaction line in 3 colourways. |
| `approval/*.svg` | The approval pulse, on a plate or bare. |
| `swiftui/EnvCloakMotion.swift` | The SwiftUI reference: tokens, timelines, `ECSymbol`, `ECReveal`, `ECBusy`, `ECProgress`, `ECRedaction`, `ECApprovalMark` and `ECMotionGallery`. |
| `checks/*.png` | The render checks (see below). |

The generators (one timeline module that compiles the SVGs, the demo page, this file and the render checks) are not in this repository yet.

## How it was checked

- **Frames:** every SVG was opened in Chromium. Its CSS animations were paused and seeked to fixed timestamps, then screenshotted. The loaders were captured at true 1x pixels. The results are in `checks/*-frames.png`.
- **Reduced motion:** each file was opened as a document with reduced motion emulated, in `checks/reduced-motion.png`. Only the soft loader fade and the approval colour turn kept running. Chromium's emulation does not reach SVGs inside an `<img>`, so that path relies on the browser applying the OS setting to SVG images.
- **Images:** the files animate on their own when used as an `<img>`, checked by comparing wall-clock samples.
- **Demo page:** it was rendered at 1280 and 390 px wide, with no horizontal scroll, in `checks/index-*.png`.
- **Swift:** the reference was type-checked with `swiftc` (Swift 6, macOS 26.5 SDK). Its timeline functions were compiled and compared with the CSS timelines every 5 ms, with no mismatches.
- **Not yet tested:** Safari and Firefox. The SVGs use only transforms, opacity and fill animations, plus `transform-box: fill-box`. CSS `round()` is behind `@supports`.
