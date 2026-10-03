# EnvCloak logo and icon kit

**Status: locked, 3 October 2026.**

**The idea in one line.** `KEY=█` cut down to its last two cells. The value is assigned and working, but it only ever shows as a block.

The symbol is concept A, "Assignment Cell", from round 2. The wordmark is `.envcloak`, set in Martian Mono and converted to outlines. All vector files are plain paths: none of them needs a font, a filter, a gradient or a script, except the one animated file in `motion/`.

Paths below are relative to `assets/brand/`. The `logo/` folder is the master for the symbol, wordmark and lockups. The `icon/` folder holds the app icon and the menu bar image, and `favicon/` holds the web icons. How to use all of it is in the brand guide, [`docs/BRAND.md`](../../../docs/BRAND.md).

---

## 1. Construction (locked)

| Part | Rule |
|---|---|
| Module | `s` is the stroke. The symbol sits on a 7 x 5 module grid (see `construction/symbol-construction.png`). |
| Block | 3s x 5s, a 3:5 ratio. **Never make it wider than 3:5**, because then it reads as a battery or a toggle. |
| `=` bars | Each bar is 3s x 1s. The gap between the bars is s, and the `=` is centred vertically on the block. |
| Gap between `=` and block | s. Stroke, both gaps and the bar height are all the same module. |
| Corners | Radius s/4 on all three shapes. The 16 px versions use square corners. |
| Optical balance | The `=` is as wide as the block. That balances the block's mass, so the symbol is centred on its bounding box. On the app icon only, the symbol is moved left by s/4, because the solid block otherwise pulls the eye to the right inside a square tile. |
| Clear space | The block width (3s) on every side, for every artwork. |

**What changed from the round 2 sketch.** The block radius was 0.375s and is now s/4, the same as the bars. The proportions stay on the exact module grid. The icon mark sits on Icon Composer's full-bleed canvas at s = 88: it is 616 px wide, which is 60 % of the tile and inside the central two thirds. The icon also uses the s/4 optical shift.

### Wordmark

| Setting | Value |
|---|---|
| Typeface | Martian Mono, weight 500, width 87.5 (SIL OFL 1.1, by Evil Martians). Its licence is in `fonts/MartianMono-OFL.txt`. The font itself comes from google/fonts. |
| Spacing | Monospace advances. Tracking is -12 units, and these pairs are kerned by eye: nv -16, vc -18, cl -4, ak -46. The `c` and `l` stay apart, so `cl` never reads as `d` at 11 px. |
| Leading dot | Drawn as a square, not the font's round period. It is 176 units with a radius of 14, sits on the baseline, and has a 145-unit gap before the `e`. The square dot echoes the block. A 3:5 mini block was tried and dropped, because it read as a comma at small sizes. |
| Metrics | UPM 1000, x-height 600, and an `l` height of 848. The baseline is at y = 0 in every wordmark and lockup file. |

### Lockups

- **Horizontal:** the block is exactly as tall as the `l` (848 units). It sits on the baseline, so the block's top and bottom align with the `l` and the `k`. The gap between the symbol and the wordmark is one block width (3s).
- **Stacked:** the symbol is 0.42 x the wordmark's width (s = 314 units) and centred over it, with a gap of 1.5s.
- **Wordmark only:** clear space is 0.6 x the height of `l`. That is the same as the block width in the horizontal lockup.

### Colour

| Name | Value | Use |
|---|---|---|
| Ink | `#111110` | Main colour. Ink on Paper is 16.6:1. |
| Paper | `#F3F0E8` | Main colour, used for the symbol on dark backgrounds. |
| Amber Phosphor | `#FFB000` | The one accent. Amber on Ink is 10.3:1. **Amber only ever sits on Ink**: on Paper it is 1.6:1, which fails. |
| Dark tile | `#0B0B0A` | Background of the app icon's dark appearance only. |
| Dark `=` | `#DCD8CE` | The `=` in the app icon's dark appearance only. It is Paper eased back, and still 13.8:1 on the dark tile. |

**One Amber element per composition.** When the symbol is present, the Amber element is the block. In the wordmark on its own, it is the dot. The `=` and the letters are never Amber.

### Minimum sizes

These were checked in `checks/minimum-sizes.png`, at 1x and 2x.

| Artwork | Screen | Print |
|---|---|---|
| Symbol | 16 px. Use `symbol-16.svg` from 16 to 23 px, `symbol-32.svg` from 24 to 47 px, and the master from 48 px up. | 5 mm wide |
| Wordmark | 80 px wide | 20 mm wide |
| Horizontal lockup | 112 px wide | 28 mm wide |
| Stacked lockup | 64 px wide | 16 mm wide |

### Do not

- Make the block wider than 3:5, or round it into a pill.
- Put Amber on Paper or on white. Do not use two Amber elements in one composition.
- Add an outline, glow, gradient or shadow to the symbol. On the app icon, the glass effect comes only from Icon Composer.
- Set `.envcloak` live in a font where the logo is meant. Use the outlined files. Martian Mono is fine for UI text.
- Put the symbol after the wordmark, change the gap, or rotate anything.
- Type a character into the block, or animate the `=` anywhere except its one draw-in during the logo reveal. Otherwise only the block moves, and only in the ways listed in `../motion/SPEC.md`: blinking, filling, and the approval colour change and pulse.

---

## 2. Files: `logo/`

### Symbol: `logo/symbol/`

| File | Use |
|---|---|
| `symbol-ink.svg` | Master symbol in Ink, for light backgrounds. The viewBox is 112 x 80 at s = 16, with a tight bounding box. Add the clear space yourself. |
| `symbol-paper.svg` | Master symbol in Paper, for dark backgrounds. |
| `symbol-amber-on-ink.svg` | Paper `=` and Amber block on an Ink field. The field already includes the clear space, so the Amber cannot end up on a light background. |
| `symbol-mono.svg` | One colour, `currentColor`. Use it inline in HTML or in SwiftUI or AppKit, and let it inherit the text colour. |
| `symbol-16.svg` | Pixel-snapped Ink version for 16 px: s = 2, every edge on a whole pixel, square corners, `crispEdges`. |
| `symbol-16-paper.svg` | The same, in Paper, for dark UI. |
| `symbol-32.svg` | Pixel-snapped Ink version for 32 px: s = 4 at (2, 6), with a radius of 1 px. |
| `symbol-32-paper.svg` | The same, in Paper. |

### Wordmark: `logo/wordmark/`

| File | Use |
|---|---|
| `wordmark-ink.svg` | `.envcloak` outlined in Ink, for light backgrounds. The viewBox is in font units and the baseline is at y = 0. |
| `wordmark-paper.svg` | The same, in Paper, for dark backgrounds. |
| `wordmark-amber-on-ink.svg` | Paper letters and an Amber dot on an Ink field that includes the clear space. |
| `wordmark-mono.svg` | One colour, `currentColor`. |

### Lockups: `logo/lockup/`

| File | Use |
|---|---|
| `lockup-horizontal-ink.svg` | The main logo for site headers, READMEs and docs on light backgrounds. |
| `lockup-horizontal-paper.svg` | The same, for dark backgrounds, such as the site in dark mode or GitHub dark. |
| `lockup-horizontal-amber-on-ink.svg` | Hero, social card and slide use: an Amber block on an Ink field that includes the clear space. |
| `lockup-horizontal-mono.svg` | One colour, `currentColor`. |
| `lockup-stacked-ink.svg` | Square-ish spaces such as avatars, stickers, the About window and print. |
| `lockup-stacked-paper.svg` | The same, for dark backgrounds. |
| `lockup-stacked-amber-on-ink.svg` | Stacked, with an Amber block on an Ink field. |
| `lockup-stacked-mono.svg` | One colour, `currentColor`. |

### Ready-made PNGs: `logo/png/`

All are transparent unless the name says `on-ink`.

| File | Use |
|---|---|
| `symbol-ink-512.png`, `symbol-paper-512.png` | The symbol at 512 px wide. |
| `symbol-amber-on-ink-512.png` | The symbol on its Ink field, 512 px wide. |
| `symbol-16-ink.png`, `symbol-16-paper.png` | 16 px renders of the pixel-snapped variants. |
| `symbol-32-ink.png`, `symbol-32-paper.png` | 32 px renders of the pixel-snapped variants. |
| `wordmark-ink-1600.png`, `wordmark-paper-1600.png`, `wordmark-amber-on-ink-1600.png` | The wordmark at 1600 px wide. |
| `lockup-horizontal-{ink,paper,amber-on-ink}-1600.png` | The horizontal lockup at 1600 px wide. |
| `lockup-stacked-{ink,paper,amber-on-ink}-1024.png` | The stacked lockup at 1024 px wide. |

### Construction, motion, fonts and checks

| File | Use |
|---|---|
| `construction/symbol-construction.svg` / `.png` | The 7 x 5 module grid, the 3:5 block, the gaps, the radius and the clear space. |
| `construction/lockup-clearspace.svg` / `.png` | The horizontal lockup's alignment (top of `l`, baseline), its gap and its clear space. |
| `motion/symbol-blink.svg` | Seed for the loader. The block blinks at the macOS caret rate, 530 ms on and 530 ms off, and never prints a character. It holds still under `prefers-reduced-motion`. The elements carry the classes `ec-equals` and `ec-block` for further motion work. The complete motion set is now in `../motion/` (see `../motion/SPEC.md`). |
| `../fonts/MartianMono-OFL.txt` | The SIL Open Font License 1.1 for Martian Mono. The font, `MartianMono[wdth,wght].ttf`, comes unmodified from google/fonts and is not in this repository. Use it for UI text and to rebuild the wordmark, and keep this licence with it. |
| `checks/minimum-sizes.png`, `checks/minimum-sizes@2x.png` | Proof of the minimum sizes, on Paper and on Ink. |
| `checks/overview.png` | Every logo master on its intended background. |

---

## 3. Files: `icon/`

### macOS 26 app icon (Icon Composer)

| File | Use |
|---|---|
| `icon/EnvCloak.icon/` | **The app icon.** An Icon Composer document (`icon.json` plus `Assets/`). Drag it into the Xcode 26 project and set the target's App Icon to `EnvCloak`. The background is a solid fill: Ink by default and `#0B0B0A` in the dark appearance. There are two groups: the block (Amber, Liquid Glass) and the `=` (Paper, Liquid Glass, `#DCD8CE` in dark). Each group has a neutral shadow at 0.5, specular highlights on and translucency off. It was verified by rendering with Xcode's `ictool`. |
| `icon/layers/background.svg` | Layer SVG: the 1024 full-bleed Ink background, for tools that need it as an image. The `.icon` uses the solid fill instead, so the system can retint it in the tinted and clear modes. |
| `icon/layers/equals.svg` | Layer SVG: the Paper `=` on a 1024 transparent canvas, already in position. |
| `icon/layers/block.svg` | Layer SVG: the Amber block on a 1024 transparent canvas, already in position. |

The layers have no blur, shadow, gradient or translucency, and the mark sits inside the central two thirds of the canvas.

### Previews: `icon/previews/`

These are rendered by Icon Composer's own renderer, `ictool` from Xcode 26.6, and converted from Display P3 to sRGB.

| File | Use |
|---|---|
| `icon-default-1024.png` | The default appearance, with Liquid Glass. |
| `icon-dark-1024.png` | The dark appearance. |
| `icon-tinted-light-1024.png`, `icon-tinted-dark-1024.png` | The tinted appearance, shown with the system's default tint. The viewer chooses the tint. |
| `icon-clear-light-1024.png`, `icon-clear-dark-1024.png` | The clear (mono) appearance. |
| `icon-default-macos-grid-1024.png` | The default render placed on the classic macOS grid (an 824 tile with a soft shadow), as used in the `.icns`. |
| `contact-sheet.png` | Every icon output on one sheet, with true-pixel zooms of the small sizes. |

### Flat previews: `icon/flat/`

These are vector files on Apple's macOS icon grid: an 824 tile on a 1024 canvas with continuous corners, and no glass.

| File | Use |
|---|---|
| `icon-default.svg` / `-1024.png` | Ink tile, Paper `=`, Amber block. Use it in docs, the website and press. |
| `icon-dark.svg` / `-1024.png` | `#0B0B0A` tile, `#DCD8CE` `=`, Amber block. |
| `icon-mono.svg` / `-1024.png` | A one-colour proof: a graphite tile with a white `=` and a white block. It shows the mark carries no meaning through colour. |

### Legacy and non-Xcode icon

| File | Use |
|---|---|
| `icon/EnvCloak.icns` | Built with `iconutil` from the iconset below. Use it for `CFBundleIconFile`, DMG volume icons, macOS before 26, and non-Xcode builds. |
| `icon/EnvCloak.iconset/` | The source for the `.icns`. It holds 16, 32, 128, 256 and 512 px at @1x and @2x. 16 px and 32 px (and 64 px for 32 @2x) are hand-hinted flat tiles, with the mark on whole pixels (s = 1, 2 and 4). 128 px and up use the Liquid Glass default render on the macOS grid. |

### Web: `favicon/`

| File | Use |
|---|---|
| `favicon.svg` | The main favicon: the bare symbol on the 16 px pixel grid. A `prefers-color-scheme` media query makes it Ink on light tabs and Paper on dark tabs. Amber is left out, so the "only on Ink" rule holds on any tab colour. |
| `favicon.ico` | Contains the hand-hinted 16, 32 and 48 px frames, identical to the PNGs below. This was verified by reading the frames back. |
| `favicon-16.png` | An Ink tile with a Paper `=` and an Amber block. The `=` is narrowed to 2s here, so the tile keeps a 2 px edge. |
| `favicon-32.png` | The same tile at 32 px (s = 3). |
| `favicon-48.png` | The same tile at 48 px (s = 4). |
| `apple-touch-icon.png` | 180 px. A full-bleed Ink square (iOS applies its own mask), with the mark at 58 % width. |
| `icon-192.png`, `icon-512.png` | For the web app manifest. Full-bleed Ink, with the mark inside the maskable safe zone, so they can be declared `"purpose": "maskable"`. |

Head tags:

```html
<link rel="icon" href="/favicon.ico" sizes="32x32">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<meta name="theme-color" content="#111110">
```

### Menu bar: `icon/menubar/`

| File | Use |
|---|---|
| `EnvCloakMenuTemplate.png` | 18 x 18 pt at @1x. A black symbol on transparent, s = 2 pt, so it is 14 x 10 pt. It uses square corners, so the only alpha values are 0 and 255. |
| `EnvCloakMenuTemplate@2x.png` | 36 x 36 px at @2x: s = 4 px, with a radius of 1 px. |
| `EnvCloakMenuTemplate.svg` | A vector version for an asset catalog. Set Render As to Template Image and turn on Preserve Vector Data. |

Because the name ends in `Template`, AppKit treats it as a template image. For example, `statusItem.button?.image = NSImage(named: "EnvCloakMenuTemplate")`. The system then tints it for light, dark and highlighted menu bars.

---

## 4. Checks and what they showed

**16 px beside the AI agents.** The render shows other projects' marks, so it is not in this repository. What it showed:
- **Codex:** EnvCloak stays distinct from Codex's `>_`. The Codex mark is a filled cloud with a chevron and an underscore knocked out of it. EnvCloak is open bars plus a solid, tall block, with no diagonal and no baseline stroke, so they share no feature at 16 px.
- **The others:** Claude (starburst), Cursor (cube), GitHub (Octocat) and OpenAI (knot) are all round silhouettes. EnvCloak is the only rectangular, horizontal shape in the row.
- **Visual weight:** at 16 px the bare symbol reads lighter than the filled round marks. In a README row of agent logos, use `favicon/favicon-16.png` (the tile) when you want equal visual weight.

**Minimum sizes** (`checks/minimum-sizes.png`): every size in the table in section 1 reads cleanly at 1x on both Paper and Ink.

**App icon** (`icon/previews/contact-sheet.png`): every appearance comes from Icon Composer's renderer. In the tinted and clear modes the block and the `=` stay separate shapes, so the mark survives without its colour.

## 5. Rebuilding

The kit was generated by Python scripts (fontTools, Pillow, and Playwright driving Chromium) and by Xcode 26's `ictool` and `iconutil`. The scripts are not in this repository yet. Every value they use is locked in section 1, so the artwork can be rebuilt from this page, and the files here are the masters.
