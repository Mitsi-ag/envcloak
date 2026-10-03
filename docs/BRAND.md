# EnvCloak brand guide

How to use the EnvCloak name, logo, colours, type, motion and voice. The files are in [`assets/brand/`](../assets/brand/), and file paths in this guide are relative to that folder. The locked construction and a file-by-file index are in [`logo/README.md`](../assets/brand/logo/README.md), motion timings are in [`motion/SPEC.md`](../assets/brand/motion/SPEC.md), and the whole system is on one page in [`brand-board.png`](../assets/brand/brand-board.png).

## 1. The idea

EnvCloak lets your AI coding agents use your API keys without ever seeing them. The brand says the same thing in the developer's own syntax: the value is assigned and doing its job, and all anyone ever sees is a block.

| Trait | In practice |
|---|---|
| Discreet | It never shows what it holds. No real-looking keys in screenshots, demos or docs. |
| Exact | The geometry sits on a fixed grid. The copy names the key, the command and the project. |
| Calm | No alarms, no hacker theatre and no selling through fear. |
| Candid | It is open source, and every claim sits next to its limits. |
| Crafted | It has a Mac-native finish: system type, system controls and pixel-snapped small sizes. |

**The mark.** The symbol is an equals sign and a solid block, the last two cells of `KEY=█`. The `=` says the assignment happened. The block says the value exists and works, but only ever shows as a block. It also reads as a terminal cursor and as a redaction bar, the other two things the product is about.

**The line to retell:** "It's `KEY=` with the value blacked out. Your agent gets the assignment, never the value."

The block is a picture, not output. The CLI masks a value as `[envcloak:<slug>]`, so never show a `█` in a screenshot of real CLI output.

## 2. Logo

| Artwork | What it is | Use it for |
|---|---|---|
| Symbol | An `=` and a 3:5 block on a 7 x 5 module grid | The app icon, favicon and menu bar, avatars, agent badge rows, and any space under 112 px wide |
| Wordmark | `.envcloak` in Martian Mono 500 at width 87.5, outlined, with a square leading dot | Text-only places, or where the symbol already appears nearby |
| Horizontal lockup | The symbol, a gap of one block width, then the wordmark | The default: README and site headers, docs, slides |
| Stacked lockup | The symbol centred over the wordmark | Square spaces: social avatars, stickers, the About window, print |

**The name.** In running text, write **EnvCloak**, never ENVCLOAK, Envcloak, Env Cloak or env-cloak. `envcloak` in code font is the command. The lowercase `.envcloak` belongs to the wordmark only.

**Clear space.** Leave one block width (3 modules) on every side of every artwork. For the wordmark on its own, leave 0.6 x the height of its `l`. No text, other logo or page edge may enter that space.

**Minimum sizes**

| Artwork | Screen | Print |
|---|---|---|
| Symbol | 16 px. Use `symbol-16.svg` from 16 to 23 px, `symbol-32.svg` from 24 to 47 px, and the master from 48 px up. | 5 mm wide |
| Wordmark | 80 px wide | 20 mm wide |
| Horizontal lockup | 112 px wide | 28 mm wide |
| Stacked lockup | 64 px wide | 16 mm wide |

**Backgrounds**

- The defaults are Ink artwork on Paper or white, and Paper artwork on Ink or black.
- The Amber block goes only on Ink. Use the `-amber-on-ink` files, whose Ink field already includes the clear space.
- On any other colour or on a photo, use whichever of Ink or Paper reaches 3:1 against it (WCAG 1.4.11). If neither does, put the artwork on an Ink field.
- In UI code, inline `symbol-mono.svg`, which uses `currentColor` and follows the text colour.

**Do not**

| Do not | Why |
|---|---|
| Make the block wider than 3:5, or round it into a pill | Any wider and it reads as a battery or a toggle. |
| Rebuild the symbol by typing `=█` in a font | Glyph widths and weights vary between fonts. The symbol is drawn on a locked grid. |
| Set `.envcloak` as live text where the logo belongs | A fallback font loses the kerning and the square dot. Use the outlined files. |
| Put Amber on Paper or white | It is 1.6:1 on Paper and 1.8:1 on white, so the block disappears and fails WCAG 1.4.11. |
| Use more than one Amber element | The block is the one held value. A second accent splits the story. |
| Add a glow, gradient, outline, shadow or glass | The mark must work in one flat colour. The app icon's glass comes only from Icon Composer. |
| Type a character into the block, or animate the `=` outside its one draw-in in the logo reveal | The value never prints, and the assignment never changes. |
| Rotate the artwork, put the symbol after the wordmark, or change the gap | The order and spacing are part of the mark. |
| Pair it with a lock, key, shield or eye | The symbol already says "held and unseen". Clichés make it generic. |

**Next to agent logos.** EnvCloak often sits beside Claude Code, Codex, Cursor, Gemini CLI and others in READMEs and on the site.

- Use the symbol, not a lockup. Set it at the same height and on the same baseline as the other marks, with at least our clear space between marks.
- In a 16 px badge row, use `favicon/favicon-16.png` (the Ink tile). The bare symbol reads lighter than the filled, round agent marks.
- Show every other mark unmodified, in its own colours and under its owner's brand rules. Never recolour theirs in Amber, or ours in their colours.
- Make no combined lockups and no "+" marks. Do not write "official" or "partner" unless it is true and agreed in writing. Words work best: "Works with Claude Code, Codex and Cursor".

## 3. Colour

| Name | Hex | RGB | Role |
|---|---|---|---|
| Ink | `#111110` | 17, 17, 16 | The main dark: text and marks on light, and the dark background |
| Paper | `#F3F0E8` | 243, 240, 232 | The main light: the light background, and marks on dark |
| Amber Phosphor | `#FFB000` | 255, 176, 0 | The one accent, for the held value. Only on Ink. |

| Pair | Contrast | Verdict |
|---|---|---|
| Ink on Paper | 16.6:1 | Passes AAA for text |
| Ink on white | 18.9:1 | Passes AAA for text |
| Amber on Ink (and Ink text on Amber) | 10.3:1 | Passes AAA for text |
| Amber on macOS dark surfaces, `#1E1E1E` to `#323232` | 9.1:1 to 6.998:1 | Passes AA for text on all of them, and AAA up to `#313131` (7.1:1). These surfaces count as Ink. |
| Amber on Paper | 1.6:1 | Fails even the 3:1 for graphics. Never use it. |
| Amber on white | 1.8:1 | Fails. Never use it. |

The ratios are WCAG 2.x contrast ratios from sRGB relative luminance, rounded to one decimal place except where rounding would cross a threshold.

**Where Amber may appear.** Amber goes only on Ink, or on the macOS dark surfaces above, and only for the held value. That means the block in the symbol and icon, the dot in the stand-alone wordmark, the caret in the site hero, a held-value block in the app's dark appearance, and at most one primary action on an Ink section of the site. It is never used for links, body text, status or charts. The light appearance has no Amber.

**Neutrals**

| Token | Light | Dark | Use |
|---|---|---|---|
| Background | Paper `#F3F0E8` | Ink `#111110` | Page and window backgrounds |
| Raised | `#FBFAF7` | `#1C1C1A` | Cards and code blocks |
| Text | Ink `#111110` | Paper `#F3F0E8` | Body text and marks |
| Secondary text | Graphite `#5E5B54` (5.9:1 on Paper) | Fog `#A9A59C` (7.7:1 on Ink) | Captions and metadata |
| Rule | `#D9D4C7` | `#2E2D2A` | Decorative dividers only, never the only edge of a control |

The app icon's dark appearance, and nothing else, uses a `#0B0B0A` tile and a `#DCD8CE` `=` (13.8:1).

**Semantic colours**, tuned to the warm neutrals:

| Role | Light | On Paper | Dark | On Ink | Pair it with |
|---|---|---|---|---|---|
| Success | `#1E6B3A` | 5.7:1 | `#4FC27E` | 8.4:1 | `checkmark.circle` |
| Warning | `#9A4A00` | 5.5:1 | `#FF8C42` | 8.2:1 | `exclamationmark.triangle` |
| Danger | `#B42318` | 5.8:1 | `#FF6B61` | 6.8:1 | `xmark.octagon` |
| Info | `#1D5A9E` | 6.1:1 | `#6EA8FE` | 7.8:1 | `info.circle` |

Each light value also reaches at least 5.1:1 on white and on `#ECECEC`, and each dark value on `#1E1E1E` and `#2A2A28`. So they all pass WCAG AA for normal text, and 1.4.11 for icons, on the site and on macOS window backgrounds.

- Colour never carries meaning alone. Pair it with the SF Symbol above (or the same glyph on the web) and with words.
- Warning is a burnt orange. In the dark appearance, the only place it can meet Amber, it sits 18 degrees of hue away, and it always carries its icon. Amber is never a status colour.
- In the macOS app, controls follow the user's system accent colour. EnvCloak sets no custom AccentColor.

## 4. Typography

**Martian Mono** (SIL OFL 1.1, by Evil Martians) is the brand face, used for the wordmark, code and site headings. Use the variable font, `MartianMono[wdth,wght].ttf` from [google/fonts](https://github.com/google/fonts/tree/main/ofl/martianmono), at width 87.5 (`font-stretch: 87.5%`), in weights 400 and 500 only. Keep its licence, `fonts/MartianMono-OFL.txt`, with every copy of the font. This repository holds the licence, not the font.

| Where | Face | Notes |
|---|---|---|
| macOS app UI | SF Pro, through the system text styles (`.body`, `.headline`, `.caption`) | Never hard-code sizes. Let the system scale them. |
| App: key names, commands and references | Martian Mono 400, bundled with the app | Set it one point under the surrounding SF Pro (12 pt beside 13 pt body), because its x-height is large. |
| CLI | The user's terminal font | Plain text only: no emoji, no icon-font glyphs, and no meaning carried by colour alone. |
| Site H1 and H2 | Martian Mono 500 | Sentence case, tracking -1 % |
| Site H3 and below, body and UI | `system-ui, -apple-system, "Segoe UI", Roboto, sans-serif` | SF Pro on Apple devices, with no body web font to load |
| Site code | Martian Mono 400 | |

| Site style | Desktop size / line height | Mobile | Face and weight |
|---|---|---|---|
| H1 | 52 / 60 px | 34 / 40 px | Martian Mono 500 |
| H2 | 32 / 40 px | 26 / 32 px | Martian Mono 500 |
| H3 | 21 / 28 px | 19 / 26 px | System 600 |
| Body | 17 / 28 px | 17 / 27 px | System 400 |
| Small | 14 / 20 px | 14 / 20 px | System 400 |
| Code | 15 / 24 px | 14 / 22 px | Martian Mono 400 |

Keep body text to 60 to 72 characters per line. Emphasis is weight 600, never italic Martian Mono.

## 5. Motion

The full spec, with timings, easing and the loader states, is `motion/SPEC.md`. These are the principles:

1. **Caret-paced.** The brand has one rhythm, a text caret's: 530 ms on, 530 ms off. Anything that blinks blinks at that rate.
2. **Only the block moves.** The loader is the symbol with its block blinking (`logo/motion/symbol-blink.svg`). After its one draw-in during the logo reveal, the `=` never moves. The block never fills with characters, scrambles, or turns into a key.
3. **Motion explains state, never decorates.** It shows that something is waiting, approved, locked or done. There is no parallax, no particle effect, no "decrypting" text and no pulsing glow.
4. **Short and settled.** UI transitions are brief and ease out, with no bounce and no overshoot. Nothing loops except a loader that is really waiting.
5. **Reduced motion.** Under `prefers-reduced-motion` on the web, and Reduce Motion on macOS, the block holds solid, transitions become crossfades or cuts, and progress is given in words ("Waiting for Touch ID"). No state is ever shown by motion alone.

## 6. Voice and tone

Write like a careful engineer explaining the tool to a colleague: plain, exact, candid and calm.

- **Name things.** Say which key, which command, which project and which agent. Numbers and names beat adjectives.
- **Put the limit next to the claim.** The guarantees table (`docs/SPEC.md`, section 1.1) is published next to the headline on the README, the site and the app's About window. A feature that has not shipped is shown as unavailable, never implied.
- **No hype and no fear.** Never write military-grade, bank-level, unhackable, bulletproof, 100 % secure, zero risk, revolutionary, seamless, magic or supercharge. No hooded hackers, no skulls and no "your keys are exposed!" alarms.
- **Calm mechanics.** Use sentence case everywhere. No exclamation marks and no emoji in product copy. Buttons are verbs: "Approve", "Deny", "Rotate key".
- **Write names as their owners do:** EnvCloak, Claude Code, Codex, Cursor, Gemini CLI, OpenCode, Touch ID, macOS.
- **Spelling** follows the docs, which use British English (colour, licence, recognise). Code and file names stay as they are.

| Before | After |
|---|---|
| Military-grade encryption keeps your secrets 100% safe. | The vault is encrypted at rest, and unlocks only with the Secure Enclave, your passphrase or your Recovery Kit. |
| Your AI agents will never see your keys. Ever. | In proxy mode the agent holds a placeholder. The real key is added only for the provider's own hosts, over verified TLS. |
| Unhackable. Total protection. | EnvCloak cannot protect you from root, kernel malware or a fully compromised account. The full list is in the guarantees table. |
| Redaction makes leaks impossible. | Redaction guards against accidents. It is not a boundary against a process that holds the key. Proxy mode is. |
| Claude Code is requesting access to your secrets. Allow? | Claude Code wants to run `npm test` in acme-web with OPENAI_API_KEY. |
| LEAK DETECTED!!! Your keys are compromised! | Found 3 keys in past Claude Code transcripts. Rotate them: EnvCloak cannot recall copies already sent to a model provider. |
| Oops! Something went wrong. | No daemon answered, so no key was released. How to start one is printed below. |
| Supercharge your AI workflow with seamless secret magic. | `envcloak run -- npm test` injects the project's keys and masks them in everything the command prints. |
| Sync everything to the cloud in one click. | Pair a new laptop with a short code. The vault travels end-to-end encrypted, peer to peer, with no account. |
| Works with every AI agent. | Works with Claude Code, Codex, Cursor, Gemini CLI and OpenCode. What each one supports is in the coverage table (`docs/SPEC.md`, section 7.1). |

## 7. Assets

Everything is in [`assets/brand/`](../assets/brand/). All vector files are plain paths: none needs a font, a filter or a script.

| Path | Contents |
|---|---|
| `brand-board.png` | The whole system on one page: symbol, icon appearances, lockups, colour, type, small sizes and motion key frames |
| `logo/README.md` | The locked construction, colour and size rules, and a file-by-file index |
| `logo/symbol/` | The symbol in Ink, Paper, Amber on Ink and `currentColor`, plus pixel-snapped 16 and 32 px versions |
| `logo/wordmark/` | `.envcloak` outlined, in Ink, Paper, Amber dot on Ink, and `currentColor` |
| `logo/lockup/` | Horizontal and stacked lockups in the same four versions |
| `logo/png/` | Ready-made PNGs of all of the above |
| `logo/construction/`, `logo/checks/` | The grid and clear-space diagrams, and the minimum-size proofs |
| `logo/motion/symbol-blink.svg` | The loader seed: the blinking block |
| `icon/EnvCloak.icon/` | The Icon Composer file, with default, dark and mono (clear and tinted) appearances |
| `icon/layers/` | The icon's layers as flat SVGs on the 1024 canvas: background, `=` and block |
| `icon/EnvCloak.icns`, `icon/EnvCloak.iconset/` | The legacy icon, for non-Xcode builds and DMGs |
| `icon/flat/`, `icon/previews/` | Flat icon SVGs for docs and press, and renders of every appearance |
| `icon/menubar/` | `EnvCloakMenuTemplate`, the template image for the menu bar |
| `favicon/` | `favicon.svg` (follows the light or dark colour scheme), `favicon.ico`, PNG favicons, `apple-touch-icon.png` and the manifest icons |
| `motion/SPEC.md` | Motion timings, easing, colours per frame and loader states |
| `motion/index.html` | A self-contained demo page that plays every moment on Ink and on Paper |
| `motion/reveal/`, `motion/loader/`, `motion/redaction/`, `motion/approval/` | The animated SVGs, which play on their own and honour reduced motion |
| `motion/swiftui/EnvCloakMotion.swift` | The SwiftUI reference implementation of the same timelines |
| `motion/checks/` | Frame-by-frame render checks |
| `fonts/MartianMono-OFL.txt` | The licence for Martian Mono. The font itself comes from google/fonts. |

The kit was generated by scripts (Python with fontTools, Pillow and Playwright, and Xcode 26's `ictool` and `iconutil`) that are not in this repository yet. The files here are the masters to use.

## 8. Licence and trademark

- **Brand files.** The logos, icons, previews, motion files, brand board and guides in `assets/brand/`, and this guide, are licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Credit them as "EnvCloak brand assets by the EnvCloak contributors, CC BY 4.0".
- **Martian Mono** is copyright 2021 The Martian Mono Project Authors, and is licensed under the SIL Open Font License 1.1 (`fonts/MartianMono-OFL.txt`). The outlined wordmark, lockups and redaction lines are artwork, not a font, so they need no font to display. `motion/index.html` embeds a Martian Mono subset under the same licence.
- **Code.** `motion/swiftui/EnvCloakMotion.swift` is under the repo's MIT or Apache 2.0 licence, like the rest of the code.
- **Trademark.** CC BY 4.0 grants no trademark rights (its section 2(b)(2)). The EnvCloak name, symbol and wordmark identify this project. You may use them unmodified, without asking, to link to EnvCloak, to write or talk about it, or to list it as an integration. Do not use them in your own product's name or logo, do not imply endorsement, and do not ship a modified build under them: a fork that distributes its own builds needs its own name and icon. For anything else, open an issue.
