# Cyferio logo assets

Concept A, "Cipher Signal" — two concentric broken rings (cyan `#23D6C4` outer, amber `#F2A93B` inner) around a solid center dot. Reads as both a signal/radar ping and a cipher wheel.

## Files

| File | Use |
|---|---|
| `mark.svg` | Icon only, transparent background, 100×100 viewBox — for placing on any existing colored surface |
| `mark-tile-dark.svg` / `mark-tile-light.svg` | Icon on a rounded-square filled tile (512×512) — app icons, favicons |
| `wordmark-light.svg` / `wordmark-dark.svg` | "Cyferio" text only, no mark |
| `logo-horizontal-dark-bg.svg` / `-light-bg.svg` | Mark + wordmark side by side |
| `logo-stacked-dark-bg.svg` / `-light-bg.svg` | Mark above wordmark, centered |
| `og-image.svg` | 1200×630 social preview card (mark + wordmark + tagline + one-line description) |
| `slack-app-icon.svg` | Slack app icon — full-bleed square (no pre-rounded corners; Slack applies its own), same mark as `mark-tile-dark.svg` scaled 2x onto a 1024 canvas |
| `github-avatar.svg` | GitHub org/repo avatar — same full-bleed-square treatment as `slack-app-icon.svg`, GitHub applies its own rounded/circular crop |
| `png/` | Rasterized exports of the above (see below) — generated, not hand-edited |

## Ring geometry — corrected 2026-08-23

Every file above draws the mark from an explicit sampled-point `<path>` (mirrored 180° gap between the two rings), not the original circle + `stroke-dasharray` + arbitrary rotation angles this repo shipped with initially. That original approach is what caused the ring-geometry bug fixed live in the app (base.html etc.) a while back — this source-of-truth set of SVGs had drifted out of sync with that fix (the app's inline copies got corrected, these standalone asset files didn't), so every one of them still had the old, wrong-looking rings until this pass regenerated them from the same corrected path data. `app/vpnadmin/static/favicon.ico`/`apple-touch-icon.png` were fixed independently before this and are NOT re-synced from this folder's own `png/favicon.ico` — the two exports currently differ slightly (different margin/size set); treat the app's own static copies as the ones actually live in the product.

Dark variants are the primary/default (matches the brand's dark-mode-native direction); light variants exist for placement on white/light surfaces (print, light-themed embeds).

## Rasterized exports (`png/`)

Generated via `@resvg/resvg-js` + `png-to-ico` — see the render script noted in the branding proposal if these ever need regenerating after an SVG edit. Sizes: `mark-tile-dark-{16,32,48,64,128,256,512}.png`, `mark-tile-light-{180,512}.png`, `favicon.ico` (multi-size, from the dark tile), `og-image.png` (1200×630), `slack-app-icon-1024.png` (Slack's required square, 512–2000px range), `github-avatar-1024.png` (GitHub's org/repo avatar upload), and both horizontal lockups at 680px wide.

## Important caveat — the wordmark is not yet outlined

`wordmark-*.svg` and every lockup that includes text use live `<text>` elements set in **Lato** (weight 900/Black), not vector-outlined letterforms. Lato was confirmed installed and renders correctly in this environment, but a real production logo should have its text converted to paths (via Illustrator/Figma/fonttools) so it renders identically on every system regardless of installed fonts — treat these as final-content, not-yet-final-file-format. Do this conversion before the wordmark goes on anything printed or embedded outside a browser context that loads its own webfont.

## Regenerating after an edit

```bash
cd branding/assets
npm install
npm run render
```

Requires the **Lato** font to be installed on whatever machine runs this (the wordmark/lockups reference it by name) — without it, `resvg` silently falls back to its default font and the wordmark renders in the wrong typeface with no error. Verify with `fc-list | grep -i lato` before trusting a fresh render.
