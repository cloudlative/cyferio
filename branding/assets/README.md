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
| `png/` | Rasterized exports of the above (see below) — generated, not hand-edited |

Dark variants are the primary/default (matches the brand's dark-mode-native direction); light variants exist for placement on white/light surfaces (print, light-themed embeds).

## Rasterized exports (`png/`)

Generated via `@resvg/resvg-js` + `png-to-ico` — see the render script noted in the branding proposal if these ever need regenerating after an SVG edit. Sizes: `mark-tile-dark-{16,32,48,64,128,256,512}.png`, `mark-tile-light-{180,512}.png`, `favicon.ico` (multi-size, from the dark tile), `og-image.png` (1200×630), `slack-app-icon-1024.png` (Slack's required square, 512–2000px range), and both horizontal lockups at 680px wide.

## Important caveat — the wordmark is not yet outlined

`wordmark-*.svg` and every lockup that includes text use live `<text>` elements set in **Lato** (weight 900/Black), not vector-outlined letterforms. Lato was confirmed installed and renders correctly in this environment, but a real production logo should have its text converted to paths (via Illustrator/Figma/fonttools) so it renders identically on every system regardless of installed fonts — treat these as final-content, not-yet-final-file-format. Do this conversion before the wordmark goes on anything printed or embedded outside a browser context that loads its own webfont.

## Regenerating after an edit

```bash
cd branding/assets
npm install
npm run render
```

Requires the **Lato** font to be installed on whatever machine runs this (the wordmark/lockups reference it by name) — without it, `resvg` silently falls back to its default font and the wordmark renders in the wrong typeface with no error. Verify with `fc-list | grep -i lato` before trusting a fresh render.
