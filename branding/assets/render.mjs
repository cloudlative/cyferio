import { Resvg } from '@resvg/resvg-js';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import pngToIco from 'png-to-ico';

// Run from anywhere -- paths are relative to this file's own location
// (this directory), not the caller's cwd or a hardcoded machine path.
const ASSETS = dirname(fileURLToPath(import.meta.url));
const OUT = `${ASSETS}/png`;
mkdirSync(OUT, { recursive: true });

function renderPng(svgPath, outPath, width) {
  const svg = readFileSync(svgPath, 'utf8');
  const resvg = new Resvg(svg, { fitTo: { mode: 'width', value: width } });
  const png = resvg.render().asPng();
  writeFileSync(outPath, png);
  console.log(`wrote ${outPath} (${width}px)`);
}

// App-icon / favicon sizes from the dark tile (primary mark)
const sizes = [512, 256, 128, 64, 48, 32, 16];
for (const size of sizes) {
  renderPng(`${ASSETS}/mark-tile-dark.svg`, `${OUT}/mark-tile-dark-${size}.png`, size);
}
renderPng(`${ASSETS}/mark-tile-light.svg`, `${OUT}/mark-tile-light-512.png`, 512);
renderPng(`${ASSETS}/mark-tile-light.svg`, `${OUT}/mark-tile-light-180.png`, 180); // apple-touch-icon size

// OG social preview
renderPng(`${ASSETS}/og-image.svg`, `${OUT}/og-image.png`, 1200);

// Lockups, for anyone who wants a raster instead of the SVG
renderPng(`${ASSETS}/logo-horizontal-dark-bg.svg`, `${OUT}/logo-horizontal-dark-bg.png`, 680);
renderPng(`${ASSETS}/logo-horizontal-light-bg.svg`, `${OUT}/logo-horizontal-light-bg.png`, 680);

// favicon.ico -- multi-size, from the dark tile (matches the site's dark-first default)
const icoBuffer = await pngToIco([
  `${OUT}/mark-tile-dark-16.png`,
  `${OUT}/mark-tile-dark-32.png`,
  `${OUT}/mark-tile-dark-48.png`,
  `${OUT}/mark-tile-dark-64.png`,
]);
writeFileSync(`${OUT}/favicon.ico`, icoBuffer);
console.log('wrote favicon.ico');
