# Vendored third-party assets

## chart.umd.min.js

Chart.js v4.5.1 (MIT), fetched from the official jsdelivr CDN distribution
(`https://cdn.jsdelivr.net/npm/chart.js@4.5.1/dist/chart.umd.min.js`) and
committed here as a self-hosted static asset -- no runtime CDN dependency.
See `LICENSE` for the full MIT license text.

SHA-256 of the exact file committed here (for future re-verification if
this file is ever manually touched):
48444a82d4edcb5bec0f1965faacdde18d9c17db3063d042abada2f705c9f54a

To upgrade: fetch the new version's UMD build from
`https://cdn.jsdelivr.net/npm/chart.js@<version>/dist/chart.umd.min.js`,
replace this file, update the version/hash in this note, and re-run the
Reports page's manual browser verification pass (chart rendering is the
one thing a version bump could silently break).
