// ESLint flat config for app/vpnadmin/static/app.js -- the one hand-written
// JS file in this repo (server-rendered Jinja2 by design, see the CI PR
// description; no bundler/build step, no package.json). Run via `npx
// eslint@9 --no-config-lookup -c eslint.config.mjs app/vpnadmin/static/*.js`
// (see .github/workflows/ci.yml's lint-js job) -- npx resolves eslint
// itself from the npm registry at CI-run time; this file intentionally has
// zero imports of its own (no `globals` package, no node_modules) so it
// needs nothing installed/committed locally, matching the "no build
// step/package.json" constraint.
//
// Rule selection is deliberately narrow: `no-undef` (real bugs -- a typo'd
// identifier, a global assumed but never declared) is a hard error; almost
// everything else, starting with `no-unused-vars`, is a warning. This file
// is 1900+ lines of pre-existing code with many top-level `function`
// declarations invoked only from inline `onclick=`/similar HTML attributes
// in the Jinja2 templates it renders into -- invisible to a linter that
// only sees app.js in isolation, so a hard gate on "unused" here would be
// mostly false positives. See the CI PR description's "Follow-up" section
// for the current warning list.
const browserGlobals = {
  window: "readonly",
  document: "readonly",
  navigator: "readonly",
  location: "readonly",
  history: "readonly",
  console: "readonly",
  fetch: "readonly",
  localStorage: "readonly",
  sessionStorage: "readonly",
  setTimeout: "readonly",
  clearTimeout: "readonly",
  setInterval: "readonly",
  clearInterval: "readonly",
  requestAnimationFrame: "readonly",
  cancelAnimationFrame: "readonly",
  alert: "readonly",
  confirm: "readonly",
  prompt: "readonly",
  URLSearchParams: "readonly",
  URL: "readonly",
  FormData: "readonly",
  Intl: "readonly",
  Event: "readonly",
  CustomEvent: "readonly",
  MouseEvent: "readonly",
  KeyboardEvent: "readonly",
  crypto: "readonly",
  performance: "readonly",
  matchMedia: "readonly",
  getComputedStyle: "readonly",
  MutationObserver: "readonly",
  IntersectionObserver: "readonly",
  ResizeObserver: "readonly",
  Node: "readonly",
  Element: "readonly",
  HTMLElement: "readonly",
  Blob: "readonly",
  atob: "readonly",
  btoa: "readonly",
  structuredClone: "readonly",
  globalThis: "readonly",
};

export default [
  {
    files: ["app/vpnadmin/static/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: {
        ...browserGlobals,
        // Loaded globally via a <script> tag in base.html
        // (static/vendor/chart.umd.min.js) before app.js runs -- not an
        // npm dependency of this file, so ESLint can't infer it.
        Chart: "readonly",
      },
    },
    rules: {
      "no-undef": "error",
      "no-unused-vars": "warn",
    },
  },
];
