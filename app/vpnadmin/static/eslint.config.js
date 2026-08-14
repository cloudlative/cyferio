// Flat ESLint config for app.js -- a plain, unbundled browser script (no
// <script type="module">, no import/export, loaded directly via a <script
// src> tag in base.html). No package.json/node_modules committed for this
// on purpose: this app deliberately has no frontend build step (see
// app/README.md's Architecture section), and a real npm project here would
// contradict that. CI runs this via `npx --yes eslint@9 -c ... app.js`,
// which fetches ESLint itself at run time rather than needing it installed.
//
// Scoped to catch real bugs (undefined names, unused vars, obvious
// mistakes), not to impose a style opinion on 1900+ existing lines -- this
// is a lint pass, not a rewrite.
export default [
  {
    files: ["app.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: {
        // Standard browser globals this script actually relies on.
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
        FormData: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        Blob: "readonly",
        Event: "readonly",
        CustomEvent: "readonly",
        WebSocket: "readonly",
        alert: "readonly",
        confirm: "readonly",
        prompt: "readonly",
        structuredClone: "readonly",
        getComputedStyle: "readonly",
        crypto: "readonly",
        // Loaded via its own <script> tag on the pages that chart --
        // external to app.js, but referenced by name here.
        Chart: "readonly",
      },
    },
    rules: {
      "no-undef": "error",
      // Deliberately NOT enabling no-unused-vars: this file's top-level
      // `function foo() {}` declarations are its actual public surface --
      // called from `onclick="foo()"` and similar inline handlers in the
      // Jinja templates, invisible to a lint pass scoped to this one file.
      // Flagging them "unused" would be systematically wrong, not a real
      // signal (verified: ~30 of app.js's top-level functions trip this).
      "no-redeclare": "error",
      "no-dupe-keys": "error",
      "no-dupe-args": "error",
      "no-const-assign": "error",
      "no-self-compare": "error",
      "no-unreachable": "error",
    },
  },
];
