"use strict";

const fs = require("node:fs");

const rollupModule = require("rollup");
const chunks = require("./chunks.cjs");

fs.mkdirSync("dist/rollup-original", { recursive: true });
fs.writeFileSync("dist/rollup-original/main.js", "/* stale */");

(async () => {
  const redirect = { name: "redirect", outputOptions: (options) => ({ ...options, dir: "dist/rollup-redirected" }) };
  const bundle = await rollupModule.rollup({ chunks, plugins: [redirect] });
  const written = await bundle.write({ dir: "dist/rollup-original", format: "es" });
  await bundle.close();
  console.log(JSON.stringify({ written }));
})();
