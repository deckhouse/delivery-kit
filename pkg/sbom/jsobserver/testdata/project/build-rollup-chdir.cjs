"use strict";

const rollupModule = require("rollup");
const chunks = require("./chunks.cjs");

(async () => {
  const chdir = { name: "chdir", writeBundle: () => process.chdir("src") };
  const bundle = await rollupModule.rollup({ chunks, plugins: [chdir] });
  const written = await bundle.write({ dir: "dist/rollup-chdir", format: "es" });
  await bundle.close();
  console.log(JSON.stringify({ written }));
})();
