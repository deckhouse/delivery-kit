"use strict";

const fs = require("node:fs");

const rollupModule = require("rollup");
const chunks = require("./chunks.cjs");

fs.mkdirSync("dist", { recursive: true });

(async () => {
  const chdir = { name: "chdir", generateBundle: () => process.chdir("dist") };
  const bundle = await rollupModule.rollup({ chunks, plugins: [chdir] });
  const written = await bundle.write({ dir: "rollup-chdir-early", format: "es" });
  await bundle.close();
  console.log(JSON.stringify({ written }));
})();
