"use strict";

const fs = require("node:fs");
const path = require("node:path");

const rollupModule = require("rollup");
const chunks = require("./chunks.cjs");

const dist = path.resolve("dist/rollup-removed-cwd");
const removed = path.resolve("removed");

(async () => {
  const bundle = await rollupModule.rollup({ chunks });
  fs.mkdirSync(removed);
  process.chdir(removed);
  fs.rmdirSync(removed);
  const written = await bundle.write({ dir: dist, format: "es" });
  await bundle.close();
  console.log(JSON.stringify({ written }));
})();
