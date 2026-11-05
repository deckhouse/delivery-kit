"use strict";

const rollupModule = require("rollup");
const chunks = require("./chunks.cjs");

(async () => {
  const bundle = await rollupModule.rollup({ chunks });
  const written = await bundle.write({ file: "dist/rollup-cjs/main.js", format: "cjs" });
  await bundle.close();

  console.log(JSON.stringify({
    exports: Object.keys(rollupModule),
    version: rollupModule.VERSION,
    rollup: [rollupModule.rollup.name, rollupModule.rollup.length],
    written,
  }));
})();
