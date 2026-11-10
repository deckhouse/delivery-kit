"use strict";

const esbuild = require("esbuild");
const plan = require("./plan.cjs");

(async () => {
  const result = await esbuild.build({ plan: plan("dist/esbuild-plain") });
  console.log(JSON.stringify({ exports: Object.keys(esbuild), result: Object.keys(result), metafile: result.metafile }));
})();
