"use strict";

const esbuild = require("esbuild");
const plan = require("./plan.cjs");

(async () => {
  const result = await esbuild.build(Object.create({ plan: plan("dist/esbuild-inherited") }));
  console.log(JSON.stringify({ result: Object.keys(result), metafile: result.metafile }));
})();
