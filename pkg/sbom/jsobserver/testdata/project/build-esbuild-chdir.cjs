"use strict";

const esbuild = require("esbuild");
const plan = require("./plan.cjs");

process.chdir("src");

(async () => {
  const result = await esbuild.build({ plan: plan("dist/esbuild-chdir") });
  console.log(JSON.stringify({ result: Object.keys(result), metafile: result.metafile }));
})();
