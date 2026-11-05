"use strict";

const path = require("node:path");

const esbuild = require("esbuild");
const plan = require("./plan.cjs");

function descriptors(api) {
  return Object.entries(Object.getOwnPropertyDescriptors(api)).map(([name, descriptor]) => [
    name,
    descriptor.get ? "get" : "value",
    descriptor.enumerable,
    descriptor.configurable,
  ]);
}

function summary(result) {
  return {
    keys: Object.keys(result),
    hasMetafile: "metafile" in result,
    metafile: result.metafile,
    outputFiles: result.outputFiles && result.outputFiles.map((file) => [path.relative(process.cwd(), file.path), file.text]),
  };
}

(async () => {
  const disk = await esbuild.build({ plan: plan("dist/esbuild-disk") });
  const memory = await esbuild.build({ plan: plan("dist/esbuild-memory"), write: false });
  const requested = await esbuild.build({ plan: plan("dist/esbuild-requested"), metafile: true });
  const viaDefault = await esbuild.default.build({ plan: plan("dist/esbuild-default"), absWorkingDir: process.cwd() });
  const ctx = await esbuild.context({ plan: plan("dist/esbuild-context") });
  const rebuilt = await ctx.rebuild();
  await ctx.dispose();
  let invalid;
  try {
    await esbuild.build({ plan: plan("dist/esbuild-invalid"), metafile: "yes" });
  } catch (err) {
    invalid = err.message;
  }

  console.log(JSON.stringify({
    exports: Object.keys(esbuild),
    defaultExports: Object.keys(esbuild.default),
    esModule: esbuild.__esModule,
    descriptors: descriptors(esbuild),
    defaultDescriptors: descriptors(esbuild.default),
    defaultIsModule: esbuild.default === esbuild,
    defaultIsOwnDefault: esbuild.default.default === esbuild.default,
    results: [disk, memory, requested, viaDefault, rebuilt].map(summary),
    invalid,
  }));
})();
