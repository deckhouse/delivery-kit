import esbuildDefault, { build } from "esbuild";

import plan from "./plan.cjs";

const named = await build({ plan: plan("dist/esbuild-esm-named") });
const viaDefault = await esbuildDefault.build({ plan: plan("dist/esbuild-esm-default") });

console.log(JSON.stringify({
  defaultExports: Object.keys(esbuildDefault),
  results: [named, viaDefault].map((result) => [Object.keys(result), result.metafile]),
}));
