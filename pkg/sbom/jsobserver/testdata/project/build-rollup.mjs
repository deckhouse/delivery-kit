import * as rollupModule from "rollup";

import chunks from "./chunks.cjs";

const { rollup } = rollupModule;
const bundle = await rollup({ chunks });
const generated = await bundle.generate({ dir: "dist/rollup-generated", format: "es" });
const written = await bundle.write({ dir: "dist/rollup-esm", format: "es" });
await bundle.close();

console.log(JSON.stringify({
  exports: Object.keys(rollupModule),
  version: rollupModule.VERSION,
  rollup: [rollup.name, rollup.length],
  bundle: Object.keys(bundle),
  generated,
  written,
}));
