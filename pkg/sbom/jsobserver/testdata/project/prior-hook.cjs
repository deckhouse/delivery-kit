"use strict";

const fs = require("node:fs");
const { fileURLToPath } = require("node:url");

// Simulates another module hook that changes bundler sources and passes them
// on as a Uint8Array.
require("node:module").registerHooks({
  load(url, context, nextLoad) {
    const result = nextLoad(url, context);
    if (!url.startsWith("file:") || !/\/(lib\/main|dist\/rollup)\.js$/.test(url)) return result;
    const source = result.source == null ? fs.readFileSync(fileURLToPath(url)) : Buffer.from(result.source);
    const changed = Buffer.concat([source, Buffer.from("\n;module.exports.priorHookApplied = true;\n")]);
    return { ...result, source: new Uint8Array(changed) };
  },
});
