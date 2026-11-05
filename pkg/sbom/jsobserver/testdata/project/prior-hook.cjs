"use strict";

const fs = require("node:fs");
const { fileURLToPath } = require("node:url");

// Simulates another module hook that passes bundler sources on as a Uint8Array.
require("node:module").registerHooks({
  load(url, context, nextLoad) {
    const result = nextLoad(url, context);
    if (!url.startsWith("file:") || !/\/(lib\/main|dist\/rollup)\.js$/.test(url)) return result;
    const source = result.source == null ? fs.readFileSync(fileURLToPath(url)) : Buffer.from(result.source);
    return { ...result, source: new Uint8Array(source) };
  },
});
