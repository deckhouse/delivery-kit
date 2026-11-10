"use strict";

const fs = require("node:fs");
const path = require("node:path");

// An esbuild API the observer does not recognize: build is inherited, not own.
const api = {
  async build(options) {
    const file = path.resolve(options.plan[0].out);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, options.plan[0].code);
    return { errors: [], warnings: [], outputFiles: undefined, metafile: undefined, mangleCache: undefined };
  },
  async context() {
    throw new Error("not used");
  },
};

module.exports = Object.create(api, { version: { value: "0.24.2", enumerable: true } });
