"use strict";

const path = require("node:path");

const abs = (file) => path.resolve(file);

module.exports = [
  {
    fileName: "main.js",
    code: "/* main */",
    modules: {
      [abs("src/main.js")]: { renderedLength: 10 },
      [abs("node_modules/dep-a/index.js")]: { renderedLength: 5 },
      [abs("node_modules/dep-a/dist/es/inner.js")]: { renderedLength: 3 },
      [abs("node_modules/unused/index.js")]: { renderedLength: 0 },
      [`\0${abs("node_modules/virtual-only/index.js")}?commonjs-proxy`]: { renderedLength: 20 },
      [`${abs("node_modules/@scope/dep-b/index.js")}?commonjs-es-import`]: { renderedLength: 4 },
    },
  },
  {
    fileName: "lazy.js",
    code: "/* lazy */",
    modules: {
      [abs("node_modules/linked-dep/index.js")]: { renderedLength: 2 },
      [abs("node_modules/inner-ws/index.js")]: { renderedLength: 4 },
      [abs("node_modules/@scope/dep-b/node_modules/no-version/index.js")]: { renderedLength: 6 },
      "virtual:generated": { renderedLength: 9 },
    },
  },
  {
    fileName: "own.js",
    code: "/* own */",
    modules: {
      [abs("src/main.js")]: { renderedLength: 10 },
    },
  },
];
