"use strict";

module.exports = (dir) => [
  {
    out: `${dir}/app.js`,
    code: "/* app */",
    inputs: {
      "src/main.js": { bytesInOutput: 10 },
      "node_modules/dep-a/index.js": { bytesInOutput: 5 },
      "node_modules/unused/index.js": { bytesInOutput: 0 },
      "virtual-ns:node_modules/virtual-only/index.js": { bytesInOutput: 7 },
      "node_modules/linked-dep/index.js": { bytesInOutput: 2 },
    },
  },
  {
    out: `${dir}/chunk.js`,
    code: "/* chunk */",
    inputs: {
      "node_modules/@scope/dep-b/index.js": { bytesInOutput: 3 },
    },
  },
  {
    out: `${dir}/app.js.map`,
    code: "{}",
    inputs: {},
  },
];
