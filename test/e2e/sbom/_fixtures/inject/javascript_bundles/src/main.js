import { uniq } from "lodash-es";
import prettyBytes from "pretty-bytes";

globalThis.bundleFixture = {
  size: prettyBytes(1536, { binary: true, bits: true }),
  loadPattern: () => import("./lazy.js").then((lazy) => lazy.pattern("a-b")),
};
