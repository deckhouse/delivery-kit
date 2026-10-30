# esbuild transform runtime observation

`0001-transform-runtime-evidence.patch` applies to upstream esbuild **v0.25.0**, commit `e9174d671b1882758cd32ac5e146200f5bee3e45` ([MIT](https://github.com/evanw/esbuild/blob/e9174d671b1882758cd32ac5e146200f5bee3e45/LICENSE.md)). It adds private per-transform evidence without changing the transform options, ordinary generated code or service version handshake. It is not a canonical SBOM record or an upstream esbuild API proposal.

The linker records whether an actual runtime part range was selected for printing into the output chunk. Parsing the runtime, visiting its graph node or finding helper names in output does not establish selection. The flag is set after the existing test-only runtime omission guard. Unit-level selection does not claim which individual bytes survive printing or minification.

Successful transform results gain this additive member:

```json
{
  "sbom": {
    "version": 1,
    "producer": "dk-sbom/1 esbuild 0.25.0",
    "inputSHA256": "sha256:<64 lowercase hex>",
    "outputSHA256": "sha256:<64 lowercase hex>",
    "runtimeSelected": true
  }
}
```

Hashes describe the actual input and output bytes before the service substitutes temporary filenames for large messages. Failed transforms carry no successful evidence. Build API result objects remain unchanged. Both the binary and Node client must be built from the patch: the stock client drops the extra response member. Missing evidence must never be interpreted as `runtimeSelected: false`.

## Apply and validate

In a clean checkout of the pinned upstream commit, with `PATCH` set to the absolute patch path:

```sh
test "$(git rev-parse HEAD)" = e9174d671b1882758cd32ac5e146200f5bee3e45
git apply --check "$PATCH"
git apply "$PATCH"
go test ./...
go build -o esbuild ./cmd/esbuild
node scripts/esbuild.js "$PWD/esbuild" --neutral
node scripts/sbom-tests.js
```

The added Go tests cover runtime selection, hash binding and failure results. The Node tests exercise async and synchronous transforms, the worker/message and large-input filesystem paths, legal comments, mangle cache and unchanged build results. The existing bundler snapshots check output compatibility. Type-check the Node client using the upstream pinned `lib/package.json` dependencies and `make lib-typecheck-node lib-typecheck-node-nolib`.

## Collector adapter

The private collector option `esbuild` accepts the explicit tool description consumed by `installEsbuildEvidence`: absolute `entry`, `binary`, `loader` paths and their expected `entrySHA256`, `binarySHA256`, `loaderSHA256`. An optional `runtimeSource` and `runtimeSourceSHA256` name the independently verified source unit for transforms that select the runtime. These expected values must come from the caller's verified build inputs, not hashes observed opportunistically by the collector.

Set `ESBUILD_BINARY_PATH` before Node starts, to the same verified binary path. `/usr/bin/esbuild` is deliberately ignored by the pinned Node client and is refused by the adapter. A client loaded before the adapter can establish its configuration is also refused. The adapter uses esbuild-loader 4.3.0's existing `implementation.transform` option, cloning per-module loader descriptors without mutating the project's shared rule options. Foreign implementations and other chains are not overridden.

The actual transform input/output, producer metadata and kept Webpack module source must agree. A selected runtime requires a verified source unit; missing observations, BOM/unsupported input normalization and unsupported chains remain `no-data`. Compiler options such as `tsconfigRaw` shape the transform but are not reported as source units. Cross-process Webpack cache hits without an observed transform are not upgraded to fresh evidence.

The adapter tests require `DK_ESBUILD_SOURCE` pointing at the patched checkout built above, with its binary and Node client present. Without this input the esbuild-specific cases are explicitly skipped; a green ordinary test run does not prove them. With it, tests exercise the real compiler and loader. `DK_ESBUILD_EVIDENCE` can name an existing owned directory for exporting the two collector proof documents; these documents preserve the fragment, not the temporary output files after fixture cleanup.

## Integration boundary

The producer patch does **not** bind the executable to an original source distribution or establish the original `internal/runtime/runtime.go` bytes. A collector still needs verified compiler inputs and original source/component identity before attributing a selected runtime unit. The npm platform package contains the executable, not that Go source file; its archive integrity must not be presented as a checksum of the missing source.

The test fixture verifies runtime source against the pinned Go module and upstream commit, then repacks that source into a real prepared PM image and reads the original bytes through the shared original reader. Its final component describes that PM distribution, not a fictitious application Go dependency. This proves the bounded Node proof fragment, not the production tool package's provenance or a full Go embed build. Production delivery must supply its own real prepared source Packet and checked tool build. This adapter alone is not complete Argo UI, SCSS, prebundled-asset or factory acceptance.
