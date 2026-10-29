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

## Integration boundary

This patch does **not** bind the executable to an original source distribution or establish the original `internal/runtime/runtime.go` bytes. A collector still needs verified compiler inputs and original source/component identity before attributing a selected runtime unit. The npm platform package contains the executable, not that Go source file; its archive integrity must not be presented as a checksum of the missing source.

The intended loader seam is esbuild-loader's existing `implementation.transform` option. A per-module adapter must bind the observed transform input/output to the verified raw source and Webpack's consumed loader output. Other loader chains, unsupported producer capabilities and cache hits without the required evidence remain incomplete. This patch alone is not complete Argo UI, SCSS, prebundled-asset or factory acceptance.
