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

## Second pinned version: v0.17.19

`0002-transform-runtime-evidence-v0.17.19.patch` is the same instrumentation for upstream esbuild
**v0.17.19**, commit `d47ab43980c457db27d2671ab618cd5c40a618a7`, which is what `esbuild-loader@3.0.1`
depends on (`esbuild: ^0.17.6`). It is a port of `0001`, not a second design: the same linker part-range
selection, the same additive transform response member, the same refusal to infer selection from parsing
or from helper names in output.

Three differences, all forced by the older tree:

- `lib/shared/types.ts` names the transform generic `SpecificOptions` there and `ProvidedOptions` in
  0.25.0, so the interface hunk carries its own context.
- `pkg/api/api_impl.go` has no `encoding/base64` neighbour in its import block, and its output-unpacking
  loop has no local variable to extend, so both hunks differ in context only.
- `scripts/sbom-tests.js` must not call `esbuild.stop()`: that API arrives in 0.18, and before it the
  service stops when the process exits. The ported script calls it only when it exists.

The producer string is per version: this patch reports `dk-sbom/1 esbuild 0.17.19`. A collector must
compare the producer against the version pair it declared, never against one constant.

Note on behaviour, not on the port: `class Foo { bar = 1 }` selects the runtime with the JS loader (class
fields are defined, which needs a helper) and does not with the TS loader (they are assigned). Both
versions behave this way; a missing selection is never evidence that no runtime was used.

### Apply and validate

```sh
test "$(git rev-parse HEAD)" = d47ab43980c457db27d2671ab618cd5c40a618a7
git apply --check "$PATCH"
git apply "$PATCH"
go build ./... && go test ./pkg/api/ -run SBOM
go build -o esbuild ./cmd/esbuild
node scripts/esbuild.js "$PWD/esbuild" --neutral
ESBUILD_BINARY_PATH="$PWD/esbuild" node scripts/sbom-tests.js
```

Checked on a pristine shallow clone of the tag: the patch applies with `git apply --check`, the tree
builds, the nine Go SBOM assertions pass and the eight Node tests pass.

### Version pairs

A build declares one pair, and the collector accepts exactly the pair it was given:

| esbuild | esbuild-loader | loader `dist/index.cjs` (official tarball) | tarball integrity |
| --- | --- | --- | --- |
| 0.25.0 | 4.3.0 | `sha256:64b2b3f0adaadc963e115caa4f0aeb137bf721eca2d0b7386fbe71cbe88f473e` | `sha512-D7HeJNdkDKKMarPQO/3dlJT6RwN2YJO7ENU6RPlpOz5YxSHnUNi2yvW41Bckvi1EVwctIaLzlb0ni5ag2GINYA==` |
| 0.17.19 | 3.0.1 | `sha256:95888f5eda79612e84c2c5723b2fee45d1acbde7fd979e8f42ede582c913b723` | `sha512-aZfGybqTeuyCd4AsVvWOOfkhIuN+wfZFjMyh3gyQEU1Uvsl8L6vye9HqP93iRa0iTA+6Jclap514PJIC3cLnMA==` |

The esbuild client and executable are built from the patched source, so their hashes belong to that build
and stay the caller's declaration. Two inputs are not declared but pinned by the pair, because they are the
same bytes for everyone who uses that version: the published loader artifact, and `internal/runtime/runtime.go`
of that esbuild — `sha256:90066c2fe560b24e55a4adfb05896b1cc5ccc219630d92a24bd614d3a4781610` for 0.25.0 and
`sha256:e2e31178a464f615a6b86e7c72469b19913b30b1140223daf08bc720b2f18df9` for 0.17.19. A build may repeat
either digest in its declaration and may not contradict it; handing over the other version's runtime source
refuses the units that would have been claimed against it.

`esbuild-loader@3.0.1` supports the same `implementation.transform` option 4.3.0 does, refuses a
non-function implementation, strips `implementation` and `tsconfig` out of the transform options, and sets
`sourcefile` to `this.resourcePath` — the three facts the per-module instrumentation depends on. It reads
its options through `loaderUtils.getOptions(this)` rather than `this.getOptions()`, which still returns the
cloned loader item this adapter installs.

## Collector adapter

The private collector option `esbuild` accepts the explicit tool description consumed by `installEsbuildEvidence`: a `versions` pair, absolute `entry`, `binary`, `loader` paths and the expected `entrySHA256` and `binarySHA256`.

`versions` names one of the described pairs — `{ esbuild: '0.25.0', esbuildLoader: '4.3.0' }` or `{ esbuild: '0.17.19', esbuildLoader: '3.0.1' }` — and selects both the producer string the transform evidence must carry and the digest the loader must have. Any other pair is a declaration this adapter cannot act on and is refused as a programming error. The loader is therefore recognized **by the digest of its published artifact**, never by the name of the directory it is installed in: the 3.0.1 artifact is installed under the alias `esbuild-loader-3.0.1` (`npm:esbuild-loader@3.0.1`) and is described exactly as a canonically installed one. A `loaderSHA256` may still be passed, but only the pinned value of the declared pair; a loader file whose bytes are those of the other version is a `hash-mismatch` of this build. An optional `runtimeSource` and `runtimeSourceSHA256` name the independently verified source unit for transforms that select the runtime. These expected values must come from the caller's verified build inputs, not hashes observed opportunistically by the collector.

Set `ESBUILD_BINARY_PATH` before Node starts, to the same verified binary path. `/usr/bin/esbuild` is deliberately ignored by the pinned Node client and is refused by the adapter. A client loaded before the adapter can establish its configuration is also refused. The adapter uses esbuild-loader 4.3.0's existing `implementation.transform` option, cloning per-module loader descriptors without mutating the project's shared rule options. Foreign implementations and other chains are not overridden.

The actual transform input/output, producer metadata and kept Webpack module source must agree. A selected runtime requires a verified source unit; missing observations, BOM/unsupported input normalization and unsupported chains remain `no-data`. Compiler options such as `tsconfigRaw` shape the transform but are not reported as source units. Cross-process Webpack cache hits without an observed transform are not upgraded to fresh evidence.

The adapter tests require `DK_ESBUILD_SOURCE` pointing at the patched 0.25.0 checkout built above, and `DK_ESBUILD_0_17_SOURCE` pointing at the patched 0.17.19 checkout of `0002-…`; without the second only the 0.25.0 pair is exercised and the three second-pair cases are explicitly skipped. Each checkout must have its binary and Node client present. Without `DK_ESBUILD_SOURCE` every esbuild case is skipped; a green ordinary test run does not prove them. With it, tests exercise the real compiler and loader. `DK_ESBUILD_EVIDENCE` can name an existing owned directory for exporting the two collector proof documents; these documents preserve the fragment, not the temporary output files after fixture cleanup.

## Integration boundary

The producer patch does **not** bind the executable to an original source distribution or establish the original `internal/runtime/runtime.go` bytes. A collector still needs verified compiler inputs and original source/component identity before attributing a selected runtime unit. The npm platform package contains the executable, not that Go source file; its archive integrity must not be presented as a checksum of the missing source.

The test fixture verifies runtime source against the pinned Go module and upstream commit, then repacks that source into a real prepared PM image and reads the original bytes through the shared original reader. Its final component describes that PM distribution, not a fictitious application Go dependency. This proves the bounded Node proof fragment, not the production tool package's provenance or a full Go embed build. Production delivery must supply its own real prepared source Packet and checked tool build. This adapter alone is not complete Argo UI, SCSS, prebundled-asset or factory acceptance.
