# Webpack asset evidence

This private producer adapter supports Webpack 5.94.0 and plain-file copies made by copy-webpack-plugin 6.1.1. It emits a source proof for the shared Go-embed validator; it is not an ELF record or a public SBOM sidecar.

```js
const AssetEvidence = require('./collector.cjs');

// Use the same concrete copy job in CopyPlugin and in the evidence declaration.
new AssetEvidence({
  proofPath: '/private-build-metadata/ui.json',
  originals: [{
    root: '/ui/node_modules/example',
    originalRoot: '/verified-originals/example',
    component: {
      id: 'example', name: 'example', version: '1.0.0',
      source: {kind: 'node', locator: distributionURL, checksum: distributionIntegrity}
    }
  }],
  copied: [{from: '/ui/node_modules/example/NOTICE.txt', to: 'NOTICE.txt'}]
});
```

The caller must first verify each distribution's identity and materialize an independent original tree. The plugin does not fetch packages, infer versions from dependency ranges, validate the distribution archive itself, or turn a lockfile into an installed composition. A Git-backed package needs its separately verified Git/distribution binding; its commit is not tarball integrity. Installed and original roots must not overlap.

For single-file chunks, the collector follows the final chunk graph, including concatenated inner modules. Selected units are checked against their physical original files and the source Webpack actually consumed. This accounts for selected contributor units, not individual surviving bytes after minification. Externals do not become embedded components. Copied files must match a configured, plain single-file CopyPlugin operation and its final emitted bytes.

Every observed output has its final SHA-256, size and a status. A `present` row contains a component dictionary, an explicit `includedComponents` set, included input evidence and tools. A valid dictionary is not itself proof that every component is present. Unknown runtime units, loader-transformed modules, multi-file chunks, unclassified output assets and copied prebundled JavaScript/Wasm/native payloads produce `no-data`, not incomplete `present` rows. Known byte changes produce `hash-mismatch`; contradictory bindings produce `invalid`. Unsupported Webpack versions or asset path spellings stop proof production.

The proof is written outside the output root. Missing outputs have no invented zero-byte row. A missing selected asset must therefore be rejected by the consuming Go-embed obligation, while an unselected unknown asset does not enter the binary's composition. Diagnostic input paths remain those of the producer; importing an output does not relocate its original source files.

## Stage delivery

A checked stage may extend the existing private `werf.io/sbom-build-context-v1` declaration:

```json
{
  "version": 1,
  "stages": {
    "install": {
      "subject": 0,
      "packages": [
        {"sourceImage":"app-source","packageName":"app-source","packageVersion":"1.0.0","packageType":"source","sourcePlatform":"linux/amd64"}
      ],
      "goEmbed": [
        {"sourceImage":"ui-assets","sourceRoot":"/ui/dist/app","targetRoot":"/build/ui/dist/app","proofPath":"/private-build-metadata/ui.json"}
      ]
    }
  }
}
```

Both images must be explicit earlier dependencies/imports. DK captures the proof from the pinned source result, checks root remapping against the actual recorded import backend and filters, and places the unmodified proof beside the read-only compiler context. The root obligation survives an empty filtered file set. Composition is not duplicated in the target context: grouped `goEmbed.bindings` hold the source-stage identity, proof reference and actual asset path mappings.

This first delivery path requires a directory import whose source is the declared output root or its ancestor. Imports of only a subtree of that root, or roots reached through symlinked source parents, fail closed rather than creating a guessed obligation. The target root must match the actual import destination.

The shared helper validates the complete proof before Go cache lookup and checks bytes for the actual `go:embed` selection. The instrumented Go SDK includes the validated semantic digest in the embedding package's action key and verifies the digest again on compilation. Neither an ordinary stage checksum nor a package's current lockfile can replace this check.

This adapter is not automatically enabled by merely setting `SBOM_BUILD_CONTEXT`: the producing Webpack configuration must include the plugin and verified originals. Production Yarn/Git original acquisition, runtime/loader attribution, directory-copy patterns and complete Argo UI/prebundled-asset closure require additional integration. An opaque Redoc bundle is not accepted as a complete single-package composition.

## Tests

Run `npm ci --ignore-scripts --no-audit --no-fund` and `npm test` in this directory. The fixtures use real Webpack and CopyPlugin runs, locally packed npm distributions with verified SHA-512 integrity, and independent original trees. They do not represent upstream Argo packages.

For a retained single-build fixture, set `DK_WEBPACK_EVIDENCE` to an empty absolute directory and run `node fixture.cjs`. It retains the outputs, raw proof, input archives and hash manifest; the source root describes the actual retained output location. No generated binaries or dependency directories belong in Git.
