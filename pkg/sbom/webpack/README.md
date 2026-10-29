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

The caller must first verify each distribution's identity and materialize an independent original tree. A private asynchronous `resolveOriginal(resourcePath)` callback may supply a verified binding for a selected resource before the static roots are consulted. Returning `undefined` delegates to those static roots; a typed failure (`status` plus `message`) refuses the asset instead of falling back to the containing project. The callback must have a fresh, bounded lifetime per compilation and must not replace a missing managed dependency with a project-owned input. The plugin does not fetch packages, infer versions from dependency ranges, validate the distribution archive itself, or turn a lockfile into an installed composition. A Git-backed package needs its separately verified Git/distribution binding; its commit is not tarball integrity. Installed and original roots must not overlap.

For single-file chunks, the collector follows the final chunk graph, including concatenated inner modules. Selected units are checked against their physical original files and the source Webpack actually consumed. This accounts for selected contributor units, not individual surviving bytes after minification. Externals do not become embedded components. Copied files must match a configured, plain single-file CopyPlugin operation and its final emitted bytes.

Every observed output has its final SHA-256, size and a status. A `present` row contains a component dictionary, an explicit `includedComponents` set, included input evidence and tools. A valid dictionary is not itself proof that every component is present. Unknown runtime units, loader-transformed modules, multi-file chunks, unclassified output assets and copied prebundled JavaScript/Wasm/native payloads produce `no-data`, not incomplete `present` rows. Known byte changes produce `hash-mismatch`; contradictory bindings produce `invalid`. Unsupported Webpack versions or asset path spellings stop proof production.

The proof is written outside the output root. Missing outputs have no invented zero-byte row. A missing selected asset must therefore be rejected by the consuming Go-embed obligation, while an unselected unknown asset does not enter the binary's composition. Diagnostic input paths remain those of the producer; importing an output does not relocate its original source files.

## Yarn 1 originals

`yarn-originals.cjs` provides the private callback for ordinary registry packages installed by Yarn 1.22.22. Supply the actual cache directory reported by the configured manager; no default path is assumed.

```js
const YarnOriginals = require('./yarn-originals.cjs');
const originals = new YarnOriginals({
  workdir: '/ui', lockPath: '/ui/yarn.lock',
  cacheDir: actualYarnCacheDirectory, outputRoot: emptyPrivateOriginalsDirectory
});
// Pass resource => originals.resolve(resource) as resolveOriginal.
// Call originals.close() after this compilation finishes, including on failure.
```

Create a new instance for every compilation. `close()` removes its extracted trees, but leaves the caller's output directory and Yarn cache in place. The resolver reads the prepared lockfile and cache metadata once, but extracts only distributions requested by selected units. It verifies the compressed `.yarn-tarball.tgz` against the strongest supported locked SRI token, extracts that same buffer into an independent read-only tree, and checks the archived package name/version. Cache directory names are never identities. Conflicting distributions for one installed name/version fail closed; an unused broken archive does not become a contributor or prevent unrelated compilation.

This path performs no network requests or installation scripts. It supports SHA-256/384/512 SRI for HTTP(S) registry archives, not a checksum synthesized from URL fragments. Missing archives are `no-data`; wrong archive bytes are `hash-mismatch`. Git/file locators, aliases, linked workspaces and archive link entries are not supported by this first adapter. In particular, a Yarn Git-cache commit string does not prove its archive: a separately verified Git/distribution binding is still required. Prepared or install-script-generated source files that differ from the distribution fail byte verification rather than being relabeled as original.

## Primary prepared-source inputs

A UI producer stage may request `"webpackSources": true` beside `subject` and `packages` in its private checked-stage declaration. After validating the scoped PM originals, DK writes `webpack-originals.json` beside the read-only `SBOM_BUILD_CONTEXT` file. This transient manifest contains the verified expected hashes and component identities for those physical source paths; it is not a second original archive, a durable receipt or a new public Context schema.

`new (require('./context-originals.cjs'))(process.env.SBOM_BUILD_CONTEXT)` provides an exact-path `resolve(resource)` callback. The collector compares the bytes it actually reads with that trusted original hash before accepting a contributor. Missing mappings fail closed; a changed source is `hash-mismatch`. A manifest dictionary entry alone contributes nothing. Compose managed-package resolution first:

```js
resolveOriginal: async resource =>
  (await yarnOriginals.resolve(resource)) ?? primaryOriginals.resolve(resource)
```

A Yarn error must propagate, not become a primary-project fallback. The stage's explicit PM subject and source distribution remain unchanged. This hash form only covers verified raw source inputs: loader-generated code still needs a supported transformation adapter.

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

This adapter is not automatically enabled by merely setting `SBOM_BUILD_CONTEXT`: the producing Webpack configuration must include the plugin and verified originals. Automatic manager-cache discovery and plugin deployment in the actual image graph, Git original acquisition, runtime/loader attribution, directory-copy patterns and complete Argo UI/prebundled-asset closure require additional integration. An opaque Redoc bundle is not accepted as a complete single-package composition.

## Tests

Run `npm ci --ignore-scripts --no-audit --no-fund` and `npm test` in this directory. The fixtures use real Webpack and CopyPlugin runs, locally packed npm distributions with verified SHA-512 integrity, and independent original trees. They do not represent upstream Argo packages.

For a retained single-build fixture, set `DK_WEBPACK_EVIDENCE` to an empty absolute directory and run `node fixture.cjs`. It retains the outputs, raw proof, input archives and hash manifest; the source root describes the actual retained output location. No generated binaries or dependency directories belong in Git.
