# Webpack asset evidence

This private producer adapter supports a bounded set of Webpack 5.94.0 compilation paths and observed file, directory and glob copies made by copy-webpack-plugin 6.1.1. It emits a source proof for the shared Go-embed validator; it is not an ELF record or a public SBOM sidecar.

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

For single-file chunks, the collector follows the final chunk graph, including concatenated inner modules. Selected units are checked against their physical original files and the source Webpack actually consumed. This accounts for selected contributor units, not individual surviving bytes after minification. Externals do not become embedded components. Copied files are bound to the actual CopyPlugin post-processing result by Buffer identity at emission, then checked against their verified original and final output bytes. Directory/glob selection is observed, not repeated; skipped and forced-overwritten copies are distinguished without choosing an owner from equal bytes. An optional explicit `copied` declaration is a cross-check, not a substitute for observation. CopyPlugin's eight pinned implementation files must themselves have verified originals available through the resolver, and its load must be recorded by the preload. Missing or altered instrumentation cannot fall back to the old static declaration.

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

## Observed runtime and bootstrap units

`node --require /path/to/runtime-preload.cjs …` records the CommonJS source and actual generator calls before Webpack loads. Without that observation, chunks requiring runtime/bootstrap evidence remain `no-data`. The adapter is limited to fingerprinted Webpack 5.94.0 implementations: three standard runtime classes and the main chunk renderer with its checked helper sources. Matching a version string alone does not make a fork supported.

The observer records real calls and their helper state, not a second execution of a generator. A prefilled generated-code cache, a replaced implementation, or changed helper state must not become evidence of stock Webpack generation. The collector binds the observed render to the bytes actually left on the output filesystem. These checks do not claim to secure the entire Node process against a hostile configuration controlling the producer itself.

Uncovered chunk renderers, additional text-producing plugin hooks and transformations between render and emission fail closed. Code splitting, library output plugins and minification therefore require further supported adapters; the initial runtime support is not complete Argo or Monaco coverage. Known generator/template units enter `inputs` as source contributions, while merely executing or formatting other units does not add the whole toolchain as composition.

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

This adapter is not automatically enabled by merely setting `SBOM_BUILD_CONTEXT`: the producing Webpack configuration must include the plugin and verified originals. Automatic tool deployment in the actual image graph, Git original acquisition, additional runtime/loader and copy-transform adapters, and complete Argo UI/prebundled-asset closure require further integration. An opaque Redoc bundle is not accepted as a complete single-package composition.

## Exact-config activation

The private `activate.cjs` preload appends the collector only to the named CommonJS Webpack configuration, without rewriting that file or its package scripts. The generated UI job supplies:

```sh
export DK_SBOM_WEBPACK_CONFIG=/ui/src/app/webpack.config.js
export DK_SBOM_WEBPACK_PROOF=/private-build-metadata/ui.json
export DK_SBOM_YARN_CACHE="$(/tools/yarn/node_modules/.bin/yarn --silent cache dir)"
export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--require /tools/sbom/activate.cjs"
/tools/yarn/node_modules/.bin/yarn build
```

The example paths describe the generated job's layout, not a discovered global installation. The job must make the pinned tool package available and request `webpackSources` in its compiler context. The producing stage and the consuming stage must agree on the proof path and output root. Existing `NODE_OPTIONS` flags remain in place.

Without `DK_SBOM_WEBPACK_CONFIG`, activation loads nothing. In active mode the Yarn parent and tool children inherit the process-local load recorder, but only loading the exact configured module attaches the collector. An unmatched configuration produces no proof; the downstream required Go-embed obligation refuses it. Multi-compiler configurations, watch mode and unsupported export shapes fail closed. Each compilation gets an independent Yarn originals resolver and owned temporary directory; normal completion and failures clean that directory.

Activation tests use real webpack-cli 4.9.2 and Node 22.20, preserving the original object/function config, CLI arguments and heap flags. They prove hook delivery and resolver execution, not complete composition of Argo assets.

## Tests

Run `npm ci --ignore-scripts --no-audit --no-fund` and `npm test` in this directory. The fixtures use real Webpack and CopyPlugin runs, locally packed npm distributions with verified SHA-512 integrity, and independent original trees. They do not represent upstream Argo packages.

For a retained single-build fixture, set `DK_WEBPACK_EVIDENCE` to an empty absolute directory and run `node fixture.cjs`. It retains the outputs, raw proof, input archives and hash manifest; the source root describes the actual retained output location. No generated binaries or dependency directories belong in Git.
