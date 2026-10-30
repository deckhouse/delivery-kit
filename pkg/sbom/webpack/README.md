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

This path performs no network requests or installation scripts. It supports the locked SHA-1/256/384/512 SRI for HTTP(S) registry archives, never a checksum synthesized from URL fragments. The manager's integrity string is retained verbatim; a stronger token, when present, cannot be bypassed using a matching weaker one. SHA-1 is collision-prone: a SHA-1-only lock retains that existing manager-pin trust limit. Computing SHA-256 over selected members of the same archive does not strengthen authentication of that archive, and the collector does not replace the lock's SHA-1 with a newly computed or registry-provided checksum. Missing archives are `no-data`; wrong archive bytes are `hash-mismatch`, malformed checksum spellings are `invalid`, and integrity using only unsupported algorithms is `unsupported`. Git/file locators, aliases, linked workspaces and archive link entries are not supported by this first adapter. In particular, a Yarn Git-cache commit string does not prove its archive: a separately verified Git/distribution binding is still required. Prepared or install-script-generated source files that differ from the distribution fail byte verification rather than being relabeled as original.

## Primary prepared-source inputs

A UI producer stage may request `"webpackSources": true` beside `subject` and `packages` in its private checked-stage declaration. After validating the scoped PM originals, DK writes `webpack-originals.json` beside the read-only `SBOM_BUILD_CONTEXT` file. This transient manifest contains the verified expected hashes and component identities for those physical source paths; it is not a second original archive, a durable receipt or a new public Context schema.

`new (require('./context-originals.cjs'))(process.env.SBOM_BUILD_CONTEXT)` provides an exact-path `resolve(resource)` callback. The collector compares the bytes it actually reads with that trusted original hash before accepting a contributor. Missing mappings fail closed; a changed source is `hash-mismatch`. A manifest dictionary entry alone contributes nothing. Compose managed-package resolution first:

```js
resolveOriginal: async resource =>
  (await yarnOriginals.resolve(resource)) ?? primaryOriginals.resolve(resource)
```

A Yarn error must propagate, not become a primary-project fallback. The stage's explicit PM subject and source distribution remain unchanged. This hash form only covers verified raw source inputs: loader-generated code still needs a supported transformation adapter.

## Observed runtime and bootstrap units

`node --require /path/to/runtime-preload.cjs …` records the CommonJS source and actual generator calls before Webpack loads. Without that observation, chunks requiring runtime/bootstrap evidence remain `no-data`. The adapter is limited to fingerprinted Webpack 5.94.0 implementations: four standard runtime classes (namespace/property helpers and the nonce unit) and the main chunk renderer with its checked helper sources. Matching a version string alone does not make a fork supported.

The observer records real calls and their helper state, not a second execution of a generator. A prefilled generated-code cache, a replaced implementation, or changed helper state must not become evidence of stock Webpack generation. The collector binds the observed render to the bytes actually left on the output filesystem. These checks do not claim to secure the entire Node process against a hostile configuration controlling the producer itself.

Uncovered chunk renderers, additional text-producing plugin hooks and transformations between render and emission fail closed. Code splitting and library output plugins therefore require further supported adapters; the initial runtime support is not complete Argo or Monaco coverage.

Minification by Webpack's default minimizer (terser-webpack-plugin 5.3.10 with terser 5.31.6, either no options or Webpack's own `compress.passes: 2` default) is observed rather than repeated. The adapter records each asset's minifier input and output from the actual `optimize` call; the rendered chunk must equal that input, and the final file on disk must equal that output. A minifier cache hit is accepted only when this process itself minified the same input to the same output. The plugin and terser files that workers execute are verified against their pinned originals. Terser rewrites selected units and contributes no component of its own. Custom minimizer options, another minimizer, asset changes before or after minification and persistent-cache hits from another process remain incomplete. The `.LICENSE.txt` file the default minimizer writes next to a bundle is described as well: its text must be the plugin's sorted, duplicate-free list of block or line comments, each present verbatim in the bytes that bundle was minified from, and it claims the same sources as its bundle. A comment spanning a blank line, or one whose line endings the minifier normalized, is not recognized and leaves the file incomplete.

Content-hashed file names (`[contenthash]`) are rewritten by Webpack's RealContentHashPlugin after minification. The collector snapshots every asset immediately before and after that stage, derives the old-to-new hash pairs from the assets' recorded content hashes and recomputes the substitution itself: each asset's new name and bytes must be exactly its previous name and bytes with those tokens replaced. A pure hash-token substitution contributes no code, so the rendered chunk's claim carries over to the renamed file. Any other change at that stage, a changed plugin source or a tapped `updateHash` makes the compilation incomplete. Non-runtime chunks of a code-split web build are described from Webpack's actual `renderChunk` call wrapped by its standard array-push chunk format: the module sources come from the compilation's own code generation results, and the format's wrapper text is a verified Webpack source unit. Foreign taps on render hooks leave the chunk incomplete. The runtime chunk describes the standard chunk-ensuring, script-loading and JSONP chunk-loading runtime modules when their customization hooks are untapped. Runtime modules that embed paths produced by `compilation.getPath` — the public path (including the default `auto`) and the chunk file name map — are described when every path they built came from this chunk's own output templates through Webpack's single standard path-template tap; their generated text is bound to the generation Webpack actually used, including the extra generation Webpack runs for hashing. A chunk that starts its own entry modules outside the runtime chunk (`optimization.runtimeChunk`) remains incomplete. Chunks of child compilations, such as the worker bundles Monaco's plugin builds, are described through the child's own render, minification and content-hash observations; the bytes the child handed over must equal what the parent emitted, and the worker's sources are inputs of the worker file only. Grandchild compilations and child assets the parent rewrites or renames remain incomplete.

Monaco's `monaco-editor-webpack-plugin` 7.1.0 rewrites `editor.api.js` and `editor.main.js` through its own pitching loader. The collector records the pitch call — its options and every request it turned into text — and rebuilds the generated glue from those recorded values: the `MonacoEnvironment` worker table must match the plugin's published template with only data in its slots, and the module source Webpack kept must equal the rebuilt text exactly. The loader and the plugin file that authors the template are the claimed units; the Monaco sources the glue imports stay ordinary modules. A second loader on those files, changed options after the build or a replaced pitch leave the modules incomplete. Webpack's AMD option and interop runtime modules (`amdO`, `n`, `nmd`) are described like the other runtime modules; a runtime module class Webpack does not export is accepted only when its generated text equals a rebuild from the verified helpers. Known generator/template units enter `inputs` as source contributions, while merely executing or formatting other units does not add the whole toolchain as composition.

## Observed stylesheet and esbuild loaders

`stylesheet-preload.cjs` composes the runtime recorder and observes actual calls to style-loader 1.3.0 and raw-loader 0.5.1. Exact-config activation loads this recorder automatically. The supported CSS path is the default, non-HMR `style-loader → raw-loader` chain or raw-loader alone. The pitched style module contributes its verified template source, not CSS it never read; the child contributes the actual verified CSS and raw-loader's wrapper source. The style injection runtime remains an ordinary verified module in the Webpack graph. Loader results must match the module source Webpack kept. Custom options, missing observations and additional loader chains remain incomplete.

SCSS through sass-loader 14.2.1 and sass 1.49.9 (default legacy API, no loader options) is described from what Sass actually consumed. The `[raw-loader, sass-loader]` module gets a per-module implementation wrapper that calls the real render once; while a render is in flight, file reads are recorded as they return. The entry contributes its verified source; every other file Sass reports as included must have been read in that render's window with bytes equal to its verified original. Unused partials are never claimed. The CSS Sass returned must be exactly what raw-loader received. Overlapping renders that read different bytes for one path, unknown reads, a replaced reader, custom importers/functions/implementations and cached modules without an observation remain incomplete. Sass is an instrument, not a component of the CSS. Overlapping-render windows are not yet exercised by a test.

The optional private `esbuild` collector option supports the instrumented esbuild 0.25.0 client/binary and esbuild-loader 4.3.0. It records the actual per-module transform without replacing the project's shared options. See [the pinned producer patch and tool-input contract](esbuild/README.md). A runtime contribution is accepted only when that transform selected the runtime source unit and the caller supplies its verified original distribution; absence of producer evidence is not an empty runtime contribution. Automatic deployment of these tool inputs is separate from the standalone collector option.

## Observed html

The `index.html` of html-webpack-plugin 5.6.0 is described from what the plugin really did, for a plugin configured with nothing but its `template`. The template file is read through the plugin's own lodash loader, compiled in a child compilation, evaluated, executed, filled with tags made from this compilation's own asset names and minified in a production build; each of those steps is observed where it happens and bound to the next by the value it handed on, down to the bytes of the emitted asset. Nothing is recompiled or minified a second time.

The html's sources are the verified template and the code that writes html text: the plugin's loader, tag writer and generating file, the lodash implementation whose compiled template the module carries, and the html-minifier-terser files when minification runs. The plugin's remaining pinned files, and the entity decoder the default options never enable, are verified instruments that contribute nothing. Since the html names content-hashed chunks, the collector follows it through the same real-content-hash substitution as a chunk asset before comparing it with the file on disk.

A tap or an interceptor on any of the plugin's six public hooks, a plugin object carrying members of its own, any option beyond the template, another loader on the template, foreign taps that could render or rewrite the template bundle in the child compilation, a cached child compilation and a second plugin instance all fail closed. The code generation of that child bundle is not re-verified: parser-level plugins such as DefinePlugin still reach the template module there.

## Ignored modules, banners and defined constants

A request a build resolves to `false` (for example `resolve.fallback`) becomes Webpack's ignored module whose whole text is the fixed comment `/* (ignored) */`; it is described as that one Webpack source and nothing else. `IgnorePlugin` creates no module at all. A `BannerPlugin` comment is rebuilt from the configured string and must be exactly what was prepended to each changed asset, between the chunk render and the minifier; templated, raw or filtered banners stay incomplete. `DefinePlugin` splices the text of its values into generated code, so a build is described only while every value is a JSON literal — data that references nothing — and every plugin that defines constants in each compilation, including child compilations and Webpack's own `process.env.NODE_ENV`, is accounted for; any other value leaves the whole compilation incomplete. `ProvidePlugin` only makes Webpack build the provided module, which is then described like any other module. A `require.context` module in its synchronous form is described as Webpack's own template around a map that may only name modules of the same chunk, each of which is described on its own; other context modes stay incomplete. External modules are described only where the configured request can appear solely as a string literal (`require("x")`) or as an identifier (the AMD, UMD, SystemJS and JSONP forms); external types that write the configured request into the chunk as an expression stay incomplete.

A UMD library bundle (`output.library` of type `umd` with one plain name, no `export`, `auxiliaryComment` or `umdNamedDefine`) is described by rebuilding Webpack's wrapper from the library name, the global object name and the externals' plain requests; the rendered chunk must start and end with exactly that text, and the externals stay references to modules nobody's code is claimed for. The trailing `//# sourceMappingURL=` line `devtool` appends is rebuilt from the map really emitted beside the asset. The `.map` files themselves are not described. A copied file that a described stage rewrites — typically a copied script the default minimizer minifies — is accepted when that stage's recorded input is exactly the verified source bytes and the file on disk is exactly the stage's output; prebuilt delivery and the opaque-script rule apply to the verified source bytes. Runtime-only chunks of a UMD build and other library types remain incomplete.

## Inline workers and CSS through css-loader

Workers built by `workerize-loader` with `?inline&fallback=false` (the Git commit Redoc locks) leave no file of their own: the worker bundle is written into the parent module as a string literal. The collector records the loader's pitch, rebuilds the parent module's text from the loader's verified template and the recorded slots, and requires the embedded literal to be exactly the bytes the worker compilation produced; the worker's own modules, runtime modules and render are then described in that child compilation and claimed by the parent asset. Other workerize options, a worker that keeps a fallback asset and option values that are not plain flags stay incomplete.

The style-loader 3.3.1 → css-loader 5.2.6 chain is described by rebuilding both generated modules from the loaders' templates and the requests they recorded; the CSS embedded by css-loader must be exactly the text it was handed — a verified stylesheet or the observed output of an esbuild CSS minifier ahead of it — and css-loader's and style-loader's runtime files are claimed as their packages' sources. A source map css-loader embeds is accepted as data, without a component, only as a strict source map v3 whose `sourcesContent` is exactly that text, whose sources use css-loader's own spellings and whose mappings stay within it. `url()`, `@import`, CSS modules and options other than the defaults stay incomplete.

## Prebuilt files proven by a rebuild

A file the build copies unchanged from a package — Redoc's `redoc.standalone.js` is the example — is a bundle of other packages, so its package identity says nothing about what it contains and it is normally incomplete. When the same build also rebuilds that package in a separate instrumented image, a stage can name the file and that image's proof (`prebuiltAssets` in its private build declaration, which needs `webpackSources` and must point at a stage image of the same configuration that collects a proof itself). DK reads the proof from the pinned image, accepts exactly one complete proof row for the file and delivers that row's composition in the private build context. The collector uses it only for a copied asset whose verified source bytes have exactly the digest of that rebuilt file and which was emitted unchanged; the composition is the rebuild's, not the package identity. The proof is trusted as the output of a producer stage of the same build; a different digest, an incomplete row or a missing proof leaves the file incomplete as before.

## npm-installed dependencies

Projects installed by npm (package-lock version 2 or 3) are resolved like Yarn ones, selectively: an installed package is identified by its directory under `node_modules`, its `package.json` must carry the name and version the lockfile states for that path, and its original is the archive npm's cache holds under the locked integrity, re-hashed before use and extracted into owned read-only scratch. A version 2 lockfile must state the same distribution in both of its trees; a duplicate member anywhere in the file refuses the whole lockfile. Bundled dependencies (their bytes come from the parent archive), npm aliases and links stay incomplete; a Git-locked dependency is described only through the verified Git manifest described below.

## Git-pinned dependencies

A Yarn dependency locked to a Git commit (`git+https://host/owner/repo.git#<40 hex>`, no integrity) is described only through a Git checkout DK made itself: an ordinary `git:` mapping of that repository at that commit in the same image, named for the dependency by the stage's private build declaration (`gitSources`, which requires `webpackSources`). DK walks the commit, its trees and blobs by hash from the commit id and recomputes every object's Git hash; it requires the root `package.json` to carry the locked name and version, and lists an installed file only when its bytes are exactly the blob at the same path. Symlinks, submodules, files the tree does not hold and files install scripts produced stay incomplete; the lifecycle scripts the package declares are recorded. The collector then claims the file as a `node` component whose locator is the lock entry verbatim and whose checksum is `git-commit:sha1:<commit>`; without that private manifest, or with another commit, the file stays incomplete. Yarn's own cache is never trusted for these dependencies. The project being built can be described the same way (`gitSources` of kind `project`): a remote `git:` mapping pinned to a commit that adds the whole repository where it is installed, its identity taken from the root `package.json` of that commit and its locator spelled from the configured URL; files under any `node_modules` of the tree are left to the lockfile that installed them. A local checkout is not accepted as a verified source: it pins no commit and its origin is unverified.

The repository a Git-pinned dependency names is compared by identity, not by spelling: the locator and the `git:` mapping's remote are both reduced to `host/owner/repo`, so the same repository reached over `https`, `http`, `ssh`, the `git` protocol or the scp-like `git@host:owner/repo.git` form is recognized as the same repository, with user info, a default port and one trailing `.git` dropped and the host lower-cased. Another owner (a fork), another repository name, another host, a non-default port or a redirect is a different repository and is refused. The commit is compared exactly; a branch, a tag or an abbreviated commit is never accepted as a pin. Git object hashes are SHA-1, the same trust a lock pin to that commit already carries.

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

Activation installs the stylesheet recorder before the configuration loads its modules. Activation tests use real webpack-cli 4.9.2 and Node 22.20, preserving the original object/function config, CLI arguments and heap flags. They prove hook delivery and resolver execution, not complete composition of Argo assets.

## Tests

Run `npm ci --ignore-scripts --no-audit --no-fund` and `npm test` in this directory. The fixtures use real Webpack and CopyPlugin runs, locally packed npm distributions with verified SHA-512 integrity, and independent original trees. They do not represent upstream Argo packages. Esbuild-specific cases require an explicit `DK_ESBUILD_SOURCE` pointing at the patched and built source tree; without it they are reported as skipped, not validated. Those cases also exercise the test-only prepared PM source image helper under `testdata/`.

For a retained single-build fixture, set `DK_WEBPACK_EVIDENCE` to an empty absolute directory and run `node fixture.cjs`. It retains the outputs, raw proof, input archives and hash manifest; the source root describes the actual retained output location. No generated binaries or dependency directories belong in Git.
