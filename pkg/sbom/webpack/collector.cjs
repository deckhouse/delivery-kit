'use strict';

// Webpack asset composition collector: emits the dk sbom source proof for the
// assets a pinned webpack build actually emitted.
//
// Trust boundary: `originals` are distribution bindings supplied by the caller,
// who is responsible for having verified the distribution identity (registry
// archive digest, signature, SRI) before materializing it. This collector only
// re-reads the materialized bytes and their read-only original counterpart and
// refuses anything it cannot bind that way; it does not acquire or verify the
// archive itself, so the transport/integrity seam upstream of `originalRoot`
// stays uncovered here.

const crypto = require('crypto');
const fs = require('fs');
const { runtimeEvidence } = require('./runtime-evidence.cjs');
const { installCopyEvidence } = require('./copy-evidence.cjs');
const { installEsbuildEvidence } = require('./esbuild-evidence.cjs');
const { installStylesheetEvidence } = require('./stylesheet-evidence.cjs');
const { installIncludeEvidence, isIncludeLoader } = require('./include-evidence.cjs');
const { voidEvidence, isVoidModule } = require('./void-evidence.cjs');
const { installDefineEvidence, defineProblem } = require('./define-evidence.cjs');
const { installTerserEvidence } = require('./terser-evidence.cjs');
const { installContentHashEvidence } = require('./content-hash-evidence.cjs');
const { installBannerEvidence } = require('./banner-evidence.cjs');
const { installSourcemapEvidence } = require('./sourcemap-evidence.cjs');
const { umdEvidence } = require('./umd-evidence.cjs');
const { installHtmlEvidence } = require('./html-evidence.cjs');
const { assetEvidence, observeAssets } = require('./bootstrap-evidence.cjs');
const { childEvidence } = require('./child-evidence.cjs');
const path = require('path');

const PLUGIN = 'DkSbomWebpackCollector';
// What the default extracted-comments filename of the minifier appends.
const COMMENTS_SUFFIX = '.LICENSE.txt';
const PROOF_VERSION = 1;
const SUPPORTED_WEBPACK = '5.94.0';
const COPY_PLUGIN = 'CopyPlugin';
const GLOB_CHARACTERS = /[*?[\]{}!]/;
const TEMPLATE_TARGET = /\[(ext|name|path|folder|emoji(:\d+)?|(([^:\]]+):)?(hash|contenthash)(:[a-z]+\d*)?(:\d+)?|\d+)\]/;
const SOURCE_KINDS = ['declared', 'pm', 'go', 'python', 'node'];

// A copied bundle carries a composition this collector cannot observe, and
// nothing in the options supplies one for it.
const OPAQUE_COPIED_EXTENSIONS = ['.js', '.cjs', '.mjs', '.wasm', '.node'];

class DkSbomWebpackCollector {
	constructor(options) {
		this.options = normalizeOptions(options);
	}

	apply(compiler) {
		const version = compiler.webpack && compiler.webpack.version;
		if (version !== SUPPORTED_WEBPACK) {
			throw new Error(`${PLUGIN}: unsupported webpack ${version || 'unknown'}, expected ${SUPPORTED_WEBPACK}`);
		}
		checkProofOutsideOutput(this.options.proofPath, compiler.options.output && compiler.options.output.path);
		// The emitted bytes have to be taken before the compiler replaces every
		// asset source with a size-only one.
		observeAssets(compiler);
		// Bound against the copy plugin instances this compiler really runs, so a
		// declaration can never stand in for a copy operation that is not configured.
		const options = { ...this.options, copied: bindCopied(this.options.copied, compiler) };
		options.copyEvidence = installCopyEvidence(compiler, resource => verifyResource(options, resource));
		if (options.esbuild) options.esbuildEvidence = installEsbuildEvidence(compiler, options.esbuild, resource => verifyResource(options, resource));
		options.stylesheetEvidence = installStylesheetEvidence(compiler, resource => verifyResource(options, resource));
		options.includeEvidence = installIncludeEvidence(compiler, resource => verifyResource(options, resource));
		options.minifierEvidence = installTerserEvidence(compiler, resource => verifyResource(options, resource));
		options.licenseEvidence = options.minifierEvidence.license;
		options.contentHashEvidence = installContentHashEvidence(compiler, resource => verifyResource(options, resource));
		options.bannerEvidence = installBannerEvidence(compiler, resource => verifyResource(options, resource));
		options.sourcemapEvidence = installSourcemapEvidence(compiler, resource => verifyResource(options, resource));
		options.umdEvidence = (compilation, chunk) => umdEvidence(compilation, chunk, resource => verifyResource(options, resource));
		options.compiler = compiler;
		options.definePlugins = installDefineEvidence(compiler);
		options.htmlEvidence = installHtmlEvidence(compiler, resource => verifyResource(options, resource));
		compiler.hooks.afterEmit.tapAsync(PLUGIN, (compilation, callback) => {
			buildProof(options, compilation)
				.then(async proof => {
					await readEmittedAssets(compilation, proof.assets);
					writeProof(this.options.proofPath, proof);
				})
				.then(() => callback(), callback);
		});
	}
}

function normalizeOptions(options) {
	if (!isPlainObject(options)) throw new Error(`${PLUGIN}: options object is required`);
	checkKeys(options, ['proofPath', 'originals', 'copied', 'resolveOriginal', 'esbuild'], 'options');
	if (options.resolveOriginal !== undefined && typeof options.resolveOriginal !== 'function') throw new Error(`${PLUGIN}: resolveOriginal must be a function`);
	const proofPath = requireAbsolutePath(options.proofPath, 'options.proofPath');
	return {
		proofPath,
		originals: normalizeOriginals(options.originals, typeof options.resolveOriginal === 'function'),
		copied: normalizeCopied(options.copied),
		resolveOriginal: options.resolveOriginal,
		esbuild: options.esbuild,
	};
}

function normalizeOriginals(originals, allowEmpty = false) {
	if (!Array.isArray(originals) || (!allowEmpty && originals.length === 0)) {
		throw new Error(`${PLUGIN}: options.originals must be a non-empty array`);
	}
	const bindings = [];
	const byComponentID = new Map();
	for (const [index, entry] of originals.entries()) {
		const where = `options.originals[${index}]`;
		if (!isPlainObject(entry)) throw new Error(`${PLUGIN}: ${where} must be an object`);
		checkKeys(entry, ['root', 'originalRoot', 'component'], where);
		const root = requireDirectory(entry.root, `${where}.root`);
		const originalRoot = requireDirectory(entry.originalRoot, `${where}.originalRoot`);
		if (contains(root, originalRoot) || contains(originalRoot, root)) {
			throw new Error(`${PLUGIN}: ${where} root and originalRoot overlap`);
		}
		const component = checkComponent(entry.component, `${where}.component`);
		const previous = byComponentID.get(component.id);
		if (previous && !sameJSON(previous, component)) {
			throw new Error(`${PLUGIN}: conflicting identities for component ${component.id}`);
		}
		byComponentID.set(component.id, component);
		for (const other of bindings) {
			if (contains(other.root, root) || contains(root, other.root)) {
				throw new Error(`${PLUGIN}: ${where}.root overlaps ${other.root}`);
			}
			// A root overlapping another entry's original could rewrite the very
			// bytes that entry is verified against; sharing one original root is fine.
			if (other.originalRoot !== originalRoot && (contains(other.originalRoot, root) || contains(root, other.originalRoot))) {
				throw new Error(`${PLUGIN}: ${where}.root overlaps the original root ${other.originalRoot}`);
			}
			if (other.originalRoot !== originalRoot && (contains(originalRoot, other.root) || contains(other.root, originalRoot))) {
				throw new Error(`${PLUGIN}: ${where}.originalRoot overlaps the root ${other.root}`);
			}
		}
		bindings.push({ root, originalRoot, component });
	}
	return bindings;
}

function normalizeCopied(copied) {
	if (copied === undefined) return new Map();
	if (!Array.isArray(copied)) throw new Error(`${PLUGIN}: options.copied must be an array`);
	const byTarget = new Map();
	for (const [index, entry] of copied.entries()) {
		const where = `options.copied[${index}]`;
		if (!isPlainObject(entry)) throw new Error(`${PLUGIN}: ${where} must be an object`);
		checkKeys(entry, ['from', 'to'], where);
		const from = requireAbsolutePath(entry.from, `${where}.from`);
		const to = requireCleanRelativePath(entry.to, `${where}.to`);
		const origins = byTarget.get(to) || new Set();
		origins.add(from);
		byTarget.set(to, origins);
	}
	return byTarget;
}

function checkComponent(component, where) {
	if (!isPlainObject(component)) throw new Error(`${PLUGIN}: ${where} must be an object`);
	checkKeys(component, ['id', 'name', 'version', 'source'], where);
	for (const field of ['id', 'name', 'version']) {
		requireNonEmptyString(component[field], `${where}.${field}`);
	}
	const source = component.source;
	if (!isPlainObject(source)) throw new Error(`${PLUGIN}: ${where}.source must be an object`);
	checkKeys(source, ['kind', 'locator', 'checksum'], `${where}.source`);
	requireNonEmptyString(source.locator, `${where}.source.locator`);
	if (!SOURCE_KINDS.includes(source.kind)) {
		throw new Error(`${PLUGIN}: ${where}.source.kind must be one of ${SOURCE_KINDS.join(', ')}`);
	}
	if (source.kind === 'declared') {
		if (source.checksum !== undefined) throw new Error(`${PLUGIN}: ${where}.source.checksum is not allowed for a declared source`);
	} else {
		requireNonEmptyString(source.checksum, `${where}.source.checksum`);
	}
	return component;
}

// Each declared mapping must correspond to a plain single-file pattern of an
// actual copy plugin instance of this compiler; a declaration is never allowed
// to stand in for the configuration.
function bindCopied(declared, compiler) {
	const configured = [];
	for (const plugin of compiler.options.plugins || []) {
		if (!plugin || !plugin.constructor || plugin.constructor.name !== COPY_PLUGIN || !Array.isArray(plugin.patterns)) continue;
		for (const pattern of plugin.patterns) configured.push(resolvePattern(pattern, compiler));
	}
	const bound = new Map();
	for (const [to, origins] of declared) {
		if (origins.size > 1) {
			bound.set(to, { failure: failure('invalid', `copied asset has conflicting declared origins: ${[...origins].sort().join(', ')}`) });
			continue;
		}
		const from = [...origins][0];
		const matching = configured.filter((pattern) => pattern.to === to);
		const unsupported = matching.find((pattern) => pattern.unsupported);
		if (matching.length === 0) {
			bound.set(to, { failure: failure('invalid', `declared copy of ${to} matches no configured copy pattern`) });
		} else if (unsupported) {
			bound.set(to, { failure: failure('invalid', `configured copy pattern for ${to} is ${unsupported.unsupported}`) });
		} else if (matching.length > 1 || matching[0].from !== from) {
			bound.set(to, { failure: failure('invalid', `declared origin of ${to} is not the configured ${matching.map((pattern) => pattern.from).sort().join(', ')}`) });
		} else {
			bound.set(to, { from });
		}
	}
	return bound;
}

// Mirrors copy-webpack-plugin 6.1.1 preProcessPattern: a relative pattern
// context joins the compiler context, and a target without an extension or with
// a template placeholder is a directory or template copy, not a plain file one.
function resolvePattern(pattern, compiler) {
	if (!isPlainObject(pattern) || typeof pattern.from !== 'string') return { to: null, unsupported: 'not a plain object pattern' };
	if (typeof pattern.to !== 'string') return { to: null, unsupported: 'without a literal target' };
	const to = path.normalize(pattern.to);
	if (pattern.toType !== undefined && pattern.toType !== 'file') return { to, unsupported: `a ${pattern.toType} target` };
	if (TEMPLATE_TARGET.test(to)) return { to, unsupported: 'a templated target' };
	if (path.extname(to) === '' || to.endsWith(path.sep)) return { to, unsupported: 'a directory target' };
	if (GLOB_CHARACTERS.test(pattern.from)) return { to, unsupported: 'a glob source' };
	const context = compiler.options.context || '';
	const patternContext =
		typeof pattern.context === 'string' ? (path.isAbsolute(pattern.context) ? pattern.context : path.join(context, pattern.context)) : context;
	const from = path.isAbsolute(pattern.from) ? path.normalize(pattern.from) : path.resolve(patternContext, pattern.from);
	let stat;
	try {
		stat = fs.statSync(from);
	} catch {
		return { to, unsupported: `an unreadable source ${from}` };
	}
	if (!stat.isFile()) return { to, unsupported: `a directory source ${from}` };
	return { to, from };
}

async function buildProof(options, compilation) {
	const sourceRoot = requireDirectory(compilation.outputOptions.path, 'compilation output path');
	checkProofOutsideOutput(options.proofPath, sourceRoot);
	const chunkUnits = await collectChunkAssets(options, compilation);
	const assets = [];
	for (const asset of compilation.getAssets()) {
		if (asset.name.includes('?') || asset.name.includes('#')) {
			throw new Error(`${PLUGIN}: unsupported asset name carrying a query or fragment: ${asset.name}`);
		}
		const assetPath = requireCleanRelativePath(asset.name, `emitted asset ${asset.name}`);
		assets.push(await describeAsset(options, assetPath, asset, chunkUnits, compilation));
	}
	assets.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
	return { version: PROOF_VERSION, sourceRoot, assets };
}

// Only final chunks of this compilation and the asset names they really emitted;
// modules reachable only through the build graph are not part of any output.
//
// A compilation this one made - the one a worker entry point is compiled in -
// hands its finished assets over to be emitted here, so its chunks account for
// assets of this compilation as well.
async function collectChunkAssets(options, compilation) {
	const byAsset = new Map();
	await collectChunksInto(options, compilation, compilation, byAsset);
	for (const child of Array.isArray(compilation.children) ? compilation.children : []) {
		try {
			// A compilation whose files this one does not emit - the one a template
			// is compiled in, whose result its plugin keeps to itself - accounts for
			// no asset here.
			if (!emitsHere(child, compilation)) continue;
			await collectChunksInto(options, child, compilation, byAsset);
		} catch (error) {
			// Anything may stand on that list; what it cost to look is a reason for
			// the assets it claims, not a failed build.
			refuseClaims(child, compilation, byAsset, error);
		}
	}
	return byAsset;
}

function emitsHere(child, compilation) {
	for (const chunk of child.chunks) {
		for (const file of chunk.files) {
			if (compilation.getAsset(file)) return true;
		}
	}
	return false;
}

function refuseClaims(child, compilation, byAsset, error) {
	const reason = `${madeBy(child)} could not be described: ${reasonOf(error)}`;
	for (const chunk of chunksOf(child)) {
		for (const file of chunk && chunk.files ? chunk.files : []) {
			if (!compilation.getAsset(file)) continue;
			const target = byAsset.get(file) || { units: new Map(), failures: new Map(), compilation };
			addFailure(target, failure('no-data', reason));
			byAsset.set(file, target);
		}
	}
}

function definedProblem(options, compilation) {
	if (!options.compiler) return Promise.resolve(null);
	if (!options.defined) options.defined = new WeakMap();
	if (!options.defined.has(compilation)) {
		options.defined.set(compilation, defineProblem(options.compiler, options.definePlugins, resource => verifyResource(options, resource), compilation));
	}
	return options.defined.get(compilation);
}

// Which compilation a reason is about, said the one way everywhere.
function madeBy(child) {
	return child && child.name ? `the compilation of ${child.name}` : 'a compilation this one made';
}

function reasonOf(error) {
	return (error && error.message) || String(error);
}

function chunksOf(child) {
	try {
		return child && child.chunks ? [...child.chunks] : [];
	} catch {
		return [];
	}
}

async function collectChunksInto(options, source, compilation, byAsset) {
	// What the constants of this build are spliced into the modules as, decided
	// for the compilation that built them: a compiler this one makes may have
	// been given definers of its own after it was made.
	const defined = await definedProblem(options, source);
	for (const chunk of source.chunks) {
		const collected = { units: new Map(), failures: new Map(), compilation: source };
		// One chunk emitting several files would need per-file attribution of its
		// modules, which this version does not do.
		if (chunk.files.size !== 1) {
			addFailure(collected, failure('no-data', `chunk ${chunk.name || chunk.id} emits ${chunk.files.size} files`));
		}
		const evidence = {
			banner: options.bannerEvidence,
			minifier: options.minifierEvidence,
			sourcemap: options.sourcemapEvidence,
			contentHash: options.contentHashEvidence,
			umd: options.umdEvidence,
		};
		if (defined) addFailure(collected, defined);
		try {
			for (const module of source.chunkGraph.getChunkModulesIterable(chunk)) {
				await collectModule(options, module, collected, source, chunk);
			}
			// Every chunk must account for generated wrapper/bootstrap code; an
			// undescribed renderChunk path remains no-data rather than ordinary
			// source.
			const bootstrap =
				source === compilation
					? await assetEvidence(compilation, chunk, resource => verifyResource(options, resource), evidence)
					: await childEvidence(compilation, chunk, source, resource => verifyResource(options, resource), evidence);
			if (bootstrap.failure) addFailure(collected, bootstrap.failure);
			for (const unit of bootstrap.units) collected.units.set(unit.path, unit);
			if (bootstrap.requiredBytes) collected.requiredBytes = bootstrap.requiredBytes;
		} catch (error) {
			// A compilation this one did not make can be in any state at all; what
			// it cost to look is a reason, not a failed build.
			if (source === compilation) throw error;
			addFailure(collected, failure('no-data', `chunk ${chunk.name || chunk.id} could not be described: ${reasonOf(error)}`));
		}
		// Which compilation a reason is about: a build has several, and the names
		// of their chunks and assets say nothing about which one they belong to.
		if (source !== compilation) {
			const made = madeBy(source);
			const named = new Map();
			for (const item of collected.failures.values()) named.set(`${made}: ${item.reason}`, failure(item.status, `${made}: ${item.reason}`));
			collected.failures = named;
		}
		for (const file of chunk.files) {
			const target = byAsset.get(file) || { units: new Map(), failures: new Map(), compilation: source };
			for (const [key, unit] of collected.units) target.units.set(key, unit);
			for (const [reason, failure] of collected.failures) target.failures.set(reason, failure);
			// The bytes the described render produced: whatever is on disk at the end
			// has to be exactly these, no matter what ran after the emit.
			if (collected.requiredBytes) {
				if (target.requiredBytes && !target.requiredBytes.equals(collected.requiredBytes)) {
					addFailure(target, failure('invalid', `asset ${file} is described by two different renders`));
				} else {
					target.requiredBytes = collected.requiredBytes;
				}
			}
			byAsset.set(file, target);
		}
	}
}

async function collectModule(options, module, collected, compilation, chunk) {
	if (module.type === 'runtime') {
		const result = await runtimeEvidence(compilation, chunk, module, resource => verifyResource(options, resource));
		if (result.failure) addFailure(collected, result.failure);
		for (const unit of result.units) collected.units.set(unit.path, unit);
		return;
	}
	// A ConcatenatedModule is a scope-hoisting wrapper: its inner modules are the
	// units that really ended up in the chunk.
	if (module.constructor && module.constructor.name === 'ConcatenatedModule' && Array.isArray(module.modules) && module.rootModule) {
		for (const inner of module.modules) await collectModule(options, inner, collected, compilation, chunk);
		return;
	}
	// An external is referenced, not bundled, so it contributes no input here.
	if (typeof module.externalType === 'string') return;
	// A module webpack built for a request it was told to drop reads no file.
	if (isVoidModule(module)) {
		const result = await voidEvidence(compilation, chunk, module, resource => verifyResource(options, resource));
		if (result.failure) addFailure(collected, result.failure);
		for (const unit of result.units) collected.units.set(unit.path, unit);
		return;
	}
	// A loader rewrites the module before webpack consumes it, so the file on disk
	// is no longer the unit that was bundled.
	if (Array.isArray(module.loaders) && module.loaders.length > 0) {
		let describe;
		if (options.esbuildEvidence && module.loaders.length === 1 && module.loaders[0].loader === options.esbuild.loader) describe = options.esbuildEvidence;
		else if (module.loaders.some(item => typeof item.loader === 'string' && /(?:^|[/\\])(?:style-loader|raw-loader)[/\\]/.test(item.loader))) describe = options.stylesheetEvidence;
		else if (module.loaders.length === 1 && isIncludeLoader(module.loaders[0].loader)) describe = options.includeEvidence;
		if (describe) {
			const transformed = await describe(module);
			if (transformed.failure) addFailure(collected, transformed.failure);
			for (const unit of transformed.units) collected.units.set(unit.path, unit);
		} else {
			addFailure(collected, failure('no-data', `loader-transformed module: ${module.identifier()}`));
		}
		return;
	}
	const resource = typeof module.resource === 'string' ? module.resource : '';
	if (resource === '' || resource.includes('?') || resource.includes('!')) {
		addFailure(collected, failure('no-data', `module without a physical source: ${module.identifier()}`));
		return;
	}
	const resolved = await verifyResource(options, resource);
	if (resolved.failure) {
		addFailure(collected, resolved.failure);
		return;
	}
	// The bytes webpack consumed, not just the bytes on disk: the input file system
	// can serve something else entirely.
	const consumed = typeof module.originalSource === 'function' ? module.originalSource() : null;
	if (!consumed || typeof consumed.buffer !== 'function') {
		addFailure(collected, failure('no-data', `consumed module source is unavailable: ${module.identifier()}`));
		return;
	}
	if (!Buffer.from(consumed.buffer()).equals(resolved.unit.bytes)) {
		addFailure(collected, failure('hash-mismatch', `consumed module source differs from its file: ${resource}`));
		return;
	}
	collected.units.set(resolved.unit.path, resolved.unit);
}

// Binds one materialized file to its read-only original counterpart and to the
// component the caller declared for that distribution root.
async function verifyResource(options, resource) {
	const actual = path.resolve(resource);
	let binding;
	if (options.resolveOriginal) {
		try {
			const resolved = await options.resolveOriginal(actual);
			if (resolved !== undefined) {
				if (resolved && Object.hasOwn(resolved, 'sha256')) {
					if (Object.keys(resolved).some(key => !['path', 'sha256', 'component'].includes(key)) || resolved.path !== actual || !/^sha256:[0-9a-f]{64}$/.test(resolved.sha256) || !isPlainObject(resolved.component) || typeof resolved.component.id !== 'string' || !resolved.component.id) return {failure: failure('invalid', `invalid expected-original binding for ${actual}`)};
					try { checkComponent(resolved.component, 'resolveOriginal().component'); }
					catch (error) { return {failure: failure('invalid', error.message)}; }
					const observed = readRegularFile(actual);
					if (observed.failure) return observed;
					if (digest(observed.bytes) !== resolved.sha256) return {failure: failure('hash-mismatch', `source differs from its verified original hash: ${actual}`)};
					return {unit: {path: actual, sha256: resolved.sha256, bytes: observed.bytes, component: resolved.component}};
				}
				binding = normalizeOriginals([resolved])[0];
				if (!contains(binding.root, actual)) return { failure: failure('invalid', `resolved original root does not cover ${actual}`) };
				for (const declared of options.originals) {
					if (contains(declared.root, binding.originalRoot) || contains(binding.originalRoot, declared.root) || contains(declared.originalRoot, binding.root) || contains(binding.root, declared.originalRoot)) {
						return { failure: failure('invalid', `resolved original overlaps a materialized root: ${actual}`) };
					}
				}
			}
		} catch (error) {
			if (!FAILURE_STATUSES.includes(error.status)) throw error;
			return { failure: failure(error.status, error.message) };
		}
	}
	if (!binding) binding = options.originals.find((candidate) => contains(candidate.root, actual));
	if (!binding) return { failure: failure('no-data', `resource outside the declared roots: ${actual}`) };
	const relative = path.relative(binding.root, actual);
	const original = path.join(binding.originalRoot, relative);
	if (!contains(binding.originalRoot, original)) {
		return { failure: failure('invalid', `original counterpart outside ${binding.originalRoot}: ${relative}`) };
	}
	const actualBytes = readRegularFile(actual);
	if (actualBytes.failure) return actualBytes;
	const originalBytes = readRegularFile(original);
	if (originalBytes.failure) return originalBytes;
	const sha256 = digest(actualBytes.bytes);
	if (sha256 !== digest(originalBytes.bytes)) {
		return { failure: failure('hash-mismatch', `materialized source differs from its original: ${actual}`) };
	}
	return { unit: { path: actual, sha256, bytes: actualBytes.bytes, component: binding.component } };
}

function readRegularFile(file) {
	let stat;
	try {
		stat = fs.lstatSync(file);
	} catch (error) {
		if (error.code === 'ENOENT' || error.code === 'ENOTDIR') {
			return { failure: failure('no-data', `missing file ${file}`) };
		}
		return { failure: failure('invalid', `unreadable file ${file}: ${error.code || error.message}`) };
	}
	// Anything but a plain file, and any symlinked ancestor, could let the bytes
	// leave the root they were bound to.
	if (!stat.isFile()) return { failure: failure('invalid', `not a regular file: ${file}`) };
	if (fs.realpathSync(file) !== file) return { failure: failure('invalid', `symlinked path: ${file}`) };
	return { bytes: fs.readFileSync(file) };
}

function describeAsset(options, assetPath, asset, chunkUnits, compilation) {
	const chunkCollected = chunkUnits.get(assetPath);
	const copied = asset.info && asset.info.copied === true;
	if (copied && chunkCollected) {
		return incomplete(assetPath, failure('invalid', `asset is both copied and emitted by a chunk`));
	}
	if (copied) return describeCopiedAsset(options, assetPath, compilation);
	if (!chunkCollected && asset.info && asset.info.extractedComments === true) {
		return describeExtractedComments(options, assetPath, compilation, chunkUnits);
	}
	// A source map is an asset of no chunk, and the adapter that watched it
	// written says in its own words why it is not described.
	if (!chunkCollected && asset.info && asset.info.development === true) {
		return describeSourceMap(options, assetPath, compilation);
	}
	if (!chunkCollected) return describeEmittedAsset(options, assetPath, compilation);
	if (chunkCollected.failures.size > 0) return incomplete(assetPath, worst([...chunkCollected.failures.values()]));
	if (chunkCollected.units.size === 0) return incomplete(assetPath, failure('no-data', `no verified source unit`));
	return present(assetPath, [...chunkCollected.units.values()], chunkCollected.requiredBytes);
}

// The comments a described minification took out of one asset and wrote to a
// file of their own. They are no code of their own: the file is claimed with
// the sources of the asset its comments came from, which is the asset named by
// the one filename the minifier writes - this one, without its suffix.
async function describeExtractedComments(options, assetPath, compilation, chunkUnits) {
	if (!assetPath.endsWith(COMMENTS_SUFFIX)) return incomplete(assetPath, failure('no-data', `${assetPath} is not the comments file of an asset of this compilation`));
	const ownerPath = assetPath.slice(0, -COMMENTS_SUFFIX.length);
	const collected = chunkUnits.get(ownerPath);
	// The minification that wrote these comments ran in the compilation the
	// asset they came from was built in, which is where they were recorded; a
	// file named after no asset of this build was written by nobody here.
	const source = (collected && collected.compilation) || compilation;
	const hashed = await options.contentHashEvidence(source, assetPath);
	if (hashed.failure) return incomplete(assetPath, hashed.failure);
	const name = hashed.name || assetPath;
	const observed = await options.licenseEvidence(source, name);
	if (observed.failure) return incomplete(assetPath, observed.failure);
	if (!observed.bytes) return incomplete(assetPath, failure('no-data', `no described minification wrote ${assetPath}`));
	if (!collected) return incomplete(assetPath, failure('no-data', `${ownerPath} belongs to no chunk of this compilation`));
	const hashedOwner = await options.contentHashEvidence(source, ownerPath);
	if (hashedOwner.failure) return incomplete(assetPath, hashedOwner.failure);
	const owner = hashedOwner.name || ownerPath;
	if (observed.owner !== owner || `${owner}${COMMENTS_SUFFIX}` !== name) {
		return incomplete(assetPath, failure('no-data', `${assetPath} holds the comments of ${observed.owner}, which is not the asset it is named after`));
	}
	if (collected.failures.size > 0) return incomplete(assetPath, worst([...collected.failures.values()]));
	if (collected.units.size === 0) return incomplete(assetPath, failure('no-data', `no verified source unit`));
	let produced = observed.bytes;
	if (hashed.input) {
		if (!hashed.input.equals(produced)) return incomplete(assetPath, failure('no-data', `${assetPath} was changed before its content hash was replaced`));
		produced = hashed.output;
	}
	return present(assetPath, [...collected.units.values()], produced);
}

// An asset no chunk emitted and no copy produced: the html a described plugin
// wrote, followed through the one stage that may still rewrite it - the html
// carries the content-hashed names of the chunks it loads, so the same
// substitution that renames them rewrites this file too.
async function describeEmittedAsset(options, assetPath, compilation) {
	const html = await options.htmlEvidence(compilation, assetPath);
	if (html.failure) return incomplete(assetPath, html.failure);
	if (!html.units) return incomplete(assetPath, failure('no-data', `asset belongs to no chunk of this compilation`));
	// Content-hash evidence lists every asset that existed before the stage,
	// unchanged ones included, so the html is always paired when it ran.
	const hashed = await options.contentHashEvidence(compilation, assetPath);
	if (hashed.failure) return incomplete(assetPath, hashed.failure);
	let produced = html.requiredBytes;
	if (hashed.input) {
		if (!hashed.input.equals(produced)) return incomplete(assetPath, failure('no-data', `${assetPath} was changed before its content hash was replaced`));
		produced = hashed.output;
	}
	return present(assetPath, html.units, produced);
}

async function describeSourceMap(options, assetPath, compilation) {
	const described = await options.sourcemapEvidence(compilation, assetPath);
	if (described.failure) return incomplete(assetPath, described.failure);
	return incomplete(assetPath, failure('no-data', `${assetPath} is not an asset this compilation wrote a source map for`));
}

async function describeCopiedAsset(options, assetPath, compilation) {
	const observed = options.copyEvidence(compilation, assetPath);
	if (observed.failure) return incomplete(assetPath, observed.failure);
	const binding = options.copied.get(assetPath);
	if (binding?.failure) return incomplete(assetPath, binding.failure);
	if (binding && binding.from !== observed.from) return incomplete(assetPath, failure('invalid', `declared copy origin disagrees with the observed source of ${assetPath}`));
	const from = observed.from;
	const extension = path.extname(assetPath).toLowerCase();
	const fromExtension = path.extname(from).toLowerCase();
	if (OPAQUE_COPIED_EXTENSIONS.includes(extension) || OPAQUE_COPIED_EXTENSIONS.includes(fromExtension)) {
		return incomplete(assetPath, failure('no-data', `copied ${fromExtension || extension} carries an unsupplied nested composition`));
	}
	const resolved = await verifyResource(options, from);
	if (resolved.failure) return incomplete(assetPath, resolved.failure);
	return present(assetPath, [resolved.unit], resolved.unit.bytes);
}

// The statuses this collector may report, worst first: an unsafe or conflicting
// claim outranks a known byte mismatch, which outranks absent evidence.
const FAILURE_STATUSES = ['invalid', 'hash-mismatch', 'unsupported', 'no-data'];

function failure(status, reason) {
	return { status, reason };
}

function addFailure(collected, entry) {
	collected.failures.set(entry.reason, entry);
}

function worst(failures) {
	const status = FAILURE_STATUSES.find((candidate) => failures.some((entry) => entry.status === candidate));
	const reasons = failures
		.filter((entry) => entry.status === status)
		.map((entry) => entry.reason)
		.sort();
	return failure(status, reasons.join('; '));
}

function present(assetPath, units, requiredBytes) {
	const inputs = units
		.map((unit) => ({
			kind: 'source',
			path: unit.path,
			sha256: unit.sha256,
			components: [unit.component.id],
			disposition: 'included',
		}))
		.sort((a, b) => (a.path < b.path ? -1 : 1));
	const components = [];
	for (const unit of units) {
		const previous = components.find(component => component.id === unit.component.id);
		if (previous && !sameJSON(previous, unit.component)) return incomplete(assetPath, failure('invalid', `conflicting identities for component ${unit.component.id}`));
		if (!previous) components.push(unit.component);
	}
	components.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
	return {
		row: {
			path: assetPath,
			sha256: '',
			size: 0,
			status: 'present',
			includedComponents: components.map((component) => component.id),
			components,
			inputs,
			tools: [],
		},
		requiredBytes,
	};
}

function incomplete(assetPath, entry) {
	return {
		row: {
			path: assetPath,
			sha256: '',
			size: 0,
			status: entry.status,
			includedComponents: [],
			components: [],
			inputs: [],
			tools: [],
			reason: entry.reason,
		},
	};
}

// The proof binds the bytes webpack actually left on the output file system,
// not an in-memory source observed before the emit stage.
async function readEmittedAssets(compilation, assets) {
	const outputFileSystem = compilation.compiler.outputFileSystem;
	const root = realResolve(compilation.outputOptions.path);
	for (const [index, asset] of assets.entries()) {
		const file = path.join(root, asset.row.path);
		const bytes = await new Promise((resolve, reject) => {
			outputFileSystem.readFile(file, (error, data) => (error ? reject(new Error(`${PLUGIN}: emitted asset ${asset.row.path} is unreadable: ${error.message}`)) : resolve(data)));
		});
		if (asset.requiredBytes && !asset.requiredBytes.equals(bytes)) {
			assets[index] = incomplete(asset.row.path, failure('hash-mismatch', `emitted asset differs from the bytes it was described from`));
			assets[index].row.sha256 = digest(bytes);
			assets[index].row.size = bytes.length;
			continue;
		}
		asset.row.sha256 = digest(bytes);
		asset.row.size = bytes.length;
	}
}

function writeProof(proofPath, proof) {
	const document = { version: proof.version, sourceRoot: proof.sourceRoot, assets: proof.assets.map((asset) => asset.row) };
	fs.mkdirSync(path.dirname(proofPath), { recursive: true });
	fs.writeFileSync(proofPath, `${JSON.stringify(document, null, 2)}\n`);
}

function checkProofOutsideOutput(proofPath, outputPath) {
	if (typeof outputPath !== 'string' || outputPath === '') return;
	const output = realResolve(outputPath);
	if (contains(output, realResolve(proofPath))) {
		throw new Error(`${PLUGIN}: proofPath ${proofPath} is inside the output root ${output}`);
	}
}

// Paths are compared after resolving the symlinks of their existing ancestors,
// so a symlinked prefix cannot hide a containment.
function realResolve(target) {
	const resolved = path.resolve(target);
	let existing = resolved;
	const suffix = [];
	for (;;) {
		if (fs.existsSync(existing)) return path.join(fs.realpathSync(existing), ...suffix);
		const parent = path.dirname(existing);
		if (parent === existing) return resolved;
		suffix.unshift(path.basename(existing));
		existing = parent;
	}
}

function contains(root, candidate) {
	return candidate === root || candidate.startsWith(root.endsWith(path.sep) ? root : root + path.sep);
}

function digest(bytes) {
	return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function sameJSON(left, right) {
	return JSON.stringify(left) === JSON.stringify(right);
}

function isPlainObject(value) {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function checkKeys(object, known, where) {
	for (const key of Object.keys(object)) {
		if (!known.includes(key)) throw new Error(`${PLUGIN}: unknown ${where} field ${JSON.stringify(key)}`);
	}
}

function requireNonEmptyString(value, where) {
	if (typeof value !== 'string' || value === '') throw new Error(`${PLUGIN}: ${where} must be a non-empty string`);
	return value;
}

function requireAbsolutePath(value, where) {
	requireNonEmptyString(value, where);
	if (!path.isAbsolute(value)) throw new Error(`${PLUGIN}: ${where} must be an absolute path`);
	return path.resolve(value);
}

function requireDirectory(value, where) {
	const resolved = requireAbsolutePath(value, where);
	const real = fs.realpathSync(resolved);
	if (!fs.statSync(real).isDirectory()) throw new Error(`${PLUGIN}: ${where} must be a directory`);
	return real;
}

function requireCleanRelativePath(value, where) {
	requireNonEmptyString(value, where);
	const normalized = value.split(path.sep).join('/');
	if (normalized.startsWith('/') || normalized !== path.posix.normalize(normalized) || normalized.split('/').includes('..')) {
		throw new Error(`${PLUGIN}: ${where} must be a clean relative path`);
	}
	return normalized;
}

module.exports = DkSbomWebpackCollector;
