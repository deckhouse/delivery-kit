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
const path = require('path');

const PLUGIN = 'DkSbomWebpackCollector';
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
		// Bound against the copy plugin instances this compiler really runs, so a
		// declaration can never stand in for a copy operation that is not configured.
		const options = { ...this.options, copied: bindCopied(this.options.copied, compiler) };
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
	checkKeys(options, ['proofPath', 'originals', 'copied', 'resolveOriginal'], 'options');
	if (options.resolveOriginal !== undefined && typeof options.resolveOriginal !== 'function') throw new Error(`${PLUGIN}: resolveOriginal must be a function`);
	const proofPath = requireAbsolutePath(options.proofPath, 'options.proofPath');
	return {
		proofPath,
		originals: normalizeOriginals(options.originals, typeof options.resolveOriginal === 'function'),
		copied: normalizeCopied(options.copied),
		resolveOriginal: options.resolveOriginal,
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
		assets.push(await describeAsset(options, assetPath, asset, chunkUnits.get(asset.name)));
	}
	assets.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
	return { version: PROOF_VERSION, sourceRoot, assets };
}

// Only final chunks of this compilation and the asset names they really emitted;
// modules reachable only through the build graph are not part of any output.
async function collectChunkAssets(options, compilation) {
	const byAsset = new Map();
	for (const chunk of compilation.chunks) {
		const collected = { units: new Map(), failures: new Map() };
		// One chunk emitting several files would need per-file attribution of its
		// modules, which this version does not do.
		if (chunk.files.size !== 1) {
			addFailure(collected, failure('no-data', `chunk ${chunk.name || chunk.id} emits ${chunk.files.size} files`));
		}
		for (const module of compilation.chunkGraph.getChunkModulesIterable(chunk)) {
			await collectModule(options, module, collected);
		}
		for (const file of chunk.files) {
			const target = byAsset.get(file) || { units: new Map(), failures: new Map() };
			for (const [key, unit] of collected.units) target.units.set(key, unit);
			for (const [reason, failure] of collected.failures) target.failures.set(reason, failure);
			byAsset.set(file, target);
		}
	}
	return byAsset;
}

async function collectModule(options, module, collected) {
	// A ConcatenatedModule is a scope-hoisting wrapper: its inner modules are the
	// units that really ended up in the chunk.
	if (module.constructor && module.constructor.name === 'ConcatenatedModule' && Array.isArray(module.modules) && module.rootModule) {
		for (const inner of module.modules) await collectModule(options, inner, collected);
		return;
	}
	// An external is referenced, not bundled, so it contributes no input here.
	if (typeof module.externalType === 'string') return;
	// A loader rewrites the module before webpack consumes it, so the file on disk
	// is no longer the unit that was bundled.
	if (Array.isArray(module.loaders) && module.loaders.length > 0) {
		addFailure(collected, failure('no-data', `loader-transformed module: ${module.identifier()}`));
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

function describeAsset(options, assetPath, asset, chunkCollected) {
	const copied = asset.info && asset.info.copied === true;
	if (copied && chunkCollected) {
		return incomplete(assetPath, failure('invalid', `asset is both copied and emitted by a chunk`));
	}
	if (copied) return describeCopiedAsset(options, assetPath);
	if (!chunkCollected) return incomplete(assetPath, failure('no-data', `asset belongs to no chunk of this compilation`));
	if (chunkCollected.failures.size > 0) return incomplete(assetPath, worst([...chunkCollected.failures.values()]));
	if (chunkCollected.units.size === 0) return incomplete(assetPath, failure('no-data', `no verified source unit`));
	return present(assetPath, [...chunkCollected.units.values()]);
}

async function describeCopiedAsset(options, assetPath) {
	const binding = options.copied.get(assetPath);
	if (!binding) return incomplete(assetPath, failure('no-data', `copied asset has no declared origin`));
	if (binding.failure) return incomplete(assetPath, binding.failure);
	const from = binding.from;
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
			assets[index] = incomplete(asset.row.path, failure('hash-mismatch', `copied asset differs from its source bytes`));
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
