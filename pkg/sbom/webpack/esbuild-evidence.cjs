'use strict';

// Binds the JavaScript webpack kept for one esbuild-loader module to the raw
// source esbuild really read, and - only when the patched compiler reports that
// a runtime part was selected for that very call - to the esbuild runtime
// source the caller declared.
//
// The executable, the client entry and the loader file are the instrument, not
// a part of any module: they contribute no unit, and their identity is the
// caller's declared hashes, which this adapter can check against disk and
// against what ran but cannot bind to a verified original on its own.
//
// The load recordings come from runtime-preload.cjs, which must already be
// installed when the esbuild client and the loader are first required.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const NAME = 'DkSbomEsbuildEvidence';
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const SUPPORTED_WEBPACK = '5.94.0';
const EVIDENCE_VERSION = 1;
// The tool pairs this adapter describes: one instrumented esbuild and the
// esbuild-loader built against it. The producer string is the one the patch of
// that esbuild reports, and the loader is recognized by the digest of its
// published artifact rather than by where it is installed, so an alias, a
// nested copy or a renamed directory changes nothing.
const SUPPORTED_PAIRS = Object.freeze([
	Object.freeze({
		esbuild: '0.25.0',
		esbuildLoader: '4.3.0',
		producer: 'dk-sbom/1 esbuild 0.25.0',
		loaderSHA256: 'sha256:64b2b3f0adaadc963e115caa4f0aeb137bf721eca2d0b7386fbe71cbe88f473e',
		runtimeSourceSHA256: 'sha256:90066c2fe560b24e55a4adfb05896b1cc5ccc219630d92a24bd614d3a4781610',
	}),
	Object.freeze({
		esbuild: '0.17.19',
		esbuildLoader: '3.0.1',
		producer: 'dk-sbom/1 esbuild 0.17.19',
		loaderSHA256: 'sha256:95888f5eda79612e84c2c5723b2fee45d1acbde7fd979e8f42ede582c913b723',
		runtimeSourceSHA256: 'sha256:e2e31178a464f615a6b86e7c72469b19913b30b1140223daf08bc720b2f18df9',
	}),
]);
const TOOL_FILES = ['entry', 'binary', 'loader', 'runtimeSource'];
const CANONICAL_SHA256 = /^sha256:[0-9a-f]{64}$/;
// lib/npm/node-platform.ts of the pinned client: an ESBUILD_BINARY_PATH of this
// value is dropped rather than used.
const IGNORED_BINARY = '/usr/bin/esbuild';
const BOM = Buffer.from([0xef, 0xbb, 0xbf]);

function installEsbuildEvidence(compiler, tool, verifyResource) {
	if (typeof verifyResource !== 'function') throw new TypeError(`${NAME}: verifyResource must be a function`);
	const spec = specOf(tool);
	const records = new WeakMap();
	let state = prepare(spec);
	if (!state.failure) {
		const unsupported = compilerProblem(compiler);
		if (unsupported) state = unsupported;
	}
	if (!state.failure) {
		compiler.hooks.compilation.tap(NAME, (compilation) => {
			compiler.webpack.NormalModule.getCompilationHooks(compilation).beforeLoaders.tap(NAME, (loaders, module, loaderContext) => {
				instrument(state, spec, records, loaders, module, loaderContext);
			});
		});
	}
	const evidenceFor = async function evidenceFor(module) {
		if (state.failure) return { units: [], failure: state.failure };
		try {
			return await describe(state, spec, records.get(module), module, verifyResource);
		} catch (error) {
			return noData(`${identify(module)} could not be described: ${error.message}`);
		}
	};
	// For a module this transform only part-authored: the units of the transform
	// and the code it returned, with no claim about what the rest of the chain
	// did to it afterwards.
	//
	// What the caller owes, and this adapter deliberately does not check: that
	// the transform stood where the caller thinks it did, and that the code
	// returned here is the text the caller's own loader was handed. Both are
	// facts about the chain, which only the adapter describing the chain holds -
	// the stylesheet seam, for one, compares the returned code with what its
	// loader read and refuses the module when they differ.
	evidenceFor.transformed = async function transformed(module) {
		if (state.failure) return { units: [], failure: state.failure };
		try {
			return await describe(state, spec, records.get(module), module, verifyResource, true);
		} catch (error) {
			return noData(`${identify(module)} could not be described: ${error.message}`);
		}
	};
	return evidenceFor;
}

// What the caller declares is a contract, not an observation: anything that is
// not a usable declaration is a programming error, while a declaration that
// does not match what is on disk or what ran is a failure of this build.
function specOf(tool) {
	if (tool === null || typeof tool !== 'object') throw new TypeError(`${NAME}: tool must be an object`);
	const spec = { pair: pairOf(tool.versions) };
	for (const key of TOOL_FILES) {
		const file = tool[key];
		const expected = tool[`${key}SHA256`];
		if (file === undefined && key === 'runtimeSource') {
			if (expected !== undefined) throw new TypeError(`${NAME}: tool.runtimeSourceSHA256 without tool.runtimeSource`);
			continue;
		}
		if (typeof file !== 'string' || !path.isAbsolute(file) || path.normalize(file) !== file) {
			throw new TypeError(`${NAME}: tool.${key} must be an absolute normalized path`);
		}
		// The loader and the runtime source are pinned by the pair, not declared:
		// their digests are those of the published artifact and of the runtime
		// source of that very esbuild. A declaration may repeat such a digest and
		// may not contradict it.
		const pinned = key === 'loader' ? spec.pair.loaderSHA256 : key === 'runtimeSource' ? spec.pair.runtimeSourceSHA256 : undefined;
		if (pinned !== undefined) {
			if (expected !== undefined && expected !== pinned) {
				throw new TypeError(`${NAME}: tool.${key}SHA256 is not the ${key === 'loader' ? `published esbuild-loader ${spec.pair.esbuildLoader}` : `runtime source of esbuild ${spec.pair.esbuild}`}`);
			}
			spec[key] = file;
			spec[`${key}SHA256`] = pinned;
			continue;
		}
		if (typeof expected !== 'string' || !CANONICAL_SHA256.test(expected)) {
			throw new TypeError(`${NAME}: tool.${key}SHA256 must be a canonical sha256`);
		}
		spec[key] = file;
		spec[`${key}SHA256`] = expected;
	}
	return Object.freeze(spec);
}

// Which instrumented esbuild and which loader this build declares. A pair this
// adapter does not describe is a declaration it cannot act on, not a build it
// may describe with the rules of another version.
function pairOf(versions) {
	if (versions === null || typeof versions !== 'object') {
		throw new TypeError(`${NAME}: tool.versions must name the esbuild and esbuild-loader of this build`);
	}
	const pair = SUPPORTED_PAIRS.find((candidate) => candidate.esbuild === versions.esbuild && candidate.esbuildLoader === versions.esbuildLoader);
	if (!pair) {
		const known = SUPPORTED_PAIRS.map((candidate) => `esbuild ${candidate.esbuild} with esbuild-loader ${candidate.esbuildLoader}`).join(', ');
		throw new TypeError(`${NAME}: esbuild ${String(versions.esbuild)} with esbuild-loader ${String(versions.esbuildLoader)} is not a described pair, only ${known}`);
	}
	return pair;
}

function prepare(spec) {
	const registry = globalThis[REGISTRY];
	if (!registry || typeof registry.getByFile !== 'function') return noData('the commonjs load registry is not installed in this process');
	// The client ignores exactly this path in its environment and runs an
	// executable of its own instead, so nothing about it could be described.
	if (spec.binary === IGNORED_BINARY) return noData(`${IGNORED_BINARY} is the path the esbuild client ignores, so it would run another executable`);
	for (const key of TOOL_FILES) {
		const file = spec[key];
		if (file === undefined) continue;
		let stats;
		try {
			stats = fs.lstatSync(file);
		} catch (error) {
			return noData(`tool.${key} could not be read: ${error.code || error.message}`);
		}
		if (!stats.isFile()) return noData(`tool.${key} is not a regular file: ${file}`);
		// The runtime source is a described input, so its bytes are bound to an
		// original through verifyResource rather than to a hash of their own.
		if (key === 'runtimeSource') continue;
		if (digest(fs.readFileSync(file)) !== spec[`${key}SHA256`]) {
			if (key === 'loader') {
				return failed('hash-mismatch', `${file} is not the published esbuild-loader ${spec.pair.esbuildLoader} this build declares`);
			}
			return failed('hash-mismatch', `${file} is not the ${key} this collector is configured for`);
		}
	}
	if (process.env.ESBUILD_BINARY_PATH !== spec.binary) {
		return noData(`this process would not run the verified executable: ESBUILD_BINARY_PATH is ${process.env.ESBUILD_BINARY_PATH === undefined ? 'unset' : process.env.ESBUILD_BINARY_PATH}`);
	}
	// Loading the client is running it, and its executable path is fixed in the
	// environment of that first load: a client this process loaded earlier may
	// have been configured for another one, and its bytes cannot say so.
	if (require.cache[spec.entry]) {
		return noData(`${spec.entry} was already loaded in this process before this collector could verify how it was configured`);
	}
	let api;
	try {
		api = require(spec.entry);
	} catch (error) {
		return noData(`${spec.entry} could not be loaded: ${error.message}`);
	}
	const entry = registry.getByFile(spec.entry);
	if (!entry || !entry.usable) return noData(`${spec.entry} was not recorded as a loaded commonjs module`);
	if (entry.sha256 !== spec.entrySHA256) return failed('hash-mismatch', `${spec.entry} ran source other than the bytes this collector verified`);
	if (api === null || typeof api !== 'object' || typeof api.transform !== 'function') return noData(`${spec.entry} does not export a transform function`);
	return { transform: api.transform, registry };
}

function compilerProblem(compiler) {
	const api = compiler.webpack;
	if (!api || typeof api.version !== 'string' || !api.NormalModule || typeof api.NormalModule.getCompilationHooks !== 'function') {
		return noData('the compiler does not expose the webpack that builds its modules');
	}
	if (api.version !== SUPPORTED_WEBPACK) {
		return failed('unsupported', `modules of webpack ${api.version} are not described, only ${SUPPORTED_WEBPACK}`);
	}
	return null;
}

// The loader runs with a clone of its item carrying this module's transform;
// the rule object the user configured is shared by every module it matches and
// is never touched.
// The transform is instrumented wherever it stands in a chain: a module it
// part-authored is described through `transformed`, by the adapter that
// describes what ran around it. Where it stands changes nothing about what the
// transform itself did.
function instrument(state, spec, records, loaders, module, loaderContext) {
	if (!Array.isArray(loaders)) return;
	// The transform may stand anywhere in a chain, and exactly once: a chain
	// that runs it twice is one this adapter cannot tell apart.
	const at = loaders.findIndex((candidate) => candidate !== null && typeof candidate === 'object' && candidate.loader === spec.loader);
	if (at < 0 || loaders.findIndex((candidate, index) => index > at && candidate !== null && typeof candidate === 'object' && candidate.loader === spec.loader) >= 0) return;
	const item = loaders[at];
	const options = item.options;
	const plain = options === undefined || options === null || (typeof options === 'object' && !Array.isArray(options) && Object.getPrototypeOf(options) === Object.prototype);
	if (!plain) return;
	// A foreign implementation is the user's own transform: it would be its
	// output, not esbuild's, that this adapter observed.
	if (options !== undefined && options !== null && options.implementation !== undefined) return;
	// loader-runner fills the context in, and names the file it really read,
	// only once it starts running the chain this clone belongs to.
	const record = { calls: 0 };
	record.transform = async (source, transformOptions) => {
		record.calls += 1;
		const call = record.calls;
		const result = await state.transform(source, transformOptions);
		if (call > 1) {
			record.observed = undefined;
			record.problem = failed('invalid', `${identify(module)} was transformed more than once`);
			return result;
		}
		if (typeof source !== 'string') {
			record.problem = noData(`${identify(module)} was transformed from something other than text`);
			return result;
		}
		const resource = loaderContext.resourcePath;
		if (typeof resource !== 'string' || resource === '' || !boundTo(module.resource, resource)) {
			record.problem = noData(`${identify(module)} was built from ${typeof resource === 'string' ? resource : 'no file of its own'}`);
			return result;
		}
		const sourcefile = transformOptions === null || typeof transformOptions !== 'object' ? undefined : transformOptions.sourcefile;
		if (sourcefile !== resource) {
			record.problem = noData(`${identify(module)} was transformed as ${sourcefile === undefined ? 'an unnamed file' : String(sourcefile)}`);
			return result;
		}
		record.resource = resource;
		// What the loader runner really read for this module, while it still has
		// it: webpack replaces the list with a snapshot once the module is built.
		const dependencies = typeof loaderContext.getDependencies === 'function' ? loaderContext.getDependencies() : undefined;
		if (!Array.isArray(dependencies)) {
			record.problem = noData(`${identify(module)} does not report what it was read from`);
			return result;
		}
		record.dependencies = [...dependencies];
		record.observed = { source, result };
		return result;
	};
	record.item = { ...item, options: { ...options, implementation: { transform: record.transform } } };
	loaders[at] = record.item;
	records.set(module, record);
}

function boundTo(resource, resourcePath) {
	if (typeof resource !== 'string') return false;
	return resource === resourcePath || resource.startsWith(`${resourcePath}?`) || resource.startsWith(`${resourcePath}#`);
}

async function describe(state, spec, record, module, verifyResource, chained = false) {
	// Nothing was observed for a module another loader chain built, for one the
	// adapter refused to instrument, and for one webpack served from its cache
	// without building it.
	if (!record) return noData(`${identify(module)} was not built by an observed esbuild transform`);
	if (record.problem) return record.problem;
	if (!record.observed) return noData(`no successful esbuild transform of ${identify(module)} was observed`);
	const { source, result } = record.observed;

	const loaders = module.loaders;
	const options = record.item.options;
	// The item this adapter installed must be the one that ran, and it must have
	// run once.
	const ran = Array.isArray(loaders) ? loaders.filter((item) => item === record.item).length : 0;
	if (ran !== 1) return noData(`${identify(module)} was not built by the loader item this adapter installed`);
	// Alone, this adapter describes only a module this transform authored whole.
	// A chain around it is described by the caller that takes on the rest of it,
	// and that caller has no business asking about a module with no rest.
	if (!chained && loaders.length !== 1) {
		return noData(`${identify(module)} was built by a chain this adapter does not describe alone`);
	}
	if (chained && loaders.length === 1) {
		return noData(`${identify(module)} was built by this transform alone, which this adapter describes without a caller`);
	}
	if (options.implementation === null || typeof options.implementation !== 'object' || options.implementation.transform !== record.transform) {
		return noData(`the transform of ${identify(module)} was replaced after this adapter installed it`);
	}
	const loader = state.registry.getByFile(spec.loader);
	if (!loader || !loader.usable) return noData(`${spec.loader} was not recorded as a loaded commonjs module`);
	if (loader.sha256 !== spec.loaderSHA256) return failed('hash-mismatch', `${spec.loader} ran source other than the bytes this collector verified`);

	const evidence = evidenceOf(result, source, module, spec.pair);
	if (evidence.failure) return evidence;
	const { sbom, code } = evidence;

	let resolved;
	try {
		resolved = await verifyResource(record.resource);
	} catch (error) {
		return noData(`${record.resource} could not be verified: ${error.message}`);
	}
	if (!resolved || (!resolved.unit && !resolved.failure)) return noData(`${record.resource} was not verified`);
	if (resolved.failure) return { units: [], failure: resolved.failure };
	const unit = resolved.unit;
	const text = textOf(unit);
	if (text.failure) return text;
	// loader-runner hands the loader the file text, with a byte order mark
	// stripped: those bytes would be described as transformed, and they were not.
	if (text.text !== source) return failed('hash-mismatch', `esbuild did not read the verified bytes of ${record.resource}`);

	for (const file of record.dependencies) {
		if (file !== record.resource) return noData(`${identify(module)} was also built from ${file}`);
	}
	// Only if webpack still holds it: the snapshot that replaces the list is an
	// optimization, and its absence is not a dependency this adapter missed.
	const snapshot = module.buildInfo && module.buildInfo.snapshot;
	if (snapshot && typeof snapshot.getFileIterable === 'function') {
		for (const file of snapshot.getFileIterable()) {
			if (file !== record.resource) return noData(`${identify(module)} was also built from ${file}`);
		}
	}

	if (!chained) {
		const kept = bufferOf(module.originalSource && module.originalSource());
		if (!kept) return noData(`${identify(module)} does not expose the source webpack kept for it`);
		if (!kept.equals(Buffer.from(code, 'utf8'))) {
			return failed('hash-mismatch', `the source webpack kept for ${identify(module)} is not the code the transform returned`);
		}
	}

	const units = [{ path: unit.path, sha256: unit.sha256, component: unit.component }];
	if (sbom.runtimeSelected) {
		const runtime = await runtimeUnit(spec, verifyResource);
		if (runtime.failure) return runtime;
		units.push(runtime.unit);
	}
	return chained ? { units, code } : { units };
}

// Metadata an unpatched esbuild never produces, checked against the very text
// and code this call carried: the producer string alone claims nothing.
function evidenceOf(result, source, module, pair) {
	if (result === null || typeof result !== 'object') return noData(`the transform of ${identify(module)} returned no result`);
	const sbom = result.sbom;
	if (sbom === undefined) return noData(`the transform of ${identify(module)} produced no evidence`);
	if (sbom === null || typeof sbom !== 'object') return failed('invalid', `the transform evidence of ${identify(module)} is not an object`);
	if (typeof sbom.producer !== 'string') return failed('invalid', `the transform evidence of ${identify(module)} names no producer`);
	if (sbom.version !== EVIDENCE_VERSION || sbom.producer !== pair.producer) {
		return failed('unsupported', `${identify(module)} was transformed by ${sbom.producer} evidence version ${String(sbom.version)}, not ${pair.producer} version ${EVIDENCE_VERSION}`);
	}
	if (typeof sbom.runtimeSelected !== 'boolean' || !CANONICAL_SHA256.test(String(sbom.inputSHA256)) || !CANONICAL_SHA256.test(String(sbom.outputSHA256))) {
		return failed('invalid', `the transform evidence of ${identify(module)} is not of the described shape`);
	}
	const code = result.code;
	if (typeof code !== 'string') return noData(`the transform of ${identify(module)} returned no code`);
	if (sbom.inputSHA256 !== digest(Buffer.from(source, 'utf8'))) {
		return failed('invalid', `the transform evidence of ${identify(module)} does not describe the text it was given`);
	}
	if (sbom.outputSHA256 !== digest(Buffer.from(code, 'utf8'))) {
		return failed('invalid', `the transform evidence of ${identify(module)} does not describe the code it returned`);
	}
	return { sbom, code };
}

function textOf(unit) {
	if (!unit || typeof unit.path !== 'string' || !CANONICAL_SHA256.test(String(unit.sha256)) || unit.component === null || typeof unit.component !== 'object') {
		return noData('the verified source is not a described unit');
	}
	if (!Buffer.isBuffer(unit.bytes)) return noData(`${unit.path} was verified without its bytes`);
	if (digest(unit.bytes) !== unit.sha256) return failed('invalid', `${unit.path} was verified as bytes other than the ones it carries`);
	if (unit.bytes.length >= BOM.length && unit.bytes.subarray(0, BOM.length).equals(BOM)) {
		return noData(`${unit.path} starts with a byte order mark the loader does not pass on`);
	}
	const text = unit.bytes.toString('utf8');
	if (!Buffer.from(text, 'utf8').equals(unit.bytes)) return noData(`${unit.path} is not valid utf8`);
	return { text };
}

// A selected runtime is a real input of this module. Which source file that is
// cannot be read off the executable, so the caller declares it; it is bound to
// a component by the same verification as any other source.
async function runtimeUnit(spec, verifyResource) {
	if (spec.runtimeSource === undefined) {
		return noData('the transform selected the esbuild runtime, whose source this collector was not given');
	}
	let resolved;
	try {
		resolved = await verifyResource(spec.runtimeSource);
	} catch (error) {
		return noData(`${spec.runtimeSource} could not be verified: ${error.message}`);
	}
	if (!resolved || (!resolved.unit && !resolved.failure)) return noData(`${spec.runtimeSource} was not verified`);
	if (resolved.failure) return { units: [], failure: resolved.failure };
	const unit = resolved.unit;
	if (typeof unit.path !== 'string' || !CANONICAL_SHA256.test(String(unit.sha256)) || unit.component === null || typeof unit.component !== 'object') {
		return noData('the verified esbuild runtime source is not a described unit');
	}
	if (unit.sha256 !== spec.runtimeSourceSHA256) {
		return failed('hash-mismatch', `${spec.runtimeSource} is not the runtime source of esbuild ${spec.pair.esbuild}`);
	}
	return { unit: { path: unit.path, sha256: unit.sha256, component: unit.component } };
}

function bufferOf(source) {
	if (!source || typeof source.buffer !== 'function') return null;
	let buffer;
	try {
		buffer = source.buffer();
	} catch {
		return null;
	}
	return Buffer.isBuffer(buffer) ? buffer : null;
}

function digest(bytes) {
	return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function identify(module) {
	try {
		const name = module.identifier();
		if (typeof name === 'string' && name !== '') return name;
	} catch {
		// An identifier of its own making is not worth failing over.
	}
	return 'the module';
}

function failed(status, reason) {
	return { units: [], failure: { status, reason } };
}

function noData(reason) {
	return failed('no-data', reason);
}

module.exports = { installEsbuildEvidence };
