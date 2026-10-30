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
const PRODUCER = 'dk-sbom/1 esbuild 0.25.0';
const EVIDENCE_VERSION = 1;
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
	return async function evidenceFor(module) {
		if (state.failure) return { units: [], failure: state.failure };
		try {
			return await describe(state, spec, records.get(module), module, verifyResource);
		} catch (error) {
			return noData(`${identify(module)} could not be described: ${error.message}`);
		}
	};
}

// What the caller declares is a contract, not an observation: anything that is
// not a usable declaration is a programming error, while a declaration that
// does not match what is on disk or what ran is a failure of this build.
function specOf(tool) {
	if (tool === null || typeof tool !== 'object') throw new TypeError(`${NAME}: tool must be an object`);
	const spec = {};
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
		if (typeof expected !== 'string' || !CANONICAL_SHA256.test(expected)) {
			throw new TypeError(`${NAME}: tool.${key}SHA256 must be a canonical sha256`);
		}
		spec[key] = file;
		spec[`${key}SHA256`] = expected;
	}
	return Object.freeze(spec);
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
function instrument(state, spec, records, loaders, module, loaderContext) {
	if (!Array.isArray(loaders) || loaders.length !== 1) return;
	const item = loaders[0];
	if (item === null || typeof item !== 'object' || item.loader !== spec.loader) return;
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
	loaders[0] = record.item;
	records.set(module, record);
}

function boundTo(resource, resourcePath) {
	if (typeof resource !== 'string') return false;
	return resource === resourcePath || resource.startsWith(`${resourcePath}?`) || resource.startsWith(`${resourcePath}#`);
}

async function describe(state, spec, record, module, verifyResource) {
	// Nothing was observed for a module another loader chain built, for one the
	// adapter refused to instrument, and for one webpack served from its cache
	// without building it.
	if (!record) return noData(`${identify(module)} was not built by an observed esbuild transform`);
	if (record.problem) return record.problem;
	if (!record.observed) return noData(`no successful esbuild transform of ${identify(module)} was observed`);
	const { source, result } = record.observed;

	const loaders = module.loaders;
	const options = record.item.options;
	if (!Array.isArray(loaders) || loaders.length !== 1 || loaders[0] !== record.item) {
		return noData(`${identify(module)} was not built by the loader item this adapter installed`);
	}
	if (options.implementation === null || typeof options.implementation !== 'object' || options.implementation.transform !== record.transform) {
		return noData(`the transform of ${identify(module)} was replaced after this adapter installed it`);
	}
	const loader = state.registry.getByFile(spec.loader);
	if (!loader || !loader.usable) return noData(`${spec.loader} was not recorded as a loaded commonjs module`);
	if (loader.sha256 !== spec.loaderSHA256) return failed('hash-mismatch', `${spec.loader} ran source other than the bytes this collector verified`);

	const evidence = evidenceOf(result, source, module);
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

	const kept = bufferOf(module.originalSource && module.originalSource());
	if (!kept) return noData(`${identify(module)} does not expose the source webpack kept for it`);
	if (!kept.equals(Buffer.from(code, 'utf8'))) {
		return failed('hash-mismatch', `the source webpack kept for ${identify(module)} is not the code the transform returned`);
	}

	const units = [{ path: unit.path, sha256: unit.sha256, component: unit.component }];
	if (sbom.runtimeSelected) {
		const runtime = await runtimeUnit(spec, verifyResource);
		if (runtime.failure) return runtime;
		units.push(runtime.unit);
	}
	return { units };
}

// Metadata an unpatched esbuild never produces, checked against the very text
// and code this call carried: the producer string alone claims nothing.
function evidenceOf(result, source, module) {
	if (result === null || typeof result !== 'object') return noData(`the transform of ${identify(module)} returned no result`);
	const sbom = result.sbom;
	if (sbom === undefined) return noData(`the transform of ${identify(module)} produced no evidence`);
	if (sbom === null || typeof sbom !== 'object') return failed('invalid', `the transform evidence of ${identify(module)} is not an object`);
	if (typeof sbom.producer !== 'string') return failed('invalid', `the transform evidence of ${identify(module)} names no producer`);
	if (sbom.version !== EVIDENCE_VERSION || sbom.producer !== PRODUCER) {
		return failed('unsupported', `${identify(module)} was transformed by ${sbom.producer} evidence version ${String(sbom.version)}, not ${PRODUCER} version ${EVIDENCE_VERSION}`);
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
		return failed('hash-mismatch', `${spec.runtimeSource} is not the runtime source this collector is configured for`);
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
