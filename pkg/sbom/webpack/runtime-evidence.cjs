'use strict';

// Binds one webpack runtime module of a chunk to the pinned webpack sources
// that produced it, for the three standard classes listed below and nothing
// else; anything else is reported as no data, never as a weaker claim.
//
// The load recordings and the observation of the generator call come from
// runtime-preload.cjs, which must already be installed when webpack is first
// required; without it there is no data.

const path = require('node:path');

const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const SUPPORTED_WEBPACK = '5.94.0';
const SOURCE_TYPE = 'runtime';
const BASE_FILE = 'RuntimeModule.js';
const HELPER_BASE_FILE = 'runtime/HelperRuntimeModule.js';
const CLASS_FILES = [
	'runtime/DefinePropertyGettersRuntimeModule.js',
	'runtime/HasOwnPropertyRuntimeModule.js',
	'runtime/MakeNamespaceObjectRuntimeModule.js',
	'runtime/NonceRuntimeModule.js',
];
const HELPER_FILES = ['Template.js', 'RuntimeTemplate.js', 'RuntimeGlobals.js'];
// The raw bytes of every file this adapter describes, in the pinned webpack
// 5.94.0 distribution. A fork or a patched install that keeps the version
// string is not that webpack, however well its own bytes verify.
const FINGERPRINTS = new Map([
	['RuntimeModule.js', 'sha256:ce95e076bc30746ca64a0d9b5d540ab42eb73cf1db79705fccfabf16f64f3986'],
	['Template.js', 'sha256:9849fa6fd40f4c38cd965c105497bd8e993961c6daa40a085ad7d3a74a383ec6'],
	['RuntimeTemplate.js', 'sha256:5a4fb4aaae186ca24e8ca3791a50fe89fe3f2cce2576ff0136b38d49e4fae06e'],
	['RuntimeGlobals.js', 'sha256:0c90301d2e7d126196ddf3378cc23cdaef02f064e1b8216140b86635087f3e50'],
	['runtime/HelperRuntimeModule.js', 'sha256:8f773a9b2b32f36ab77331a14da3fb7870588a151b12a842ff2961a63097a94b'],
	['runtime/DefinePropertyGettersRuntimeModule.js', 'sha256:a8616912437a5fbad7859198d242fc1615ac5be21107a358942537082bcfb7ea'],
	['runtime/HasOwnPropertyRuntimeModule.js', 'sha256:1839066ca40c63cc0e655c0453e9163aaa0d4bb92be4c4c0ac23d16b14d70c18'],
	['runtime/MakeNamespaceObjectRuntimeModule.js', 'sha256:3b04cbcb66679c0889f27536bcb3008720285953552a5f1dd0bd02a71fb3a0d4'],
	['javascript/JavascriptModulesPlugin.js', 'sha256:a62f97847080a4f4ebf2e5075bd14f55f29ab5e862e7fac608e6cd081dfb3198'],
	['APIPlugin.js', 'sha256:b6b1aa7b66f08aeaa2ea8e141ee7567120200855a9fbc88bc3351988a9fe686e'],
	['runtime/NonceRuntimeModule.js', 'sha256:a5f4cdf3351b259a972eefe4bb7d48c94f13933dd415c0a7108d645bfe026fcf'],
]);

async function runtimeEvidence(compilation, chunk, runtimeModule, verifyResource) {
	const registry = globalThis[REGISTRY];
	if (!registry || typeof registry.findByExport !== 'function' || typeof registry.getByFile !== 'function' || typeof registry.getGeneration !== 'function' || typeof registry.snapshot !== 'function') {
		return noData('the commonjs load registry is not installed in this process');
	}
	const api = compilation.compiler && compilation.compiler.webpack;
	if (!api || typeof api.version !== 'string') return noData('the compiler does not expose its webpack');
	if (api.version !== SUPPORTED_WEBPACK) {
		return failed('unsupported', `runtime modules of webpack ${api.version} are not described, only ${SUPPORTED_WEBPACK}`);
	}

	const base = registry.findByExport(api.RuntimeModule);
	const baseProblem = entryProblem(base, 'the webpack RuntimeModule base class');
	if (baseProblem) return baseProblem;
	const lib = path.dirname(base.file);
	if (path.basename(base.file) !== BASE_FILE) return noData(`the RuntimeModule base class comes from ${base.file}`);

	const chain = [];
	const prototype = Object.getPrototypeOf(runtimeModule);
	const moduleClass = prototype === null ? undefined : prototype.constructor;
	if (!moduleClass || moduleClass.prototype !== prototype) return noData(`${identify(runtimeModule)} does not carry its own class`);
	for (let current = moduleClass; current !== api.RuntimeModule && chain.length < 2; current = Object.getPrototypeOf(current)) {
		if (typeof current !== 'function') break;
		const entry = registry.findByExport(current);
		const problem = entryProblem(entry, 'the class of the runtime module');
		if (problem) return problem;
		const relative = relativeName(lib, entry.file);
		const known = chain.length === 0 ? CLASS_FILES : [HELPER_BASE_FILE];
		if (!known.includes(relative)) return noData(`${identify(runtimeModule)} is built by ${entry.file}, which is not a described webpack runtime module`);
		chain.push(entry);
	}
	if (chain.length === 0 || Object.getPrototypeOf(chain[chain.length - 1].exports) !== api.RuntimeModule) {
		return noData(`${identify(runtimeModule)} does not derive from the loaded RuntimeModule`);
	}
	chain.push(base);

	const helpers = [];
	for (const relative of HELPER_FILES) {
		const entry = registry.getByFile(path.join(lib, ...relative.split('/')));
		const problem = entryProblem(entry, relative);
		if (problem) return problem;
		helpers.push(entry);
	}
	const [template, runtimeTemplate, runtimeGlobals] = helpers;
	if (api.Template !== template.exports || api.RuntimeGlobals !== runtimeGlobals.exports) {
		return noData('the compiler exposes helper modules other than the ones loaded from its lib directory');
	}
	for (const entry of [...chain, ...helpers]) {
		const drift = compareMembers(entry.members, registry.snapshot(entry.exports), 'exports') || compareMembers(entry.prototypeMembers, registry.snapshot(prototypeOf(entry.exports)), 'prototype');
		if (drift) return noData(`${relativeName(lib, entry.file)} no longer exports what it exported when it was loaded: ${drift}`);
	}

	const own = ownImplementation(registry.snapshot(runtimeModule));
	if (own) return noData(`${identify(runtimeModule)} carries an own ${own}`);
	const generate = memberOf(chain[0], 'generate');
	if (!generate || runtimeModule.generate !== generate.value) return noData(`${identify(runtimeModule)} would not run the generator its class exported`);
	for (const name of ['getGeneratedCode', 'codeGeneration']) {
		const inherited = memberOf(base, name);
		if (!inherited || runtimeModule[name] !== inherited.value) return noData(`${identify(runtimeModule)} would not run the loaded ${name}`);
	}
	if (runtimeModule.fullHash !== false || runtimeModule.dependentHash !== false) {
		return noData(`${identify(runtimeModule)} regenerates its code for the compilation hash`);
	}
	if (runtimeModule.compilation !== compilation) return noData(`${identify(runtimeModule)} is attached to another compilation`);
	// The generators read their strings off this instance.
	const instance = compilation.runtimeTemplate;
	const runtimeTemplatePrototype = prototypeOf(runtimeTemplate.exports);
	if (!instance || Object.getPrototypeOf(instance) !== runtimeTemplatePrototype) return noData('the compilation does not use the loaded RuntimeTemplate');
	const ownInstance = ownImplementation(registry.snapshot(instance));
	if (ownInstance) return noData(`the compilation runtime template carries an own ${ownInstance}`);

	// What the generator really returned, seen from inside its own call: a
	// prefilled cache, a generator swapped only for the call, or a helper put back
	// before this point are all invisible to any later reading.
	const observed = registry.getGeneration(runtimeModule);
	if (!observed || typeof observed.code !== 'string' || !Array.isArray(observed.states)) {
		return noData(`the generator of ${identify(runtimeModule)} was not observed running${observed && observed.reason ? `: ${observed.reason}` : ''}`);
	}
	if (observed.file !== chain[0].file || observed.method !== runtimeModule.generate) return noData(`${identify(runtimeModule)} was generated by another implementation`);
	if (observed.compilation !== compilation) return noData(`${identify(runtimeModule)} was generated for another compilation`);
	for (const state of observed.states) {
		for (const entry of [...chain, ...helpers]) {
			const atCall = state.helpers.get(entry.file);
			if (!atCall) return noData(`${relativeName(lib, entry.file)} was not loaded when the generator ran`);
			const drift = compareMembers(entry.members, atCall.members, 'exports') || compareMembers(entry.prototypeMembers, atCall.prototypeMembers, 'prototype');
			if (drift) return noData(`${relativeName(lib, entry.file)} was not what it exported when it was loaded while the generator ran: ${drift}`);
		}
		if (!state.runtimeTemplate || state.runtimeTemplate.prototype !== runtimeTemplatePrototype) return noData('another runtime template was in place while the generator ran');
		const ownAtCall = ownImplementation(state.runtimeTemplate.own);
		if (ownAtCall) return noData(`the runtime template carried an own ${ownAtCall} while the generator ran`);
	}

	const chunkGraph = compilation.chunkGraph;
	if (!chunkGraph || typeof chunkGraph.getChunkRuntimeModulesIterable !== 'function') return noData('the compilation does not expose the runtime modules of its chunks');
	let attached = false;
	for (const candidate of chunkGraph.getChunkRuntimeModulesIterable(chunk)) {
		if (candidate === runtimeModule) attached = true;
	}
	if (!attached) return noData(`${identify(runtimeModule)} is not a runtime module of this chunk`);

	let used;
	try {
		used = compilation.codeGenerationResults.getSource(runtimeModule, chunk.runtime, SOURCE_TYPE);
	} catch (error) {
		return noData(`no code generation result for ${identify(runtimeModule)}: ${error.message}`);
	}
	if (!used || typeof used.source !== 'function') return noData(`no runtime source was generated for ${identify(runtimeModule)}`);
	const usedCode = used.source();
	const generated = runtimeModule._cachedGeneratedCode;
	if (typeof usedCode !== 'string' || typeof generated !== 'string') return noData(`the runtime source of ${identify(runtimeModule)} is not text`);
	if (observed.code !== generated) {
		return failed('hash-mismatch', `the cached runtime code of ${identify(runtimeModule)} is not what its generator returned`);
	}
	if (!Buffer.from(usedCode, 'utf8').equals(Buffer.from(generated, 'utf8'))) {
		return failed('hash-mismatch', `the runtime source used for ${identify(runtimeModule)} is not the code its generator produced`);
	}

	const units = [];
	const verified = new Set();
	let component;
	for (const entry of [...chain, ...helpers]) {
		if (verified.has(entry.file)) continue;
		verified.add(entry.file);
		const resolved = await verifyResource(entry.file);
		if (!resolved || (!resolved.unit && !resolved.failure)) return noData(`${entry.file} was not verified`);
		if (resolved.failure) return { units: [], failure: resolved.failure };
		const unit = resolved.unit;
		if (unit.sha256 !== entry.sha256) return failed('hash-mismatch', `${entry.file} differs from the bytes this process loaded from it`);
		const pinned = FINGERPRINTS.get(relativeName(lib, entry.file));
		if (unit.sha256 !== pinned) {
			return failed('unsupported', `${relativeName(lib, entry.file)} is not the source of the pinned webpack ${SUPPORTED_WEBPACK}`);
		}
		if (component === undefined) component = unit.component;
		else if (!sameJSON(component, unit.component)) {
			return failed('invalid', `the webpack runtime sources bind to conflicting components ${component.id} and ${unit.component.id}`);
		}
		units.push({ path: unit.path, sha256: unit.sha256, component: unit.component });
	}
	if (component.version !== api.version) {
		return failed('invalid', `component ${component.id} is not the webpack ${api.version} that is running`);
	}
	return { units };
}

function entryProblem(entry, what) {
	if (!entry) return noData(`${what} was not recorded as a loaded commonjs module`);
	if (!entry.usable) return noData(`${what} was ${entry.reason}`);
	return null;
}

function relativeName(lib, file) {
	return path.relative(lib, file).split(path.sep).join('/');
}

function memberOf(entry, name) {
	const snapshot = entry.prototypeMembers && entry.prototypeMembers.get(name);
	return snapshot && snapshot.kind === 'data' && typeof snapshot.value === 'function' ? snapshot : null;
}

function prototypeOf(value) {
	const descriptor = typeof value === 'function' ? Object.getOwnPropertyDescriptor(value, 'prototype') : undefined;
	return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

// An own function, or an own accessor that could return one, shadows whatever
// the verified prototypes hold.
function ownImplementation(snapshot) {
	if (snapshot === null) return null;
	for (const [key, descriptor] of snapshot) {
		if (descriptor.kind !== 'data') return `${String(key)} accessor`;
		if (typeof descriptor.value === 'function') return `${String(key)} implementation`;
	}
	return null;
}

function compareMembers(snapshot, now, where) {
	if (snapshot === null || now === null) return snapshot === now ? null : `${where} is no longer an object`;
	for (const key of snapshot.keys()) {
		if (!now.has(key)) return `${where}.${String(key)} is gone`;
	}
	for (const [key, is] of now) {
		const was = snapshot.get(key);
		if (!was) return `${where}.${String(key)} was added`;
		if (was.kind !== is.kind) return `${where}.${String(key)} was replaced`;
		if (was.kind === 'data' ? !Object.is(was.value, is.value) : !Object.is(was.get, is.get) || !Object.is(was.set, is.set)) {
			return `${where}.${String(key)} was replaced`;
		}
	}
	return null;
}

function identify(runtimeModule) {
	try {
		const name = runtimeModule.identifier();
		if (typeof name === 'string' && name !== '') return name;
	} catch {
		// An identifier of its own making is not worth failing over.
	}
	return 'the runtime module';
}

function sameJSON(left, right) {
	return JSON.stringify(left) === JSON.stringify(right);
}

function failed(status, reason) {
	return { units: [], failure: { status, reason } };
}

function noData(reason) {
	return failed('no-data', reason);
}

module.exports = { runtimeEvidence, internals: Object.freeze({ SUPPORTED_WEBPACK, FINGERPRINTS, compareMembers, ownImplementation, relativeName, prototypeOf, entryProblem, sameJSON, failed, noData }) };
