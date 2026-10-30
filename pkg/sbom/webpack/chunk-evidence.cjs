'use strict';

// Binds one rendered non-runtime chunk to the pinned webpack sources that
// produced it: the chunk renderer of JavascriptModulesPlugin and the one stock
// chunk-format plugin that wraps its modules, both seen from inside the render
// call, and the bytes that call returned.
//
// A lazy chunk carries no bootstrap: its text is the wrapper of the array-push
// chunk format around the module sources of this very compilation. The modules
// themselves are described by the collector, from the same code generation
// results this render read.
//
// Recordings come from runtime-preload.cjs; without it there is no data.

const path = require('node:path');

const { internals } = require('./runtime-evidence.cjs');

const { SUPPORTED_WEBPACK, FINGERPRINTS, compareMembers, relativeName, prototypeOf, entryProblem, sameJSON, failed, noData } = internals;
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const BASE_FILE = 'RuntimeModule.js';
const RENDERER = 'javascript/JavascriptModulesPlugin.js';
const FORMAT = 'javascript/ArrayPushCallbackChunkFormatPlugin.js';
const HELPER_FILES = ['Template.js', 'RuntimeTemplate.js', 'RuntimeGlobals.js'];
// Every hook whose taps can change the text this renderer returns. Two of them
// carry one stock tap each and nothing else: the chunk format that wraps the
// modules, and the api plugin on the module content.
const SHAPING = ['render', 'renderContent', 'renderStartup', 'renderRequire', 'renderModuleContainer', 'renderModulePackage', 'inlineInRuntimeBailout', 'embedInRuntimeBailout', 'strictRuntimeBailout'];
const CHUNK_HOOK = 'renderChunk';
const FORMAT_PLUGIN = 'ArrayPushCallbackChunkFormatPlugin';
const MODULE_CONTENT = 'renderModuleContent';
const API_PLUGIN = 'APIPlugin';
const API_PLUGIN_FILE = 'APIPlugin.js';
const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

// The bytes the described render produced; the caller chains them to the file
// on disk the same way it does for a runtime chunk.
async function chunkEvidence(compilation, chunk, verifyResource) {
	const registry = globalThis[REGISTRY];
	if (!registry || typeof registry.getRender !== 'function' || typeof registry.snapshot !== 'function') {
		return noData('the commonjs load registry is not installed in this process');
	}
	const api = compilation.compiler && compilation.compiler.webpack;
	if (!api || typeof api.version !== 'string') return noData('the compiler does not expose its webpack');
	if (api.version !== SUPPORTED_WEBPACK) return failed('unsupported', `the chunk renderer of webpack ${api.version} is not described, only ${SUPPORTED_WEBPACK}`);
	if (typeof chunk.hasRuntime !== 'function' || chunk.hasRuntime()) {
		return noData(`chunk ${chunk.name || chunk.id} carries the runtime and is not described by this renderer`);
	}
	// A chunk carrying its own entry modules is wrapped in startup code built from
	// files this path neither claims nor pins.
	const chunkGraph = compilation.chunkGraph;
	if (!chunkGraph || typeof chunkGraph.getNumberOfEntryModules !== 'function') return noData('the compilation does not expose the entry modules of its chunks');
	if (chunkGraph.getNumberOfEntryModules(chunk) > 0) {
		return noData(`chunk ${chunk.name || chunk.id} starts its own entry modules, whose startup code this adapter does not describe`);
	}

	const base = registry.findByExport(api.RuntimeModule);
	const baseProblem = entryProblem(base, 'the webpack RuntimeModule base class');
	if (baseProblem) return baseProblem;
	if (path.basename(base.file) !== BASE_FILE) return noData(`the RuntimeModule base class comes from ${base.file}`);
	const lib = path.dirname(base.file);

	const entries = [];
	for (const relative of [RENDERER, FORMAT, ...HELPER_FILES]) {
		const entry = registry.getByFile(path.join(lib, ...relative.split('/')));
		const problem = entryProblem(entry, relative);
		if (problem) return problem;
		entries.push(entry);
	}
	const [renderer, , template, runtimeTemplate, runtimeGlobals] = entries;
	if (!api.javascript || api.javascript.JavascriptModulesPlugin !== renderer.exports) {
		return noData('the compiler renders its chunks with another JavascriptModulesPlugin');
	}
	if (api.Template !== template.exports || api.RuntimeGlobals !== runtimeGlobals.exports) {
		return noData('the compiler exposes helper modules other than the ones loaded from its lib directory');
	}

	const observed = registry.getRender(chunk);
	const call = observed && observed[CHUNK_HOOK];
	if (!call) return noData(`chunk ${chunk.name || chunk.id} was not observed being rendered`);
	for (const state of call.states) {
		const tapped = tapsProblem(state.taps);
		if (tapped) return noData(`${tapped} while chunk ${chunk.name || chunk.id} was rendered`);
	}
	// The stock tap on the module content is allowed, and then its source is
	// part of the claim.
	if (call.states[0].taps.get(MODULE_CONTENT).length > 0) {
		const entry = registry.getByFile(path.join(lib, API_PLUGIN_FILE));
		const problem = entryProblem(entry, API_PLUGIN_FILE);
		if (problem) return problem;
		entries.push(entry);
	}
	if (call.file !== renderer.file) return noData(`chunk ${chunk.name || chunk.id} was rendered by another plugin`);
	if (call.calls !== 1) return noData(`chunk ${chunk.name || chunk.id} was rendered ${call.calls} times`);
	const current = Object.getOwnPropertyDescriptor(prototypeOf(renderer.exports) || {}, CHUNK_HOOK);
	if (!current || current.value !== call.method) return noData(`${CHUNK_HOOK} is no longer the implementation that rendered this chunk`);
	// The graph and the generated module code this render read have to be the
	// ones of the compilation the caller is describing.
	const context = call.context;
	if (!context || context.chunkGraph !== chunkGraph || context.codeGenerationResults !== compilation.codeGenerationResults || context.runtimeTemplate !== compilation.runtimeTemplate) {
		return noData(`chunk ${chunk.name || chunk.id} was rendered from another compilation`);
	}
	// The chunk format carries the name of the global object into the text
	// unquoted.
	if (!IDENTIFIER.test(compilation.runtimeTemplate.globalObject)) {
		return noData(`chunk ${chunk.name || chunk.id} was rendered while the name of its global object is not an identifier`);
	}
	for (const state of call.states) {
		for (const entry of entries) {
			const atCall = state.helpers.get(entry.file);
			if (!atCall) return noData(`${relativeName(lib, entry.file)} was not loaded while the chunk was rendered`);
			const drift = compareMembers(entry.members, atCall.members, 'exports') || compareMembers(entry.prototypeMembers, atCall.prototypeMembers, 'prototype');
			if (drift) return noData(`${relativeName(lib, entry.file)} was not what it exported when it was loaded while the chunk was rendered: ${drift}`);
		}
	}
	for (const entry of entries) {
		const drift = compareMembers(entry.members, registry.snapshot(entry.exports), 'exports') || compareMembers(entry.prototypeMembers, registry.snapshot(prototypeOf(entry.exports)), 'prototype');
		if (drift) return noData(`${relativeName(lib, entry.file)} no longer exports what it exported when it was loaded: ${drift}`);
	}
	const source = call.result;
	if (!source || typeof source.source !== 'function') return noData(`the render of chunk ${chunk.name || chunk.id} produced no source`);
	const rendered = source.source();
	if (typeof rendered !== 'string') return noData(`the render of chunk ${chunk.name || chunk.id} produced no text`);

	const units = [];
	let component;
	for (const entry of entries) {
		const resolved = await verifyResource(entry.file);
		if (!resolved || (!resolved.unit && !resolved.failure)) return noData(`${entry.file} was not verified`);
		if (resolved.failure) return { units: [], failure: resolved.failure };
		const unit = resolved.unit;
		if (unit.sha256 !== entry.sha256) return failed('hash-mismatch', `${entry.file} differs from the bytes this process loaded from it`);
		if (unit.sha256 !== FINGERPRINTS.get(relativeName(lib, entry.file))) {
			return failed('unsupported', `${relativeName(lib, entry.file)} is not the source of the pinned webpack ${SUPPORTED_WEBPACK}`);
		}
		if (component === undefined) component = unit.component;
		else if (!sameJSON(component, unit.component)) return failed('invalid', `the webpack sources bind to conflicting components ${component.id} and ${unit.component.id}`);
		units.push({ path: unit.path, sha256: unit.sha256, component: unit.component });
	}
	if (component.version !== api.version) return failed('invalid', `component ${component.id} is not the webpack ${api.version} that is running`);
	return { units, rendered: Buffer.from(rendered, 'utf8') };
}

// A tap on a shaping hook contributes code this adapter cannot attribute to a
// verified source; the chunk format and the api plugin carry the two stock taps
// and nothing else stands beside them.
function tapsProblem(taps) {
	if (!taps) return 'the taps in place could not be observed';
	for (const name of [...SHAPING, CHUNK_HOOK, MODULE_CONTENT]) {
		const names = taps.get(name);
		if (!names) return `the ${name} taps could not be observed`;
		const stock = name === CHUNK_HOOK ? FORMAT_PLUGIN : name === MODULE_CONTENT ? API_PLUGIN : null;
		const foreign = stock === null ? names : names.filter((tap) => tap !== stock);
		if (foreign.length > 0) return `${foreign.join(', ')} tapped ${name}`;
	}
	// The chunk format is what wraps the modules; without its tap the text is
	// not the one these sources describe.
	const format = taps.get(CHUNK_HOOK);
	if (format.length !== 1) return `${format.length} plugins tapped ${CHUNK_HOOK}`;
	return null;
}

module.exports = { chunkEvidence };
