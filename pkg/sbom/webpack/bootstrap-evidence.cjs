'use strict';

// Binds the bootstrap of one rendered runtime chunk to the pinned webpack
// source that produced it: the chunk renderer of JavascriptModulesPlugin, seen
// from inside its own call, and the bytes that call produced, compared with the
// bytes the compilation was about to emit.
//
// Observing the emit hook is not a convenience: by the time the assets are on
// disk the compiler has replaced every asset source with a size-only one, so
// the bytes have to be taken while they still exist.
//
// Recordings come from runtime-preload.cjs; without it there is no data.

const path = require('node:path');

const { internals } = require('./runtime-evidence.cjs');

const { SUPPORTED_WEBPACK, FINGERPRINTS, compareMembers, relativeName, prototypeOf, entryProblem, sameJSON, failed, noData } = internals;
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const OBSERVER = 'DkSbomWebpackRuntimeObserver';
const RENDERER = 'javascript/JavascriptModulesPlugin.js';
const BASE_FILE = 'RuntimeModule.js';
const HELPER_FILES = ['Template.js', 'RuntimeTemplate.js', 'RuntimeGlobals.js'];
// Every hook whose taps can change the text the renderer returns, including the
// three that only decide whether code is inlined; none of them may be tapped.
const SHAPING = [
	'renderMain',
	'render',
	'renderContent',
	'renderStartup',
	'renderRequire',
	'renderModuleContainer',
	'renderModulePackage',
	'inlineInRuntimeBailout',
	'embedInRuntimeBailout',
	'strictRuntimeBailout',
];
// The one stock tap webpack itself always registers; it is described by its own
// verified source unit, and nothing else is allowed beside it.
const MODULE_CONTENT = 'renderModuleContent';
const API_PLUGIN = 'APIPlugin';
const API_PLUGIN_FILE = 'APIPlugin.js';

const emitted = new WeakMap();

function observeAssets(compiler) {
	compiler.hooks.emit.tap(OBSERVER, (compilation) => {
		const bytes = new Map();
		for (const asset of compilation.getAssets()) {
			const source = asset.source;
			if (!source || (typeof source.buffer !== 'function' && typeof source.source !== 'function')) continue;
			bytes.set(asset.name, Buffer.from(typeof source.buffer === 'function' ? source.buffer() : source.source()));
		}
		emitted.set(compilation, bytes);
	});
}

async function bootstrapEvidence(compilation, chunk, verifyResource, minifierEvidence) {
	const registry = globalThis[REGISTRY];
	if (!registry || typeof registry.getRender !== 'function' || typeof registry.snapshot !== 'function') {
		return noData('the commonjs load registry is not installed in this process');
	}
	const api = compilation.compiler && compilation.compiler.webpack;
	if (!api || typeof api.version !== 'string') return noData('the compiler does not expose its webpack');
	if (api.version !== SUPPORTED_WEBPACK) return failed('unsupported', `the chunk renderer of webpack ${api.version} is not described, only ${SUPPORTED_WEBPACK}`);
	if (typeof chunk.hasRuntime !== 'function' || !chunk.hasRuntime()) {
		return noData(`chunk ${chunk.name || chunk.id} is not rendered by the described main renderer`);
	}

	const base = registry.findByExport(api.RuntimeModule);
	const baseProblem = entryProblem(base, 'the webpack RuntimeModule base class');
	if (baseProblem) return baseProblem;
	if (path.basename(base.file) !== BASE_FILE) return noData(`the RuntimeModule base class comes from ${base.file}`);
	const lib = path.dirname(base.file);

	const entries = [];
	for (const relative of [RENDERER, ...HELPER_FILES]) {
		const entry = registry.getByFile(path.join(lib, ...relative.split('/')));
		const problem = entryProblem(entry, relative);
		if (problem) return problem;
		entries.push(entry);
	}
	const [renderer, template, runtimeTemplate, runtimeGlobals] = entries;
	if (!api.javascript || api.javascript.JavascriptModulesPlugin !== renderer.exports) {
		return noData('the compiler renders its chunks with another JavascriptModulesPlugin');
	}
	if (api.Template !== template.exports || api.RuntimeGlobals !== runtimeGlobals.exports) {
		return noData('the compiler exposes helper modules other than the ones loaded from its lib directory');
	}
	const rendererPrototype = prototypeOf(renderer.exports);

	const observed = registry.getRender(chunk);
	if (!observed || !observed.renderMain || !observed.renderBootstrap) {
		return noData(`the bootstrap of chunk ${chunk.name || chunk.id} was not observed being rendered`);
	}
	const calls = [['renderMain', observed.renderMain], ['renderBootstrap', observed.renderBootstrap]];
	for (const [name, call] of calls) {
		for (const state of call.states) {
			const tapped = tapsProblem(state.taps);
			if (tapped) return noData(`${tapped} while ${name} ran`);
		}
	}
	// The stock tap is allowed, and then its source is part of the claim.
	if (observed.renderMain.states[0].taps.get(MODULE_CONTENT).length > 0) {
		const entry = registry.getByFile(path.join(lib, API_PLUGIN_FILE));
		const problem = entryProblem(entry, API_PLUGIN_FILE);
		if (problem) return problem;
		entries.push(entry);
	}
	for (const [name, call] of calls) {
		if (call.file !== renderer.file) return noData(`${name} of another plugin rendered this chunk`);
		if (name === 'renderMain' ? call.calls !== 1 : call.calls < 1) return noData(`${name} ran ${call.calls} times for this chunk`);
		const current = rendererPrototype && Object.getOwnPropertyDescriptor(rendererPrototype, name);
		if (!current || current.value !== call.method) return noData(`${name} is no longer the implementation that rendered this chunk`);
		for (const state of call.states) {
			for (const entry of entries) {
				const atCall = state.helpers.get(entry.file);
				if (!atCall) return noData(`${relativeName(lib, entry.file)} was not loaded while ${name} ran`);
				const drift = compareMembers(entry.members, atCall.members, 'exports') || compareMembers(entry.prototypeMembers, atCall.prototypeMembers, 'prototype');
				if (drift) return noData(`${relativeName(lib, entry.file)} was not what it exported when it was loaded while ${name} ran: ${drift}`);
			}
		}
	}
	if (observed.renderMain.compilation !== compilation) return noData('the chunk was rendered for another compilation');
	for (const entry of entries) {
		const drift = compareMembers(entry.members, registry.snapshot(entry.exports), 'exports') || compareMembers(entry.prototypeMembers, registry.snapshot(prototypeOf(entry.exports)), 'prototype');
		if (drift) return noData(`${relativeName(lib, entry.file)} no longer exports what it exported when it was loaded: ${drift}`);
	}
	if (chunk.files.size !== 1) return noData(`chunk ${chunk.name || chunk.id} emits ${chunk.files.size} files`);
	const file = [...chunk.files][0];
	const bytes = emitted.get(compilation);
	if (!bytes || !bytes.has(file)) return noData(`the bytes of ${file} were not observed before they were emitted`);
	const source = observed.renderMain.result;
	if (!source || typeof source.source !== 'function') return noData(`the render of ${file} produced no source`);
	const rendered = source.source();
	if (typeof rendered !== 'string') return noData(`the render of ${file} produced no text`);
	const renderedBytes = Buffer.from(rendered, 'utf8');
	// A described minification is the one thing allowed to stand between the
	// render and the emit, and only for exactly the bytes that were rendered.
	const minified = minifierEvidence ? await minifierEvidence(compilation, file) : { status: 'none' };
	if (minified.failure) return { units: [], failure: minified.failure };
	if (minified.input && !minified.input.equals(renderedBytes)) {
		return noData(`${file} was changed between its render and its minification`);
	}
	// Anything else between the render and the emit - another minifier, a banner -
	// leaves bytes this adapter cannot attribute; it refuses rather than guesses.
	const final = minified.output || renderedBytes;
	if (!final.equals(bytes.get(file))) {
		return noData(`${file} was changed between its render and its emit`);
	}

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
	// The emit snapshot is not the end of the story: a plugin can still rewrite
	// the file afterwards, so the caller has to compare these bytes with the ones
	// that stayed on disk.
	return { units, requiredBytes: final };
}

// A tap on a shaping hook contributes code this adapter cannot attribute to a
// verified source; renderModuleContent carries the one stock tap and nothing else.
function tapsProblem(taps) {
	if (!taps) return 'the taps in place could not be observed';
	for (const name of [...SHAPING, MODULE_CONTENT]) {
		const names = taps.get(name);
		if (!names) return `the ${name} taps could not be observed`;
		const foreign = name === MODULE_CONTENT ? names.filter((tap) => tap !== API_PLUGIN) : names;
		if (foreign.length > 0) return `${foreign.join(', ')} tapped ${name}`;
	}
	return null;
}

module.exports = { bootstrapEvidence, observeAssets };
