'use strict';

// Rebuilds the wrapper webpack's UmdLibraryPlugin puts around the code of a
// chunk when the build asks for a library of type `umd`.
//
// Redoc's bundles are built that way (`webpack.config.ts:46-47`), so the asset
// is the rendered chunk between a prologue naming the library and its externals
// and an epilogue of three characters. The prologue is code, and the data in it
// - the name of the library, the requests of the externals, the global object -
// is read off the build and written out again here, so what stands in the asset
// is accounted for rather than trusted.
//
// The externals named in it are references, not code: each is a module of the
// graph with no source of its own, and this adapter claims nothing for them.
//
// The load recordings come from runtime-preload.cjs; without them there is no
// data.

const path = require('node:path');

const { internals } = require('./runtime-evidence.cjs');

const { SUPPORTED_WEBPACK, compareMembers, prototypeOf, failed, noData } = internals;
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const BASE_FILE = 'RuntimeModule.js';
// The two files the wrapper is written in: the one that builds the text, and
// the one that decides which chunks get it at all.
// Their raw bytes in the webpack 5.94.0 registry archive whose sha512 is the
// integrity pinned in package-lock.json.
const CLASS_FILES = new Map([
	['library/UmdLibraryPlugin.js', 'sha256:6d0cd572002fb99a86bd98c0d8ffb317d49af6595f2fa5f8db225e84e3e5b2ed'],
	['library/AbstractLibraryPlugin.js', 'sha256:90d15ed7d1d9b2e752bafacb6907deec657cbd6bafb18a444dba0c08c45c6c1e'],
	// Installed beside the wrapper for every library that can export a member
	// of its own. Its source adds nothing to a library that exports none, which
	// is the only shape this adapter describes.
	['library/ExportPropertyLibraryPlugin.js', 'sha256:baf249c2eca112e4bc535f2e41344f44b9709e9bdacf6bb4ccdef3dbf8fda912'],
]);
const PLUGIN_TAP = 'UmdLibraryPlugin';
const EXPORT_TAP = 'ExportPropertyLibraryPlugin';
const DESCRIBED_TYPE = 'umd';
const EXTERNAL_TYPES = new Set(['umd', 'umd2']);
const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
// A name or a request carrying one of these would be rewritten per chunk by the
// path templating this adapter does not describe.
const TEMPLATED = /[[\]]/;

async function umdEvidence(compilation, chunk, verifyResource) {
	const registry = globalThis[REGISTRY];
	if (!registry || typeof registry.getByFile !== 'function' || typeof registry.findByExport !== 'function') {
		return noData('the commonjs load registry is not installed in this process');
	}
	const api = compilation.compiler && compilation.compiler.webpack;
	if (!api || typeof api.version !== 'string') return noData('the compiler does not expose its webpack');
	if (api.version !== SUPPORTED_WEBPACK) return failed('unsupported', `the libraries of webpack ${api.version} are not described, only ${SUPPORTED_WEBPACK}`);

	const base = registry.findByExport(api.RuntimeModule);
	if (!base || !base.usable) return noData('the webpack RuntimeModule base class was not observed being loaded by this process');
	if (path.basename(base.file) !== BASE_FILE) return noData(`the RuntimeModule base class comes from ${base.file}`);
	const lib = path.dirname(base.file);

	const entries = [];
	for (const relative of CLASS_FILES.keys()) {
		const entry = registry.getByFile(path.join(lib, ...relative.split('/')));
		if (!entry || !entry.usable || !('exports' in entry)) return noData(`${relative} was not observed being loaded by this process`);
		const drift = compareMembers(entry.members, registry.snapshot(entry.exports), 'exports') || compareMembers(entry.prototypeMembers, registry.snapshot(prototypeOf(entry.exports)), 'prototype');
		if (drift) return noData(`${relative} no longer exports what it exported when it was loaded: ${drift}`);
		entries.push(entry);
	}
	// The classes that shape the chunk must be the ones those files export, and
	// both must still derive from the one that decides who gets them.
	if (Object.getPrototypeOf(entries[0].exports) !== entries[1].exports) return noData('UmdLibraryPlugin no longer derives from the loaded AbstractLibraryPlugin');
	if (Object.getPrototypeOf(entries[2].exports) !== entries[1].exports) return noData('ExportPropertyLibraryPlugin no longer derives from the loaded AbstractLibraryPlugin');

	const shaped = shapeOf(compilation, chunk, api);
	if (shaped.failure) return shaped;
	const taps = renderTaps(api, compilation);
	if (taps === null) return noData('the taps shaping the chunks of this compilation could not be observed');
	if (taps.length !== 1 || taps[0] !== PLUGIN_TAP) {
		return noData(`${taps.join(', ') || 'nothing'} shaped the chunks of this compilation besides its library wrapper`);
	}

	const units = [];
	for (const [index, [relative, fingerprint]] of [...CLASS_FILES].entries()) {
		const entry = entries[index];
		let resolved;
		try {
			resolved = await verifyResource(entry.file);
		} catch (error) {
			return noData(`${entry.file} could not be verified: ${error.message}`);
		}
		if (!resolved || (!resolved.unit && !resolved.failure)) return noData(`${entry.file} was not verified`);
		if (resolved.failure) return { units: [], failure: resolved.failure };
		if (resolved.unit.sha256 !== entry.sha256) return failed('hash-mismatch', `${entry.file} differs from the bytes this process loaded from it`);
		if (resolved.unit.sha256 !== fingerprint) {
			return failed('unsupported', `${relative} is not the source of the pinned webpack ${SUPPORTED_WEBPACK}`);
		}
		if (resolved.unit.component.version !== api.version) return failed('invalid', `component ${resolved.unit.component.id} is not the webpack ${api.version} that is running`);
		units.push({ path: resolved.unit.path, sha256: resolved.unit.sha256, component: resolved.unit.component });
	}
	return {
		units,
		prefix: prologue(shaped),
		suffix: ';\n})',
		externals: shaped.externals.map((external) => external.request),
		// The hooks these two shape the chunk through, and nothing else.
		taps: new Map([['render', PLUGIN_TAP], ['renderStartup', EXPORT_TAP]]),
	};
}

// Everything the wrapper is written out of, taken off this build: refused
// wherever the text would be shaped by something this adapter does not read.
function shapeOf(compilation, chunk, api) {
	// A chunk with no entry module of its own is rendered without a wrapper at
	// all; the library of an entry is the one its own options name, which may be
	// `false` to say it has none.
	if (compilation.chunkGraph.getNumberOfEntryModules(chunk) === 0) return noData(`chunk ${chunk.name || chunk.id} carries no entry module to wrap as a library`);
	const entry = chunk.getEntryOptions();
	const library = entry && entry.library !== undefined ? entry.library : compilation.outputOptions.library;
	if (!library || library.type !== DESCRIBED_TYPE) return noData(`chunk ${chunk.name || chunk.id} is not wrapped as a library of type ${DESCRIBED_TYPE}`);
	if (typeof library.name !== 'string') return noData('the library of this build is not named with a name of its own');
	if (TEMPLATED.test(library.name)) return noData('the library of this build is named with a template');
	if (library.auxiliaryComment !== undefined) return noData('the library of this build carries comments of its own');
	if (library.umdNamedDefine === true) return noData('the library of this build names itself to its amd loader');
	if (library.export !== undefined) return noData('the library of this build exports a member of its own');

	const runtimeTemplate = compilation.runtimeTemplate;
	const globalObject = runtimeTemplate && runtimeTemplate.outputOptions && runtimeTemplate.outputOptions.globalObject;
	// It is written into the wrapper as code, so only a name can stand there.
	if (typeof globalObject !== 'string' || !IDENTIFIER.test(globalObject)) return noData('this build reaches its global object by something other than a name');

	const externals = [];
	for (const module of compilation.chunkGraph.getChunkModules(chunk)) {
		if (!(module instanceof api.ExternalModule) || !EXTERNAL_TYPES.has(module.externalType)) continue;
		// Only a request that is one name: the other shapes name a different
		// request per loader, or reach into a member of it.
		if (typeof module.request !== 'string') return noData(`chunk ${chunk.name || chunk.id} references an external this adapter does not describe`);
		if (TEMPLATED.test(module.request)) return noData(`chunk ${chunk.name || chunk.id} references an external named with a template`);
		if (module.isOptional(compilation.moduleGraph)) return noData(`chunk ${chunk.name || chunk.id} references an external it can do without`);
		externals.push({ request: module.request, id: `${compilation.chunkGraph.getModuleId(module)}` });
	}
	return { name: library.name, globalObject, arrow: runtimeTemplate.supportsArrowFunction() === true, externals, toIdentifier: api.Template.toIdentifier };
}

// The text UmdLibraryPlugin.js:288-337 builds for a library named with one
// name, in front of the code of the chunk.
function prologue(shaped) {
	const { name, globalObject, arrow, externals } = shaped;
	const quoted = JSON.stringify(name);
	const args = externals.map((external) => `__WEBPACK_EXTERNAL_MODULE_${shaped.toIdentifier(external.id)}__`).join(', ');
	const required = externals.map((external) => `require(${JSON.stringify(external.request)})`).join(', ');
	const roots = externals.map((external) => `root[${JSON.stringify(external.request)}]`).join(', ');
	const deps = `[${externals.map((external) => JSON.stringify(external.request)).join(', ')}]`;
	return (
		'(function webpackUniversalModuleDefinition(root, factory) {\n' +
		"	if(typeof exports === 'object' && typeof module === 'object')\n" +
		`		module.exports = factory(${required});\n` +
		"	else if(typeof define === 'function' && define.amd)\n" +
		`		define(${deps}, factory);\n` +
		"	else if(typeof exports === 'object')\n" +
		`		exports[${quoted}] = factory(${required});\n` +
		'	else\n' +
		`		root[${quoted}] = factory(${roots});\n` +
		`})(${globalObject}, ${arrow ? `(${args}) =>` : `function(${args})`} {\nreturn `
	);
}

// The taps that shape the rendered code of a chunk; the wrapper is the only one
// this adapter accounts for.
function renderTaps(api, compilation) {
	const hooks = api.javascript && api.javascript.JavascriptModulesPlugin && api.javascript.JavascriptModulesPlugin.getCompilationHooks(compilation);
	if (!hooks || !hooks.render || !Array.isArray(hooks.render.taps)) return null;
	return hooks.render.taps.map((tap) => tap.name);
}

module.exports = { umdEvidence };
