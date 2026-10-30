'use strict';

// Opt-in CommonJS load recorder, used as `node --require runtime-preload.cjs`.
// It records, per compiled file, the digest of the source text Node executed and
// a snapshot of the exported members taken right after that execution, and it
// observes the generator of the three standard runtime module classes from
// inside the call. Requires nothing of webpack: it has to be wrapping the loader
// before the first webpack file is compiled.

const crypto = require('node:crypto');
const Module = require('node:module');
const path = require('node:path');

const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const OBSERVED = [
	'DefinePropertyGettersRuntimeModule.js',
	'HasOwnPropertyRuntimeModule.js',
	'MakeNamespaceObjectRuntimeModule.js',
	'NonceRuntimeModule.js',
	'EnsureChunkRuntimeModule.js',
	'GlobalRuntimeModule.js',
	'LoadScriptRuntimeModule.js',
	'JsonpChunkLoadingRuntimeModule.js',
	'GetChunkFilenameRuntimeModule.js',
	'PublicPathRuntimeModule.js',
	'AutoPublicPathRuntimeModule.js',
	'CompatGetDefaultExportRuntimeModule.js',
];
// Files that export their runtime modules as members of a namespace rather than
// as the whole of their exports.
const OBSERVED_MEMBERS = new Map([['AMDRuntimeModules.js', ['AMDDefineRuntimeModule', 'AMDOptionsRuntimeModule']]]);
const RENDERED = ['renderMain', 'renderBootstrap', 'renderChunk'];
const RENDERER = 'JavascriptModulesPlugin.js';
// The hooks of its own class through which a runtime module lets other plugins
// shape the text it generates.
const MODULE_HOOKS = new Map([
	['LoadScriptRuntimeModule.js', ['createScript']],
	['JsonpChunkLoadingRuntimeModule.js', ['linkPreload', 'linkPrefetch']],
]);
// The hook of the compilation through which a generated filename is built.
const PATH_HOOK = 'assetPath';
// The hooks that shape the source a runtime chunk is rendered from; a tap on
// any of them contributes code this registry cannot attribute.
const SHAPING = [
	'renderMain',
	'renderChunk',
	'render',
	'renderContent',
	'renderStartup',
	'renderRequire',
	'renderModuleContainer',
	'renderModulePackage',
	'renderModuleContent',
	'inlineInRuntimeBailout',
	'embedInRuntimeBailout',
	'strictRuntimeBailout',
];
const AT_CALL = [
	'RuntimeModule.js',
	'Template.js',
	'RuntimeTemplate.js',
	'RuntimeGlobals.js',
	'runtime/HelperRuntimeModule.js',
	'APIPlugin.js',
	'javascript/JavascriptModulesPlugin.js',
	'javascript/ArrayPushCallbackChunkFormatPlugin.js',
	'javascript/StartupHelpers.js',
	'util/compileBooleanMatcher.js',
	'TemplatedPathPlugin.js',
	'util/identifier.js',
	'util/SetHelpers.js',
	'Compilation.js',
];

if (!globalThis[REGISTRY]) {
	const entries = new Map();
	const generations = new WeakMap();
	const renders = new WeakMap();
	const compile = Module.prototype._compile;
	Module.prototype._compile = function (content, filename, ...rest) {
		const result = compile.call(this, content, filename, ...rest);
		record(entries, generations, renders, this, content, filename);
		return result;
	};
	Object.defineProperty(globalThis, REGISTRY, {
		value: Object.freeze({
			getByFile: (file) => entries.get(file),
			getGeneration: (runtimeModule) => generations.get(runtimeModule),
			getRender: (chunk) => renders.get(chunk),
			snapshot: (target) => members(target),
			// Several files, or several members of one file, holding the same
			// class make its owner ambiguous.
			findByExportedMember: (value) => {
				let found;
				for (const entry of entries.values()) {
					if (!('exports' in entry) || !entry.members) continue;
					for (const [key, descriptor] of entry.members) {
						if (descriptor.kind !== 'data' || descriptor.value !== value) continue;
						if (found) return undefined;
						found = { entry, key };
					}
				}
				return found;
			},
			// Several files exporting the same object make its owner ambiguous.
			findByExport: (value) => {
				let found;
				for (const entry of entries.values()) {
					if (!('exports' in entry) || entry.exports !== value) continue;
					if (found) return undefined;
					found = entry;
				}
				return found;
			},
		}),
		writable: false,
		enumerable: false,
		configurable: false,
	});
}

function record(entries, generations, renders, loaded, content, filename) {
	if (typeof filename !== 'string' || filename === '') return;
	if (entries.has(filename)) {
		entries.set(filename, unusable(filename, 'compiled more than once'));
		return;
	}
	if (typeof content !== 'string') {
		entries.set(filename, unusable(filename, 'compiled from a non-textual source'));
		return;
	}
	const exported = loaded.exports;
	// Before the snapshot, so that the wrapper is the generator the snapshot
	// holds and the one a module must still carry to be described.
	const base = path.basename(filename);
	if (OBSERVED.includes(base)) observe(entries, generations, exported, filename, null);
	for (const member of OBSERVED_MEMBERS.get(base) || []) observe(entries, generations, exported, filename, member);
	if (path.basename(filename) === RENDERER) observeRenders(entries, renders, exported, filename);
	const prototype = describe(exported, 'prototype');
	entries.set(
		filename,
		Object.freeze({
			file: filename,
			usable: true,
			sha256: `sha256:${crypto.createHash('sha256').update(Buffer.from(content, 'utf8')).digest('hex')}`,
			exports: exported,
			members: members(exported),
			prototypeMembers: prototype && 'value' in prototype ? members(prototype.value) : null,
			// The same, per declared member, for a file that exports a namespace
			// of classes instead of one class.
			memberPrototypes: memberPrototypes(exported, OBSERVED_MEMBERS.get(base) || []),
		}),
	);
}

function memberPrototypes(exported, names) {
	if (names.length === 0) return null;
	const byName = new Map();
	for (const name of names) {
		const owner = (describe(exported, name) || {}).value;
		const prototype = describe(owner, 'prototype');
		byName.set(name, prototype && 'value' in prototype ? members(prototype.value) : null);
	}
	return byName;
}

// What the generator of one runtime module instance really returned, and what
// the code it reads looked like at that very moment - a helper swapped for the
// duration of the call and restored afterwards is invisible from the outside.
// Every call is kept: a module whose code depends on the chunk hashes generates
// again while they are computed, and only one of those runs is the one used.
function observe(entries, generations, exported, file, member) {
	// A namespace of classes is observed one declared member at a time, and the
	// member is recorded with the generation so the siblings stay apart.
	const owner = member === null ? exported : (describe(exported, member) || {}).value;
	if (member !== null && typeof owner !== 'function') return;
	const prototype = describe(owner, 'prototype');
	if (!prototype || !('value' in prototype)) return;
	const descriptor = describe(prototype.value, 'generate');
	if (!descriptor || typeof descriptor.value !== 'function' || !descriptor.writable || !descriptor.configurable) return;
	const generate = descriptor.value;
	const lib = path.dirname(path.dirname(file));
	const hookNames = MODULE_HOOKS.get(path.basename(file)) || [];
	// Taken while the class is loaded: a replacement installed later is not what
	// these recordings are read through.
	const getHooks = typeof exported.getCompilationHooks === 'function' ? exported.getCompilationHooks : null;
	const wrapper = function (...args) {
		const compilation = this === null || typeof this !== 'object' ? null : this.compilation;
		// Every filename this generator builds, with the taps that built it, and
		// whether this recording was the one in place the whole time.
		const built = { calls: [], ownBefore: false, delegate: undefined, intact: false };
		const restore = recordPaths(compilation, built);
		let code;
		// Both sides of the call: a helper that swaps itself in, forges the text and
		// puts the original back during the call leaves an honest state behind.
		const before = state(entries, lib, file, this, getHooks, hookNames, exported);
		try {
			code = generate.apply(this, args);
		} finally {
			if (restore) restore();
		}
		const after = state(entries, lib, file, this, getHooks, hookNames, exported);
		const previous = generations.get(this);
		const run = Object.freeze({
			code,
			compilation,
			paths: restore ? Object.freeze({ ...built, calls: Object.freeze(built.calls) }) : null,
			states: Object.freeze([before, after]),
		});
		generations.set(this, Object.freeze({ file, member, method: wrapper, runs: Object.freeze(previous ? [...previous.runs, run] : [run]) }));
		return code;
	};
	Object.defineProperty(prototype.value, 'generate', { ...descriptor, value: wrapper });
}

// The filenames a generator builds come out of one method of the compilation;
// an own one for the duration of the call records what it was asked for and
// what was tapped at that very moment, without changing a single result.
//
// What the recording is worth is recorded with it: whether the compilation
// already carried a method of its own, which method this one delegates to, and
// whether it was still the one installed when the call returned. A generator
// that swaps the method away mid-call leaves that visible instead of leaving
// nothing behind.
function recordPaths(compilation, built) {
	if (compilation === null || typeof compilation !== 'object' || typeof compilation.getAssetPath !== 'function') return null;
	const own = Object.getOwnPropertyDescriptor(compilation, 'getAssetPath');
	const delegate = compilation.getAssetPath;
	const wrapper = function (filename, data) {
		built.calls.push(
			Object.freeze({
				template: typeof filename === 'string' ? filename : null,
				data: data === null || typeof data !== 'object' ? null : Object.freeze(Object.keys(data).sort()),
				taps: hookTaps(this.hooks, PATH_HOOK),
			}),
		);
		return delegate.call(this, filename, data);
	};
	try {
		Object.defineProperty(compilation, 'getAssetPath', { value: wrapper, writable: true, enumerable: false, configurable: true });
	} catch {
		return null;
	}
	built.ownBefore = Boolean(own);
	built.delegate = delegate;
	return () => {
		const now = Object.getOwnPropertyDescriptor(compilation, 'getAssetPath');
		built.intact = Boolean(now && now.value === wrapper);
		if (own) Object.defineProperty(compilation, 'getAssetPath', own);
		else delete compilation.getAssetPath;
	};
}

// What the chunk renderers of the pinned plugin really returned for one chunk,
// with the taps that were in place while they ran: a later reading sees neither,
// and by the time the assets are on disk their sources are size-only.
function observeRenders(entries, renders, exported, file) {
	const prototype = describe(exported, 'prototype');
	if (!prototype || !('value' in prototype)) return;
	const lib = path.dirname(path.dirname(file));
	for (const name of RENDERED) {
		const descriptor = describe(prototype.value, name);
		if (!descriptor || typeof descriptor.value !== 'function' || !descriptor.writable || !descriptor.configurable) continue;
		const rendered = descriptor.value;
		const wrapper = function (renderContext, hooks, compilation) {
			const chunk = renderContext && renderContext.chunk;
			const before = Object.freeze({ ...state(entries, lib, file, null), taps: taps(hooks) });
			const result = rendered.apply(this, arguments);
			const after = Object.freeze({ ...state(entries, lib, file, null), taps: taps(hooks) });
			if (chunk === null || (typeof chunk !== 'object' && typeof chunk !== 'function')) return result;
			const observed = renders.get(chunk) || {};
			const previous = observed[name];
			observed[name] = Object.freeze({
				file,
				result,
				method: wrapper,
				compilation: name === 'renderMain' ? compilation : undefined,
				// The graph and the generated code this render read its modules from.
				context: contextOf(renderContext),
				calls: previous ? previous.calls + 1 : 1,
				// renderBootstrap also runs while the chunk is hashed; every call it
				// makes has to have seen the pinned sources, not just the last.
				states: Object.freeze(previous ? [...previous.states, before, after] : [before, after]),
			});
			renders.set(chunk, observed);
			return result;
		};
		Object.defineProperty(prototype.value, name, { ...descriptor, value: wrapper });
	}
}

function contextOf(renderContext) {
	if (renderContext === null || typeof renderContext !== 'object') return null;
	return Object.freeze({
		chunkGraph: renderContext.chunkGraph,
		codeGenerationResults: renderContext.codeGenerationResults,
		runtimeTemplate: renderContext.runtimeTemplate,
	});
}

// The names of what is tapped, not just how many: the one stock tap that is
// always there has to be told apart from anything else.
function taps(hooks) {
	const named = new Map();
	for (const name of SHAPING) named.set(name, hookTaps(hooks, name));
	return named;
}

function hookTaps(hooks, name) {
	const hook = hooks && hooks[name];
	return hook && Array.isArray(hook.taps) ? Object.freeze(hook.taps.map((tap) => String(tap && tap.name))) : null;
}

function state(entries, lib, source, runtimeModule, getHooks, hookNames, exported) {
	return Object.freeze({
		helpers: helpersAtCall(entries, lib, source),
		runtimeTemplate: runtimeModule === null || runtimeModule === undefined ? null : templateAtCall(runtimeModule),
		hooks: moduleTaps(getHooks, exported, runtimeModule, hookNames),
	});
}

// The taps on the hooks of the class itself, read through the function it
// exported when it was loaded, while its generator runs.
function moduleTaps(getHooks, exported, runtimeModule, hookNames) {
	if (!hookNames || hookNames.length === 0) return null;
	const compilation = runtimeModule && runtimeModule.compilation;
	if (!getHooks || !compilation) return new Map(hookNames.map((name) => [name, null]));
	let hooks;
	try {
		hooks = getHooks.call(exported, compilation);
	} catch {
		return new Map(hookNames.map((name) => [name, null]));
	}
	const named = new Map();
	for (const name of hookNames) named.set(name, hookTaps(hooks, name));
	return named;
}

function helpersAtCall(entries, lib, source) {
	const snapshots = new Map();
	for (const file of [source, ...AT_CALL.map((relative) => path.join(lib, ...relative.split('/')))]) {
		const entry = entries.get(file);
		if (!entry || !entry.usable) continue;
		const prototype = describe(entry.exports, 'prototype');
		snapshots.set(
			file,
			Object.freeze({
				members: members(entry.exports),
				prototypeMembers: prototype && 'value' in prototype ? members(prototype.value) : null,
			}),
		);
	}
	return snapshots;
}

function templateAtCall(runtimeModule) {
	const compilation = runtimeModule && runtimeModule.compilation;
	const template = compilation && compilation.runtimeTemplate;
	if (template === null || (typeof template !== 'object' && typeof template !== 'function')) return null;
	return Object.freeze({ prototype: Object.getPrototypeOf(template), own: members(template) });
}

function unusable(file, reason) {
	return Object.freeze({ file, usable: false, reason });
}

// Descriptors only: reading a property would run an accessor of the very code
// this snapshot is supposed to describe from the outside.
function members(target) {
	if (target === null || (typeof target !== 'object' && typeof target !== 'function')) return null;
	const snapshot = new Map();
	const descriptors = Object.getOwnPropertyDescriptors(target);
	for (const key of Reflect.ownKeys(descriptors)) {
		const descriptor = descriptors[key];
		snapshot.set(
			key,
			Object.freeze(
				'value' in descriptor
					? { kind: 'data', value: descriptor.value, writable: descriptor.writable, enumerable: descriptor.enumerable, configurable: descriptor.configurable }
					: { kind: 'accessor', get: descriptor.get, set: descriptor.set, enumerable: descriptor.enumerable, configurable: descriptor.configurable },
			),
		);
	}
	return snapshot;
}

function describe(target, key) {
	if (target === null || (typeof target !== 'object' && typeof target !== 'function')) return undefined;
	return Object.getOwnPropertyDescriptor(target, key);
}
