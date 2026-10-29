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
const OBSERVED = ['DefinePropertyGettersRuntimeModule.js', 'HasOwnPropertyRuntimeModule.js', 'MakeNamespaceObjectRuntimeModule.js'];
const RENDERED = ['renderMain', 'renderBootstrap'];
const RENDERER = 'JavascriptModulesPlugin.js';
// The hooks that shape the source a runtime chunk is rendered from; a tap on
// any of them contributes code this registry cannot attribute.
const SHAPING = [
	'renderMain',
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
const AT_CALL = ['RuntimeModule.js', 'Template.js', 'RuntimeTemplate.js', 'RuntimeGlobals.js', 'runtime/HelperRuntimeModule.js', 'APIPlugin.js'];

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
	if (OBSERVED.includes(path.basename(filename))) observe(entries, generations, exported, filename);
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
		}),
	);
}

// What the generator of one runtime module instance really returned, and what
// the code it reads looked like at that very moment - a helper swapped for the
// duration of the call and restored afterwards is invisible from the outside.
function observe(entries, generations, exported, file) {
	const prototype = describe(exported, 'prototype');
	if (!prototype || !('value' in prototype)) return;
	const descriptor = describe(prototype.value, 'generate');
	if (!descriptor || typeof descriptor.value !== 'function' || !descriptor.writable || !descriptor.configurable) return;
	const generate = descriptor.value;
	const lib = path.dirname(path.dirname(file));
	const wrapper = function (...args) {
		// Both sides of the call: a helper that swaps itself in, forges the text and
		// puts the original back during the call leaves an honest state behind.
		const before = state(entries, lib, file, this);
		const code = generate.apply(this, args);
		const after = state(entries, lib, file, this);
		if (generations.has(this)) {
			generations.set(this, Object.freeze({ file, reason: 'generated more than once' }));
		} else {
			generations.set(this, Object.freeze({ file, code, method: wrapper, compilation: this.compilation, states: Object.freeze([before, after]) }));
		}
		return code;
	};
	Object.defineProperty(prototype.value, 'generate', { ...descriptor, value: wrapper });
}

// What the chunk renderer of the pinned plugin really returned for one chunk,
// with the taps that were in place while it ran: a later reading sees neither,
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
				calls: previous ? previous.calls + 1 : 1,
				taps: taps(hooks),
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

// The names of what is tapped, not just how many: the one stock tap that is
// always there has to be told apart from anything else.
function taps(hooks) {
	const named = new Map();
	for (const name of SHAPING) {
		const hook = hooks && hooks[name];
		named.set(name, hook && Array.isArray(hook.taps) ? Object.freeze(hook.taps.map((tap) => String(tap && tap.name))) : null);
	}
	return named;
}

function state(entries, lib, source, runtimeModule) {
	return Object.freeze({ helpers: helpersAtCall(entries, lib, source), runtimeTemplate: runtimeModule === null ? null : templateAtCall(runtimeModule) });
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
