'use strict';

// Opt-in recorder of the two stylesheet loaders, used as
// `node --require stylesheet-preload.cjs`. It wraps the exported loader of
// style-loader and of raw-loader the moment their file is compiled, and records
// per built module what the published function was given and what it returned.
//
// It composes the commonjs load recorder rather than replacing it: the registry
// records a file right after it runs and before this file wraps anything, so
// every function the registry holds is the published one and the wrappers
// installed here can be told apart from it by identity.

require('./runtime-preload.cjs');

const crypto = require('node:crypto');
const Module = require('node:module');
const path = require('node:path');

const STYLESHEET = Symbol.for('dk.sbom.webpack.stylesheet');
// The published artifacts this recorder knows how to read, by the bytes of the
// file node compiles and by the place they occupy in their distribution.
const KNOWN = [
	{ kind: 'style', suffix: path.join('style-loader', 'dist', 'index.js'), sha256: 'sha256:ca8bd425c4b174b307cd98525514c088a04dca73ae8e476066ddffa79d317f41' },
	{ kind: 'raw', suffix: path.join('raw-loader', 'index.js'), sha256: 'sha256:caa83fec5bfb9c0544967fb0ce9b94d10e984c97bd427c7b69a8fb23771cf5c0' },
];

if (!globalThis[STYLESHEET]) {
	const loaders = new Map();
	const pitches = new WeakMap();
	const calls = new WeakMap();
	const compile = Module.prototype._compile;
	Module.prototype._compile = function (content, filename, ...rest) {
		const result = compile.call(this, content, filename, ...rest);
		recognize(loaders, pitches, calls, this, content, filename);
		return result;
	};
	Object.defineProperty(globalThis, STYLESHEET, {
		value: Object.freeze({
			loaderOf: (kind) => loaders.get(kind),
			pitchOf: (module) => pitches.get(module),
			callOf: (module) => calls.get(module),
		}),
		writable: false,
		enumerable: false,
		configurable: false,
	});
}

function recognize(loaders, pitches, calls, loaded, content, filename) {
	if (typeof filename !== 'string' || typeof content !== 'string') return;
	const known = KNOWN.find((candidate) => filename.endsWith(path.sep + candidate.suffix) && digest(content) === candidate.sha256);
	if (!known) return;
	if (loaders.has(known.kind)) {
		loaders.set(known.kind, Object.freeze({ kind: known.kind, file: filename, usable: false, reason: 'loaded more than once' }));
		return;
	}
	loaders.set(known.kind, known.kind === 'style' ? wrapPitch(loaders, pitches, known, loaded, filename) : wrapLoader(loaders, calls, known, loaded, filename));
}

function wrapPitch(loaders, pitches, known, loaded, file) {
	const exported = loaded.exports;
	const api = exported === null || typeof exported !== 'object' ? undefined : exported.default;
	const descriptor = own(api, 'pitch');
	if (!descriptor || typeof descriptor.value !== 'function' || !descriptor.writable || !descriptor.configurable) {
		return Object.freeze({ kind: known.kind, file, usable: false, reason: 'exports no replaceable pitch function' });
	}
	const original = descriptor.value;
	const wrapper = function (...args) {
		const before = state(loaders);
		const output = original.apply(this, args);
		const after = state(loaders);
		remember(pitches, this && this._module, { file, method: wrapper, output, request: args[0], arity: args.length, context: contextOf(this), states: Object.freeze([before, after]) });
		return output;
	};
	keep(wrapper, original);
	// The members of the loader api as they were before this wrapper went in:
	// the published pitch is the one this descriptor names.
	const members = snapshot(api);
	Object.defineProperty(api, 'pitch', { ...descriptor, value: wrapper });
	return Object.freeze({ kind: known.kind, file, usable: true, sha256: known.sha256, exports: exported, api, original, wrapper, members });
}

function wrapLoader(loaders, calls, known, loaded, file) {
	const original = loaded.exports;
	if (typeof original !== 'function') return Object.freeze({ kind: known.kind, file, usable: false, reason: 'exports no loader function' });
	const wrapper = function (...args) {
		const before = state(loaders);
		const output = original.apply(this, args);
		const after = state(loaders);
		remember(calls, this && this._module, { file, method: wrapper, output, input: args[0], arity: args.length, context: contextOf(this), states: Object.freeze([before, after]) });
		return output;
	};
	keep(wrapper, original);
	const members = snapshot(original);
	loaded.exports = wrapper;
	return Object.freeze({ kind: known.kind, file, usable: true, sha256: known.sha256, original, wrapper, members });
}

function remember(records, key, record) {
	if (key === null || (typeof key !== 'object' && typeof key !== 'function')) return;
	if (records.has(key)) {
		records.set(key, Object.freeze({ file: record.file, usable: false, reason: 'ran more than once for this module' }));
		return;
	}
	records.set(key, Object.freeze({ ...record, usable: true }));
}

// What the loader was told about the module it was running for. The context is
// emptied once the chain is done, so none of this can be read afterwards.
function contextOf(loaderContext) {
	if (loaderContext === null || typeof loaderContext !== 'object') return null;
	const chain = Array.isArray(loaderContext.loaders) ? loaderContext.loaders : null;
	const item = chain ? chain[loaderContext.loaderIndex] : undefined;
	const options = item === null || typeof item !== 'object' ? undefined : item.options;
	return Object.freeze({
		resourcePath: loaderContext.resourcePath,
		resourceQuery: loaderContext.resourceQuery,
		resourceFragment: loaderContext.resourceFragment,
		context: loaderContext.context,
		loaderIndex: loaderContext.loaderIndex,
		loaderCount: chain ? chain.length : null,
		hot: loaderContext.hot,
		options,
		optionKeys: options === null || typeof options !== 'object' ? null : Object.freeze(Reflect.ownKeys(options).map(String)),
		query: loaderContext.query,
	});
}

// Both sides of the call: a loader whose helpers are swapped in for the
// duration of the call and put back afterwards leaves an honest state behind.
function state(loaders) {
	const snapshotted = new Map();
	for (const info of loaders.values()) {
		if (!info.usable) continue;
		snapshotted.set(info.file, Object.freeze({ exports: require.cache[info.file]?.exports, members: snapshot(info.api || info.wrapper) }));
	}
	return snapshotted;
}

function keep(wrapper, original) {
	Object.defineProperties(wrapper, Object.getOwnPropertyDescriptors(original));
}

// Descriptors only: reading a property would run an accessor of the very code
// this snapshot is supposed to describe from the outside.
function snapshot(target) {
	if (target === null || (typeof target !== 'object' && typeof target !== 'function')) return null;
	const members = new Map();
	const descriptors = Object.getOwnPropertyDescriptors(target);
	for (const key of Reflect.ownKeys(descriptors)) {
		const descriptor = descriptors[key];
		members.set(
			key,
			Object.freeze(
				'value' in descriptor
					? { kind: 'data', value: descriptor.value, writable: descriptor.writable, enumerable: descriptor.enumerable, configurable: descriptor.configurable }
					: { kind: 'accessor', get: descriptor.get, set: descriptor.set, enumerable: descriptor.enumerable, configurable: descriptor.configurable },
			),
		);
	}
	return members;
}

function own(target, key) {
	if (target === null || (typeof target !== 'object' && typeof target !== 'function')) return undefined;
	return Object.getOwnPropertyDescriptor(target, key);
}

function digest(content) {
	return `sha256:${crypto.createHash('sha256').update(Buffer.from(content, 'utf8')).digest('hex')}`;
}
