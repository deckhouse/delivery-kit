'use strict';

// Opt-in recorder of the two loaders of a style-loader 3 chain, used as
// `node --require stylesheet3-preload.cjs`. It wraps the pitch style-loader
// exports and the loader css-loader exports the moment their file is compiled,
// and records per built module what the published function was given, what the
// requests it wrote were contextified from, and what it returned.
//
// It composes the commonjs load recorder rather than replacing it: the registry
// records a file right after it runs and before this file wraps anything, so
// every function the registry holds is the published one and the wrappers
// installed here can be told apart from it by identity.
//
// Both loaders build the requests of their generated code through the loader
// context rather than from their own text - style-loader through
// `utils.contextify` and css-loader through loader-utils - so what those calls
// answered is recorded as it happens. A request is never recomputed from a path
// this recorder guessed: the module behind each one is held against the graph.

require('./runtime-preload.cjs');

const crypto = require('node:crypto');
const Module = require('node:module');
const path = require('node:path');

const STYLESHEET3 = Symbol.for('dk.sbom.webpack.stylesheet3');
// The published artifacts this recorder knows how to read, by the bytes of the
// file node compiles and by the place they occupy in their distribution. An
// alias changes the directory and neither of those.
const KNOWN = [
	{ kind: 'style', suffix: path.join('dist', 'index.js'), package: 'style-loader', sha256: 'sha256:96b6870d8119a984c56a74e32dc44e5fb919d13dfc892ffbd4f93b797f7381c7' },
	{ kind: 'css', suffix: path.join('dist', 'index.js'), package: 'css-loader', sha256: 'sha256:7ab8378e32b9a131eae561322265b73682ed2b81130051611476fe1f23a002af' },
];

if (!globalThis[STYLESHEET3]) {
	const loaders = new Map();
	const pitches = new WeakMap();
	const calls = new WeakMap();
	const compile = Module.prototype._compile;
	Module.prototype._compile = function (content, filename, ...rest) {
		const result = compile.call(this, content, filename, ...rest);
		recognize(loaders, pitches, calls, this, content, filename);
		return result;
	};
	Object.defineProperty(globalThis, STYLESHEET3, {
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

// style-loader exports its api as the default member of a commonjs module, and
// pitches through it.
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
		const requests = [];
		const restore = recordContextify(this, requests);
		let output;
		try {
			output = original.apply(this, args);
		} finally {
			if (restore) restore();
		}
		const after = state(loaders);
		remember(pitches, this && this._module, {
			file,
			method: wrapper,
			output,
			request: args[0],
			arity: args.length,
			context: contextOf(this),
			requests: Object.freeze(requests),
			states: Object.freeze([before, after]),
		});
		return output;
	};
	keep(wrapper, original);
	const members = snapshot(api);
	Object.defineProperty(api, 'pitch', { ...descriptor, value: wrapper });
	return Object.freeze({ kind: known.kind, file, usable: true, sha256: known.sha256, exports: exported, api, original, wrapper, members });
}

// css-loader is an ordinary loader that answers through the callback of
// this.async(), so both what it was handed and what it wrote are recorded
// around one call.
function wrapLoader(loaders, calls, known, loaded, file) {
	const exported = loaded.exports;
	const descriptor = own(exported, 'default');
	if (!descriptor || typeof descriptor.value !== 'function' || !descriptor.writable || !descriptor.configurable) {
		return Object.freeze({ kind: known.kind, file, usable: false, reason: 'exports no replaceable loader function' });
	}
	const original = descriptor.value;
	const wrapper = function (...args) {
		const before = state(loaders);
		const answers = [];
		const restore = recordAsync(this, answers);
		try {
			original.apply(this, args);
		} finally {
			if (restore) restore();
		}
		remember(calls, this && this._module, {
			file,
			method: wrapper,
			input: args[0],
			map: args[1],
			meta: args[2],
			arity: args.length,
			context: contextOf(this),
			answers,
			states: Object.freeze([before, state(loaders)]),
		});
	};
	keep(wrapper, original);
	const members = snapshot(exported);
	Object.defineProperty(exported, 'default', { ...descriptor, value: wrapper });
	return Object.freeze({ kind: known.kind, file, usable: true, sha256: known.sha256, exports: exported, original, wrapper, members });
}

// What `utils.contextify` answered while the loader ran. style-loader writes
// every request of its generated code through it, so these are the requests
// themselves rather than a reconstruction of them.
function recordContextify(loaderContext, requests) {
	const utils = loaderContext === null || typeof loaderContext !== 'object' ? null : loaderContext.utils;
	if (utils === null || typeof utils !== 'object' || typeof utils.contextify !== 'function') return null;
	const descriptor = Object.getOwnPropertyDescriptor(utils, 'contextify');
	const delegate = utils.contextify;
	const wrapper = function (context, request, ...rest) {
		const answer = delegate.apply(this, arguments);
		requests.push(Object.freeze({ context, request, answer, arity: arguments.length }));
		return answer;
	};
	try {
		Object.defineProperty(utils, 'contextify', { value: wrapper, writable: true, enumerable: true, configurable: true });
	} catch {
		return null;
	}
	return () => {
		const now = Object.getOwnPropertyDescriptor(utils, 'contextify');
		requests.intact = Boolean(now && now.value === wrapper);
		if (descriptor) Object.defineProperty(utils, 'contextify', descriptor);
		else delete utils.contextify;
	};
}

function recordAsync(loaderContext, answers) {
	if (loaderContext === null || typeof loaderContext !== 'object' || typeof loaderContext.async !== 'function') return null;
	const descriptor = Object.getOwnPropertyDescriptor(loaderContext, 'async');
	const delegate = loaderContext.async;
	const wrapper = function (...args) {
		const callback = delegate.apply(this, args);
		if (typeof callback !== 'function') return callback;
		return function (error, content, sourceMap, ...tail) {
			answers.push(Object.freeze({ error, content, sourceMap, arity: arguments.length }));
			return callback.apply(this, arguments);
		};
	};
	try {
		Object.defineProperty(loaderContext, 'async', { value: wrapper, writable: true, enumerable: false, configurable: true });
	} catch {
		return null;
	}
	return () => {
		const now = Object.getOwnPropertyDescriptor(loaderContext, 'async');
		answers.intact = Boolean(now && now.value === wrapper);
		if (descriptor) Object.defineProperty(loaderContext, 'async', descriptor);
		else delete loaderContext.async;
	};
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
		rootContext: loaderContext.rootContext,
		loaderIndex: loaderContext.loaderIndex,
		loaderCount: chain ? chain.length : null,
		hot: loaderContext.hot,
		sourceMap: loaderContext.sourceMap,
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
		snapshotted.set(info.file, Object.freeze({ exports: require.cache[info.file]?.exports, members: snapshot(info.api || info.exports) }));
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
