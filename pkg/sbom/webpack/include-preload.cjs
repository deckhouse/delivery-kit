'use strict';

// Opt-in recorder of the include loader of monaco-editor-webpack-plugin, used
// as `node --require include-preload.cjs`. It wraps the exported pitch function
// the moment the loader file is compiled, and records per built module what the
// published function was given, what it was told, and what it returned.
//
// It composes the commonjs load recorder rather than replacing it: the registry
// records a file right after it runs and before this file wraps anything, so
// the function the registry holds is the published one and the wrapper
// installed here can be told apart from it by identity.
//
// The loader turns the requests it is given into text through the contextify of
// its own loader context, which belongs to webpack and not to the loader: every
// call of it is recorded too, so that what the loader wrote can be recomputed
// without calling anything again.

require('./runtime-preload.cjs');

const crypto = require('node:crypto');
const Module = require('node:module');
const path = require('node:path');

const INCLUDE = Symbol.for('dk.sbom.webpack.include');
// The published artifact this recorder knows how to read, by the bytes of the
// file node compiles and by the place it occupies in its distribution.
const KNOWN = {
	suffix: path.join('monaco-editor-webpack-plugin', 'out', 'loaders', 'include.js'),
	sha256: 'sha256:5bb553fd45212f2f3e08f87dddea60bb83aa7dd92583113a35248a9338ec8a69',
};

if (!globalThis[INCLUDE]) {
	let loader;
	const pitches = new WeakMap();
	const compile = Module.prototype._compile;
	Module.prototype._compile = function (content, filename, ...rest) {
		const result = compile.call(this, content, filename, ...rest);
		if (typeof filename === 'string' && typeof content === 'string' && filename.endsWith(path.sep + KNOWN.suffix) && digest(content) === KNOWN.sha256) {
			loader = loader ? Object.freeze({ file: filename, usable: false, reason: 'loaded more than once' }) : wrap(pitches, this, filename);
		}
		return result;
	};
	Object.defineProperty(globalThis, INCLUDE, {
		value: Object.freeze({ loader: () => loader, pitchOf: (module) => pitches.get(module) }),
		writable: false,
		enumerable: false,
		configurable: false,
	});
}

function wrap(pitches, loaded, file) {
	const exported = loaded.exports;
	const descriptor = own(exported, 'pitch');
	if (!descriptor || typeof descriptor.value !== 'function' || !descriptor.writable || !descriptor.configurable) {
		return Object.freeze({ file, usable: false, reason: 'exports no replaceable pitch function' });
	}
	const original = descriptor.value;
	const wrapper = function (...args) {
		// What webpack turned each request into, recorded where the loader asks
		// for it: the loader's own text is built out of these answers.
		const contextified = [];
		const restore = recordContextify(this, contextified);
		let output;
		try {
			output = original.apply(this, args);
		} finally {
			if (restore) restore();
		}
		remember(pitches, this && this._module, {
			file,
			method: wrapper,
			output,
			request: args[0],
			arity: args.length,
			context: contextOf(this),
			contextified: Object.freeze(contextified),
			userRequest: this && this._module ? this._module.userRequest : undefined,
		});
		return output;
	};
	keep(wrapper, original);
	const members = snapshot(exported);
	Object.defineProperty(exported, 'pitch', { ...descriptor, value: wrapper });
	return Object.freeze({ file, usable: true, sha256: KNOWN.sha256, exports: exported, original, wrapper, members });
}

// An own contextify for the duration of the call, delegating and changing
// nothing. What it was before and whether it was still in place afterwards is
// recorded with the answers, so a utils object swapped mid-call is visible.
function recordContextify(loaderContext, contextified) {
	const utils = loaderContext === null || typeof loaderContext !== 'object' ? null : loaderContext.utils;
	if (utils === null || typeof utils !== 'object' || typeof utils.contextify !== 'function') return null;
	const own = Object.getOwnPropertyDescriptor(utils, 'contextify');
	const delegate = utils.contextify;
	const wrapper = function (context, request) {
		const answer = delegate.apply(this, arguments);
		contextified.push(Object.freeze({ context, request, answer, arity: arguments.length }));
		return answer;
	};
	try {
		Object.defineProperty(utils, 'contextify', { value: wrapper, writable: true, enumerable: false, configurable: true });
	} catch {
		return null;
	}
	contextified.recorded = true;
	contextified.delegate = delegate;
	return () => {
		const now = Object.getOwnPropertyDescriptor(utils, 'contextify');
		contextified.intact = Boolean(now && now.value === wrapper);
		if (own) Object.defineProperty(utils, 'contextify', own);
		else delete utils.contextify;
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
		options,
		query: loaderContext.query,
		utils: loaderContext.utils,
	});
}

function snapshot(target) {
	if (target === null || (typeof target !== 'object' && typeof target !== 'function')) return null;
	const members = new Map();
	for (const key of Reflect.ownKeys(target)) {
		const descriptor = Object.getOwnPropertyDescriptor(target, key);
		members.set(key, 'value' in descriptor ? Object.freeze({ kind: 'data', value: descriptor.value }) : Object.freeze({ kind: 'accessor' }));
	}
	return members;
}

function own(target, key) {
	if (target === null || (typeof target !== 'object' && typeof target !== 'function')) return null;
	return Object.getOwnPropertyDescriptor(target, key);
}

function keep(wrapper, original) {
	Object.defineProperty(wrapper, 'name', { value: original.name, configurable: true });
	Object.defineProperty(wrapper, 'length', { value: original.length, configurable: true });
}

function digest(content) {
	return `sha256:${crypto.createHash('sha256').update(content, 'utf8').digest('hex')}`;
}
