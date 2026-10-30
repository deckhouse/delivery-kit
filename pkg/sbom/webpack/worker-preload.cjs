'use strict';

// Opt-in recorder of workerize-loader, used as `node --require worker-preload.cjs`.
// It wraps the exported pitch function the moment the loader file is compiled,
// and records per built module what the published loader was given, which child
// compiler it made, and the text it handed back.
//
// It composes the commonjs load recorder rather than replacing it, exactly like
// the include recorder: the registry holds the published function, and the
// wrapper installed here is told apart from it by identity.
//
// The loader answers through `this.async()` and builds its text from a child
// compilation it creates itself, so both are intercepted for the duration of
// the call: the callback, to see what was written, and `createChildCompiler`,
// to know which of the compilations next door is the one this module's text was
// made of. Neither is called again later - nothing here re-runs the loader.

require('./runtime-preload.cjs');

const crypto = require('node:crypto');
const Module = require('node:module');
const path = require('node:path');

const WORKER = Symbol.for('dk.sbom.webpack.worker');
// The published artifacts this recorder knows how to read: the loader node
// compiles, and the two files its text names. All three are bytes of the
// Git-pinned distribution, and the evidence binds each of them to an original.
const KNOWN = {
	suffix: path.join('workerize-loader', 'dist', 'index.js'),
	sha256: 'sha256:3f7172d462ef8ec9704c0c586cd6e454a44093fa73ac94a0a3cf110b932e46f1',
	wrapper: { file: 'rpc-wrapper.js', sha256: 'sha256:a2e669e15b433058ae3233080418e7eaefbf268f5b6be26ba52edbd9f69edfe3' },
	workerLoader: { file: 'rpc-worker-loader.js', sha256: 'sha256:ba393a4cec8272c020121b3fd3be32836fa1bbf01e67ee0e02c540269b2d19dc' },
};

if (!globalThis[WORKER]) {
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
	Object.defineProperty(globalThis, WORKER, {
		value: Object.freeze({ known: KNOWN, loader: () => loader, pitchOf: (module) => pitches.get(module) }),
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
		const children = [];
		const answers = [];
		const restoreChild = recordChildCompilers(this, children);
		const restoreAsync = recordAsync(this, answers);
		try {
			original.apply(this, args);
		} finally {
			if (restoreChild) restoreChild();
			if (restoreAsync) restoreAsync();
		}
		remember(pitches, this && this._module, {
			file,
			method: wrapper,
			request: args[0],
			arity: args.length,
			context: contextOf(this),
			compilation: this && this._compilation,
			children: Object.freeze(children),
			answers,
			userRequest: this && this._module ? this._module.userRequest : undefined,
		});
	};
	keep(wrapper, original);
	const members = snapshot(exported);
	Object.defineProperty(exported, 'pitch', { ...descriptor, value: wrapper });
	return Object.freeze({ file, usable: true, sha256: KNOWN.sha256, exports: exported, original, wrapper, members });
}

// An own createChildCompiler for the duration of the call, delegating and
// changing nothing. Which compiler each call produced is what says, later,
// which compilation next door this module's text was built from.
function recordChildCompilers(loaderContext, children) {
	const compilation = loaderContext === null || typeof loaderContext !== 'object' ? null : loaderContext._compilation;
	if (compilation === null || typeof compilation !== 'object' || typeof compilation.createChildCompiler !== 'function') return null;
	const own = Object.getOwnPropertyDescriptor(compilation, 'createChildCompiler');
	const delegate = compilation.createChildCompiler;
	const wrapper = function (name, outputOptions, ...rest) {
		const child = delegate.apply(this, arguments);
		children.push(Object.freeze({ name, outputOptions, child, arity: arguments.length }));
		return child;
	};
	try {
		Object.defineProperty(compilation, 'createChildCompiler', { value: wrapper, writable: true, enumerable: false, configurable: true });
	} catch {
		return null;
	}
	return () => {
		const now = Object.getOwnPropertyDescriptor(compilation, 'createChildCompiler');
		children.intact = Boolean(now && now.value === wrapper);
		if (own) Object.defineProperty(compilation, 'createChildCompiler', own);
		else delete compilation.createChildCompiler;
	};
}

// The loader writes its module through the callback of this.async(), so the
// callback is the only place its text can be read. The pitch returns long
// before the callback runs: the array it fills is read when the module is
// described, not here.
function recordAsync(loaderContext, answers) {
	if (loaderContext === null || typeof loaderContext !== 'object' || typeof loaderContext.async !== 'function') return null;
	const own = Object.getOwnPropertyDescriptor(loaderContext, 'async');
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
		if (own) Object.defineProperty(loaderContext, 'async', own);
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
		context: loaderContext.context,
		rootContext: loaderContext.rootContext,
		loaderIndex: loaderContext.loaderIndex,
		loaderCount: chain ? chain.length : null,
		target: loaderContext.target,
		options,
		query: loaderContext.query,
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
