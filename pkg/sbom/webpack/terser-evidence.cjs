'use strict';

// Binds the bytes a pinned terser-webpack-plugin 5.3.10 put into one asset to
// the bytes it was given, so that a rendered chunk whose source this process
// described can still be followed to the minified file on disk.
//
// The observation is the plugin's own optimization call: its first statement
// asks the compilation for its cache, so an own getCache of this compilation,
// installed for exactly that synchronous prefix, hands out the item caches the
// call then reads. Each of them names one asset, whose source is snapshotted
// right where its cache key was computed and again once the call has resolved.
//
// Terser rewrites what it is given and contributes nothing of itself: no
// component comes from here, and the source units of the asset keep the claim
// they had before it ran. Per-byte survival through the minifier is not traced.
//
// A minification this process did not perform is not evidence of one: an output
// taken from a cache is only accepted when the same input of the same asset was
// already minified here, in this process.
//
// The load recordings come from runtime-preload.cjs; without them there is no
// data.

const crypto = require('node:crypto');
const path = require('node:path');

const NAME = 'DkSbomTerserEvidence';
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const PLUGIN_NAME = 'terser-webpack-plugin';
const SUPPORTED_PLUGIN = '5.3.10';
const TERSER_NAME = 'terser';
const SUPPORTED_TERSER = '5.31.6';
const CACHE_NAME = 'TerserWebpackPlugin';
const ENTRY_FILE = 'index.js';
// The file that decides what is minified and what is cached, the one the
// parallel workers run, and the one holding the minifier implementation they
// are handed.
const DIST_FILES = ['index.js', 'minify.js', 'utils.js'];
// Their raw bytes and terser's own entry point, taken from the registry
// archives of these versions, whose sha512 are the integrity pinned in
// package-lock.json. A fork keeping the version string is not this plugin.
const FINGERPRINTS = new Map([
	['index.js', 'sha256:c4954a793da40e7c1e3812b7f3d7e61badb7758910272029f8ff7ddee32d1012'],
	['minify.js', 'sha256:83fc302758585ede630d112b5e18742fda0980e85c143281318a295ec89f6742'],
	['utils.js', 'sha256:8d5b9d5c8b7826c6d26e78b75c17f16ff6ab998618bed9194298daeb48bc3b1e'],
]);
const TERSER_FINGERPRINT = 'sha256:38af5a0fb14c73bc49acc03cb5e1187ff45470b7dec04571aea44525aa063ce8';
// The only two option sets nobody chose: the plugin's own default and the one
// webpack 5.94.0 builds when a production build leaves its minimizer alone.
const DEFAULT_TERSER_OPTIONS = [{}, { compress: { passes: 2 } }];

// One observer per terser-webpack-plugin of this process: several compilers and
// collectors share the one wrapped optimization and its per-compilation records.
const observers = new WeakMap();

function installTerserEvidence(compiler, verifyResource) {
	if (typeof verifyResource !== 'function') throw new TypeError(`${NAME}: verifyResource must be a function`);
	let prepared;
	// The default minimizer of a production build is loaded while webpack applies
	// its options, after this plugin was applied and before the first compilation.
	compiler.hooks.compilation.tap(NAME, () => {
		if (!prepared) prepared = prepare(compiler);
	});
	const verified = new WeakMap();
	return async function evidenceFor(compilation, assetName) {
		const observer = prepared && prepared.observer;
		// Nothing observable minified anything here; an asset that was changed all
		// the same no longer carries the bytes it was described from.
		if (!observer) return { status: 'none' };
		const records = (observer.records.get(compilation) || new Map()).get(assetName);
		if (!records) return { status: 'none' };
		if (records.length > 1) return noData(`${assetName} was minified ${records.length} times`);
		const [record] = records;
		if (record.problem) return noData(`${assetName} was minified while ${record.problem}`);
		const failure = await verify(observer, verified, verifyResource, compilation);
		if (failure) return { failure };
		return { input: record.input, output: record.output };
	};
}

function prepare(compiler) {
	const registry = globalThis[REGISTRY];
	if (!registry || typeof registry.findByExport !== 'function' || typeof registry.getByFile !== 'function' || typeof registry.snapshot !== 'function') {
		return { problem: 'the commonjs load registry is not installed in this process' };
	}
	const api = compiler.webpack;
	const base = api && api.RuntimeModule && registry.findByExport(api.RuntimeModule);
	if (!base || !base.usable) return { problem: 'the webpack this compiler runs was not observed being loaded' };
	// Resolved the way webpack's own defaults resolve their lazy minimizer, from
	// the directory of the file that requires it.
	let entryFile;
	let terserEntry;
	try {
		entryFile = require.resolve(PLUGIN_NAME, { paths: [path.join(path.dirname(base.file), 'config')] });
		terserEntry = require.resolve(TERSER_NAME, { paths: [path.dirname(entryFile)] });
	} catch {
		return { problem: `no ${PLUGIN_NAME} is installed for this webpack` };
	}
	if (path.basename(entryFile) !== ENTRY_FILE) return { problem: `${PLUGIN_NAME} is entered through ${entryFile}` };
	const modules = [];
	for (const name of DIST_FILES) {
		const entry = registry.getByFile(path.join(path.dirname(entryFile), name));
		if (!entry || !entry.usable || !('exports' in entry)) return { problem: `${name} of ${PLUGIN_NAME} was not observed being loaded` };
		modules.push({ name, entry });
	}
	const observer = observe(registry, modules, terserEntry);
	if (!observer) return { problem: `the minification of ${PLUGIN_NAME} could not be observed` };
	return { observer };
}

function observe(registry, modules, terserEntry) {
	const index = modules[0];
	const plugin = index.entry.exports;
	const existing = observers.get(plugin);
	if (existing) return existing;
	const prototype = prototypeOf(plugin);
	const descriptor = prototype && Object.getOwnPropertyDescriptor(prototype, 'optimize');
	if (!descriptor || typeof descriptor.value !== 'function' || !descriptor.writable || !descriptor.configurable) return null;
	// What is about to be wrapped has to be what the file exported when it was
	// loaded: a replacement installed before this point is not that source.
	const loaded = index.entry.prototypeMembers && index.entry.prototypeMembers.get('optimize');
	if (!loaded || loaded.kind !== 'data' || !Object.is(loaded.value, descriptor.value)) return null;
	// The implementation the plugin offers has to be the one its own utils file
	// exported, or the call runs code no fingerprint covers.
	const minify = modules[2].entry.members && modules[2].entry.members.get('terserMinify');
	if (!minify || minify.kind !== 'data' || !Object.is(minify.value, plugin.terserMinify)) return null;
	const observer = { registry, modules, index, plugin, terserEntry, original: descriptor.value, records: new WeakMap(), minified: new Map() };
	observer.wrapper = function (compiler, compilation, assets, optimizeOptions) {
		const call = { records: [], problem: drift(observer) || pluginProblem(observer, this) };
		let active = true;
		const own = Object.getOwnPropertyDescriptor(compilation, 'getCache');
		const inherited = compilation.getCache;
		Object.defineProperty(compilation, 'getCache', {
			value: function (name) {
				const cache = inherited.call(this, name);
				return active && name === CACHE_NAME ? wrapCache(cache, compilation, call) : cache;
			},
			writable: true,
			enumerable: false,
			configurable: true,
		});
		let running;
		try {
			running = observer.original.call(this, compiler, compilation, assets, optimizeOptions);
		} finally {
			// Synchronously, before anything is awaited: no other plugin ever sees
			// a compilation whose cache is this one.
			active = false;
			if (own) Object.defineProperty(compilation, 'getCache', own);
			else delete compilation.getCache;
		}
		return Promise.resolve(running).then((result) => {
			complete(observer, compilation, call);
			return result;
		});
	};
	Object.defineProperty(prototype, 'optimize', { ...descriptor, value: observer.wrapper });
	observers.set(plugin, observer);
	return observer;
}

// Only the plugin's own instances, running its own minifier on options nobody
// chose: everything else changes what the bytes of the asset are made of.
function pluginProblem(observer, plugin) {
	if (plugin === null || typeof plugin !== 'object' || Object.getPrototypeOf(plugin) !== prototypeOf(observer.plugin)) {
		return `another object borrowed the minification of ${PLUGIN_NAME}`;
	}
	const options = plugin.options;
	if (!isPlainObject(options) || !isPlainObject(options.minimizer)) return 'its options are not the ones this plugin builds';
	if (options.minimizer.implementation !== observer.plugin.terserMinify) return 'it was configured with another minifier implementation';
	if (options.extractComments !== true) return 'it was configured to extract comments in its own way';
	if (!DEFAULT_TERSER_OPTIONS.some((candidate) => sameData(candidate, options.minimizer.options))) return 'it was configured with terser options of its own';
	return null;
}

// The cache the plugin is about to read, with the one method that names the
// assets of this call; everything else stays the cache of the compilation.
function wrapCache(cache, compilation, call) {
	return new Proxy(cache, {
		get(target, property) {
			if (property === 'getItemCache') {
				return (name, eTag) => wrapItem(target.getItemCache(name, eTag), name, compilation, call);
			}
			const value = Reflect.get(target, property, target);
			return typeof value === 'function' ? value.bind(target) : value;
		},
	});
}

// The input of one asset, taken where its cache key was computed from the very
// same source, and whether the plugin found its output already made.
function wrapItem(item, name, compilation, call) {
	const asset = compilation.getAsset(name);
	const record = { name, input: bytesOf(asset && asset.source), hit: undefined };
	call.records.push(record);
	return new Proxy(item, {
		get(target, property) {
			if (property === 'getPromise') {
				return (...args) =>
					Promise.resolve(target.getPromise(...args)).then((output) => {
						record.hit = Boolean(output);
						return output;
					});
			}
			const value = Reflect.get(target, property, target);
			return typeof value === 'function' ? value.bind(target) : value;
		},
	});
}

function complete(observer, compilation, call) {
	let byName = observer.records.get(compilation);
	if (!byName) observer.records.set(compilation, (byName = new Map()));
	const drifted = call.problem || drift(observer);
	for (const record of call.records) {
		const asset = compilation.getAsset(record.name);
		record.output = bytesOf(asset && asset.source);
		record.problem = drifted || recordProblem(observer, record);
		const previous = byName.get(record.name) || [];
		previous.push(record);
		byName.set(record.name, previous);
	}
}

function recordProblem(observer, record) {
	if (!record.input || !record.output) return 'the bytes it was given or produced could not be read';
	if (record.hit === undefined) return 'its cache was not the one this adapter observed';
	const key = `${record.name}\u0000${digest(record.input)}`;
	if (!record.hit) {
		observer.minified.set(key, digest(record.output));
		return null;
	}
	// A stored output is somebody else's work until this process has done it:
	// nothing here reruns the minifier or touches what the cache holds.
	const known = observer.minified.get(key);
	if (known === undefined) return 'its output came from a cache this process did not fill';
	if (known !== digest(record.output)) return 'its cached output is not the one this process produced for those bytes';
	return null;
}

// Verified once per compilation: a later compilation of the same compiler reads
// the instrument files again.
async function verify(observer, verified, verifyResource, compilation) {
	if (verified.has(compilation)) return verified.get(compilation);
	const failure = await verifySources(observer, verifyResource);
	verified.set(compilation, failure);
	return failure;
}

// The minification is only described when every file that performed it - in
// this process and in the parallel workers alike - is the pinned source, still
// holds the bytes this process loaded from it where it loaded it, and belongs to
// one terser-webpack-plugin 5.3.10 driving one terser 5.31.6. These files are
// the instrument, not a part of any asset: nothing here contributes a component.
async function verifySources(observer, verifyResource) {
	let component;
	for (const { name, entry } of observer.modules) {
		const resolved = await resolve(verifyResource, entry.file);
		if (resolved.failure) return resolved.failure;
		if (resolved.unit.sha256 !== entry.sha256) return failure('hash-mismatch', `${entry.file} differs from the bytes this process loaded from it`);
		if (resolved.unit.sha256 !== FINGERPRINTS.get(name)) return failure('unsupported', `${name} is not the source of the pinned ${PLUGIN_NAME} ${SUPPORTED_PLUGIN}`);
		const bound = resolved.unit.component;
		if (bound === null || typeof bound !== 'object') return failure('invalid', `${name} is bound to no component`);
		if (component === undefined) component = bound;
		else if (!sameJSON(component, bound)) return failure('invalid', `the ${PLUGIN_NAME} sources bind to conflicting components ${component.id} and ${bound.id}`);
	}
	if (component === undefined || component.name !== PLUGIN_NAME || component.version !== SUPPORTED_PLUGIN) {
		return failure('invalid', `component ${component === undefined ? 'none' : component.id} is not ${PLUGIN_NAME} ${SUPPORTED_PLUGIN}`);
	}
	// The workers read it from disk, so its bytes there are what minified the
	// asset; when this process loaded it too, that load has to be those bytes.
	const terser = await resolve(verifyResource, observer.terserEntry);
	if (terser.failure) return terser.failure;
	if (terser.unit.sha256 !== TERSER_FINGERPRINT) return failure('unsupported', `${observer.terserEntry} is not the entry point of the pinned ${TERSER_NAME} ${SUPPORTED_TERSER}`);
	const loaded = observer.registry.getByFile(observer.terserEntry);
	if (loaded && (!loaded.usable || loaded.sha256 !== TERSER_FINGERPRINT)) {
		return failure('hash-mismatch', `${observer.terserEntry} is not what this process loaded from it`);
	}
	const bound = terser.unit.component;
	if (bound === null || typeof bound !== 'object' || bound.name !== TERSER_NAME || bound.version !== SUPPORTED_TERSER) {
		return failure('invalid', `component ${bound && bound.id ? bound.id : 'none'} is not ${TERSER_NAME} ${SUPPORTED_TERSER}`);
	}
	return null;
}

async function resolve(verifyResource, file) {
	let resolved;
	try {
		resolved = await verifyResource(file);
	} catch (error) {
		return { failure: failure('no-data', `${file} could not be verified: ${error.message}`) };
	}
	if (!resolved || (!resolved.unit && !resolved.failure)) return { failure: failure('no-data', `${file} was not verified`) };
	return resolved;
}

function drift(observer) {
	for (const module of observer.modules) {
		const entry = module.entry;
		const snapshot = observer.registry.snapshot(entry.exports);
		const changed =
			compareMembers(entry.members, snapshot, 'exports', null, null) ||
			compareMembers(entry.prototypeMembers, observer.registry.snapshot(prototypeOf(entry.exports)), 'prototype', module === observer.index ? 'optimize' : null, observer.wrapper);
		if (changed) return `${module.name} no longer exports what it exported when it was loaded: ${changed}`;
	}
	return null;
}

function compareMembers(snapshot, now, where, allowedKey, allowedValue) {
	if (snapshot === null || now === null) return snapshot === now ? null : `${where} is no longer an object`;
	for (const key of snapshot.keys()) {
		if (!now.has(key)) return `${where}.${String(key)} is gone`;
	}
	for (const [key, is] of now) {
		const was = snapshot.get(key);
		if (!was) return `${where}.${String(key)} was added`;
		if (key === allowedKey && is.kind === 'data' && Object.is(is.value, allowedValue)) continue;
		if (was.kind !== is.kind) return `${where}.${String(key)} was replaced`;
		if (was.kind === 'data' ? !Object.is(was.value, is.value) : !Object.is(was.get, is.get) || !Object.is(was.set, is.set)) {
			return `${where}.${String(key)} was replaced`;
		}
	}
	return null;
}

function bytesOf(source) {
	if (!source || (typeof source.buffer !== 'function' && typeof source.source !== 'function')) return null;
	try {
		return Buffer.from(typeof source.buffer === 'function' ? source.buffer() : source.source());
	} catch {
		return null;
	}
}

function digest(bytes) {
	return crypto.createHash('sha256').update(bytes).digest('hex');
}

function prototypeOf(value) {
	const descriptor = typeof value === 'function' ? Object.getOwnPropertyDescriptor(value, 'prototype') : undefined;
	return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

function isPlainObject(value) {
	return typeof value === 'object' && value !== null && Object.getPrototypeOf(value) === Object.prototype;
}

// Plain data compared by its own enumerable keys and values: nothing that
// serializes like an expected value while holding another one passes.
function sameData(left, right) {
	if (Array.isArray(left) || Array.isArray(right)) {
		if (!Array.isArray(left) || !Array.isArray(right) || Object.getPrototypeOf(right) !== Array.prototype || left.length !== right.length) return false;
		return left.every((value, index) => sameData(value, right[index]));
	}
	if (isPlainObject(left) || isPlainObject(right)) {
		if (!isPlainObject(left) || !isPlainObject(right)) return false;
		const keys = Object.keys(left);
		if (Reflect.ownKeys(right).length !== keys.length) return false;
		return keys.every((key) => {
			const descriptor = Object.getOwnPropertyDescriptor(right, key);
			return descriptor !== undefined && 'value' in descriptor && descriptor.enumerable && sameData(left[key], descriptor.value);
		});
	}
	return Object.is(left, right);
}

function sameJSON(left, right) {
	return JSON.stringify(left) === JSON.stringify(right);
}

function failure(status, reason) {
	return { status, reason };
}

function noData(reason) {
	return { failure: failure('no-data', reason) };
}

module.exports = { installTerserEvidence };
