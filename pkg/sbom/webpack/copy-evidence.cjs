'use strict';

// Binds an asset a pinned copy-webpack-plugin 6.1.1 emitted to the file that
// copy really read it from, for directory, glob and plain patterns alike.
//
// The binding is the identity of the buffer: the copy keeps the very Buffer it
// read from disk, hands it to the RawSource of the asset, and until the emit
// writes the files that source still returns that same object. Identical bytes
// are not a binding - two files of two packages can hold them, and a plugin can
// replace an asset with a new source carrying a copy of them - so anything that
// cannot be tied to exactly one observed copy is reported as no data.
//
// The load recordings come from runtime-preload.cjs, which must already be
// installed when the copy plugin is first required; without it there is no data.

const path = require('node:path');

const NAME = 'DkSbomCopyEvidence';
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const PLUGIN_NAME = 'copy-webpack-plugin';
const SUPPORTED_PLUGIN = '6.1.1';
const ENTRY_FILE = 'cjs.js';
const POST_FILE = 'postProcessPattern.js';
// Every file that decides what is read, selected and written where: the four
// stages, the entry point and the three helpers they call into.
const DIST_FILES = [
	'cjs.js',
	'index.js',
	'preProcessPattern.js',
	'processPattern.js',
	'postProcessPattern.js',
	'utils/createPatternGlob.js',
	'utils/isTemplateLike.js',
	'utils/promisify.js',
];
// Their raw bytes, taken from the registry archive of copy-webpack-plugin 6.1.1
// whose sha512 is the integrity pinned in package-lock.json. A fork keeping the
// version string is not that plugin, however well its own bytes verify.
const FINGERPRINTS = new Map([
	['cjs.js', 'sha256:f4fb6ba1bd7c090da21d82fd0f01c16b96b76a08b7fda757db4f39ec532d8ee8'],
	['index.js', 'sha256:e25b75d6d16309343d43743d0155a58df6e48db14b3cdeb8304281a38dc26671'],
	['preProcessPattern.js', 'sha256:a7c5a70832f4063ff3cab8d8e213402c6b6508f2ce096a087a119b1da6d4dd52'],
	['processPattern.js', 'sha256:8d5afb5af189f4e025cae20478ed091be44a49de00b55ed5569f22fed6cc5e71'],
	['postProcessPattern.js', 'sha256:c68901a9b0866c82673d41360c2893cd5575f1ff5eef4725a236b8972b70266e'],
	['utils/createPatternGlob.js', 'sha256:2184e3f06ffdeaa5c8320425107d61da6eb3419ca738f47510a6a417e952d6b4'],
	['utils/isTemplateLike.js', 'sha256:c5b7fa8564ccc5b081a174e3bcf05a423870cead69bdca82378d71a7321c18c0'],
	['utils/promisify.js', 'sha256:1d0d83d105af64ce92abfd0c6498799effd38af70d0199ec86307b24172a1990'],
]);

// One observer per postProcessPattern module of this process: the plugin calls
// it through the live exports object, so several compilers and several
// collectors share the one wrapper and its per-compilation records.
const observers = new WeakMap();

function installCopyEvidence(compiler, verifyResource) {
	if (typeof verifyResource !== 'function') throw new TypeError(`${NAME}: verifyResource must be a function`);
	const prepared = prepare(compiler);
	const results = new WeakMap();
	if (prepared.items) {
		// Before Compiler.emitAssets replaces every asset source with a size-only
		// one, and late enough for the assets of this compilation to be final.
		compiler.hooks.emit.tapPromise(NAME, async (compilation) => {
			try {
				results.set(compilation, { byTarget: await attribute(prepared.items, compilation, verifyResource) });
			} catch (error) {
				results.set(compilation, { failure: noData(`the copied assets could not be described: ${error.message}`).failure });
			}
		});
	}
	return function evidenceFor(compilation, assetName) {
		if (prepared.problem) return noData(prepared.problem);
		const result = results.get(compilation);
		if (!result) return noData('the copied assets of this compilation were not observed');
		if (result.failure) return { failure: result.failure };
		return result.byTarget.get(assetName) || noData(`no observed copy produced ${assetName}`);
	};
}

function prepare(compiler) {
	const registry = globalThis[REGISTRY];
	if (!registry || typeof registry.findByExport !== 'function' || typeof registry.getByFile !== 'function' || typeof registry.snapshot !== 'function') {
		return { problem: 'the commonjs load registry is not installed in this process' };
	}
	const items = [];
	const distributions = new Set();
	for (const plugin of compiler.options.plugins || []) {
		const constructor = plugin === null || typeof plugin !== 'object' ? undefined : plugin.constructor;
		if (typeof constructor !== 'function') continue;
		const entry = registry.findByExport(constructor);
		if (!entry || !entry.usable || path.basename(entry.file) !== ENTRY_FILE) continue;
		const distribution = path.dirname(entry.file);
		if (distributions.has(distribution)) continue;
		distributions.add(distribution);
		const observer = observe(registry, distribution);
		if (observer) items.push(observer);
	}
	if (items.length === 0) return { problem: `no observable ${PLUGIN_NAME} instance is configured in this compiler` };
	return { items };
}

function observe(registry, distribution) {
	const modules = [];
	for (const name of DIST_FILES) {
		const entry = registry.getByFile(path.join(distribution, ...name.split('/')));
		if (!entry || !entry.usable || !('exports' in entry)) return null;
		modules.push({ name, entry });
	}
	const post = modules[DIST_FILES.indexOf(POST_FILE)];
	const existing = observers.get(post.entry.exports);
	if (existing) return existing;
	const descriptor = Object.getOwnPropertyDescriptor(post.entry.exports, 'default');
	if (!descriptor || typeof descriptor.value !== 'function' || !descriptor.writable || !descriptor.configurable) return null;
	// What is about to be wrapped has to be what the file exported when it was
	// loaded: a replacement installed before this point is not that source, and
	// wrapping it would describe its copies as the pinned plugin's.
	const loaded = post.entry.members && post.entry.members.get('default');
	if (!loaded || loaded.kind !== 'data' || !Object.is(loaded.value, descriptor.value)) return null;
	const observer = { registry, modules, post, original: descriptor.value, records: new WeakMap() };
	observer.wrapper = async function (globalRef, pattern, file) {
		// Both sides of the call: a plugin that swaps a dist module in, copies
		// something else and puts the original back leaves an honest state behind.
		const before = drift(observer);
		const copied = await observer.original.call(this, globalRef, pattern, file);
		record(observer, globalRef, pattern, copied, before || drift(observer));
		return copied;
	};
	Object.defineProperty(post.entry.exports, 'default', { ...descriptor, value: observer.wrapper });
	observers.set(post.entry.exports, observer);
	return observer;
}

function record(observer, globalRef, pattern, copied, drifted) {
	const compilation = globalRef === null || typeof globalRef !== 'object' ? undefined : globalRef.compilation;
	if (compilation === null || typeof compilation !== 'object') return;
	// A pattern that selected nothing, or a source that could not be read, copies
	// nothing: there is no asset to attribute either.
	if (copied === null || typeof copied !== 'object') return;
	if (typeof copied.targetPath !== 'string' || copied.targetPath === '') return;
	let entries = observer.records.get(compilation);
	if (!entries) observer.records.set(compilation, (entries = []));
	entries.push({
		observer,
		target: copied.targetPath,
		from: copied.absoluteFrom,
		data: copied.data,
		problem: drifted || problemOf(pattern, copied),
	});
}

function problemOf(pattern, copied) {
	if (pattern === null || typeof pattern !== 'object') return 'the copy pattern is not an object';
	if (pattern.transform !== undefined || pattern.cacheTransform !== undefined) return 'the pattern transforms the copied content';
	if (pattern.transformPath !== undefined) return 'the pattern rewrites the copied target path';
	if (pattern.toType === 'template') return 'the pattern interpolates its target';
	if (!Buffer.isBuffer(copied.data)) return 'the copied content is not the bytes that were read';
	if (typeof copied.absoluteFrom !== 'string' || !path.isAbsolute(copied.absoluteFrom)) return 'the copy has no absolute source path';
	return null;
}

async function attribute(items, compilation, verifyResource) {
	const candidates = new Map();
	for (const observer of items) {
		for (const entry of observer.records.get(compilation) || []) {
			const list = candidates.get(entry.target) || [];
			list.push(entry);
			candidates.set(entry.target, list);
		}
	}
	const byTarget = new Map();
	const verified = new Map();
	for (const asset of compilation.getAssets()) {
		if (!asset.info || asset.info.copied !== true) continue;
		byTarget.set(asset.name, await describe(asset, candidates.get(asset.name) || [], verified, verifyResource));
	}
	return byTarget;
}

async function describe(asset, candidates, verified, verifyResource) {
	const buffer = bufferOf(asset.source);
	if (!buffer) return noData(`the source of ${asset.name} does not expose the bytes it carries`);
	const matched = candidates.filter((entry) => entry.data === buffer);
	if (matched.length === 0) return noData(`${asset.name} does not carry the bytes of an observed copy`);
	const problem = matched.find((entry) => entry.problem);
	if (problem) return noData(`${asset.name} was copied while ${problem.problem}`);
	// Two patterns copying the same file to the same target are one copy of one
	// file; two different files sharing those bytes are not attributable.
	if (matched.some((entry) => entry.from !== matched[0].from)) return noData(`several observed copies produced the bytes of ${asset.name}`);
	const [entry] = matched;
	const failure = await verify(entry.observer, verified, verifyResource);
	if (failure) return { failure };
	return { from: entry.from };
}

function bufferOf(source) {
	if (!source || typeof source.buffer !== 'function') return null;
	let buffer;
	try {
		buffer = source.buffer();
	} catch {
		return null;
	}
	return Buffer.isBuffer(buffer) ? buffer : null;
}

async function verify(observer, verified, verifyResource) {
	if (verified.has(observer)) return verified.get(observer);
	const failure = await verifySources(observer, verifyResource);
	verified.set(observer, failure);
	return failure;
}

// The copy is only described when every file that decided it is the pinned
// source, still holds the bytes this process loaded from it and belongs to one
// copy-webpack-plugin 6.1.1. These files are the instrument, not a part of any
// asset: nothing here contributes a component.
async function verifySources(observer, verifyResource) {
	let component;
	for (const { name, entry } of observer.modules) {
		let resolved;
		try {
			resolved = await verifyResource(entry.file);
		} catch (error) {
			return failure('no-data', `${entry.file} could not be verified: ${error.message}`);
		}
		if (!resolved || (!resolved.unit && !resolved.failure)) return failure('no-data', `${entry.file} was not verified`);
		if (resolved.failure) return resolved.failure;
		if (resolved.unit.sha256 !== entry.sha256) return failure('hash-mismatch', `${entry.file} differs from the bytes this process loaded from it`);
		if (resolved.unit.sha256 !== FINGERPRINTS.get(name)) return failure('unsupported', `${name} is not the source of the pinned ${PLUGIN_NAME} ${SUPPORTED_PLUGIN}`);
		const bound = resolved.unit.component;
		if (bound === null || typeof bound !== 'object') return failure('invalid', `${name} is bound to no component`);
		if (component === undefined) component = bound;
		else if (!sameJSON(component, bound)) {
			return failure('invalid', `the ${PLUGIN_NAME} sources bind to conflicting components ${component.id} and ${bound.id}`);
		}
	}
	if (component === undefined || component.name !== PLUGIN_NAME || component.version !== SUPPORTED_PLUGIN) {
		return failure('invalid', `component ${component === undefined ? 'none' : component.id} is not ${PLUGIN_NAME} ${SUPPORTED_PLUGIN}`);
	}
	return null;
}

function drift(observer) {
	for (const module of observer.modules) {
		const entry = module.entry;
		const allowed = module === observer.post ? 'default' : null;
		const changed =
			compareMembers(entry.members, observer.registry.snapshot(entry.exports), 'exports', allowed, observer.wrapper) ||
			compareMembers(entry.prototypeMembers, observer.registry.snapshot(prototypeOf(entry.exports)), 'prototype', null, null);
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

function prototypeOf(value) {
	const descriptor = typeof value === 'function' ? Object.getOwnPropertyDescriptor(value, 'prototype') : undefined;
	return descriptor && 'value' in descriptor ? descriptor.value : undefined;
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

module.exports = { installCopyEvidence };
