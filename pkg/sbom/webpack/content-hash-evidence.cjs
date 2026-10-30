'use strict';

// Binds an asset webpack renamed and rewrote for its real content hash to the
// asset it was before: the pinned RealContentHashPlugin 5.94.0 replaces every
// content-hash token of the compilation, in asset names and in asset bytes
// alike, and nothing else.
//
// What the plugin did is not taken on trust. The assets are snapshotted on both
// sides of its stage, the old-to-new hash map is read off the asset info it
// updated, and the substitution is performed again here: unless every name and
// every byte of the compilation comes out of the recomputation exactly, nothing
// is described.
//
// A hash token is not code: the asset keeps the composition it had before this
// stage, and this adapter contributes no component and no source unit.
//
// The load recordings come from runtime-preload.cjs; without them there is no
// data.

const path = require('node:path');

const NAME = 'DkSbomContentHashEvidence';
const HASH_TOKEN = /^[A-Za-z0-9+/=_-]+$/;
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const SUPPORTED_WEBPACK = '5.94.0';
const PLUGIN_FILE = 'optimize/RealContentHashPlugin.js';
// Its raw bytes in the webpack 5.94.0 registry archive whose sha512 is the
// integrity pinned in package-lock.json.
const FINGERPRINT = 'sha256:a831672c978182b4f5d22cec43606187e165f0684395f349219bab036685ba58';

function installContentHashEvidence(compiler, verifyResource) {
	if (typeof verifyResource !== 'function') throw new TypeError(`${NAME}: verifyResource must be a function`);
	const states = new WeakMap();
	compiler.hooks.compilation.tap(NAME, (compilation) => {
		const api = compiler.webpack;
		const stage = api && api.Compilation && api.Compilation.PROCESS_ASSETS_STAGE_OPTIMIZE_HASH;
		if (typeof stage !== 'number') return;
		const state = { renames: [] };
		states.set(compilation, state);
		// Around the one stage the plugin works in, and nothing else: the renames
		// it performs there are the only way to tell which asset became which.
		compilation.hooks.processAssets.tap({ name: NAME, stage: stage - 1 }, () => {
			state.before = snapshot(compilation);
			state.tapsBefore = updateHashTaps(compiler, compilation);
			state.ownRename = Object.getOwnPropertyDescriptor(compilation, 'renameAsset');
			const inherited = compilation.renameAsset;
			Object.defineProperty(compilation, 'renameAsset', {
				value: function (file, newFile) {
					state.renames.push([file, newFile]);
					return inherited.call(this, file, newFile);
				},
				writable: true,
				enumerable: false,
				configurable: true,
			});
		});
		compilation.hooks.processAssets.tap({ name: NAME, stage: stage + 1 }, () => {
			if (state.ownRename) Object.defineProperty(compilation, 'renameAsset', state.ownRename);
			else delete compilation.renameAsset;
			state.after = snapshot(compilation);
			state.tapsAfter = updateHashTaps(compiler, compilation);
		});
	});
	return async function evidenceFor(compilation, assetName) {
		const state = states.get(compilation);
		if (!state || !state.before || !state.after) return { status: 'none' };
		if (!state.analysis) state.analysis = analyse(compiler, state, verifyResource);
		const analysed = await state.analysis;
		if (analysed.failure) return { failure: analysed.failure };
		const described = analysed.byName.get(assetName);
		if (!described) return noData(`${assetName} is not an asset this compilation hashed`);
		return described;
	};
}

function snapshot(compilation) {
	const assets = new Map();
	for (const { name, source, info } of compilation.getAssets()) {
		assets.set(name, { name, bytes: bytesOf(source), hashes: hashList(info && info.contenthash) });
	}
	return assets;
}

// The same list the plugin builds from one asset's info.
function hashList(value) {
	if (Array.isArray(value)) return value.filter((item) => item);
	return value ? [value] : [];
}

async function analyse(compiler, state, verifyResource) {
	const pairs = pairAssets(state);
	if (pairs.failure) return pairs;
	// Nothing was renamed and no byte moved: this stage left the compilation as
	// it was, and no asset of it is described by a substitution.
	if (pairs.list.every(({ before, after }) => before.name === after.name && before.bytes && after.bytes && before.bytes.equals(after.bytes))) {
		return { byName: new Map(pairs.list.map(({ after }) => [after.name, { status: 'none' }])) };
	}
	const problem = await verifyPlugin(compiler, state, verifyResource);
	if (problem) return { failure: problem };
	const hashes = hashMap(pairs.list);
	if (hashes.failure) return hashes;
	// Rebuilt the way the plugin builds it, from the hashes of the assets in the
	// order it collected them.
	const pattern = new RegExp([...hashes.map.keys()].map(quoteMeta).join('|'), 'g');
	const substitute = (text) => text.replace(pattern, (hash) => hashes.map.get(hash));
	const byName = new Map();
	for (const { before, after } of pairs.list) {
		if (!before.bytes || !after.bytes) return { failure: failure('no-data', `the bytes of ${before.name} could not be read on both sides of its content hash`) };
		if (substitute(before.name) !== after.name) {
			return { failure: failure('no-data', `${before.name} became ${after.name}, which is not its content-hash substitution`) };
		}
		// latin1 keeps every byte of the asset and every ascii hash token intact,
		// so the substitution is the one the plugin performed on its text.
		const expected = Buffer.from(substitute(before.bytes.toString('latin1')), 'latin1');
		if (!expected.equals(after.bytes)) {
			return { failure: failure('no-data', `${after.name} is not the content-hash substitution of the asset it was made from`) };
		}
		byName.set(after.name, { name: before.name, input: before.bytes, output: after.bytes });
	}
	return { byName };
}

// Which asset of this stage became which: the chain of renames it performed,
// and identity for everything it left alone.
function pairAssets(state) {
	const renamed = new Map();
	for (const [from, to] of state.renames) {
		if (renamed.has(from)) return { failure: failure('no-data', `${from} was renamed more than once while the content hashes were replaced`) };
		renamed.set(from, to);
	}
	const list = [];
	const taken = new Set();
	for (const before of state.before.values()) {
		let name = before.name;
		for (let step = 0; renamed.has(name); step += 1) {
			if (step > renamed.size) return { failure: failure('no-data', `${before.name} was renamed in a circle while the content hashes were replaced`) };
			name = renamed.get(name);
		}
		const after = state.after.get(name);
		if (!after || taken.has(name)) return { failure: failure('no-data', `${before.name} has no single asset it became while the content hashes were replaced`) };
		taken.add(name);
		list.push({ before, after });
	}
	if (taken.size !== state.after.size) {
		return { failure: failure('no-data', 'the assets of this compilation changed while their content hashes were replaced') };
	}
	return { list };
}

// Read off the asset info the plugin updated, never recomputed: one old hash
// that became two different new ones describes no substitution at all.
function hashMap(list) {
	const map = new Map();
	for (const { before, after } of list) {
		if (before.hashes.length !== after.hashes.length) {
			return { failure: failure('no-data', `${before.name} carries ${after.hashes.length} content hashes instead of ${before.hashes.length}`) };
		}
		for (const [index, hash] of before.hashes.entries()) {
			const replacement = after.hashes[index];
			if (typeof hash !== 'string' || hash === '') {
				return { failure: failure('no-data', `${before.name} carries a content hash that is not a string`) };
			}
			if (typeof replacement !== 'string' || replacement === '') {
				return { failure: failure('no-data', `the content hash ${hash} of ${before.name} was not replaced by one of its own`) };
			}
			// The plugin cuts every new hash from a digest to the length of the old
			// one; anything else in its place is text, not a hash.
			if (!HASH_TOKEN.test(replacement) || replacement.length > hash.length) {
				return { failure: failure('no-data', `the replacement ${JSON.stringify(replacement)} of ${hash} in ${before.name} is not a content hash`) };
			}
			if (map.has(hash) && map.get(hash) !== replacement) {
				return { failure: failure('no-data', `the content hash ${hash} was replaced by ${map.get(hash)} and by ${replacement}`) };
			}
			map.set(hash, replacement);
		}
	}
	if (map.size === 0) return { failure: failure('no-data', 'the assets of this compilation changed without carrying a content hash') };
	return { map };
}

// The substitution is only described when the plugin that performed it is the
// pinned source of the webpack that is running and nothing taps the hook that
// replaces its hashes. This file is the instrument, not a part of any asset:
// nothing here contributes a component or a unit.
async function verifyPlugin(compiler, state, verifyResource) {
	const registry = globalThis[REGISTRY];
	if (!registry || typeof registry.findByExport !== 'function' || typeof registry.getByFile !== 'function') {
		return failure('no-data', 'the commonjs load registry is not installed in this process');
	}
	const api = compiler.webpack;
	if (!api || typeof api.version !== 'string') return failure('no-data', 'the compiler does not expose its webpack');
	if (api.version !== SUPPORTED_WEBPACK) return failure('unsupported', `the content hashes of webpack ${api.version} are not described, only ${SUPPORTED_WEBPACK}`);
	const entry = pluginEntry(compiler, registry);
	if (!entry) return failure('no-data', `${PLUGIN_FILE} was not observed being loaded by this process`);
	if (state.tapsBefore === null || state.tapsAfter === null) return failure('no-data', 'the taps deciding the new content hashes could not be observed');
	if (state.tapsBefore !== 0 || state.tapsAfter !== 0) {
		return failure('no-data', 'another plugin decides the new content hashes of this compilation');
	}
	let resolved;
	try {
		resolved = await verifyResource(entry.file);
	} catch (error) {
		return failure('no-data', `${entry.file} could not be verified: ${error.message}`);
	}
	if (!resolved || (!resolved.unit && !resolved.failure)) return failure('no-data', `${entry.file} was not verified`);
	if (resolved.failure) return resolved.failure;
	if (resolved.unit.sha256 !== entry.sha256) return failure('hash-mismatch', `${entry.file} differs from the bytes this process loaded from it`);
	if (resolved.unit.sha256 !== FINGERPRINT) return failure('unsupported', `${PLUGIN_FILE} is not the source of the pinned webpack ${SUPPORTED_WEBPACK}`);
	const component = resolved.unit.component;
	if (component === null || typeof component !== 'object' || component.name !== 'webpack' || component.version !== SUPPORTED_WEBPACK) {
		return failure('invalid', `component ${component && component.id ? component.id : 'none'} is not the webpack ${SUPPORTED_WEBPACK} that is running`);
	}
	return null;
}

function pluginEntry(compiler, registry) {
	const base = compiler.webpack && compiler.webpack.RuntimeModule && registry.findByExport(compiler.webpack.RuntimeModule);
	if (!base || !base.usable) return null;
	const entry = registry.getByFile(path.join(path.dirname(base.file), ...PLUGIN_FILE.split('/')));
	return entry && entry.usable && 'exports' in entry ? entry : null;
}

// How many taps decide the new hashes of this compilation; the hooks object is
// the one the plugin itself asks for, and asking for it changes nothing.
function updateHashTaps(compiler, compilation) {
	const registry = globalThis[REGISTRY];
	const entry = registry && typeof registry.findByExport === 'function' ? pluginEntry(compiler, registry) : null;
	const plugin = entry && entry.exports;
	if (typeof plugin !== 'function' || typeof plugin.getCompilationHooks !== 'function') return null;
	let hooks;
	try {
		hooks = plugin.getCompilationHooks(compilation);
	} catch {
		return null;
	}
	return hooks && hooks.updateHash && Array.isArray(hooks.updateHash.taps) ? hooks.updateHash.taps.length : null;
}

// The same escaping the plugin applies to the hashes it builds its pattern from.
function quoteMeta(text) {
	return text.replace(/[-[\]\\/{}()*+?.^$|]/g, '\\$&');
}

function bytesOf(source) {
	if (!source || (typeof source.buffer !== 'function' && typeof source.source !== 'function')) return null;
	try {
		return Buffer.from(typeof source.buffer === 'function' ? source.buffer() : source.source());
	} catch {
		return null;
	}
}

function failure(status, reason) {
	return { status, reason };
}

function noData(reason) {
	return { failure: failure('no-data', reason) };
}

module.exports = { installContentHashEvidence };
