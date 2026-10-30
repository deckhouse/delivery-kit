'use strict';

// Binds the one line webpack adds to an asset when the build writes source maps
// to the pinned source that wrote it.
//
// `devtool: 'source-map'` makes SourceMapDevToolPlugin emit a `.map` file beside
// each asset and put a `sourceMappingURL` comment at the end of the asset
// itself. The comment is the last thing that happens to the bytes of the
// published file - redoc's `redoc.standalone.js`, the file Argo copies, ends
// with exactly such a line - so without it that asset cannot be described at
// all.
//
// The comment is a fixed line naming the map that was emitted beside the asset,
// so it is recomputed here and compared byte for byte. **The map itself is not
// described**: its bytes are a json document webpack builds out of every module
// of the chunk, and nothing here recomputes that.
//
// The load recordings come from runtime-preload.cjs; without them there is no
// data.

const path = require('node:path');

const NAME = 'DkSbomSourcemapEvidence';
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const SUPPORTED_WEBPACK = '5.94.0';
const PLUGIN_FILE = 'SourceMapDevToolPlugin.js';
const PLUGIN_TAP = 'SourceMapDevToolPlugin';
// Its raw bytes in the webpack 5.94.0 registry archive whose sha512 is the
// integrity pinned in package-lock.json.
const FINGERPRINT = 'sha256:45773dd13f63338a0e03dbe6b3031a53bd78dbbfe396eb84b85a9dd8302f98c3';
// The comment the plugin appends when the build does not ask for another one,
// and the shape it takes in a stylesheet.
const COMMENT = '\n//# sourceMappingURL=';
const CSS_ASSET = /\.css($|\?)/i;

function installSourcemapEvidence(compiler, verifyResource) {
	if (typeof verifyResource !== 'function') throw new TypeError(`${NAME}: verifyResource must be a function`);
	const states = new WeakMap();
	compiler.hooks.compilation.tap(NAME, (compilation) => {
		// A child compiler copies the taps of the one that made it; the assets of
		// its compilations are described through their own render.
		if (compilation.compiler !== compiler) return;
		const api = compiler.webpack;
		const stage = api && api.Compilation && api.Compilation.PROCESS_ASSETS_STAGE_DEV_TOOLING;
		if (typeof stage !== 'number') return;
		const state = {};
		states.set(compilation, state);
		compilation.hooks.processAssets.tap({ name: NAME, stage: stage - 1 }, () => {
			state.before = snapshot(compilation);
			state.taps = tapsAt(compilation, stage);
		});
		compilation.hooks.processAssets.tap({ name: NAME, stage: stage + 1 }, () => {
			state.after = snapshot(compilation);
		});
	});
	return async function evidenceFor(compilation, assetName) {
		const state = states.get(compilation);
		if (!state || !state.before || !state.after) return { status: 'none' };
		if (!state.analysis) state.analysis = analyse(compiler, state, verifyResource);
		const analysed = await state.analysis;
		if (analysed.failure) return { failure: analysed.failure };
		const described = analysed.byName.get(assetName);
		if (!described) return noData(`${assetName} is not an asset this compilation wrote a source map for`);
		return described;
	};
}

function snapshot(compilation) {
	const assets = new Map();
	for (const { name, source, info } of compilation.getAssets()) {
		assets.set(name, { bytes: bytesOf(source), map: info && info.related ? info.related.sourceMap : undefined });
	}
	return assets;
}

function tapsAt(compilation, stage) {
	const taps = compilation.hooks.processAssets && compilation.hooks.processAssets.taps;
	if (!Array.isArray(taps)) return null;
	return taps.filter((tap) => tap && tap.stage === stage).map((tap) => tap.name);
}

async function analyse(compiler, state, verifyResource) {
	const silent = { byName: new Map([...state.after.keys()].map((name) => [name, { status: 'none' }])) };
	const changed = [];
	const written = [];
	for (const [name, after] of state.after) {
		const before = state.before.get(name);
		// An asset that was not there before this stage: the map itself, or
		// something else a plugin of that stage wrote.
		if (!before) written.push(name);
		else if (!before.bytes || !after.bytes) return { failure: failure('no-data', `the bytes of ${name} could not be read on both sides of its source map`) };
		else if (!before.bytes.equals(after.bytes)) changed.push({ name, before: before.bytes, after: after.bytes, map: after.map });
	}
	for (const name of state.before.keys()) {
		if (!state.after.has(name)) return { failure: failure('no-data', `${name} is not an asset of this compilation any more`) };
	}
	// Nothing was written in that stage, or nothing of it was a source map: this
	// adapter describes no asset of this compilation.
	if ((changed.length === 0 && written.length === 0) || (state.taps !== null && !state.taps.includes(PLUGIN_TAP))) return silent;

	const verified = await verifyPlugin(compiler, state, verifyResource);
	if (verified.failure) return verified;
	const byName = silent.byName;
	const maps = new Set();
	for (const { name, before, after, map } of changed) {
		if (typeof map !== 'string' || map === '') return { failure: failure('no-data', `${name} changed in this stage without being given a source map`) };
		if (!state.after.has(map)) return { failure: failure('no-data', `the source map ${map} of ${name} is not an asset of this compilation`) };
		const expected = Buffer.concat([before, Buffer.from(comment(name, map), 'utf8')]);
		if (!expected.equals(after)) return { failure: failure('no-data', `${name} is not the asset the source map comment was added to`) };
		maps.add(map);
		byName.set(name, { input: before, output: after, units: verified.units });
	}
	// The maps are the only assets this stage is allowed to have written, and
	// none of them is described: what is in them is a document built out of
	// every module of the chunk, which nothing here recomputes.
	for (const name of written) {
		if (!maps.has(name)) return { failure: failure('no-data', `${name} was written while the source maps of this compilation were`) };
		byName.set(name, { failure: failure('no-data', `${name} is the source map of an asset of this build, which this collector does not describe`) });
	}
	return { byName };
}

// The line the plugin puts at the end of the asset: the map named from the
// directory the asset itself stands in, wrapped as a comment of the language
// the asset is written in.
function comment(file, map) {
	const url = path.posix.relative(path.posix.dirname(`/${file}`), `/${map}`);
	const text = `${COMMENT}${url}`;
	return CSS_ASSET.test(file) ? text.replace(/^\n\/\/(.*)$/, '\n/*$1*/') : text;
}

// The comment is only described when the plugin that added it is the pinned
// source of the webpack that is running and is the only one working in that
// stage. Its text is webpack's own, so that file is claimed with the asset.
async function verifyPlugin(compiler, state, verifyResource) {
	const registry = globalThis[REGISTRY];
	if (!registry || typeof registry.findByExport !== 'function' || typeof registry.getByFile !== 'function') {
		return { failure: failure('no-data', 'the commonjs load registry is not installed in this process') };
	}
	const api = compiler.webpack;
	if (!api || typeof api.version !== 'string') return { failure: failure('no-data', 'the compiler does not expose its webpack') };
	if (api.version !== SUPPORTED_WEBPACK) return { failure: failure('unsupported', `the source maps of webpack ${api.version} are not described, only ${SUPPORTED_WEBPACK}`) };
	const base = api.RuntimeModule && registry.findByExport(api.RuntimeModule);
	if (!base || !base.usable) return { failure: failure('no-data', 'the webpack RuntimeModule base class was not observed being loaded by this process') };
	const entry = registry.getByFile(path.join(path.dirname(base.file), PLUGIN_FILE));
	if (!entry || !entry.usable || !('exports' in entry)) return { failure: failure('no-data', `${PLUGIN_FILE} was not observed being loaded by this process`) };
	if (api.SourceMapDevToolPlugin !== entry.exports) return { failure: failure('no-data', 'the compiler exposes a SourceMapDevToolPlugin other than the one loaded from its lib directory') };
	if (state.taps === null) return { failure: failure('no-data', 'the taps writing the source maps of this compilation could not be observed') };
	if (state.taps.length !== 1 || state.taps[0] !== PLUGIN_TAP) {
		return { failure: failure('no-data', `${state.taps.join(', ') || 'nothing'} wrote into the assets of this compilation in the stage the source maps are written in`) };
	}
	let resolved;
	try {
		resolved = await verifyResource(entry.file);
	} catch (error) {
		return { failure: failure('no-data', `${entry.file} could not be verified: ${error.message}`) };
	}
	if (!resolved || (!resolved.unit && !resolved.failure)) return { failure: failure('no-data', `${entry.file} was not verified`) };
	if (resolved.failure) return { failure: resolved.failure };
	if (resolved.unit.sha256 !== entry.sha256) return { failure: failure('hash-mismatch', `${entry.file} differs from the bytes this process loaded from it`) };
	if (resolved.unit.sha256 !== FINGERPRINT) return { failure: failure('unsupported', `${PLUGIN_FILE} is not the source of the pinned webpack ${SUPPORTED_WEBPACK}`) };
	const component = resolved.unit.component;
	if (component === null || typeof component !== 'object' || component.name !== 'webpack' || component.version !== SUPPORTED_WEBPACK) {
		return { failure: failure('invalid', `component ${component && component.id ? component.id : 'none'} is not the webpack ${SUPPORTED_WEBPACK} that is running`) };
	}
	return { units: [{ path: resolved.unit.path, sha256: resolved.unit.sha256, component }] };
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

module.exports = { installSourcemapEvidence };
