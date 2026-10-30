'use strict';

// Binds the comment webpack's BannerPlugin puts in front of an asset to the
// pinned source that wrote it.
//
// The plugin works in one stage of its own, before anything minifies or renames
// the assets. The assets are snapshotted on both sides of that stage, the
// comment is built again here out of the banner the plugin was configured with,
// and unless every asset of the compilation comes out of that recomputation
// exactly, nothing is described.
//
// The banner itself is text the build was configured with, not a file: it
// contributes no component. What the plugin wraps it in is webpack's own source,
// which is the one unit this adapter claims.
//
// The load recordings come from runtime-preload.cjs; without them there is no
// data.

const path = require('node:path');

const NAME = 'DkSbomBannerEvidence';
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const SUPPORTED_WEBPACK = '5.94.0';
const PLUGIN_FILE = 'BannerPlugin.js';
const PLUGIN_TAP = 'BannerPlugin';
// Its raw bytes in the webpack 5.94.0 registry archive whose sha512 is the
// integrity pinned in package-lock.json.
const FINGERPRINT = 'sha256:14e40801a9931517c7953a2ce562d1051984338d6e374d7dd5c311aff643bd4c';
// The options that make the plugin write something other than one comment in
// front of every asset of the build.
const UNDESCRIBED = ['raw', 'footer', 'test', 'include', 'exclude', 'stage'];

function installBannerEvidence(compiler, verifyResource) {
	if (typeof verifyResource !== 'function') throw new TypeError(`${NAME}: verifyResource must be a function`);
	const states = new WeakMap();
	compiler.hooks.compilation.tap(NAME, (compilation) => {
		// A child compiler copies the taps of the one that made it; the assets
		// of its compilations are described through their own render, and a tap
		// of this adapter there is a tap another adapter would have to account
		// for.
		if (compilation.compiler !== compiler) return;
		const api = compiler.webpack;
		const stage = api && api.Compilation && api.Compilation.PROCESS_ASSETS_STAGE_ADDITIONS;
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
		if (!described) return noData(`${assetName} is not an asset this compilation banners`);
		return described;
	};
}

function snapshot(compilation) {
	const assets = new Map();
	for (const { name, source } of compilation.getAssets()) assets.set(name, bytesOf(source));
	return assets;
}

// The taps that work in the very stage this adapter watches; the plugin renames
// nothing, so a tap of anyone else there is a change it cannot attribute.
function tapsAt(compilation, stage) {
	const taps = compilation.hooks.processAssets && compilation.hooks.processAssets.taps;
	if (!Array.isArray(taps)) return null;
	return taps.filter((tap) => tap && tap.stage === stage).map((tap) => tap.name);
}

async function analyse(compiler, state, verifyResource) {
	const silent = { byName: new Map([...state.before.keys()].map((name) => [name, { status: 'none' }])) };
	// Nothing in this stage was a banner at all: this adapter describes no asset
	// of this compilation, and whatever did change there is left to the
	// comparison of the render with the bytes that were emitted.
	if (state.taps !== null && !state.taps.includes(PLUGIN_TAP)) return silent;
	const changed = [];
	const unreadable = [];
	for (const [name, before] of state.before) {
		const after = state.after.get(name);
		if (!state.after.has(name)) unreadable.push(`${name} is not an asset of this compilation any more`);
		else if (!before || !after) unreadable.push(`the bytes of ${name} could not be read on both sides of its banner`);
		else if (!before.equals(after)) changed.push({ name, before, after });
	}
	// Nothing was put in front of anything here.
	if (changed.length === 0 && unreadable.length === 0 && state.before.size === state.after.size) return silent;
	if (state.before.size !== state.after.size) return { failure: failure('no-data', 'the assets of this compilation changed while their banner was added') };
	if (unreadable.length > 0) return { failure: failure('no-data', unreadable[0]) };
	if (changed.length === 0) return silent;

	const verified = await verifyPlugin(compiler, state, verifyResource);
	if (verified.failure) return verified;
	// Built again out of the banner the plugin was configured with, the way its
	// own source builds it.
	const comment = wrapComment(verified.banner);
	// A token in the comment would be replaced with something of the asset's own
	// by the path templating this adapter does not describe.
	if (/[[\]]/.test(comment)) return { failure: failure('no-data', 'the banner of this compilation carries a path template') };
	const prefix = Buffer.from(`${comment}\n`, 'utf8');
	const byName = silent.byName;
	for (const { name, before, after } of changed) {
		if (!after.equals(Buffer.concat([prefix, before]))) {
			return { failure: failure('no-data', `${name} is not the asset the banner of this compilation was put in front of`) };
		}
		byName.set(name, { input: before, output: after, units: verified.units });
	}
	return { byName };
}

// The one comment the pinned source builds for a banner of several lines, and
// for one of a single line.
function wrapComment(text) {
	if (!text.includes('\n')) return toComment(text);
	return `/*!\n * ${text
		.replace(/\*\//g, '* /')
		.split('\n')
		.join('\n * ')
		.replace(/\s+\n/g, '\n')
		.trimEnd()}\n */`;
}

function toComment(text) {
	if (!text) return '';
	return `/*! ${text.replace(/\*\//g, '* /')} */`;
}

// The banner is only described when the plugin that added it is the pinned
// source of the webpack that is running, is the only one working in that stage,
// and was configured with text rather than with code of its own.
async function verifyPlugin(compiler, state, verifyResource) {
	const registry = globalThis[REGISTRY];
	if (!registry || typeof registry.findByExport !== 'function' || typeof registry.getByFile !== 'function') {
		return { failure: failure('no-data', 'the commonjs load registry is not installed in this process') };
	}
	const api = compiler.webpack;
	if (!api || typeof api.version !== 'string') return { failure: failure('no-data', 'the compiler does not expose its webpack') };
	if (api.version !== SUPPORTED_WEBPACK) return { failure: failure('unsupported', `the banners of webpack ${api.version} are not described, only ${SUPPORTED_WEBPACK}`) };
	const base = api.RuntimeModule && registry.findByExport(api.RuntimeModule);
	if (!base || !base.usable) return { failure: failure('no-data', 'the webpack RuntimeModule base class was not observed being loaded by this process') };
	const entry = registry.getByFile(path.join(path.dirname(base.file), PLUGIN_FILE));
	if (!entry || !entry.usable || !('exports' in entry)) return { failure: failure('no-data', `${PLUGIN_FILE} was not observed being loaded by this process`) };
	if (api.BannerPlugin !== entry.exports) return { failure: failure('no-data', 'the compiler exposes a BannerPlugin other than the one loaded from its lib directory') };
	if (state.taps === null) return { failure: failure('no-data', 'the taps adding the banners of this compilation could not be observed') };
	if (state.taps.length !== 1 || state.taps[0] !== PLUGIN_TAP) {
		return { failure: failure('no-data', `${state.taps.join(', ') || 'nothing'} added to the assets of this compilation in the stage the banner is added in`) };
	}

	const plugins = Array.isArray(compiler.options.plugins) ? compiler.options.plugins.filter((plugin) => plugin instanceof entry.exports) : [];
	if (plugins.length !== 1) return { failure: failure('no-data', `this compilation is configured with ${plugins.length} banner plugins`) };
	const plugin = plugins[0];
	if (Object.getPrototypeOf(plugin) !== entry.exports.prototype) return { failure: failure('no-data', 'the banner was added by a plugin derived from BannerPlugin') };
	const options = plugin.options;
	if (options === null || typeof options !== 'object' || Object.getPrototypeOf(options) !== Object.prototype) {
		return { failure: failure('no-data', 'the banner plugin of this compilation was not configured with plain options') };
	}
	for (const key of UNDESCRIBED) {
		if (options[key] !== undefined) return { failure: failure('no-data', `the banner plugin of this compilation was configured with ${key}`) };
	}
	// Text, not a function: what a function would return is code of its own,
	// built from data this adapter never saw.
	const descriptor = Object.getOwnPropertyDescriptor(options, 'banner');
	if (!descriptor || !('value' in descriptor) || typeof descriptor.value !== 'string') {
		return { failure: failure('no-data', 'the banner of this compilation is not text of its own') };
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
	return { banner: descriptor.value, units: [{ path: resolved.unit.path, sha256: resolved.unit.sha256, component }] };
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

module.exports = { installBannerEvidence };
