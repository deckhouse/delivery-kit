'use strict';

// Decides whether the values webpack's DefinePlugin splices into the code of
// every module it parses are data.
//
// The plugin replaces an expression with the **text** of the value it was
// configured with: `'"2.4.0"'` becomes the string literal, but
// `'require("x")'` would become that call. Such text stands in the asset while
// the module it was spliced into still matches its file on disk, so nothing
// else in this collector can see it.
//
// A value that reads as a json literal cannot reference anything: it is data
// the build was configured with, it carries no component, and the modules it
// was spliced into keep their claim. Anything else - a function, a regular
// expression, a runtime value, or a string that is not a literal - is code this
// collector cannot attribute, and every module of the compilation is refused.
//
// The load recordings come from runtime-preload.cjs; without them there is no
// data.

const path = require('node:path');

const NAME = 'DkSbomDefineEvidence';
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const SUPPORTED_WEBPACK = '5.94.0';
const PLUGIN_FILE = 'DefinePlugin.js';
const PLUGIN_TAP = 'DefinePlugin';
// Webpack defines one constant of its own when the build sets it, from this
// file, with a value it writes as json.
const OPTIONS_FILE = 'WebpackOptionsApply.js';
// Its raw bytes in the webpack 5.94.0 registry archive whose sha512 is the
// integrity pinned in package-lock.json.
const FINGERPRINT = 'sha256:938087ec33eb83ada89f76fa0cb8dc2ba7451d5ebf45b891c978a6049bc048e7';
const OPTIONS_FINGERPRINT = 'sha256:f64d02ab13536119f4021f14335bb49f83df3f8399be86665e761a1dbea414bf';

// How many plugins were defining constants when each compilation started, which
// is after anything that applies a plugin to the compiler it runs on and before
// any of them could have taken its tap away again. A compiler this one makes is
// watched the same way: the taps it was given are copied from this one, and a
// plugin may add to them afterwards.
function installDefineEvidence(compiler) {
	const counted = new WeakMap();
	const watched = new WeakSet();
	const watch = (candidate) => {
		if (watched.has(candidate)) return;
		watched.add(candidate);
		candidate.hooks.compilation.tap(NAME, (compilation) => {
			counted.set(compilation, tapsNamed(candidate, PLUGIN_TAP));
			compilation.hooks.childCompiler.tap(NAME, (child) => watch(child));
		});
	};
	watch(compiler);
	return counted;
}

// Null when the modules of this compilation may keep their claim.
async function defineProblem(compiler, counted, verifyResource, compilation) {
	const api = compiler.webpack;
	const plugin = api && api.DefinePlugin;
	if (typeof plugin !== 'function') return null;
	const configured = Array.isArray(compiler.options.plugins) ? compiler.options.plugins.filter((candidate) => candidate instanceof plugin) : [];
	const taps = counted && compilation ? counted.get(compilation) : undefined;
	if (typeof taps !== 'number') return failure('no-data', 'the plugins defining the constants of this compilation could not be observed');
	// Webpack defines the one constant of its own in that same way, and writes
	// its value as json.
	const nodeEnv = compiler.options.optimization && compiler.options.optimization.nodeEnv;
	const own = nodeEnv === false || nodeEnv === undefined ? 0 : 1;
	if (own === 1 && typeof nodeEnv !== 'string') return failure('no-data', 'this build defines an environment of its own that is not a name');
	// One that is neither configured in the build nor webpack's own defines
	// constants this collector never saw.
	if (taps !== configured.length + own) return failure('no-data', `${taps} plugins define constants in this compilation and ${configured.length + own} of them are accounted for`);
	if (taps === 0) return null;

	const verified = await verifyPlugin(compiler, verifyResource, own === 1);
	if (verified) return verified;
	for (const candidate of configured) {
		if (Object.getPrototypeOf(candidate) !== plugin.prototype) return failure('no-data', 'the constants of this build are defined by a plugin derived from DefinePlugin');
		const problem = dataProblem(candidate.definitions, []);
		if (problem) return failure('no-data', `the build defines ${problem} as code rather than as data`);
	}
	return null;
}

// Which of the definitions is text the plugin would splice as code, named the
// way it is written in the configuration.
function dataProblem(value, keys) {
	const where = keys.join('.');
	if (value === null || value === undefined || typeof value === 'number' || typeof value === 'boolean') return null;
	if (typeof value === 'string') {
		if (isJson(value)) return null;
		return `${where} = ${JSON.stringify(value)}`;
	}
	if (typeof value !== 'object') return where;
	if (Array.isArray(value)) {
		for (const [index, item] of value.entries()) {
			const problem = dataProblem(item, [...keys, index]);
			if (problem) return problem;
		}
		return null;
	}
	// A plain object is walked; anything else - a regular expression, a runtime
	// value, a class of its own - is text of its own making.
	if (Object.getPrototypeOf(value) !== Object.prototype) return where || 'a value of its own';
	for (const key of Reflect.ownKeys(value)) {
		if (typeof key !== 'string') return where || 'a key of its own';
		const descriptor = Object.getOwnPropertyDescriptor(value, key);
		if (!('value' in descriptor)) return [...keys, key].join('.');
		const problem = dataProblem(descriptor.value, [...keys, key]);
		if (problem) return problem;
	}
	return null;
}

function isJson(text) {
	try {
		JSON.parse(text);
		return true;
	} catch {
		return false;
	}
}

function tapsNamed(compiler, name) {
	const taps = compiler.hooks.compilation && compiler.hooks.compilation.taps;
	if (!Array.isArray(taps)) return null;
	return taps.filter((tap) => tap && tap.name === name).length;
}

// The plugin reading those definitions has to be the pinned source of the
// webpack that is running; nothing of it lands in an asset, so it is the
// instrument here and claims nothing.
async function verifyPlugin(compiler, verifyResource, withOwn) {
	const registry = globalThis[REGISTRY];
	if (!registry || typeof registry.findByExport !== 'function' || typeof registry.getByFile !== 'function') {
		return failure('no-data', 'the commonjs load registry is not installed in this process');
	}
	const api = compiler.webpack;
	if (api.version !== SUPPORTED_WEBPACK) return failure('unsupported', `the constants of webpack ${api.version} are not described, only ${SUPPORTED_WEBPACK}`);
	const base = api.RuntimeModule && registry.findByExport(api.RuntimeModule);
	if (!base || !base.usable) return failure('no-data', 'the webpack RuntimeModule base class was not observed being loaded by this process');
	const entry = registry.getByFile(path.join(path.dirname(base.file), PLUGIN_FILE));
	if (!entry || !entry.usable || !('exports' in entry)) return failure('no-data', `${PLUGIN_FILE} was not observed being loaded by this process`);
	if (api.DefinePlugin !== entry.exports) return failure('no-data', 'the compiler exposes a DefinePlugin other than the one loaded from its lib directory');
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
	if (!withOwn) return null;
	return verifyFile(registry, path.join(path.dirname(base.file), OPTIONS_FILE), OPTIONS_FILE, OPTIONS_FINGERPRINT, verifyResource);
}

async function verifyFile(registry, file, name, fingerprint, verifyResource) {
	const entry = registry.getByFile(file);
	if (!entry || !entry.usable) return failure('no-data', `${name} was not observed being loaded by this process`);
	let resolved;
	try {
		resolved = await verifyResource(file);
	} catch (error) {
		return failure('no-data', `${file} could not be verified: ${error.message}`);
	}
	if (!resolved || (!resolved.unit && !resolved.failure)) return failure('no-data', `${file} was not verified`);
	if (resolved.failure) return resolved.failure;
	if (resolved.unit.sha256 !== entry.sha256) return failure('hash-mismatch', `${file} differs from the bytes this process loaded from it`);
	if (resolved.unit.sha256 !== fingerprint) return failure('unsupported', `${name} is not the source of the pinned webpack ${SUPPORTED_WEBPACK}`);
	return null;
}

function failure(status, reason) {
	return { status, reason };
}

module.exports = { installDefineEvidence, defineProblem };
