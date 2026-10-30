'use strict';

// Binds the css one sass-loader module produced to the Sass sources that were
// really consumed to produce it: the stylesheet the loader was given as data,
// and every partial whose bytes this process watched Sass read while that one
// render was running.
//
// Sass has no public api that reports the bytes of what it loaded, and the file
// list it does report is a list of paths read back after the fact. So the
// implementation the loader compiles with is a wrapper of this adapter's own
// making, and the reads it performs are observed through a pass-through of
// fs.readFileSync that records only while a wrapped render is in flight. A read
// whose path or bytes cannot be told, a path with no read behind it, and two
// reads of one path that disagree all leave the module undescribed.
//
// The sass-loader distribution and the sass it loads are the instrument, not an
// input: they contribute no unit of their own. The identity of the files this
// process ran comes from runtime-preload.cjs, which must already be installed
// when either of them is first required.

const crypto = require('node:crypto');
const fs = require('node:fs');
const { createRequire } = require('node:module');
const path = require('node:path');

const NAME = 'DkSbomSassEvidence';
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const SUPPORTED_WEBPACK = '5.94.0';
const CANONICAL_SHA256 = /^sha256:[0-9a-f]{64}$/;
const BOM = Buffer.from([0xef, 0xbb, 0xbf]);
// The published artifacts this adapter knows how to drive, by their place in
// the distribution and by the bytes of the npm archives of these two versions.
const LOADER_ENTRY = path.join('sass-loader', 'dist', 'cjs.js');
const LOADER_FILES = new Map([
	[path.join('dist', 'cjs.js'), 'sha256:a45bce1d967c168463dd71645f57b95e1541ee18db961014f48559eecaae5e32'],
	[path.join('dist', 'index.js'), 'sha256:91440b3eca176f7b3656b8dcad7e5523154d6fd8ff2544d524c0fc932b976296'],
	[path.join('dist', 'utils.js'), 'sha256:4d0948db6eab79ab87776b929b3e374b51d394065a80dd3e5d5c14b703d57598'],
]);
const SASS_ENTRY = 'sass.default.dart.js';
const SASS_FILES = new Map([
	[SASS_ENTRY, 'sha256:146019ec68f94ef65359450094c4d8ac7af37ba02c324f2314555374977e9b92'],
	['sass.dart.js', 'sha256:bed180ba1d59efe0bcfb0d27862f30766995acd3a393a242a17031766561439d'],
]);

// One recorder for the whole process: Sass reaches the file system through the
// fs module object every build shares, and the renders of concurrently built
// modules interleave on it.
const reads = { seq: 0, inflight: 0, records: [], wrapper: null };
const loaders = new Map();
const implementations = new Map();

function installSassEvidence(compiler, verifyResource) {
	if (typeof verifyResource !== 'function') throw new TypeError(`${NAME}: verifyResource must be a function`);
	const records = new WeakMap();
	const state = prepare(compiler);
	if (!state.failure) {
		compiler.hooks.compilation.tap(NAME, (compilation) => {
			compiler.webpack.NormalModule.getCompilationHooks(compilation).beforeLoaders.tap(NAME, (chain, module) => {
				instrument(records, chain, module);
			});
		});
	}
	return async function evidenceFor(module, rawInput) {
		if (state.failure) return { units: [], failure: state.failure };
		try {
			return await describe(state, records.get(module), module, rawInput, verifyResource);
		} catch (error) {
			return noData(`${identify(module)} could not be described: ${error.message}`);
		}
	};
}

function prepare(compiler) {
	const registry = globalThis[REGISTRY];
	if (!registry || typeof registry.getByFile !== 'function') return noData('the commonjs load registry is not installed in this process');
	const api = compiler.webpack;
	if (!api || typeof api.version !== 'string' || !api.NormalModule || typeof api.NormalModule.getCompilationHooks !== 'function') {
		return noData('the compiler does not expose the webpack that builds its modules');
	}
	if (api.version !== SUPPORTED_WEBPACK) return failed('unsupported', `modules of webpack ${api.version} are not described, only ${SUPPORTED_WEBPACK}`);
	return { registry };
}

// The file of a sass-loader distribution this adapter recognizes, or nothing:
// the bytes on disk are what node is about to compile, and what really ran is
// checked against the registry once the module has been built.
function isKnownSassLoader(file) {
	return knownLoader(file) !== null;
}

function knownLoader(file) {
	if (typeof file !== 'string' || file === '') return null;
	if (loaders.has(file)) return loaders.get(file);
	const known = recognize(file);
	// A failed recognition may be a transient read error, so only a recognized
	// loader is remembered.
	if (known) loaders.set(file, known);
	return known;
}

function recognize(file) {
	let entry;
	try {
		entry = require.resolve(file);
	} catch {
		return null;
	}
	if (!entry.endsWith(path.sep + LOADER_ENTRY)) return null;
	const root = path.dirname(path.dirname(entry));
	const files = new Map();
	for (const [relative, sha256] of LOADER_FILES) {
		const member = path.join(root, relative);
		let bytes;
		try {
			bytes = fs.readFileSync(member);
		} catch {
			return null;
		}
		if (digest(bytes) !== sha256) return null;
		files.set(member, sha256);
	}
	return { entry, root, files };
}

// The sass the loader itself would load, resolved the way the loader resolves
// it, verified on disk before it is required and fingerprinted through the
// registry once it has run.
function implementationOf(known) {
	if (implementations.has(known.root)) return implementations.get(known.root);
	const tool = resolveSass(known);
	implementations.set(known.root, tool);
	return tool;
}

function resolveSass(known) {
	const from = createRequire(path.join(known.root, 'dist', 'utils.js'));
	let entry;
	try {
		entry = from.resolve('sass');
	} catch (error) {
		return noData(`the sass of ${known.root} could not be resolved: ${error.message}`);
	}
	if (path.basename(entry) !== SASS_ENTRY) return noData(`${entry} is not the entry of a sass distribution this adapter describes`);
	const root = path.dirname(entry);
	const files = new Map();
	for (const [name, sha256] of SASS_FILES) {
		const member = path.join(root, name);
		let bytes;
		try {
			bytes = fs.readFileSync(member);
		} catch (error) {
			return noData(`${member} could not be read: ${error.code || error.message}`);
		}
		if (digest(bytes) !== sha256) return failed('hash-mismatch', `${member} is not the published file of the sass this adapter describes`);
		files.set(member, sha256);
	}
	let sass;
	try {
		sass = from(entry);
	} catch (error) {
		return noData(`${entry} could not be loaded: ${error.message}`);
	}
	if (sass === null || typeof sass !== 'object' || typeof sass.info !== 'string' || typeof sass.render !== 'function') {
		return noData(`${entry} does not export the sass api this adapter drives`);
	}
	return { entry, files, module: sass, render: sass.render, info: sass.info };
}

// The loader runs with a clone of its item carrying this module's render; the
// rule object the user configured is shared by every module it matches and is
// never touched.
function instrument(records, chain, module) {
	// A style-loader at the head pitches over the rest of the chain: the module
	// that really runs sass is the one of the request it pitches, which resolves
	// its loader options from the rule again rather than from this module.
	if (!Array.isArray(chain) || chain.length !== 2) return;
	if (chain.filter((item) => isKnownSassLoader(item && item.loader)).length !== 1) return;
	const index = chain.length - 1;
	const item = chain[index];
	const known = knownLoader(item && item.loader);
	if (!known) return;
	// Every option of this loader changes what Sass is given, where it reads
	// from, or which implementation produces the css, and none of that would be
	// observed here.
	if (!plain(item.options)) return;
	const tool = implementationOf(known);
	if (tool.failure) {
		records.set(module, { problem: tool });
		return;
	}
	const record = { known, tool, calls: 0 };
	// From here on this process watches every file read: the reads of this
	// module's render are the ones that happen inside its window.
	watch();
	record.render = function (options, callback) {
		return render(record, tool, options, callback, this);
	};
	record.implementation = { info: tool.info, render: record.render };
	record.item = { ...item, options: { ...item.options, implementation: record.implementation } };
	chain[index] = record.item;
	records.set(module, record);
}

function plain(options) {
	if (options === undefined || options === null || options === '') return true;
	if (typeof options !== 'object' || Array.isArray(options) || Object.getPrototypeOf(options) !== Object.prototype) return false;
	return Reflect.ownKeys(options).length === 0;
}

// The published render, called once, with what the loader passed and a callback
// that forwards whatever it is given. Everything observed about the call is the
// window of reads it spans and a copy of the result taken before anything else
// can see it.
function render(record, tool, options, callback, receiver) {
	record.calls += 1;
	if (record.calls > 1) {
		record.observed = undefined;
		record.problem = failed('invalid', 'sass rendered this module more than once');
		return tool.render.call(tool.module, options, callback);
	}
	const intact = fs.readFileSync === reads.wrapper;
	const start = open();
	let settled = false;
	const done = (error, result) => {
		if (settled) return callback.call(receiver, error, result);
		settled = true;
		const window = close(start);
		if (error) record.problem = noData(`sass did not render this module: ${error && error.message ? error.message : String(error)}`);
		else record.observed = observed(options, result, window, intact && fs.readFileSync === reads.wrapper);
		return callback.call(receiver, error, result);
	};
	try {
		return tool.render.call(tool.module, options, done);
	} catch (error) {
		if (!settled) {
			settled = true;
			close(start);
			record.problem = noData(`sass did not render this module: ${error && error.message ? error.message : String(error)}`);
		}
		throw error;
	}
}

// Copied while the call is still inside the wrapper: the result object is the
// Sass compiler's own, and the records are released as soon as the last render
// of this process ends.
function observed(options, result, window, intact) {
	const css = result === null || typeof result !== 'object' ? undefined : result.css;
	const stats = result === null || typeof result !== 'object' ? undefined : result.stats;
	const included = stats === null || typeof stats !== 'object' ? undefined : stats.includedFiles;
	return {
		intact,
		window,
		css: Buffer.isBuffer(css) ? Buffer.from(css) : typeof css === 'string' ? Buffer.from(css, 'utf8') : null,
		included: Array.isArray(included) ? included.slice() : null,
		file: options === null || typeof options !== 'object' ? undefined : options.file,
		data: options === null || typeof options !== 'object' ? undefined : options.data,
		importer: options === null || typeof options !== 'object' ? undefined : options.importer,
	};
}

function watch() {
	if (reads.wrapper) return;
	const original = fs.readFileSync;
	const wrapper = function (file, options) {
		const result = original.apply(this, arguments);
		if (reads.inflight > 0) {
			// Another function installed over this one may hand Sass other bytes
			// than the ones read here, so its presence poisons the window.
			if (fs.readFileSync !== wrapper) poison();
			else capture(file, options, result);
		}
		return result;
	};
	Object.defineProperties(wrapper, Object.getOwnPropertyDescriptors(original));
	reads.wrapper = wrapper;
	fs.readFileSync = wrapper;
}

function open() {
	reads.inflight += 1;
	return reads.seq;
}

function close(start) {
	const end = reads.seq;
	const window = reads.records.filter((record) => record.seq > start && record.seq <= end);
	reads.inflight -= 1;
	if (reads.inflight === 0) reads.records.length = 0;
	return window;
}

// What a read returned, as bytes, taken before the caller can hand the value on
// or mutate it. A path or a value this adapter cannot tell is recorded as
// unknown rather than guessed at.
function capture(file, options, result) {
	reads.seq += 1;
	reads.records.push(Object.freeze({ seq: reads.seq, path: typeof file === 'string' && file !== '' ? path.resolve(file) : null, bytes: bytesOf(options, result) }));
}

function poison() {
	reads.seq += 1;
	reads.records.push(Object.freeze({ seq: reads.seq, path: null, bytes: null }));
}

function bytesOf(options, result) {
	if (Buffer.isBuffer(result)) return Buffer.from(result);
	if (typeof result !== 'string') return null;
	const encoding = typeof options === 'string' ? options : options === null || typeof options !== 'object' ? undefined : options.encoding;
	return typeof encoding === 'string' && Buffer.isEncoding(encoding) ? Buffer.from(result, encoding) : null;
}

async function describe(state, record, module, rawInput, verifyResource) {
	// Nothing was observed for a module another chain built, for one the adapter
	// refused to instrument, and for one webpack served from its cache without
	// building it.
	if (!record) return noData(`${identify(module)} was not built by an observed sass render`);
	if (record.problem) return record.problem;
	if (!record.observed) return noData(`no successful sass render of ${identify(module)} was observed`);
	const { known, tool, observed: call } = record;

	const chain = module.loaders;
	if (!Array.isArray(chain) || chain.length === 0 || chain[chain.length - 1] !== record.item) {
		return noData(`${identify(module)} was not built by the loader item this adapter installed`);
	}
	if (record.item.options.implementation !== record.implementation || record.implementation.render !== record.render) {
		return noData(`the sass implementation of ${identify(module)} was replaced after this adapter installed it`);
	}
	if (!call.intact) return noData(`the file reads of ${identify(module)} were not observed: fs.readFileSync was replaced while sass ran`);
	const ran = instrumentRan(state.registry, known, tool);
	if (ran) return ran;
	if (!Array.isArray(call.importer) || call.importer.length !== 1) {
		return noData(`${identify(module)} was rendered with ${Array.isArray(call.importer) ? call.importer.length : 'no array of'} importers, not the one the loader installs`);
	}
	if (typeof call.file !== 'string' || call.file === '' || call.file !== module.resource) {
		return noData(`${identify(module)} was rendered as ${typeof call.file === 'string' ? call.file : 'no file of its own'}`);
	}
	if (typeof call.data !== 'string' || !Buffer.isBuffer(call.css) || !Array.isArray(call.included)) {
		return noData(`the sass render of ${identify(module)} did not report what it compiled`);
	}
	if (typeof rawInput !== 'string') return noData(`${identify(module)} did not hand on the css sass returned`);
	if (call.css.toString('utf8') !== rawInput) {
		return failed('hash-mismatch', `the css of ${identify(module)} is not what sass returned for it`);
	}
	if (call.window.some((read) => read.path === null || read.bytes === null)) {
		return noData(`${identify(module)} was rendered while a file read this adapter cannot tell the bytes of was in flight`);
	}

	const entry = await sourceUnit(verifyResource, call.file, call.data);
	if (entry.failure) return entry;
	const units = [entry.unit];
	const seen = new Set([call.file]);
	for (const included of call.included) {
		if (typeof included !== 'string' || included === '') return noData(`${identify(module)} reported a file it included without naming it`);
		const file = path.normalize(included);
		if (!path.isAbsolute(file)) return noData(`${identify(module)} included ${included}, which is not a file of this file system`);
		if (seen.has(file)) continue;
		seen.add(file);
		const partial = await partialUnit(verifyResource, call.window, file, module);
		if (partial.failure) return partial;
		units.push(partial.unit);
	}
	return { units };
}

// The bytes the loader and the compiler really ran, as the registry recorded
// them when node compiled each file.
function instrumentRan(registry, known, tool) {
	for (const [file, sha256] of [...known.files, ...tool.files]) {
		const entry = registry.getByFile(file);
		if (!entry || !entry.usable) return noData(`${file} was not recorded as a loaded commonjs module`);
		if (entry.sha256 !== sha256) return failed('hash-mismatch', `${file} ran source other than the published bytes`);
	}
	const entry = registry.getByFile(tool.entry);
	if (require.cache[tool.entry] === undefined || require.cache[tool.entry].exports !== tool.module || entry.exports !== tool.module) {
		return noData(`${tool.entry} does not export the sass this adapter rendered with`);
	}
	if (tool.module.render !== tool.render) return noData(`the render of ${tool.entry} was replaced after this adapter recorded it`);
	return null;
}

// The stylesheet the loader handed to sass as data: it is never read while the
// render runs, so what binds it is the text the loader itself was given.
async function sourceUnit(verifyResource, file, data) {
	const resolution = await verified(verifyResource, file);
	if (resolution.failure) return resolution;
	const text = textOf(resolution.unit);
	if (text.failure) return text;
	if (text.text !== data) return failed('hash-mismatch', `sass did not compile the verified bytes of ${file}`);
	return { unit: unitOf(resolution.unit) };
}

// A file sass reported as included is a source of this module only if this
// process watched it being read and every read of it agrees with the verified
// bytes; a path with no read behind it is one this adapter cannot speak for.
async function partialUnit(verifyResource, window, file, module) {
	const observations = window.filter((read) => read.path === file);
	if (observations.length === 0) return noData(`${identify(module)} included ${file} without this adapter observing it being read`);
	for (const read of observations) {
		if (!read.bytes.equals(observations[0].bytes)) return noData(`${file} was read more than once with different bytes while ${identify(module)} was rendered`);
	}
	const resolution = await verified(verifyResource, file);
	if (resolution.failure) return resolution;
	const unit = resolution.unit;
	if (!Buffer.isBuffer(unit.bytes)) return noData(`${unit.path} was verified without its bytes`);
	if (digest(unit.bytes) !== unit.sha256) return failed('invalid', `${unit.path} was verified as bytes other than the ones it carries`);
	if (!unit.bytes.equals(observations[0].bytes)) return failed('hash-mismatch', `sass did not read the verified bytes of ${unit.path}`);
	return { unit: unitOf(unit) };
}

async function verified(verifyResource, file) {
	let resolution;
	try {
		resolution = await verifyResource(file);
	} catch (error) {
		return noData(`${file} could not be verified: ${error.message}`);
	}
	if (!resolution || (!resolution.unit && !resolution.failure)) return noData(`${file} was not verified`);
	if (resolution.failure) return { units: [], failure: resolution.failure };
	const unit = resolution.unit;
	if (!unit || typeof unit.path !== 'string' || !CANONICAL_SHA256.test(String(unit.sha256)) || unit.component === null || typeof unit.component !== 'object') {
		return noData(`${file} was not verified as a described unit`);
	}
	return { unit };
}

function textOf(unit) {
	if (!Buffer.isBuffer(unit.bytes)) return noData(`${unit.path} was verified without its bytes`);
	if (digest(unit.bytes) !== unit.sha256) return failed('invalid', `${unit.path} was verified as bytes other than the ones it carries`);
	// loader-runner hands a loader the file text with a byte order mark stripped:
	// those bytes would be described as compiled, and they were not.
	if (unit.bytes.length >= BOM.length && unit.bytes.subarray(0, BOM.length).equals(BOM)) {
		return noData(`${unit.path} starts with a byte order mark the loader does not pass on`);
	}
	const text = unit.bytes.toString('utf8');
	if (!Buffer.from(text, 'utf8').equals(unit.bytes)) return noData(`${unit.path} is not valid utf8`);
	return { text };
}

function unitOf(unit) {
	return { path: unit.path, sha256: unit.sha256, component: unit.component };
}

function digest(bytes) {
	return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function identify(module) {
	try {
		const name = module.identifier();
		if (typeof name === 'string' && name !== '') return name;
	} catch {
		// An identifier of its own making is not worth failing over.
	}
	return 'the module';
}

function failed(status, reason) {
	return { units: [], failure: { status, reason } };
}

function noData(reason) {
	return failed('no-data', reason);
}

module.exports = { installSassEvidence, isKnownSassLoader };
