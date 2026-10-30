'use strict';

// Binds the two modules workerize-loader builds to the files that authored
// them, and the worker's own bytes to the compilation that produced them.
//
// The loader pitches: the module it was asked for is never read in the parent
// compilation. What the parent gets instead is a small text the loader writes
// around a child compilation it runs itself - a `new Worker(...)` factory whose
// url, with the `inline` option redoc builds with, is the whole child asset
// embedded as a string literal. None of that text is in any file, so it is
// described by recomputing it from what the loader was given and binding it to
// the loader's own published source.
//
// The worker's bytes are not described here either: they are an asset of the
// child compilation, which observed its own render, runtime modules, minifier
// and content hashes like any other, and they are handed to the ordinary asset
// evidence of that compilation. What this adapter adds is the proof that the
// literal in the parent is exactly those bytes.
//
// The second module is the worker's entry: the loader compiles it through
// `rpc-worker-loader.js`, which appends a script it builds at run time from its
// own source text. That text is recomputed from the verified file - the same
// function source, the same regexp - and the module is refused when anything
// else transformed it.
//
// The recordings come from worker-preload.cjs, which must already be installed
// when the loader is first required, and the identity of the files it
// recognized comes from runtime-preload.cjs underneath it.

const path = require('node:path');

const { assetEvidence, observedBytes } = require('./bootstrap-evidence.cjs');

const NAME = 'DkSbomWorkerEvidence';
const BOM = Buffer.from([0xef, 0xbb, 0xbf]);
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const WORKER = Symbol.for('dk.sbom.webpack.worker');
const SUPPORTED_WEBPACK = '5.94.0';
const LOADER_FILE = path.join('workerize-loader', 'dist', 'index.js');
// dist/index.js:177, with its four interpolations marked. Every other character
// of it is the loader's own code.
const WRAPPER_TEMPLATE = '\n\t\t\t\tvar addMethods = require(\0)\n\t\t\t\tvar methods = \0\n\t\t\t\tmodule.exports = function() {\n\t\t\t\t\tvar w = new Worker(\0, { name: \0 })\n\t\t\t\t\taddMethods(w, methods)\n\t\t\t\t\t\n\t\t\t\t\treturn w\n\t\t\t\t}\n\t\t\t';
// The options this adapter describes. `ready` and `import` write further text,
// and a build that asks for them is refused rather than described by halves.
const DESCRIBED_OPTIONS = ['inline', 'fallback', 'name'];
// dist/rpc-worker-loader.js:1, the one expression that turns the loader's own
// function source into the script it appends to the worker entry.
const WORKER_SETUP = 'function workerSetup(';
const SETUP_STRIP = /(^.*\{|\}.*$|\n\s*)/g;

// `describeModule(module, compilation, chunk)` is the collector's own module
// describer: the worker's inputs are modules of a compilation nobody else
// walks, so they are described through it and claimed by the module that
// embeds them. The chunk is passed because a generated runtime module is
// described against the chunk it was generated for. `tailTransform` describes a
// loader that ran before the worker entry loader and returns the code it
// handed on; without it a worker entry built by a chain is not described.
function installWorkerEvidence(compiler, verifyResource, options = {}) {
	if (typeof verifyResource !== 'function') throw new TypeError(`${NAME}: verifyResource must be a function`);
	checkKeys(options, ['describeModule', 'tailTransform', 'readObservedBytes']);
	const describeModule = options.describeModule;
	const tailTransform = options.tailTransform;
	// How the bytes of an emitted asset are read back. The collector leaves this
	// to the observation of the compilation that emitted them; a caller may
	// supply another reader, and then it owns what that reader answers.
	const readObservedBytes = options.readObservedBytes || observedBytes;
	if (describeModule !== undefined && typeof describeModule !== 'function') throw new TypeError(`${NAME}: options.describeModule must be a function`);
	if (tailTransform !== undefined && typeof tailTransform !== 'function') throw new TypeError(`${NAME}: options.tailTransform must be a function`);
	if (options.readObservedBytes !== undefined && typeof options.readObservedBytes !== 'function') throw new TypeError(`${NAME}: options.readObservedBytes must be a function`);
	const recorder = globalThis[WORKER];
	const registry = globalThis[REGISTRY];
	const problem = prepare(compiler, recorder, registry);
	return async function evidenceFor(module, compilation, evidence = {}) {
		if (problem) return problem;
		try {
			return await describe({ recorder, registry, verifyResource, evidence, describeModule, tailTransform, readObservedBytes }, module, compilation);
		} catch (error) {
			return noData(`${identify(module)} could not be described: ${error.message}`);
		}
	};
}

function checkKeys(object, known) {
	for (const key of Object.keys(object)) {
		if (!known.includes(key)) throw new TypeError(`${NAME}: unknown option ${JSON.stringify(key)}`);
	}
}

function prepare(compiler, recorder, registry) {
	if (!recorder || typeof recorder.pitchOf !== 'function') return noData('the worker load recorder is not installed in this process');
	if (!registry || typeof registry.getByFile !== 'function') return noData('the commonjs load registry is not installed in this process');
	const api = compiler.webpack;
	if (!api || typeof api.version !== 'string') return noData('the compiler does not expose the webpack that builds its modules');
	if (api.version !== SUPPORTED_WEBPACK) return failed('unsupported', `modules of webpack ${api.version} are not described, only ${SUPPORTED_WEBPACK}`);
	return null;
}

async function describe(setup, module, compilation) {
	const loaders = Array.isArray(module.loaders) ? module.loaders : [];
	const first = loaders.length > 0 ? loaders[0].loader : undefined;
	// workerize-loader pitches, so whatever stands behind it in the chain never
	// ran: the module is its text alone. The worker entry is the other way
	// round - the chain behind the entry loader built the text it appends to.
	if (isWorkerEntryLoader(first)) return describeWorkerEntry(setup, module, compilation, loaders);
	if (!isWorkerLoader(first)) return noData(`${identify(module)} is not pitched by workerize-loader`);
	return describeWrapper(setup, module, compilation, first);
}

// The module the parent compilation got in place of the file it asked for.
async function describeWrapper(setup, module, compilation, loaderFile) {
	const loader = setup.recorder.loader();
	const pitch = setup.recorder.pitchOf(module);
	const bound = boundTo(loader, pitch, module, loaderFile);
	if (bound) return bound;

	const child = childOf(compilation, pitch);
	if (child.failure) return child;
	const asset = await workerAsset(setup, child.compilation, child.chunk);
	if (asset.failure) return asset;

	const loaderUnit = await verifiedFile(setup, loaderFile, setup.recorder.known.sha256, 'the loader that wrote this module');
	if (loaderUnit.failure) return loaderUnit;
	const wrapperUnit = await verifiedFile(setup, path.join(path.dirname(loaderFile), setup.recorder.known.wrapper.file), setup.recorder.known.wrapper.sha256, 'the rpc wrapper this module requires');
	if (wrapperUnit.failure) return wrapperUnit;

	const recomputed = recompute(pitch, asset, child, wrapperUnit.unit.path);
	if (recomputed.failure) return recomputed;
	const written = answerOf(pitch);
	if (written.failure) return written;
	if (written.content !== recomputed.text) {
		return failed('hash-mismatch', `${identify(module)} is not the text workerize-loader writes for what it was given`);
	}
	const kept = keptSource(module);
	if (kept === null) return noData(`the source webpack kept for ${identify(module)} is unavailable`);
	if (kept !== written.content) {
		return failed('hash-mismatch', `${identify(module)} was changed between the loader and the compilation`);
	}
	// The worker's own composition, described where it was built: the bytes this
	// module embeds are the asset of a compilation nobody else walks, so its
	// modules are claimed here as well. The rpc wrapper is a module of the
	// parent graph in its own right and is described there; it is named here
	// only because the text that requires it is this module's.
	const inputs = await childModules(setup, child);
	if (inputs.failure) return inputs;
	return { units: [unitOf(loaderUnit.unit), ...asset.units, ...inputs.units] };
}

// The worker's entry module: the text the chain behind the entry loader built,
// with a script appended that the loader builds from its own source text at run
// time.
async function describeWorkerEntry(setup, module, compilation, loaders) {
	const loaderUnit = await verifiedFile(setup, loaders[0].loader, setup.recorder.known.workerLoader.sha256, 'the loader that builds the worker entry');
	if (loaderUnit.failure) return loaderUnit;
	const appended = workerSetupScript(loaderUnit.unit.bytes);
	if (appended === null) return noData(`${loaderUnit.unit.path} does not hold the worker setup function this version recomputes`);

	const built = loaders.length === 1 ? await entrySource(setup, module) : await entryTail(setup, module, compilation);
	if (built.failure) return built;

	const kept = keptSource(module);
	if (kept === null) return noData(`the source webpack kept for ${identify(module)} is unavailable`);
	if (kept !== built.content + appended) {
		return failed('hash-mismatch', `${identify(module)} is not ${built.what} with the recomputed worker setup appended`);
	}
	return { units: [...built.units, unitOf(loaderUnit.unit)] };
}

// Nothing but the entry loader ran: the text is the file itself, as the loader
// runner handed it over.
async function entrySource(setup, module) {
	const resource = typeof module.resource === 'string' ? module.resource : '';
	if (resource === '' || resource.includes('?') || resource.includes('!')) {
		return noData(`the worker entry ${identify(module)} has no physical source`);
	}
	const entry = await setup.verifyResource(resource);
	if (entry.failure) return entry;
	const text = textOf(entry.unit);
	if (text.failure) return text;
	return { content: text.text, what: resource, units: [unitOf(entry.unit)] };
}

// A chain ran behind the entry loader, and its last transform authored the text
// the loader appended to. That transform describes itself and hands over the
// code it returned; this module owes only what happened to it afterwards.
async function entryTail(setup, module, compilation) {
	if (typeof setup.tailTransform !== 'function') {
		return noData(`the worker entry ${identify(module)} was built by a chain this collector describes no tail for`);
	}
	const tail = await setup.tailTransform(module, compilation);
	if (tail.failure) return tail;
	if (typeof tail.code !== 'string') return noData(`the tail of the worker entry ${identify(module)} returned no code`);
	return { content: tail.code, what: 'the code its loader chain returned', units: [...tail.units] };
}

// The modules of the worker's own chunk, described by the collector that walks
// every other compilation. A module of it that cannot be described leaves the
// embedded bytes unaccounted for, so the refusal is this module's too.
async function childModules(setup, child) {
	if (typeof setup.describeModule !== 'function') {
		return noData('the modules of the worker compilation are not described by this collector');
	}
	const graph = child.compilation.chunkGraph;
	if (!graph || typeof graph.getChunkModulesIterable !== 'function' || typeof graph.getChunkRuntimeModulesIterable !== 'function') {
		return noData('the worker compilation exposes no module graph');
	}
	// The runtime webpack generated for this chunk is code of the worker like any
	// other: the evidence of the asset binds the helpers its renderer wrote, not
	// the runtime module classes that wrote their own text.
	const units = [];
	// Both iterables are read because neither is documented to contain the other,
	// and a module reached twice is described once.
	for (const module of new Set([...graph.getChunkModulesIterable(child.chunk), ...graph.getChunkRuntimeModulesIterable(child.chunk)])) {
		const described = await setup.describeModule(module, child.compilation, child.chunk);
		if (described.failure) return { units: [], failure: described.failure };
		units.push(...described.units);
	}
	return { units };
}

// The script rpc-worker-loader appends, recomputed from the verified file: the
// source text of its own function, stripped by its own expression.
function workerSetupScript(bytes) {
	const text = bytes.toString('utf8');
	const at = text.indexOf(WORKER_SETUP);
	if (at < 0) return null;
	const body = balanced(text, at);
	if (body === null) return null;
	return `\n${body.replace(SETUP_STRIP, '')}`;
}

// The function declaration starting at `at`, as Function.prototype.toString
// answers for it: its own source text, braces included.
function balanced(text, at) {
	const open = text.indexOf('{', at);
	if (open < 0) return null;
	let depth = 0;
	for (let i = open; i < text.length; i++) {
		const character = text[i];
		if (character === '{') depth++;
		else if (character === '}') {
			depth--;
			if (depth === 0) return text.slice(at, i + 1);
		} else if (character === '"' || character === "'" || character === '`') {
			for (i++; i < text.length && text[i] !== character; i++) if (text[i] === '\\') i++;
		}
	}
	return null;
}

// Which compilation next door this module's text was made of, and the single
// chunk and file it produced.
function childOf(compilation, pitch) {
	const made = Array.isArray(pitch.children) ? pitch.children.filter((entry) => entry.name === 'worker') : [];
	if (pitch.children.intact !== true) return noData('the child compiler recording of this pitch is not intact');
	if (made.length !== 1) return noData(`workerize-loader made ${made.length} worker compilers for this module`);
	const children = Array.isArray(compilation.children) ? compilation.children.filter((candidate) => candidate.compiler === made[0].child) : [];
	if (children.length !== 1) return noData(`${children.length} compilations of this one were run by the worker compiler`);
	const childCompilation = children[0];
	const chunks = [...childCompilation.chunks];
	if (chunks.length !== 1) return noData(`the worker compilation emitted ${chunks.length} chunks`);
	const files = [...chunks[0].files];
	if (files.length !== 1) return noData(`the worker chunk emits ${files.length} files`);
	return { compilation: childCompilation, chunk: chunks[0], file: files[0], outputOptions: made[0].outputOptions };
}

// The worker's bytes, as its own compilation left them, described by the
// ordinary asset evidence of that compilation.
async function workerAsset(setup, child, chunk) {
	const bytes = setup.readObservedBytes(child, [...chunk.files][0]);
	if (!bytes) return noData(`the bytes of the worker asset were not observed in the compilation that built it`);
	const described = await assetEvidence(child, chunk, setup.verifyResource, setup.evidence);
	if (described.failure) return { units: [], failure: described.failure };
	return { bytes, units: described.units };
}

// The text the loader writes, rebuilt from what it was given.
function recompute(pitch, asset, child, wrapperPath) {
	const given = givenOptions(pitch.context);
	if (given === null) return noData('workerize-loader was given options this version cannot read');
	const unknown = Object.keys(given).filter((key) => !DESCRIBED_OPTIONS.includes(key));
	if (unknown.length > 0) return noData(`workerize-loader was given ${unknown.join(', ')}, which this version does not describe`);
	if (given.inline !== true) return noData('only an inline worker is described, whose bytes this module holds');
	if (given.fallback !== false) return noData('only a worker without a fallback asset is described');
	const written = answerOf(pitch);
	if (written.failure) return written;
	const methods = methodsIn(written.content);
	if (methods === null) return noData('the exported method names of this module cannot be read back');
	const wrapperRequest = stringifyRequest(pitch.context.context, wrapperPath);
	if (wrapperRequest === null) return noData('the request of the rpc wrapper cannot be recomputed for this module');
	const named = workerFilename(child);
	if (named.failure) return named;
	const slots = [
		wrapperRequest,
		JSON.stringify(methods),
		`URL.createObjectURL(new Blob([${JSON.stringify(asset.bytes.toString('utf8'))}]))`,
		JSON.stringify(named.filename),
	];
	let text = '';
	const parts = WRAPPER_TEMPLATE.split('\0');
	for (const [index, part] of parts.entries()) text += part + (index < slots.length ? slots[index] : '');
	return { text };
}

// What the loader was told, from a rule's options object or from the query of
// an inline request. Only the plain grammar is read - a name, a `+name`, a
// `-name` or a `name=true|false` - because the loader reads the query through
// loader-utils, which also understands a JSON5 object, arrays and encodings.
// A query spelled any other way is not described rather than guessed at.
function givenOptions(context) {
	if (!context) return null;
	if (isPlainObject(context.options)) return context.options;
	const query = context.query;
	if (isPlainObject(query)) return query;
	if (typeof query !== 'string' || !query.startsWith('?')) return null;
	const given = {};
	for (const item of query.slice(1).split('&')) {
		if (item === '' || item.includes(',') || item.includes('%') || item.includes('[')) return null;
		const at = item.indexOf('=');
		if (at < 0) {
			const sign = item.slice(0, 1);
			const name = sign === '+' || sign === '-' ? item.slice(1) : item;
			if (name === '') return null;
			given[name] = sign !== '-';
			continue;
		}
		const name = item.slice(0, at);
		const value = item.slice(at + 1);
		if (name === '' || (value !== 'true' && value !== 'false')) return null;
		given[name] = value === 'true';
	}
	return given;
}

// The name the loader gives the worker. It is not the emitted file: the loader
// interpolates it through loader-utils, which leaves webpack's own `[fullhash]`
// alone, and webpack fills that in only when the asset is named. The template is
// the one the loader handed to the child compiler, held against the file that
// compiler emitted.
function workerFilename(child) {
	const options = child.outputOptions;
	if (!isPlainObject(options) || typeof options.filename !== 'string' || options.filename === '') {
		return noData('the worker compiler was made without a filename this version can read');
	}
	if (options.chunkFilename !== `[id].${options.filename}` || options.namedChunkFilename !== null) {
		return noData('the worker compiler was made with output options workerize-loader does not write');
	}
	// Webpack fills the template in itself, hash length and all, so the
	// comparison asks it rather than spelling its rules out again.
	if (typeof child.compilation.getPath !== 'function') return noData('the worker compilation cannot name its own assets');
	if (child.compilation.getPath(options.filename, {}) !== child.file) {
		return noData(`the worker compiler named ${options.filename}, and ${child.file} was emitted`);
	}
	return { filename: options.filename };
}

// The text a loader is handed for a file: its bytes, with a byte order mark
// stripped, as the loader runner hands them over. Bytes that are not utf8, and
// a file that starts with the mark, are not text this version compares.
function textOf(unit) {
	if (!unit || !Buffer.isBuffer(unit.bytes)) return noData('the verified source was verified without its bytes');
	if (unit.bytes.length >= BOM.length && unit.bytes.subarray(0, BOM.length).equals(BOM)) {
		return noData(`${unit.path} starts with a byte order mark the loader does not pass on`);
	}
	const text = unit.bytes.toString('utf8');
	if (!Buffer.from(text, 'utf8').equals(unit.bytes)) return noData(`${unit.path} is not valid utf8`);
	return { text };
}

// loaderUtils.stringifyRequest for a single absolute path with no query: an
// absolute request is always spelled relative to the module's own directory,
// however far up it has to walk, and is marked `./` when it does not walk up.
function stringifyRequest(context, request) {
	if (typeof context !== 'string' || context === '') return null;
	const walked = path.relative(context, request);
	// On Windows there is no relative path between two drives, and the loader
	// keeps the absolute request it was given.
	if (path.isAbsolute(walked)) return JSON.stringify(request);
	const relative = walked.split(path.sep).join('/');
	if (relative === '') return null;
	return JSON.stringify(/^\.\.?\//.test(relative) ? relative : `./${relative}`);
}

// The names the child compilation was observed exporting, as the loader wrote
// them. They are not in any file and nothing recomputes them: the loader
// harvests them while the worker's entry is parsed, so this slot is read back
// out of the text rather than checked. What stands behind it is that the text
// around it is the pinned loader's own template and that the loader that wrote
// it is the published file.
function methodsIn(text) {
	const match = /\n\t+var methods = (\[[^\n]*\])\n/.exec(text);
	if (!match) return null;
	let parsed;
	try {
		parsed = JSON.parse(match[1]);
	} catch {
		return null;
	}
	if (!Array.isArray(parsed) || parsed.some((name) => typeof name !== 'string')) return null;
	return parsed;
}

function answerOf(pitch) {
	const answers = Array.isArray(pitch.answers) ? pitch.answers : [];
	if (pitch.answers.intact !== true) return noData('the callback recording of this pitch is not intact');
	if (answers.length !== 1) return noData(`workerize-loader answered ${answers.length} times for this module`);
	const answer = answers[0];
	if (answer.error) return noData(`workerize-loader failed for this module: ${answer.error.message || answer.error}`);
	if (typeof answer.content !== 'string') return noData('workerize-loader wrote no text for this module');
	return { content: answer.content };
}

// Everything that has to hold before a recording may be read at all.
function boundTo(loader, pitch, module, loaderFile) {
	if (!loader) return noData('the workerize loader was not loaded in this process');
	if (!loader.usable) return noData(`the workerize loader cannot be described: ${loader.reason}`);
	if (loader.file !== loaderFile) return noData(`${identify(module)} was built by ${loaderFile}, not by the recorded ${loader.file}`);
	if (!pitch) return noData(`no workerize pitch was recorded for ${identify(module)}`);
	if (!pitch.usable) return noData(`the workerize pitch of ${identify(module)} cannot be described: ${pitch.reason}`);
	if (pitch.method !== loader.wrapper) return noData(`${identify(module)} was pitched by a function this recorder did not install`);
	// webpack pitches with the remaining request, the preceding one and the data
	// object; a chain that calls it otherwise is not the one this version reads.
	if (pitch.arity !== 3) return noData(`workerize-loader was pitched with ${pitch.arity} arguments`);
	if (!pitch.context || typeof pitch.context.context !== 'string') return noData('the loader context of this pitch was not recorded');
	// The function that was wrapped was the published one, and the one still
	// exported is the wrapper: a pitch replaced in between built something else.
	const was = loader.members ? loader.members.get('pitch') : undefined;
	if (!was || was.kind !== 'data' || !Object.is(was.value, loader.original)) {
		return noData('the workerize loader did not export the pitch this recorder wrapped');
	}
	if (!Object.is(loader.exports.pitch, loader.wrapper)) {
		return noData('the workerize loader no longer exports the pitch this recorder installed');
	}
	return null;
}

async function verifiedFile(setup, file, sha256, what) {
	const held = setup.registry.getByFile(file);
	if (held && held.sha256 !== sha256) {
		return failed('hash-mismatch', `${file} is not ${what} this version describes`);
	}
	const resolved = await setup.verifyResource(file);
	if (resolved.failure) return resolved;
	if (resolved.unit.sha256 !== sha256) {
		return failed('hash-mismatch', `${file} is not ${what} this version describes`);
	}
	return { unit: { ...resolved.unit } };
}

function keptSource(module) {
	const source = typeof module.originalSource === 'function' ? module.originalSource() : null;
	if (!source || typeof source.source !== 'function') return null;
	const text = source.source();
	return typeof text === 'string' ? text : Buffer.from(text).toString('utf8');
}

function unitOf(unit) {
	return { path: unit.path, sha256: unit.sha256, component: unit.component };
}

function isWorkerLoader(file) {
	return typeof file === 'string' && file.endsWith(path.sep + LOADER_FILE);
}

function isWorkerEntryLoader(file) {
	return typeof file === 'string' && file.endsWith(path.sep + path.join('workerize-loader', 'dist', 'rpc-worker-loader.js'));
}

function identify(module) {
	return typeof module.identifier === 'function' ? module.identifier() : String(module.resource || 'a module');
}

function isPlainObject(value) {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function noData(reason) {
	return failed('no-data', reason);
}

function failed(status, reason) {
	return { units: [], failure: { status, reason } };
}

module.exports = { installWorkerEvidence, isWorkerLoader, isWorkerEntryLoader };
