'use strict';

// Binds the JavaScript webpack kept for one stylesheet module to what the two
// loaders of the chain really did: the raw module to the stylesheet text
// raw-loader was handed, and the module style-loader pitched to the template
// its own source carries.
//
// Behind those two loaders the chain may end in a sass-loader, and then the
// text raw-loader was handed is css no file carries: what that module
// contributes is what sass-evidence.cjs observed the render consume.
//
// A described module contributes the inputs those two observations cover: the
// verified stylesheet raw-loader was given, and the verified loader file whose
// code the module is. The style-loader runtime that ends up in the bundle is an
// ordinary module of the webpack graph and is described there, not here.
//
// The recordings come from stylesheet-preload.cjs, which must already be
// installed when the loaders are first required, and the identity of the files
// it recognized comes from runtime-preload.cjs underneath it.

const crypto = require('node:crypto');
const path = require('node:path');

const { installSassEvidence, isKnownSassLoader } = require('./sass-evidence.cjs');

const NAME = 'DkSbomStylesheetEvidence';
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const STYLESHEET = Symbol.for('dk.sbom.webpack.stylesheet');
const SUPPORTED_WEBPACK = '5.94.0';
const RUNTIME = path.join('runtime', 'injectStylesIntoStyleTag.js');
const CANONICAL_SHA256 = /^sha256:[0-9a-f]{64}$/;
const BOM = Buffer.from([0xef, 0xbb, 0xbf]);

function installStylesheetEvidence(compiler, verifyResource) {
	if (typeof verifyResource !== 'function') throw new TypeError(`${NAME}: verifyResource must be a function`);
	const recorder = globalThis[STYLESHEET];
	const registry = globalThis[REGISTRY];
	const problem = prepare(compiler, recorder, registry);
	// Installed whatever this adapter can describe: the sass tail of a chain has
	// to be instrumented before the first module is built, and the records it
	// keeps are read through the raw module of that very chain.
	const sassEvidence = problem ? undefined : installSassEvidence(compiler, verifyResource);
	const compilations = new Set();
	if (!problem) {
		compiler.hooks.compilation.tap(NAME, (compilation) => compilations.add(compilation));
		// Every module of this build has been described by the time it is done.
		compiler.hooks.done.tap(NAME, () => compilations.clear());
	}
	return async function evidenceFor(module) {
		if (problem) return problem;
		try {
			return await describe({ recorder, registry, compilations, verifyResource, sassEvidence }, module);
		} catch (error) {
			return noData(`${identify(module)} could not be described: ${error.message}`);
		}
	};
}

function prepare(compiler, recorder, registry) {
	if (!recorder || typeof recorder.pitchOf !== 'function') return noData('the stylesheet load recorder is not installed in this process');
	if (!registry || typeof registry.getByFile !== 'function') return noData('the commonjs load registry is not installed in this process');
	const api = compiler.webpack;
	if (!api || typeof api.version !== 'string') return noData('the compiler does not expose the webpack that builds its modules');
	if (api.version !== SUPPORTED_WEBPACK) return failed('unsupported', `modules of webpack ${api.version} are not described, only ${SUPPORTED_WEBPACK}`);
	return null;
}

async function describe(context, module) {
	const pitch = context.recorder.pitchOf(module);
	const call = context.recorder.callOf(module);
	if (pitch && call) return noData(`${identify(module)} was built by both stylesheet loaders at once`);
	if (pitch) return describeStyle(context, module, pitch);
	if (call) return describeRaw(context, module, call);
	// Nothing was recorded for a module another chain built, for one the loaders
	// never ran for, and for one webpack served from its cache without building.
	return noData(`${identify(module)} was not built by an observed stylesheet loader`);
}

// What raw-loader turned the stylesheet into: the text it was handed has to be
// the verified bytes of the file, and what it returned has to be the one string
// its published body can produce from that text.
//
// Behind a sass tail that text is no file of its own but the css a render
// produced, and the sources of the module are the ones that render consumed.
async function describeRaw(context, module, call) {
	const info = context.recorder.loaderOf('raw');
	const ready = usable(info, call, 'raw-loader');
	if (ready) return ready;
	const published = publishedLoader(context.registry, info);
	if (published) return published;
	const chain = Array.isArray(module.loaders) ? module.loaders : [];
	const compiled = chain.length === 2 && isKnownSassLoader(chain[1].loader);
	if ((chain.length !== 1 && !compiled) || resolved(chain[0].loader) !== info.file) {
		return noData(`${identify(module)} was not built by raw-loader alone`);
	}
	if (loadedExports(info.file) !== info.wrapper) return noData(`${info.file} was replaced after this adapter recorded it`);
	const bound = boundTo(call.context, module, chain.length, 0);
	if (bound) return bound;
	// Behind a sass tail the loader is handed the css and the source map of the
	// render; raw-loader keeps the text and drops the rest.
	if (call.arity !== (compiled ? 2 : 1) || typeof call.input !== 'string' || typeof call.output !== 'string') {
		return noData(`${identify(module)} was not built from text alone`);
	}

	const source = compiled ? await context.sassEvidence(module, call.input) : await sourceUnit(context, call.context.resourcePath, call.input);
	if (source.failure) return source;
	const sources = compiled ? source.units : [source.unit];
	// The one string the published loader body returns for that text; its own
	// output is the record, this is what it has to be.
	if (call.output !== `module.exports = ${JSON.stringify(call.input)}`) {
		return failed('invalid', `raw-loader did not return the stylesheet it was given for ${identify(module)}`);
	}
	const kept = keptSource(module);
	if (kept.failure) return kept;
	if (!kept.buffer.equals(Buffer.from(call.output, 'utf8'))) {
		return failed('hash-mismatch', `the source webpack kept for ${identify(module)} is not what raw-loader returned`);
	}

	const loader = await loaderUnit(context, info);
	if (loader.failure) return loader;
	return { units: [...sources, loader.unit] };
}

// What style-loader pitched: it never read the stylesheet, so its module is the
// template of its own source, and the only claim made here is that the code is
// that template filled in with the two modules the graph really holds.
async function describeStyle(context, module, pitch) {
	const info = context.recorder.loaderOf('style');
	const ready = usable(info, pitch, 'style-loader');
	if (ready) return ready;
	const member = info.members && info.members.get('pitch');
	if (!member || member.value !== info.original) return noData(`${info.file} did not export the pitch this adapter recorded`);
	const published = publishedLoader(context.registry, info);
	if (published) return published;
	if (info.api.pitch !== info.wrapper || pitch.method !== info.wrapper) return noData(`the pitch of ${info.file} was replaced after this adapter recorded it`);

	const raw = context.recorder.loaderOf('raw');
	const chain = Array.isArray(module.loaders) ? module.loaders : [];
	// The tail never ran for this module: style-loader pitched over it, and what
	// it did run for is the module of the very request that was pitched.
	const compiled = chain.length === 3 && isKnownSassLoader(chain[2].loader);
	if ((chain.length !== 2 && !compiled) || loadedExports(chain[0] && chain[0].loader) !== info.api) {
		return noData(`${identify(module)} was not pitched by style-loader at the head of its chain`);
	}
	if (!raw || !raw.usable || resolved(chain[1].loader) !== raw.file) {
		return noData(`${identify(module)} was not pitched over raw-loader alone`);
	}
	const bound = boundTo(pitch.context, module, chain.length, 0);
	if (bound) return bound;
	if (typeof pitch.request !== 'string' || pitch.request === '' || typeof pitch.output !== 'string') {
		return noData(`${identify(module)} was pitched without a request of its own`);
	}

	const required = requiredModules(context, module, pitch, info);
	if (required.failure) return required;
	if (pitch.output !== template(required.content.rawRequest, required.api.rawRequest)) {
		return failed('invalid', `style-loader did not pitch its own template for ${identify(module)}`);
	}
	const kept = keptSource(module);
	if (kept.failure) return kept;
	if (!kept.buffer.equals(Buffer.from(pitch.output, 'utf8'))) {
		return failed('hash-mismatch', `the source webpack kept for ${identify(module)} is not what style-loader pitched`);
	}

	const loader = await loaderUnit(context, info);
	if (loader.failure) return loader;
	return { units: [loader.unit] };
}

// The two modules the pitched code requires, as the graph holds them: the
// stylesheet behind the very request this call was given, and the physical
// runtime file of the recognized distribution. Both are ordinary modules, and
// the literals of the code are checked against the requests webpack parsed out
// of it rather than against a path this adapter guessed.
function requiredModules(context, module, pitch, info) {
	const compilations = [...context.compilations].filter((compilation) => compilation.modules.has(module));
	if (compilations.length !== 1) return noData(`${identify(module)} is not a module of exactly one observed compilation`);
	const graph = compilations[0].moduleGraph;
	const runtimeFile = path.join(path.dirname(info.file), RUNTIME);
	let content;
	let api;
	for (const connection of graph.getOutgoingConnections(module)) {
		const required = connection.module;
		if (!required || required === module) continue;
		if (required.request === pitch.request && typeof required.rawRequest === 'string' && required.rawRequest.startsWith('!!')) {
			if (content) return noData(`${identify(module)} requires the stylesheet of its own request more than once`);
			content = required;
			continue;
		}
		if (required.resource === runtimeFile && Array.isArray(required.loaders) && required.loaders.length === 0) {
			if (api) return noData(`${identify(module)} requires the style-loader runtime more than once`);
			api = required;
			continue;
		}
		return noData(`${identify(module)} also requires ${identify(required)}`);
	}
	if (!content) return noData(`${identify(module)} does not require the stylesheet of the request it was pitched for`);
	if (!api) return noData(`${identify(module)} does not require the runtime of ${info.file}`);
	return { content, api };
}

// style-loader 1.3.0 with no options of its own: a style tag inserted into the
// head, no lazy interface, no es modules and no hot module replacement.
function template(contentRequest, apiRequest) {
	return `var api = require(${JSON.stringify(apiRequest)});
            var content = require(${JSON.stringify(contentRequest)});

            content = content.__esModule ? content.default : content;

            if (typeof content === 'string') {
              content = [[module.id, content, '']];
            }

var options = {};

options.insert = "head";
options.singleton = false;

var update = api(content, options);



module.exports = content.locals || {};`;
}

function usable(info, record, name) {
	if (!info || !info.usable) return noData(`${name} is not the published file this adapter recognizes${info && info.reason ? `: ${info.reason}` : ''}`);
	if (!record.usable) return failed('invalid', `${info.file} ${record.reason}`);
	if (!sameState(record.states[0], record.states[1])) return failed('invalid', `${info.file} changed while it ran`);
	return null;
}

// The file the recorder wrapped is the file node really compiled, and the
// function it wrapped is the one that file exported before anything else saw it.
function publishedLoader(registry, info) {
	const entry = registry.getByFile(info.file);
	if (!entry || !entry.usable) return noData(`${info.file} was not recorded as a loaded commonjs module`);
	if (entry.sha256 !== info.sha256) return failed('hash-mismatch', `${info.file} ran source other than the published bytes`);
	const recorded = info.kind === 'style' ? entry.exports === info.exports && memberOf(entry, 'default') === info.api : entry.exports === info.original;
	if (!recorded) return noData(`${info.file} did not export what this adapter recorded`);
	return null;
}

function memberOf(entry, key) {
	const member = entry && entry.usable && entry.members && entry.members.get(key);
	return member && member.kind === 'data' ? member.value : undefined;
}

function boundTo(context, module, loaderCount, loaderIndex) {
	if (!context) return noData(`${identify(module)} was built without a loader context of its own`);
	if (context.resourcePath !== module.resource) return noData(`${identify(module)} was built from ${typeof context.resourcePath === 'string' ? context.resourcePath : 'no file of its own'}`);
	if (context.resourceQuery || context.resourceFragment) return noData(`${identify(module)} was built from a request this adapter does not describe`);
	if (context.loaderCount !== loaderCount || context.loaderIndex !== loaderIndex) return noData(`${identify(module)} was built by a loader chain this adapter does not describe`);
	if (context.hot) return noData(`${identify(module)} was built for hot module replacement`);
	if (!plain(context.options) || !plain(context.query)) return noData(`${identify(module)} was built by a loader configured with options this adapter does not describe`);
	return null;
}

// Only the defaults are described: every option of either loader changes what
// the pitched code is, and none of it would be observed here.
function plain(options) {
	if (options === undefined || options === null || options === '') return true;
	if (typeof options !== 'object' || Array.isArray(options) || Object.getPrototypeOf(options) !== Object.prototype) return false;
	return Reflect.ownKeys(options).length === 0;
}

async function sourceUnit(context, resource, read) {
	const resolution = await verified(context, resource);
	if (resolution.failure) return resolution;
	const unit = resolution.unit;
	if (!Buffer.isBuffer(unit.bytes)) return noData(`${unit.path} was verified without its bytes`);
	if (digest(unit.bytes) !== unit.sha256) return failed('invalid', `${unit.path} was verified as bytes other than the ones it carries`);
	// loader-runner hands a loader the file text with a byte order mark stripped:
	// those bytes would be described as read, and they were not.
	if (unit.bytes.length >= BOM.length && unit.bytes.subarray(0, BOM.length).equals(BOM)) {
		return noData(`${unit.path} starts with a byte order mark the loader does not pass on`);
	}
	const text = unit.bytes.toString('utf8');
	if (!Buffer.from(text, 'utf8').equals(unit.bytes)) return noData(`${unit.path} is not valid utf8`);
	if (text !== read) return failed('hash-mismatch', `raw-loader did not read the verified bytes of ${unit.path}`);
	return { unit: { path: unit.path, sha256: unit.sha256, component: unit.component } };
}

// The loader file is a source of the module it produced code for, bound to its
// component by the same verification as any other source and to the bytes this
// process really ran by the registry recording of them.
async function loaderUnit(context, info) {
	const resolution = await verified(context, info.file);
	if (resolution.failure) return resolution;
	const unit = resolution.unit;
	if (unit.sha256 !== info.sha256) return failed('hash-mismatch', `${info.file} is not the published file this process ran`);
	return { unit: { path: unit.path, sha256: unit.sha256, component: unit.component } };
}

async function verified(context, file) {
	let resolution;
	try {
		resolution = await context.verifyResource(file);
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

function keptSource(module) {
	const source = module.originalSource && module.originalSource();
	if (!source || typeof source.buffer !== 'function') return noData(`${identify(module)} does not expose the source webpack kept for it`);
	let buffer;
	try {
		buffer = source.buffer();
	} catch (error) {
		return noData(`${identify(module)} does not expose the source webpack kept for it: ${error.message}`);
	}
	if (!Buffer.isBuffer(buffer)) return noData(`${identify(module)} does not expose the source webpack kept for it`);
	return { buffer };
}

function sameState(before, after) {
	if (!(before instanceof Map) || !(after instanceof Map) || before.size !== after.size) return false;
	for (const [file, state] of before) {
		const other = after.get(file);
		if (!other || other.exports !== state.exports || !sameMembers(state.members, other.members)) return false;
	}
	return true;
}

function sameMembers(before, after) {
	if (before === null || after === null) return before === after;
	if (before.size !== after.size) return false;
	for (const [key, member] of before) {
		const other = after.get(key);
		if (!other || other.kind !== member.kind) return false;
		if (member.kind === 'data' ? other.value !== member.value || other.writable !== member.writable : other.get !== member.get || other.set !== member.set) return false;
		if (other.enumerable !== member.enumerable || other.configurable !== member.configurable) return false;
	}
	return true;
}

function loadedExports(file) {
	const entry = require.cache[resolved(file)];
	return entry ? entry.exports : undefined;
}

function resolved(file) {
	if (typeof file !== 'string') return undefined;
	try {
		return require.resolve(file);
	} catch {
		return undefined;
	}
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

module.exports = { installStylesheetEvidence };
