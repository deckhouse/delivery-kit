'use strict';

// Binds the module monaco-editor-webpack-plugin builds for the monaco entry to
// the loader that built it.
//
// The plugin puts one loader in front of the monaco api module, and that loader
// throws the file away: it pitches text of its own, made of the globals, the
// feature imports and the language imports the plugin configured, around a
// re-export of the very module it was asked for. None of that text is in any
// file, so the module is described by recomputing it from what the loader was
// given and binding it to the loader's own published source.
//
// What the generated text imports - the monaco sources, the remaining request -
// are ordinary modules of the webpack graph and are described there, not here.
//
// The recordings come from include-preload.cjs, which must already be installed
// when the loader is first required, and the identity of the file it recognized
// comes from runtime-preload.cjs underneath it.

const path = require('node:path');

const NAME = 'DkSbomIncludeEvidence';
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const INCLUDE = Symbol.for('dk.sbom.webpack.include');
const SUPPORTED_WEBPACK = '5.94.0';
const LOADER_FILE = path.join('monaco-editor-webpack-plugin', 'out', 'loaders', 'include.js');
// The published file that authors the one global the loader writes unquoted.
const PLUGIN_SHA256 = 'sha256:01cf13c3cffcf9b305207b3e5cd988acc1d0a6a973a740770a90c655e76c7049';
const ENVIRONMENT = 'MonacoEnvironment';
// The fixed alternative of the path prefix, written when the plugin was given
// no public path of its own.
const DYNAMIC_PATH = "typeof __webpack_public_path__ === 'string' ? __webpack_public_path__ : ";
// The text out/index.js:160-186 builds for that global, with its three
// interpolations marked. Every other character of it is the plugin's own code.
const ENVIRONMENT_TEMPLATE = "(function (paths) {\n      function stripTrailingSlash(str) {\n        return str.replace(/\\/$/, '');\n      }\n      return {\n        globalAPI: \0,\n        getWorkerUrl: function (moduleId, label) {\n          var pathPrefix = \0;\n          var result = (pathPrefix ? stripTrailingSlash(pathPrefix) + '/' : '') + paths[label];\n          if (/^((http:)|(https:)|(file:)|(\\/\\/))/.test(result)) {\n            var currentUrl = String(window.location);\n            var currentOrigin = currentUrl.substr(0, currentUrl.length - window.location.hash.length - window.location.search.length - window.location.pathname.length);\n            if (result.substring(0, currentOrigin.length) !== currentOrigin) {\n              if(/^(\\/\\/)/.test(result)) {\n                result = window.location.protocol + result\n              }\n              var js = '/*' + label + '*/importScripts(\"' + result + '\");';\n              var blob = new Blob([js], { type: 'application/javascript' });\n              return URL.createObjectURL(blob);\n            }\n          }\n          return result;\n        }\n      };\n    })(\0)";

function installIncludeEvidence(compiler, verifyResource) {
	if (typeof verifyResource !== 'function') throw new TypeError(`${NAME}: verifyResource must be a function`);
	const recorder = globalThis[INCLUDE];
	const registry = globalThis[REGISTRY];
	const problem = prepare(compiler, recorder, registry);
	return async function evidenceFor(module) {
		if (problem) return problem;
		try {
			return await describe({ recorder, registry, verifyResource }, module);
		} catch (error) {
			return noData(`${identify(module)} could not be described: ${error.message}`);
		}
	};
}

function prepare(compiler, recorder, registry) {
	if (!recorder || typeof recorder.pitchOf !== 'function') return noData('the include load recorder is not installed in this process');
	if (!registry || typeof registry.getByFile !== 'function') return noData('the commonjs load registry is not installed in this process');
	const api = compiler.webpack;
	if (!api || typeof api.version !== 'string') return noData('the compiler does not expose the webpack that builds its modules');
	if (api.version !== SUPPORTED_WEBPACK) return failed('unsupported', `modules of webpack ${api.version} are not described, only ${SUPPORTED_WEBPACK}`);
	return null;
}

async function describe(context, module) {
	const info = context.recorder.loader();
	const pitch = context.recorder.pitchOf(module);
	if (!pitch) return noData(`${identify(module)} was not built by the observed include loader`);
	const ready = usable(info, pitch);
	if (ready) return ready;
	const member = info.members && info.members.get('pitch');
	if (!member || member.value !== info.original) return noData(`${info.file} did not export the pitch this adapter recorded`);
	const published = publishedLoader(context.registry, info);
	if (published) return published;
	if (info.exports.pitch !== info.wrapper || pitch.method !== info.wrapper) return noData(`the pitch of ${info.file} was replaced after this adapter recorded it`);

	const chain = Array.isArray(module.loaders) ? module.loaders : [];
	if (chain.length !== 1 || resolved(chain[0].loader) !== info.file) {
		return noData(`${identify(module)} was not built by the include loader alone`);
	}
	const bound = boundTo(pitch, module);
	if (bound) return bound;

	const text = recompute(pitch);
	if (text.failure) return text;
	const kept = keptSource(module);
	if (kept.failure) return kept;
	if (!kept.buffer.equals(Buffer.from(text.output, 'utf8'))) {
		return failed('hash-mismatch', `the source webpack kept for ${identify(module)} is not what the include loader pitched`);
	}
	const loader = await loaderUnit(context, info, info.file, info.sha256, 'the include loader');
	if (loader.failure) return loader;
	// The text of the one global is authored by the plugin itself, not by the
	// loader that writes it out.
	const author = path.join(path.dirname(path.dirname(info.file)), 'index.js');
	const plugin = await loaderUnit(context, info, author, PLUGIN_SHA256, 'the plugin that configured it');
	if (plugin.failure) return plugin;
	return { units: [loader.unit, plugin.unit] };
}

// What the loader wrote, built again here out of what it was given and what
// webpack answered when it asked for a request in its own terms. Nothing is
// called again: every answer is the one recorded while it ran.
function recompute(pitch) {
	const query = pitch.context.query;
	if (query === null || typeof query !== 'object' || Array.isArray(query)) return noData('the include loader was configured with options this adapter does not describe');
	// What loader-runner hands a pitch: the rest of the request, the part before
	// it, and the data object of this loader.
	if (pitch.arity !== 3 || typeof pitch.request !== 'string' || pitch.request === '') return noData('the include loader was asked for no request of its own');
	if (typeof pitch.output !== 'string') return noData('the include loader wrote no text');
	const { globals, pre, post } = query;
	// Read once, into values of its own: everything after this reads the
	// snapshot, so an object that answers differently each time it is asked
	// cannot show one text to the check and hand another to the loader.
	const snapshot = snapshotGlobals(globals);
	if (typeof snapshot === 'string') return noData(snapshot);
	// The loader writes every global out unquoted, so the only one this adapter
	// describes is the one the plugin authors, in the shape its own source
	// builds.
	const environment = environmentProblem(snapshot);
	if (environment) return noData(environment);
	for (const list of [pre, post]) {
		if (list === undefined) continue;
		if (!Array.isArray(list) || list.some((item) => typeof item !== 'string')) return noData('the include loader was given includes this adapter does not describe');
	}
	const contextified = pitch.contextified;
	// Every request it wrote has to have gone through the recorded answerer: one
	// that was never installed means the loader fell back to a helper of its
	// own, and one taken away mid-call means some of its answers are unobserved.
	if (!Array.isArray(contextified) || !contextified.recorded) return noData('the include loader did not turn its requests into text through its own webpack');
	if (!contextified.intact) return noData('what turned the requests of the include loader into text was replaced while it ran');
	// The loader asks for every request through the one answerer, in the order
	// it writes them; a request answered twice is answered the same way.
	const answers = new Map();
	for (const call of contextified) {
		if (call.arity !== 2 || call.context !== (pitch.context.context || pitch.context.rootContext) || typeof call.answer !== 'string') {
			return noData('the include loader asked for a request this adapter does not describe');
		}
		if (answers.has(call.request) && answers.get(call.request) !== call.answer) return noData('one request of the include loader was answered in two ways');
		answers.set(call.request, call.answer);
	}
	const stringify = (request) => {
		if (!answers.has(request)) throw new Error(`the include loader never asked for ${request}`);
		return JSON.stringify(answers.get(request));
	};
	let rebuilt;
	try {
		rebuilt = [
			...[...snapshot].map(([key, text]) => `self[${JSON.stringify(key)}] = ${text};`),
			...(pre || []).map((include) => `import ${stringify(include)};`),
			`
import * as monaco from ${stringify(`!!${pitch.request}`)};
export * from ${stringify(`!!${pitch.request}`)};
export default monaco;
\t\t`,
			...(post || []).map((include) => `import ${stringify(include)};`),
		].join('\n');
	} catch (error) {
		return noData(error.message);
	}
	if (rebuilt !== pitch.output) return failed('invalid', 'the include loader did not write the text its own source builds');
	// Nothing was asked for beyond what it wrote.
	const written = new Set([...(pre || []), ...(post || []), `!!${pitch.request}`]);
	for (const request of answers.keys()) {
		if (!written.has(request)) return noData('the include loader asked for a request it did not write');
	}
	return { output: rebuilt };
}

// The globals as plain text of this adapter's own, read exactly once. A global
// behind an accessor, or behind anything that is not a plain own value, is not
// something a text can be rebuilt from.
function snapshotGlobals(globals) {
	if (globals === undefined) return new Map();
	if (globals === null || typeof globals !== 'object' || Array.isArray(globals)) return 'the include loader was given globals this adapter does not describe';
	const snapshot = new Map();
	for (const key of Reflect.ownKeys(globals)) {
		if (typeof key !== 'string') return 'the include loader was given globals this adapter does not describe';
		const descriptor = Object.getOwnPropertyDescriptor(globals, key);
		if (!descriptor.enumerable) continue;
		if (!('value' in descriptor)) return `the ${key} it was given is not a value of its own`;
		if (typeof descriptor.value !== 'string') return `the ${key} it was given is not text`;
		snapshot.set(key, descriptor.value);
	}
	return snapshot;
}

// What out/index.js builds for MonacoEnvironment: its text with three slots,
// each of which has to be data of the shape that source puts there. Anything
// else in the globals is code this adapter cannot attribute to the plugin.
function environmentProblem(globals) {
	if (globals.size === 0) return null;
	const keys = [...globals.keys()];
	if (keys.length !== 1 || keys[0] !== ENVIRONMENT) return `the include loader was given globals other than ${ENVIRONMENT}`;
	const text = globals.get(ENVIRONMENT);
	const slots = environmentSlots(text);
	if (typeof slots === 'string') return slots;
	const [globalAPI, pathPrefix, workerPaths] = slots;
	if (globalAPI !== 'true' && globalAPI !== 'false') return `the ${ENVIRONMENT} it was given does not say whether monaco keeps its global api`;
	const prefix = pathPrefix.startsWith(DYNAMIC_PATH) ? pathPrefix.slice(DYNAMIC_PATH.length) : pathPrefix;
	if (!isJsonString(prefix)) return `the ${ENVIRONMENT} it was given builds its worker urls from something other than a path`;
	if (!isWorkerPaths(workerPaths)) return `the ${ENVIRONMENT} it was given names its workers with something other than paths`;
	return null;
}

// The text of index.js around its three interpolations, as published; what
// stands between those pieces is what this adapter checks.
function environmentSlots(text) {
	const parts = ENVIRONMENT_TEMPLATE.split('\u0000');
	const slots = [];
	let rest = text;
	for (const [index, piece] of parts.entries()) {
		if (index === parts.length - 1) {
			if (rest !== piece) return `the ${ENVIRONMENT} it was given is not the text the plugin builds`;
			break;
		}
		if (!rest.startsWith(piece)) return `the ${ENVIRONMENT} it was given is not the text the plugin builds`;
		rest = rest.slice(piece.length);
		const end = rest.indexOf(parts[index + 1]);
		if (end < 0) return `the ${ENVIRONMENT} it was given is not the text the plugin builds`;
		slots.push(rest.slice(0, end));
		rest = rest.slice(end);
	}
	return slots;
}

function isJsonString(text) {
	try {
		return typeof JSON.parse(text) === 'string';
	} catch {
		return false;
	}
}

// A plain object of strings, written out the way the plugin writes it.
function isWorkerPaths(text) {
	let parsed;
	try {
		parsed = JSON.parse(text);
	} catch {
		return false;
	}
	if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return false;
	if (Object.values(parsed).some((value) => typeof value !== 'string')) return false;
	return JSON.stringify(parsed, null, 2) === text;
}

function boundTo(pitch, module) {
	const context = pitch.context;
	if (!context) return noData(`${identify(module)} was built without a loader context of its own`);
	if (context.resourcePath !== module.resource) return noData(`${identify(module)} was built from ${typeof context.resourcePath === 'string' ? context.resourcePath : 'no file of its own'}`);
	if (context.resourceQuery || context.resourceFragment) return noData(`${identify(module)} was built from a request this adapter does not describe`);
	if (context.loaderCount !== 1 || context.loaderIndex !== 0) return noData(`${identify(module)} was built by a loader chain this adapter does not describe`);
	if (context.hot) return noData(`${identify(module)} was built for hot module replacement`);
	if (context.options !== context.query) return noData(`${identify(module)} was built by a loader configured with options this adapter does not describe`);
	// The loader renames the module it built; what it renamed has to be the file
	// it was given.
	if (typeof pitch.userRequest !== 'string' || !pitch.userRequest.startsWith('include-loader!')) {
		return noData(`${identify(module)} was not renamed by the include loader`);
	}
	return null;
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

async function loaderUnit(context, info, file, sha256, what) {
	// The file this process really ran, not merely one that is on disk now.
	if (file !== info.file) {
		const entry = context.registry.getByFile(file);
		if (!entry || !entry.usable) return noData(`${what} was not recorded as a loaded commonjs module`);
		if (entry.sha256 !== sha256) return failed('hash-mismatch', `${file} ran source other than the published bytes`);
		const drift = compareMembers(entry.members, context.registry.snapshot(entry.exports));
		if (drift) return noData(`${file} no longer exports what it exported when it was loaded: ${drift}`);
	}
	let resolution;
	try {
		resolution = await context.verifyResource(file);
	} catch (error) {
		return noData(`${file} could not be verified: ${error.message}`);
	}
	if (!resolution || (!resolution.unit && !resolution.failure)) return noData(`${file} was not verified`);
	if (resolution.failure) return { units: [], failure: resolution.failure };
	const unit = resolution.unit;
	if (unit.sha256 !== sha256) return failed('hash-mismatch', `${file} is not the published file this process ran`);
	return { unit: { path: unit.path, sha256: unit.sha256, component: unit.component } };
}

function compareMembers(snapshot, now) {
	if (!snapshot || !now) return snapshot === now ? null : 'it is no longer an object';
	for (const key of snapshot.keys()) {
		if (!now.has(key)) return `${String(key)} is gone`;
	}
	for (const [key, is] of now) {
		const was = snapshot.get(key);
		if (!was) return `${String(key)} was added`;
		if (was.kind !== is.kind) return `${String(key)} was replaced`;
		if (was.kind === 'data' ? !Object.is(was.value, is.value) : !Object.is(was.get, is.get) || !Object.is(was.set, is.set)) {
			return `${String(key)} was replaced`;
		}
	}
	return null;
}

function publishedLoader(registry, info) {
	const entry = registry.getByFile(info.file);
	if (!entry || !entry.usable) return noData(`${info.file} was not recorded as a loaded commonjs module`);
	if (entry.sha256 !== info.sha256) return failed('hash-mismatch', `${info.file} ran source other than the published bytes`);
	if (entry.exports !== info.exports) return noData(`${info.file} did not export what this adapter recorded`);
	return null;
}

function usable(info, record) {
	if (!info || !info.usable) return noData(`the include loader is not the published file this adapter recognizes${info && info.reason ? `: ${info.reason}` : ''}`);
	if (!record.usable) return failed('invalid', `${info.file} ${record.reason}`);
	return null;
}

function resolved(loader) {
	return typeof loader === 'string' ? path.resolve(loader) : '';
}

function identify(module) {
	return typeof module.identifier === 'function' ? module.identifier() : String(module);
}

function failed(status, reason) {
	return { units: [], failure: { status, reason } };
}

function noData(reason) {
	return failed('no-data', reason);
}

// Which modules this adapter is asked about: the file the plugin puts in front
// of the monaco entry, wherever it is installed. Whether that file is the
// published one is decided by the adapter, not by its name.
function isIncludeLoader(loader) {
	return typeof loader === 'string' && resolved(loader).endsWith(path.sep + LOADER_FILE);
}

module.exports = { installIncludeEvidence, isIncludeLoader };
