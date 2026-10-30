'use strict';

// Binds a module webpack built for a `require.context` - a ContextModule - to
// the pinned webpack source that produced it.
//
// Such a module reads no file. Its text is a map from request to module id,
// written by webpack around a fixed function body, so nothing of the project is
// in it: every request it names is answered by a module of this same chunk,
// built and described on its own. What has to hold is that the class is
// webpack's, that the shape is one this adapter speaks for, that the generated
// text is what that class writes for this graph, and - the check the rest rests
// on - that every entry of the map names a module this build describes.

const path = require('node:path');

const { internals } = require('./runtime-evidence.cjs');

const { SUPPORTED_WEBPACK, FINGERPRINTS, compareMembers, ownImplementation, relativeName, prototypeOf, entryProblem, failed, noData } = internals;
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const BASE_FILE = 'RuntimeModule.js';
const CLASS_FILE = 'ContextModule.js';
const ELEMENT_FILE = 'dependencies/ContextElementDependency.js';
const GLOBALS_FILE = 'RuntimeGlobals.js';
const SOURCE_TYPE = 'javascript';
// The only mode whose text this adapter can account for. Every other mode
// writes a different template, with chunk loading in it.
const MODE = 'sync';
// Methods the module may carry of its own: the ones a ContextModule is given
// by the factory that built it, which hold no text.
const OWN_METHODS = ['resolveDependencies'];

// Which modules this adapter is asked about: one webpack built for the
// requests of a `require.context`, named by the class it was built by - the
// prototype chain, so that a module of a derived class is refused here with a
// reason rather than falling through to one that says less.
function isContextModule(module) {
	if (module === null || typeof module !== 'object' || typeof module.resource === 'string' || module.options === null || typeof module.options !== 'object') return false;
	for (let current = Object.getPrototypeOf(module); current; current = Object.getPrototypeOf(current)) {
		if (current.constructor && current.constructor.name === 'ContextModule') return true;
	}
	return false;
}

async function contextModuleEvidence(compilation, chunk, module, verifyResource) {
	const registry = globalThis[REGISTRY];
	if (!registry || typeof registry.getByFile !== 'function' || typeof registry.findByExport !== 'function' || typeof registry.snapshot !== 'function') {
		return noData('the commonjs load registry is not installed in this process');
	}
	const api = compilation.compiler && compilation.compiler.webpack;
	if (!api || typeof api.version !== 'string') return noData('the compiler does not expose its webpack');
	if (api.version !== SUPPORTED_WEBPACK) return failed('unsupported', `the modules of webpack ${api.version} are not described, only ${SUPPORTED_WEBPACK}`);

	const base = registry.findByExport(api.RuntimeModule);
	const baseProblem = entryProblem(base, 'the webpack RuntimeModule base class');
	if (baseProblem) return baseProblem;
	if (path.basename(base.file) !== BASE_FILE) return noData(`the RuntimeModule base class comes from ${base.file}`);
	const lib = path.dirname(base.file);

	const entry = registry.getByFile(path.join(lib, CLASS_FILE));
	const classProblem = entryProblem(entry, CLASS_FILE);
	if (classProblem) return classProblem;
	// The globals this class writes into the text it builds, which have to be
	// the ones the compiler itself is using and the ones that were loaded.
	const globals = registry.getByFile(path.join(lib, GLOBALS_FILE));
	const globalsProblem = entryProblem(globals, GLOBALS_FILE);
	if (globalsProblem) return globalsProblem;
	if (api.RuntimeGlobals !== globals.exports) return noData(`the compiler exposes a ${GLOBALS_FILE} other than the one loaded from its lib directory`);
	for (const [file, loaded] of [
		[CLASS_FILE, entry],
		[GLOBALS_FILE, globals],
	]) {
		const drift = compareMembers(loaded.members, registry.snapshot(loaded.exports), 'exports') || (loaded === entry ? compareMembers(loaded.prototypeMembers, registry.snapshot(prototypeOf(loaded.exports)), 'prototype') : null);
		if (drift) return noData(`${file} no longer exports what it exported when it was loaded: ${drift}`);
	}
	// The class itself, not something derived from it: a subclass carries code
	// of its own that this file does not hold.
	const classPrototype = prototypeOf(entry.exports);
	if (Object.getPrototypeOf(module) !== classPrototype) return noData(`${identify(module)} is not built by the loaded ${CLASS_FILE}`);
	// Nothing of the module's own stands between that class and the text: an own
	// method would be the one that wrote it.
	const own = ownImplementation(registry.snapshot(module), OWN_METHODS);
	if (own) return noData(`${identify(module)} carries an implementation of its own: ${own}`);

	const shape = shapeProblem(module);
	if (shape) return noData(`${identify(module)}: ${shape}`);

	const element = registry.getByFile(path.join(lib, ...ELEMENT_FILE.split('/')));
	const elementProblem = entryProblem(element, ELEMENT_FILE);
	if (elementProblem) return elementProblem;
	const mapped = mappedModules(compilation, chunk, module, prototypeOf(element.exports));
	if (typeof mapped === 'string') return noData(`${identify(module)}: ${mapped}`);

	const rebuilt = rebuild(compilation, module, classPrototype);
	if (rebuilt.problem) return noData(`${identify(module)}: ${rebuilt.problem}`);
	let used;
	try {
		used = compilation.codeGenerationResults.getSource(module, chunk.runtime, SOURCE_TYPE);
	} catch (error) {
		return noData(`no code generation result for ${identify(module)}: ${error.message}`);
	}
	if (!used || typeof used.source !== 'function') return noData(`no source was generated for ${identify(module)}`);
	// A source map wraps the same text, so the text is what is compared.
	if (used.source() !== rebuilt.text) return failed('hash-mismatch', `the generated source of ${identify(module)} is not what ${CLASS_FILE} writes for this graph`);

	const units = [];
	for (const [relative, file] of [
		[CLASS_FILE, entry],
		[GLOBALS_FILE, globals],
	]) {
		const resolved = await verifyResource(file.file);
		if (!resolved || (!resolved.unit && !resolved.failure)) return noData(`${file.file} was not verified`);
		if (resolved.failure) return { units: [], failure: resolved.failure };
		const unit = resolved.unit;
		if (unit.sha256 !== file.sha256) return failed('hash-mismatch', `${file.file} differs from the bytes this process loaded from it`);
		if (unit.sha256 !== FINGERPRINTS.get(relativeName(lib, file.file))) {
			return failed('unsupported', `${relative} is not the source of the pinned webpack ${SUPPORTED_WEBPACK}`);
		}
		if (unit.component.version !== api.version) return failed('invalid', `component ${unit.component.id} is not the webpack ${api.version} that is running`);
		units.push({ path: unit.path, sha256: unit.sha256, component: unit.component });
	}
	return { units };
}

// Whether this is a context whose text this adapter can account for. Only the
// synchronous one, with no asynchronous block and no namespace object: the
// other modes write chunk loading into the module, and a namespace object adds
// a second map built from the exports of every target.
function shapeProblem(module) {
	const options = module.options;
	if (options.mode !== MODE) return `its requests are resolved ${String(options.mode)}, and only ${MODE} is described`;
	if (options.namespaceObject) return 'its requests answer with a namespace object';
	if (!Array.isArray(module.blocks) || module.blocks.length > 0) return 'it loads some of its requests from another chunk';
	if (!Array.isArray(module.dependencies) || module.dependencies.length === 0) return 'it resolves no request at all';
	return null;
}

// The check the rest rests on. Every entry of the map webpack writes is a
// request paired with the id of the module that answers it, so each dependency
// has to be one of the element dependencies this webpack loaded - its own class,
// not a fingerprinted file - and its module has to be in this chunk - where the collector describes it as a module of its own. The
// directory that was read is then data: whichever files it holds, the text can
// only name modules this build already accounts for.
function mappedModules(compilation, chunk, module, elementPrototype) {
	const { chunkGraph, moduleGraph } = compilation;
	if (!chunkGraph || !moduleGraph) return 'the compilation exposes no module graph';
	for (const dependency of module.dependencies) {
		if (Object.getPrototypeOf(dependency) !== elementPrototype) return `it resolves a request through ${dependency && dependency.constructor ? dependency.constructor.name : String(dependency)}, which is not the element dependency this webpack loaded`;
		if (typeof dependency.userRequest !== 'string' || dependency.userRequest === '') return 'it resolves a request that names nothing';
		const target = moduleGraph.getModule(dependency);
		// A request no module answers is left out of the map by webpack itself.
		if (!target) continue;
		if (!chunkGraph.isModuleInChunk(target, chunk)) return `it names ${identify(target)}, which this chunk does not hold`;
	}
	return null;
}

// The text that class writes for this graph, built by calling the pinned method
// through an object that carries nothing but the validated options. What this
// establishes is that no override and no hook stands between the class and the
// emitted text; what bounds the content is the map check above.
function rebuild(compilation, module, classPrototype) {
	const { chunkGraph } = compilation;
	const id = chunkGraph.getModuleId(module);
	if (typeof id !== 'string' && typeof id !== 'number') return { problem: 'it was given no module id' };
	const stub = Object.create(classPrototype);
	stub.options = { mode: module.options.mode, namespaceObject: module.options.namespaceObject };
	try {
		return { text: stub.getSyncSource(module.dependencies, id, chunkGraph) };
	} catch (error) {
		return { problem: `its source could not be rebuilt: ${error.message}` };
	}
}

function identify(module) {
	return typeof module.identifier === 'function' ? module.identifier() : String(module);
}

module.exports = { contextModuleEvidence, isContextModule };
