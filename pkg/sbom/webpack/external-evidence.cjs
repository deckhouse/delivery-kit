'use strict';

// Binds a module webpack built for an external - a request answered from
// outside the bundle - to the pinned webpack source that produced it.
//
// Such a module reads no file, and the package it names is not here: what
// stands in the chunk is a line webpack writes to reach it. For the shapes
// described here that line holds no code of the build's own configuration -
// either the request appears in it as a string literal, or it does not appear
// at all and the line reaches a variable named after the module's id. Every
// other shape writes the request as an expression, and is refused by name.

const path = require('node:path');

const { internals } = require('./runtime-evidence.cjs');

const { SUPPORTED_WEBPACK, FINGERPRINTS, compareMembers, ownImplementation, relativeName, prototypeOf, entryProblem, failed, noData } = internals;
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const BASE_FILE = 'RuntimeModule.js';
const CLASS_FILE = 'ExternalModule.js';
const TEMPLATE_FILE = 'Template.js';
const SOURCE_TYPE = 'javascript';
// The request is written as a string literal, inside a call to require.
const QUOTED_TYPES = new Set(['commonjs', 'commonjs2', 'commonjs-module', 'commonjs-static']);
// The same, but only for a module built as a script: built as an esm module it
// reaches the request through `createRequire` and an init fragment instead.
const SCRIPT_ONLY_TYPE = 'node-commonjs';
// The request is not written at all: the line reaches a variable the loader of
// the chunk declared, named after the id webpack gave this module.
const VARIABLE_TYPES = new Set(['amd', 'amd-require', 'umd', 'umd2', 'system', 'jsonp']);

function isExternalModule(module) {
	return module !== null && typeof module === 'object' && typeof module.externalType === 'string';
}

// `concatenated` says the module is a part of a scope-hoisted module rather
// than a module of the chunk: it has no generated source of its own, and the
// line it contributes stands in the text of the module that holds it.
async function externalEvidence(compilation, chunk, module, verifyResource, concatenated = false) {
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
	if (api.ExternalModule !== entry.exports) return noData(`the compiler exposes an ${CLASS_FILE} other than the one loaded from its lib directory`);
	const drift = compareMembers(entry.members, registry.snapshot(entry.exports), 'exports') || compareMembers(entry.prototypeMembers, registry.snapshot(prototypeOf(entry.exports)), 'prototype');
	if (drift) return noData(`${CLASS_FILE} no longer exports what it exported when it was loaded: ${drift}`);
	// The class itself, not something derived from it, and nothing of the
	// module's own between that class and the line it writes.
	if (Object.getPrototypeOf(module) !== prototypeOf(entry.exports)) return noData(`${identify(module)} is not built by the loaded ${CLASS_FILE}`);
	const own = ownImplementation(registry.snapshot(module));
	if (own) return noData(`${identify(module)} carries an implementation of its own: ${own}`);

	const files = [entry];
	const expected = expectedSource(compilation, module, api, registry, lib, files);
	if (typeof expected === 'string') return noData(`${identify(module)}: ${expected}`);

	// A module of the chunk writes that line as its whole source, and it is
	// compared below. One hoisted into another module writes a binding of that
	// scope instead, and nothing compares those bytes: the shape gate above is
	// the whole guarantee there, and it is what keeps the build's own
	// configuration out of the text in either form.
	if (!concatenated) {
		let used;
		try {
			used = compilation.codeGenerationResults.getSource(module, chunk.runtime, SOURCE_TYPE);
		} catch (error) {
			return noData(`no code generation result for ${identify(module)}: ${error.message}`);
		}
		if (!used || typeof used.source !== 'function') return noData(`no source was generated for ${identify(module)}`);
		// A source map wraps the same text, so the text is what is compared.
		if (used.source() !== expected.text) return failed('hash-mismatch', `the generated source of ${identify(module)} is not the line ${CLASS_FILE} writes to reach it`);
	}

	const units = [];
	for (const file of files) {
		const relative = relativeName(lib, file.file);
		const resolved = await verifyResource(file.file);
		if (!resolved || (!resolved.unit && !resolved.failure)) return noData(`${file.file} was not verified`);
		if (resolved.failure) return { units: [], failure: resolved.failure };
		const unit = resolved.unit;
		if (unit.sha256 !== file.sha256) return failed('hash-mismatch', `${file.file} differs from the bytes this process loaded from it`);
		if (unit.sha256 !== FINGERPRINTS.get(relative)) return failed('unsupported', `${relative} is not the source of the pinned webpack ${SUPPORTED_WEBPACK}`);
		if (unit.component.version !== api.version) return failed('invalid', `component ${unit.component.id} is not the webpack ${api.version} that is running`);
		units.push({ path: unit.path, sha256: unit.sha256, component: unit.component });
	}
	return { units };
}

// The line webpack writes for this external, rebuilt from what it was given.
// Only the two shapes that hold no expression of the build's own: a request
// written as a string literal, and one not written at all.
function expectedSource(compilation, module, api, registry, lib, files) {
	const request = module.request;
	if (Array.isArray(request)) return 'it is requested by a name reaching into what that name found';
	if (typeof request !== 'string') return 'it is requested by one name per way of reaching it';
	if (module.isOptional(compilation.moduleGraph)) return 'it is an external the build can do without';
	// Inside a scope-hoisted module the line declares a binding of that scope
	// instead; the text comparison refuses that, and the module that holds it
	// answers for those bytes.
	const quoted = QUOTED_TYPES.has(module.externalType) || (module.externalType === SCRIPT_ONLY_TYPE && module.buildInfo && module.buildInfo.module === false);
	if (quoted) return { text: `module.exports = require(${JSON.stringify(request)});` };
	if (module.externalType === SCRIPT_ONLY_TYPE) return `it is reached as ${SCRIPT_ONLY_TYPE} from a module, which reaches the request through a fragment of its own`;
	if (!VARIABLE_TYPES.has(module.externalType)) return `it is reached as ${module.externalType}, which writes ${configuredText(module.externalType)} into the chunk as an expression`;
	const template = registry.getByFile(path.join(lib, TEMPLATE_FILE));
	const problem = entryProblem(template, TEMPLATE_FILE);
	if (problem) return problem.failure.reason;
	if (api.Template !== template.exports) return `the compiler exposes a ${TEMPLATE_FILE} other than the one loaded from its lib directory`;
	const drift = compareMembers(template.members, registry.snapshot(template.exports), 'exports');
	if (drift) return `${TEMPLATE_FILE} no longer exports what it exported when it was loaded: ${drift}`;
	files.push(template);
	// Exactly what ExternalModule.js names the variable after.
	const id = compilation.chunkGraph.getModuleId(module);
	const named = id !== null ? id : module.identifier();
	return { text: `module.exports = __WEBPACK_EXTERNAL_MODULE_${api.Template.toIdentifier(`${named}`)}__;` };
}

// What the chunk would be given for a type this adapter refuses: the text the
// build configured for the request, or - where the type names a place to look
// it up in - an expression built around it.
function configuredText(externalType) {
	return externalType === 'module' || externalType === 'import' || externalType === 'module-import' ? 'an import of the request' : 'the configured request';
}

function identify(module) {
	return typeof module.identifier === 'function' ? module.identifier() : String(module);
}

module.exports = { externalEvidence, isExternalModule };
