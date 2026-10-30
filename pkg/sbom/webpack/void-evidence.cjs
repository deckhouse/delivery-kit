'use strict';

// Binds a module webpack built for a request it was told not to resolve - a
// `resolve.fallback` of false, or a plugin that answered the resolution with
// nothing - to the pinned webpack source that produced it.
//
// Such a module reads no file. Webpack builds it out of one fixed comment of
// its own, so nothing of the project is in it and there is nothing to verify on
// disk; what has to hold is that the class is webpack's, that the text really
// is that fixed comment, and that the comment is all the chunk was given for
// this module.

const path = require('node:path');

const { internals } = require('./runtime-evidence.cjs');

const { SUPPORTED_WEBPACK, FINGERPRINTS, compareMembers, relativeName, prototypeOf, entryProblem, failed, noData } = internals;
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const BASE_FILE = 'RuntimeModule.js';
const CLASS_FILE = 'RawModule.js';
const SOURCE_TYPE = 'javascript';
// What webpack writes for a request it was told to drop, and the identifier it
// gives such a module.
const VOID_SOURCE = '/* (ignored) */';
const VOID_IDENTIFIER = /^ignored\|/;

// Which modules this adapter is asked about: one that reads no file and
// carries text instead. Whether that text is webpack's own, and the class the
// module's own, is decided by the adapter.
function isVoidModule(module) {
	return typeof module.sourceStr === 'string' && typeof module.resource !== 'string';
}

async function voidEvidence(compilation, chunk, module, verifyResource) {
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
	const problem = entryProblem(entry, CLASS_FILE);
	if (problem) return problem;
	const drift = compareMembers(entry.members, registry.snapshot(entry.exports), 'exports') || compareMembers(entry.prototypeMembers, registry.snapshot(prototypeOf(entry.exports)), 'prototype');
	if (drift) return noData(`${CLASS_FILE} no longer exports what it exported when it was loaded: ${drift}`);

	// The class itself, not something derived from it: a subclass carries code
	// of its own that this file does not hold.
	if (Object.getPrototypeOf(module) !== prototypeOf(entry.exports)) return noData(`${identify(module)} is not built by the loaded ${CLASS_FILE}`);
	if (!VOID_IDENTIFIER.test(module.identifier())) return noData(`${identify(module)} is not a module webpack built for a request it dropped`);
	// Whoever built it chose this text; only the one fixed comment is text no
	// project of its own stands behind.
	if (module.sourceStr !== VOID_SOURCE) return noData(`${identify(module)} carries text other than the comment webpack writes for a dropped request`);

	let used;
	try {
		used = compilation.codeGenerationResults.getSource(module, chunk.runtime, SOURCE_TYPE);
	} catch (error) {
		return noData(`no code generation result for ${identify(module)}: ${error.message}`);
	}
	if (!used || typeof used.source !== 'function') return noData(`no source was generated for ${identify(module)}`);
	if (used.source() !== VOID_SOURCE) return failed('hash-mismatch', `the generated source of ${identify(module)} is not the comment it carries`);

	const resolved = await verifyResource(entry.file);
	if (!resolved || (!resolved.unit && !resolved.failure)) return noData(`${entry.file} was not verified`);
	if (resolved.failure) return { units: [], failure: resolved.failure };
	const unit = resolved.unit;
	if (unit.sha256 !== entry.sha256) return failed('hash-mismatch', `${entry.file} differs from the bytes this process loaded from it`);
	if (unit.sha256 !== FINGERPRINTS.get(relativeName(lib, entry.file))) {
		return failed('unsupported', `${CLASS_FILE} is not the source of the pinned webpack ${SUPPORTED_WEBPACK}`);
	}
	if (unit.component.version !== api.version) return failed('invalid', `component ${unit.component.id} is not the webpack ${api.version} that is running`);
	return { units: [{ path: unit.path, sha256: unit.sha256, component: unit.component }] };
}

function identify(module) {
	return typeof module.identifier === 'function' ? module.identifier() : String(module);
}

module.exports = { voidEvidence, isVoidModule };
