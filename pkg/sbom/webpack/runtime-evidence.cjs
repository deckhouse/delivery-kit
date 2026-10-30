'use strict';

// Binds one webpack runtime module of a chunk to the pinned webpack sources
// that produced it, for the three standard classes listed below and nothing
// else; anything else is reported as no data, never as a weaker claim.
//
// The load recordings and the observation of the generator call come from
// runtime-preload.cjs, which must already be installed when webpack is first
// required; without it there is no data.

const path = require('node:path');

const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const SUPPORTED_WEBPACK = '5.94.0';
const SOURCE_TYPE = 'runtime';
const BASE_FILE = 'RuntimeModule.js';
const HELPER_BASE_FILE = 'runtime/HelperRuntimeModule.js';
const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const DOTTED = /^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$/;
const PATH_HOOK = 'assetPath';
const PATH_PLUGIN = 'TemplatedPathPlugin';
const COMPILATION_FILE = 'Compilation.js';
const CLASS_FILES = new Map([
	['runtime/DefinePropertyGettersRuntimeModule.js', {}],
	['runtime/HasOwnPropertyRuntimeModule.js', {}],
	['runtime/MakeNamespaceObjectRuntimeModule.js', {}],
	['runtime/NonceRuntimeModule.js', {}],
	['runtime/EnsureChunkRuntimeModule.js', {}],
	['runtime/GlobalRuntimeModule.js', {}],
	// It writes one more of the pinned runtime globals into its text.
	['runtime/CompatGetDefaultExportRuntimeModule.js', {}],
	// Declared inside the plugin that installs it and exported by nothing, so
	// there is no exported class to bind this instance to, and no load-time
	// wrapper that observed it generating. What makes the claim sound is the
	// comparison of the emitted code with what this rebuild produces out of the
	// verified helpers; finding the class's source in the pinned file only says
	// which file to claim for it.
	[
		'dependencies/CommonJsPlugin.js',
		{
			declares: 'NodeModuleDecoratorRuntimeModule',
			rebuild: (api, runtimeTemplate) =>
				api.Template.asString([
					`${api.RuntimeGlobals.nodeModuleDecorator} = ${runtimeTemplate.basicFunction('module', ['module.paths = [];', 'if (!module.children) module.children = [];', 'return module;'])};`,
				]),
		},
	],
	// Its text runs through a hook another plugin can rewrite, and carries the
	// load timeout unquoted.
	['runtime/LoadScriptRuntimeModule.js', { hooks: ['createScript'], check: (compilation) => (Number.isFinite(compilation.outputOptions.chunkLoadTimeout) ? null : 'its load timeout is not a number') }],
	// It reads the chunk condition map and the initial chunk ids off three more
	// pinned files, offers two hooks nothing may tap, and carries the name of the
	// global object unquoted.
	[
		'web/JsonpChunkLoadingRuntimeModule.js',
		{
			helpers: ['javascript/JavascriptModulesPlugin.js', 'javascript/StartupHelpers.js', 'util/compileBooleanMatcher.js'],
			hooks: ['linkPreload', 'linkPrefetch'],
			check: (compilation) => (IDENTIFIER.test(compilation.runtimeTemplate.globalObject) ? null : 'the name of its global object is not an identifier'),
		},
	],
	// The three that build a filename out of a template of the output options.
	// Each of them is described only while that is the one stock substitution,
	// and the chunk filename map of the first is generated again while the chunk
	// hashes are computed.
	[
		'runtime/GetChunkFilenameRuntimeModule.js',
		{
			helpers: [COMPILATION_FILE, 'TemplatedPathPlugin.js', 'util/SetHelpers.js'],
			// One for every chunk it can reach, and never none.
			paths: { min: 1 },
			dependentHash: true,
			// The function it was built with decides nothing this adapter has to
			// trust: every template it returns is checked against the output
			// options where the filename is built. The name it assigns to is
			// carried into the text unquoted.
			ownFunctions: ['getFilenameForChunk'],
			check: (compilation, runtimeModule) => (DOTTED.test(runtimeModule.global) ? null : 'the name it assigns its function to is not an identifier'),
		},
	],
	['runtime/PublicPathRuntimeModule.js', { helpers: [COMPILATION_FILE, 'TemplatedPathPlugin.js'], paths: { exact: 1 } }],
	// Two classes of one file, exported as members of a namespace rather than as
	// the whole of its exports. The options of the second are written into its
	// text as json, so they have to be data this adapter can write out again.
	[
		'dependencies/AMDRuntimeModules.js',
		{
			members: new Map([
				['AMDDefineRuntimeModule', {}],
				['AMDOptionsRuntimeModule', { check: (compilation, runtimeModule) => (plainData(runtimeModule.options) ? null : 'the amd options it writes out are not plain data') }],
			]),
		},
	],
	[
		'runtime/AutoPublicPathRuntimeModule.js',
		{
			helpers: [COMPILATION_FILE, 'TemplatedPathPlugin.js', 'util/identifier.js', 'javascript/JavascriptModulesPlugin.js'],
			paths: { exact: 1 },
			check: (compilation) =>
				compilation.outputOptions.scriptType !== 'module' || DOTTED.test(compilation.outputOptions.importMetaName) ? null : 'the name it reads its own url from is not an identifier',
		},
	],
]);
const HELPER_FILES = ['Template.js', 'RuntimeTemplate.js', 'RuntimeGlobals.js'];
// The raw bytes of every file this adapter describes, in the pinned webpack
// 5.94.0 distribution. A fork or a patched install that keeps the version
// string is not that webpack, however well its own bytes verify.
const FINGERPRINTS = new Map([
	['RuntimeModule.js', 'sha256:ce95e076bc30746ca64a0d9b5d540ab42eb73cf1db79705fccfabf16f64f3986'],
	['Template.js', 'sha256:9849fa6fd40f4c38cd965c105497bd8e993961c6daa40a085ad7d3a74a383ec6'],
	['RuntimeTemplate.js', 'sha256:5a4fb4aaae186ca24e8ca3791a50fe89fe3f2cce2576ff0136b38d49e4fae06e'],
	['RuntimeGlobals.js', 'sha256:0c90301d2e7d126196ddf3378cc23cdaef02f064e1b8216140b86635087f3e50'],
	['runtime/HelperRuntimeModule.js', 'sha256:8f773a9b2b32f36ab77331a14da3fb7870588a151b12a842ff2961a63097a94b'],
	['runtime/DefinePropertyGettersRuntimeModule.js', 'sha256:a8616912437a5fbad7859198d242fc1615ac5be21107a358942537082bcfb7ea'],
	['runtime/HasOwnPropertyRuntimeModule.js', 'sha256:1839066ca40c63cc0e655c0453e9163aaa0d4bb92be4c4c0ac23d16b14d70c18'],
	['runtime/MakeNamespaceObjectRuntimeModule.js', 'sha256:3b04cbcb66679c0889f27536bcb3008720285953552a5f1dd0bd02a71fb3a0d4'],
	['javascript/JavascriptModulesPlugin.js', 'sha256:a62f97847080a4f4ebf2e5075bd14f55f29ab5e862e7fac608e6cd081dfb3198'],
	['APIPlugin.js', 'sha256:b6b1aa7b66f08aeaa2ea8e141ee7567120200855a9fbc88bc3351988a9fe686e'],
	['runtime/NonceRuntimeModule.js', 'sha256:a5f4cdf3351b259a972eefe4bb7d48c94f13933dd415c0a7108d645bfe026fcf'],
	['runtime/EnsureChunkRuntimeModule.js', 'sha256:ce45b3ec61b19811f95e0bd5ef9c3be813fce036a3b9c39d7fd2fd84790e9439'],
	['runtime/GlobalRuntimeModule.js', 'sha256:38f5f7ccac8a7aa838f527a36fa957a618b7b86cccdb6e4d6742a9c6989d1102'],
	['runtime/LoadScriptRuntimeModule.js', 'sha256:9933ec291ccb384df3ef81f80f21804f683adfb791a74ed126b96211badc21ef'],
	['web/JsonpChunkLoadingRuntimeModule.js', 'sha256:b7a2ebf120a529026ca03507fdb208d0f2c5231f7ab084f0d4e95c1c173d0d47'],
	['javascript/StartupHelpers.js', 'sha256:ded5e4278e62a46aef92b411f29987c8bb9f60b5c995077224d2225830831f9f'],
	['util/compileBooleanMatcher.js', 'sha256:cb762da791f38be832cfc25fcb01d9e2493860e1379f00f60699d35e8457592b'],
	['javascript/ArrayPushCallbackChunkFormatPlugin.js', 'sha256:f2ab83fbc0c9b3e00a6f5a2a0c9faf1ddcb129ebe2dc6655245f36c4d1a1493e'],
	['runtime/GetChunkFilenameRuntimeModule.js', 'sha256:fcfd0150ea1cf23bc14ae55353cff99a84bf4df21a0c93a1408deb98801da787'],
	['runtime/PublicPathRuntimeModule.js', 'sha256:7f635d52043494b753948bef9ce8e965d4923b490f245e5ba0e972b10d248f1e'],
	['runtime/AutoPublicPathRuntimeModule.js', 'sha256:e0b7c5868ced21164319290833361f4b3bde46dd0bf2ca0440f73e26acffdd35'],
	['TemplatedPathPlugin.js', 'sha256:3fe4b95afb8dad6a3d08f947515b827c1a7086273c88a902be663ac4ef2a0878'],
	['util/identifier.js', 'sha256:c62d0fdafde3137620eeab4c20dcba7ed6d82d8634b8770ed824b30c096ee5ed'],
	['util/SetHelpers.js', 'sha256:d89244af8666d3885f545b6bc8eb36a9b896e97c89542b0f7beece0752a8dd0f'],
	['Compilation.js', 'sha256:de23e5130f99b6ee579790d32a333e144ce52bbb9db08b258f8f615b81914a1e'],
	['dependencies/AMDRuntimeModules.js', 'sha256:50d240952310f884e3b46834b4b1e098cab22a0050dbd18457eb79fccfd70a09'],
	['runtime/CompatGetDefaultExportRuntimeModule.js', 'sha256:dc3f62221eb87296467e3f2d2783b46c6d3910d6a0b0086038b7b108fe16e0b2'],
	['dependencies/CommonJsPlugin.js', 'sha256:d6d1c3fd918161c21f4eb794b00fe8e792f3b74f8c43f8796c50a2c83caae4bb'],
]);

async function runtimeEvidence(compilation, chunk, runtimeModule, verifyResource) {
	const registry = globalThis[REGISTRY];
	if (!registry || typeof registry.findByExport !== 'function' || typeof registry.getByFile !== 'function' || typeof registry.getGeneration !== 'function' || typeof registry.snapshot !== 'function') {
		return noData('the commonjs load registry is not installed in this process');
	}
	const api = compilation.compiler && compilation.compiler.webpack;
	if (!api || typeof api.version !== 'string') return noData('the compiler does not expose its webpack');
	if (api.version !== SUPPORTED_WEBPACK) {
		return failed('unsupported', `runtime modules of webpack ${api.version} are not described, only ${SUPPORTED_WEBPACK}`);
	}

	const base = registry.findByExport(api.RuntimeModule);
	const baseProblem = entryProblem(base, 'the webpack RuntimeModule base class');
	if (baseProblem) return baseProblem;
	const lib = path.dirname(base.file);
	if (path.basename(base.file) !== BASE_FILE) return noData(`the RuntimeModule base class comes from ${base.file}`);

	const chain = [];
	const prototype = Object.getPrototypeOf(runtimeModule);
	const moduleClass = prototype === null ? undefined : prototype.constructor;
	if (!moduleClass || moduleClass.prototype !== prototype) return noData(`${identify(runtimeModule)} does not carry its own class`);
	for (let current = moduleClass; current !== api.RuntimeModule && chain.length < 2; current = Object.getPrototypeOf(current)) {
		if (typeof current !== 'function') break;
		// The file that exports the class, whether as the whole of its exports or
		// as one named member of them. A class no file exports at all - one
		// declared inside the plugin that installs it - is not described, and
		// saying it was never loaded would name the wrong thing.
		const exporting = registry.findByExport(current);
		const member = exporting ? null : registry.findByExportedMember(current);
		const declaring = exporting || member ? null : declaredBy(registry, lib, current);
		const entry = exporting || (member && member.entry) || declaring;
		if (!entry) return noData(`${identify(runtimeModule)} is built by ${current.name}, which no file of this process exports or declares`);
		const problem = entryProblem(entry, `the class ${current.name} of ${identify(runtimeModule)}`);
		if (problem) return problem;
		const relative = relativeName(lib, entry.file);
		const known = chain.length === 0 ? [...CLASS_FILES.keys()] : [HELPER_BASE_FILE];
		if (!known.includes(relative)) {
			return noData(`${identify(runtimeModule)} is built by ${entry.file}, which is not a described webpack runtime module`);
		}
		chain.push({ ...entry, member: member ? member.key : null, declared: declaring ? current.name : null, class: current });
	}
	if (chain.length === 0 || Object.getPrototypeOf(chain[chain.length - 1].class) !== api.RuntimeModule) {
		return noData(`${identify(runtimeModule)} does not derive from the loaded RuntimeModule`);
	}
	chain.push({ ...base, member: null, class: base.exports });

	const helpers = [];
	const declared = CLASS_FILES.get(relativeName(lib, chain[0].file));
	// A file of several classes describes each of them on its own.
	const described = declared.members ? declared.members.get(chain[0].member) : declared;
	if (!described) return noData(`${identify(runtimeModule)} is built by a class ${chain[0].file} does not declare`);
	for (const relative of [...HELPER_FILES, ...(described.helpers || [])]) {
		const entry = registry.getByFile(path.join(lib, ...relative.split('/')));
		const problem = entryProblem(entry, relative);
		if (problem) return problem;
		helpers.push(entry);
	}
	const [template, runtimeTemplate, runtimeGlobals] = helpers;
	// The one implementation a described filename may be built with.
	const builder = described.paths ? memberOf(helpers.find((entry) => relativeName(lib, entry.file) === COMPILATION_FILE), 'getAssetPath') : null;
	if (api.Template !== template.exports || api.RuntimeGlobals !== runtimeGlobals.exports) {
		return noData('the compiler exposes helper modules other than the ones loaded from its lib directory');
	}
	for (const entry of [...chain, ...helpers]) {
		// A class the file only declares was never part of its exports, so there
		// is nothing of it to have drifted; its own source text is what binds it.
		const drift =
			compareMembers(entry.members, registry.snapshot(entry.exports), 'exports') ||
			(entry.declared ? null : compareMembers(prototypeSnapshot(entry), registry.snapshot(prototypeOf(entry.class !== undefined ? entry.class : entry.exports)), 'prototype'));
		if (drift) return noData(`${relativeName(lib, entry.file)} no longer exports what it exported when it was loaded: ${drift}`);
	}

	const own = ownImplementation(registry.snapshot(runtimeModule), described.ownFunctions);
	if (own) return noData(`${identify(runtimeModule)} carries an own ${own}`);
	if (chain[0].declared) {
		if (runtimeModule.generate !== prototypeOf(chain[0].class).generate) return noData(`${identify(runtimeModule)} would not run the generator of the class it carries`);
	} else {
		const generate = memberOf(chain[0], 'generate', chain[0].member);
		if (!generate || runtimeModule.generate !== generate.value) return noData(`${identify(runtimeModule)} would not run the generator its class exported`);
	}
	for (const name of ['getGeneratedCode', 'codeGeneration']) {
		const inherited = memberOf(base, name);
		if (!inherited || runtimeModule[name] !== inherited.value) return noData(`${identify(runtimeModule)} would not run the loaded ${name}`);
	}
	if (runtimeModule.fullHash !== false) return noData(`${identify(runtimeModule)} regenerates its code for the compilation hash`);
	if (runtimeModule.dependentHash !== (described.dependentHash === true)) {
		return noData(`${identify(runtimeModule)} does not regenerate its code for the chunk hashes the way its class does`);
	}
	if (runtimeModule.compilation !== compilation) return noData(`${identify(runtimeModule)} is attached to another compilation`);
	// Values of the output options this class interpolates unquoted: a shape that
	// is not the one its text is built for is text this adapter cannot describe.
	const unusable = described.check ? described.check(compilation, runtimeModule) : null;
	if (unusable) return noData(`${identify(runtimeModule)} is generated while ${unusable}`);
	// The generators read their strings off this instance.
	const instance = compilation.runtimeTemplate;
	const runtimeTemplatePrototype = prototypeOf(runtimeTemplate.exports);
	if (!instance || Object.getPrototypeOf(instance) !== runtimeTemplatePrototype) return noData('the compilation does not use the loaded RuntimeTemplate');
	const ownInstance = ownImplementation(registry.snapshot(instance));
	if (ownInstance) return noData(`the compilation runtime template carries an own ${ownInstance}`);

	// What the generator really returned, seen from inside its own call: a
	// prefilled cache, a generator swapped only for the call, or a helper put back
	// before this point are all invisible to any later reading. A class whose code
	// depends on the chunk hashes generates again while they are computed, so every
	// run has to have been the verified one, and the used code one of their results.
	const observed = chain[0].declared ? null : registry.getGeneration(runtimeModule);
	if (!chain[0].declared && (!observed || !Array.isArray(observed.runs) || observed.runs.length === 0)) {
		return noData(`the generator of ${identify(runtimeModule)} was not observed running`);
	}
	if (observed && (observed.file !== chain[0].file || (observed.member || null) !== chain[0].member || observed.method !== runtimeModule.generate)) {
		return noData(`${identify(runtimeModule)} was generated by another implementation`);
	}
	for (const run of observed ? observed.runs : []) {
		if (typeof run.code !== 'string') return noData(`a run of the generator of ${identify(runtimeModule)} produced no text`);
		if (run.compilation !== compilation) return noData(`${identify(runtimeModule)} was generated for another compilation`);
		const built = pathsProblem(run.paths, described.paths, templates(compilation, chunk), builder);
		if (built) return noData(`${built} while ${identify(runtimeModule)} was generated`);
		for (const state of run.states) {
			for (const entry of [...chain, ...helpers]) {
				const atCall = state.helpers.get(entry.file);
				if (!atCall) return noData(`${relativeName(lib, entry.file)} was not loaded when the generator ran`);
				const drift = compareMembers(entry.members, atCall.members, 'exports') || compareMembers(entry.prototypeMembers, atCall.prototypeMembers, 'prototype');
				if (drift) return noData(`${relativeName(lib, entry.file)} was not what it exported when it was loaded while the generator ran: ${drift}`);
			}
			if (!state.runtimeTemplate || state.runtimeTemplate.prototype !== runtimeTemplatePrototype) return noData('another runtime template was in place while the generator ran');
			const ownAtCall = ownImplementation(state.runtimeTemplate.own);
			if (ownAtCall) return noData(`the runtime template carried an own ${ownAtCall} while the generator ran`);
			// A tap on a hook this class calls contributes text no verified source
			// holds; the taps are the ones in place while it generated.
			for (const name of described.hooks || []) {
				const tapped = state.hooks && state.hooks.get(name);
				if (!tapped) return noData(`the ${name} taps could not be observed while ${identify(runtimeModule)} was generated`);
				if (tapped.length > 0) return noData(`${tapped.join(', ')} tapped ${name} while ${identify(runtimeModule)} was generated`);
			}
		}
	}

	const chunkGraph = compilation.chunkGraph;
	if (!chunkGraph || typeof chunkGraph.getChunkRuntimeModulesIterable !== 'function') return noData('the compilation does not expose the runtime modules of its chunks');
	let attached = false;
	for (const candidate of chunkGraph.getChunkRuntimeModulesIterable(chunk)) {
		if (candidate === runtimeModule) attached = true;
	}
	if (!attached) return noData(`${identify(runtimeModule)} is not a runtime module of this chunk`);

	let used;
	try {
		used = compilation.codeGenerationResults.getSource(runtimeModule, chunk.runtime, SOURCE_TYPE);
	} catch (error) {
		return noData(`no code generation result for ${identify(runtimeModule)}: ${error.message}`);
	}
	if (!used || typeof used.source !== 'function') return noData(`no runtime source was generated for ${identify(runtimeModule)}`);
	const usedCode = used.source();
	const generated = runtimeModule._cachedGeneratedCode;
	if (typeof usedCode !== 'string' || typeof generated !== 'string') return noData(`the runtime source of ${identify(runtimeModule)} is not text`);
	if (observed && !observed.runs.some((run) => run.code === generated)) {
		return failed('hash-mismatch', `the cached runtime code of ${identify(runtimeModule)} is not what its generator returned`);
	}
	// A class that was never observed generating is held to what its own pinned
	// source builds out of the verified helpers instead. This is the comparison
	// the whole claim for such a class rests on.
	if (chain[0].declared && generated !== described.rebuild(api, instance)) {
		return failed('hash-mismatch', `the runtime code of ${identify(runtimeModule)} is not what ${relativeName(lib, chain[0].file)} builds`);
	}
	if (!Buffer.from(usedCode, 'utf8').equals(Buffer.from(generated, 'utf8'))) {
		return failed('hash-mismatch', `the runtime source used for ${identify(runtimeModule)} is not the code its generator produced`);
	}

	const units = [];
	const verified = new Set();
	let component;
	for (const entry of [...chain, ...helpers]) {
		if (verified.has(entry.file)) continue;
		verified.add(entry.file);
		const resolved = await verifyResource(entry.file);
		if (!resolved || (!resolved.unit && !resolved.failure)) return noData(`${entry.file} was not verified`);
		if (resolved.failure) return { units: [], failure: resolved.failure };
		const unit = resolved.unit;
		if (unit.sha256 !== entry.sha256) return failed('hash-mismatch', `${entry.file} differs from the bytes this process loaded from it`);
		const pinned = FINGERPRINTS.get(relativeName(lib, entry.file));
		if (unit.sha256 !== pinned) {
			return failed('unsupported', `${relativeName(lib, entry.file)} is not the source of the pinned webpack ${SUPPORTED_WEBPACK}`);
		}
		if (component === undefined) component = unit.component;
		else if (!sameJSON(component, unit.component)) {
			return failed('invalid', `the webpack runtime sources bind to conflicting components ${component.id} and ${unit.component.id}`);
		}
		// Which file to claim for a class nothing exports: its whole source text
		// stands in the bytes just verified. This decides attribution, not
		// soundness - what the code is made of is settled by the rebuild above.
		if (entry.declared && !(unit.bytes || Buffer.alloc(0)).includes(Buffer.from(Function.prototype.toString.call(entry.class), 'utf8'))) {
			return noData(`the class ${entry.declared} of ${identify(runtimeModule)} is not the one ${relativeName(lib, entry.file)} declares`);
		}
		units.push({ path: unit.path, sha256: unit.sha256, component: unit.component });
	}
	if (component.version !== api.version) {
		return failed('invalid', `component ${component.id} is not the webpack ${api.version} that is running`);
	}
	return { units };
}

// Every filename this generator built, and how. A class that is not described
// as building one may not have built one at all; a class that is builds it from
// a template string of the output options, through the one stock substitution,
// and never from path data naming a file of its own.
function pathsProblem(record, expected, known, builder) {
	if (!record || !Array.isArray(record.calls)) return 'the filenames it built could not be observed';
	if (record.ownBefore) return 'its compilation already built filenames with a method of its own';
	if (!record.intact) return 'the method it built its filenames with was replaced while it generated';
	if (!expected) return record.calls.length === 0 ? null : 'it built a filename this adapter does not describe';
	if (!builder || record.delegate !== builder.value) return 'it built its filenames with another implementation';
	if (expected.exact !== undefined && record.calls.length !== expected.exact) return `it built ${record.calls.length} filenames instead of ${expected.exact}`;
	if (expected.min !== undefined && record.calls.length < expected.min) return `it built ${record.calls.length} filenames`;
	for (const built of record.calls) {
		if (typeof built.template !== 'string') return 'it built a filename from a template of its own making';
		if (!known.has(built.template)) return 'it built a filename from a template that is not one of the output options';
		if (!built.data || built.data.includes('filename')) return 'it built a filename from path data this adapter does not describe';
		if (!built.taps) return `the ${PATH_HOOK} taps could not be observed`;
		const foreign = built.taps.filter((tap) => tap !== PATH_PLUGIN);
		if (foreign.length > 0 || built.taps.length !== 1) return `${built.taps.join(', ') || 'nothing'} tapped ${PATH_HOOK}`;
	}
	return null;
}

// The templates a filename may be built from: what the output options hold for
// this chunk, as the generators pass them on - bare, or quoted for the text.
// Only this chunk's own template is among them: a filename built from the
// template of some other chunk is one this adapter has not seen configured, and
// stays refused.
function templates(compilation, chunk) {
	const options = compilation.outputOptions;
	const known = new Set();
	for (const candidate of [options.filename, options.chunkFilename, options.publicPath, chunk.filenameTemplate, '']) {
		if (typeof candidate !== 'string') continue;
		known.add(candidate);
		known.add(JSON.stringify(candidate));
	}
	return known;
}

function entryProblem(entry, what) {
	if (!entry) return noData(`${what} was not recorded as a loaded commonjs module`);
	if (!entry.usable) return noData(`${what} was ${entry.reason}`);
	return null;
}

function relativeName(lib, file) {
	return path.relative(lib, file).split(path.sep).join('/');
}

function memberOf(entry, name, member) {
	const prototype = member ? prototypeSnapshot(entry) : entry.prototypeMembers;
	const snapshot = prototype && prototype.get(name);
	return snapshot && snapshot.kind === 'data' && typeof snapshot.value === 'function' ? snapshot : null;
}

// What the prototype of this entry's class held when the file was loaded: of
// its whole exports, or of the one member it was found under.
// The file whose pinned source declares a class of this name without exporting
// it. Only the files this adapter describes are searched, and a name it does
// not describe finds nothing.
function declaredBy(registry, lib, current) {
	for (const [relative, described] of CLASS_FILES) {
		if (described.declares !== current.name) continue;
		return registry.getByFile(path.join(lib, ...relative.split('/')));
	}
	return undefined;
}

function prototypeSnapshot(entry) {
	if (!entry.member) return entry.prototypeMembers;
	return (entry.memberPrototypes && entry.memberPrototypes.get(entry.member)) || null;
}

// Values this adapter can write out as json again: the plugin interpolates them
// with JSON.stringify, which a getter or a toJSON of its own would make
// something other than what is here.
function plainData(value) {
	if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
	if (Object.getPrototypeOf(value) !== Object.prototype) return false;
	for (const key of Reflect.ownKeys(value)) {
		if (typeof key !== 'string') return false;
		const descriptor = Object.getOwnPropertyDescriptor(value, key);
		if (!('value' in descriptor) || !descriptor.enumerable) return false;
		const held = descriptor.value;
		if (typeof held !== 'boolean' && typeof held !== 'number' && typeof held !== 'string') return false;
	}
	return true;
}

function prototypeOf(value) {
	const descriptor = typeof value === 'function' ? Object.getOwnPropertyDescriptor(value, 'prototype') : undefined;
	return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

// An own function, or an own accessor that could return one, shadows whatever
// the verified prototypes hold.
function ownImplementation(snapshot, allowed = []) {
	if (snapshot === null) return null;
	for (const [key, descriptor] of snapshot) {
		if (descriptor.kind !== 'data') return `${String(key)} accessor`;
		if (typeof descriptor.value === 'function' && !allowed.includes(key)) return `${String(key)} implementation`;
	}
	return null;
}

function compareMembers(snapshot, now, where) {
	if (snapshot === null || now === null) return snapshot === now ? null : `${where} is no longer an object`;
	for (const key of snapshot.keys()) {
		if (!now.has(key)) return `${where}.${String(key)} is gone`;
	}
	for (const [key, is] of now) {
		const was = snapshot.get(key);
		if (!was) return `${where}.${String(key)} was added`;
		if (was.kind !== is.kind) return `${where}.${String(key)} was replaced`;
		if (was.kind === 'data' ? !Object.is(was.value, is.value) : !Object.is(was.get, is.get) || !Object.is(was.set, is.set)) {
			return `${where}.${String(key)} was replaced`;
		}
	}
	return null;
}

function identify(runtimeModule) {
	try {
		const name = runtimeModule.identifier();
		if (typeof name === 'string' && name !== '') return name;
	} catch {
		// An identifier of its own making is not worth failing over.
	}
	return 'the runtime module';
}

function sameJSON(left, right) {
	return JSON.stringify(left) === JSON.stringify(right);
}

function failed(status, reason) {
	return { units: [], failure: { status, reason } };
}

function noData(reason) {
	return failed('no-data', reason);
}

module.exports = { runtimeEvidence, internals: Object.freeze({ SUPPORTED_WEBPACK, FINGERPRINTS, compareMembers, ownImplementation, relativeName, prototypeOf, entryProblem, sameJSON, failed, noData }) };
