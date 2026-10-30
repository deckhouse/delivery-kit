'use strict';

// Binds the html a pinned html-webpack-plugin 5.6.0 emitted to the template
// file it was compiled from and to the code that wrote the rest of its text.
//
// The plugin compiles the template in a child compilation through its own
// lodash loader, evaluates the result into a function, executes it, injects the
// tags of the assets the compilation itself produced and minifies the whole
// text in a production build. Every one of those steps is observed where it
// happens - the loader call, the evaluation, the template execution, the post
// processing and the minification - and the steps are chained to one another by
// the very values they handed on: the function the evaluation returned is the
// one that was executed, the html it returned is the one that was post
// processed, and the bytes of the emitted asset are the text that came out.
// Nothing here recompiles a template or repeats a minification.
//
// The template file is a source of the html. So is the code that writes html
// text: the loader that turns the template into a function, the lodash
// implementation whose compiled template source that function is, the tag
// writer and the plugin file that injects the tags, and - where minification
// runs - the minifier and the entity decoder it rewrites the text with. Those
// units are claimed with the components they were verified as. The remaining
// pinned plugin files decide which template and which assets are used, and
// contribute no text of their own.
//
// The tags are written from the names of the assets of this very compilation,
// so no foreign code supplies them - as long as no foreign code can reach the
// text at all: every one of the plugin's six public hooks has to be untapped,
// and only the plugin's own default options are described.
//
// The load recordings come from runtime-preload.cjs, which must already be
// installed when the plugin is first required; without them there is no data.

const crypto = require('node:crypto');
const path = require('node:path');

const NAME = 'DkSbomHtmlEvidence';
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const SUPPORTED_WEBPACK = '5.94.0';
const PLUGIN_NAME = 'html-webpack-plugin';
const SUPPORTED_PLUGIN = '5.6.0';
const LODASH_NAME = 'lodash';
const SUPPORTED_LODASH = '4.17.23';
const MINIFIER_NAME = 'html-minifier-terser';
const SUPPORTED_MINIFIER = '6.1.0';
const ENTITIES_NAME = 'he';
const SUPPORTED_ENTITIES = '1.2.0';
const ENTRY_FILE = 'index.js';
const LOADER_FILE = 'lib/loader.js';
const CHILD_COMPILER = 'HtmlWebpackCompiler';
const PLUGIN_TAP = 'HtmlWebpackPlugin';
// What a plugin instance of the recorded class carries, and nothing else: an
// own property shadowing a method this adapter does not wrap - the tag
// generators, the template parameters, the whole generation - would write html
// of its own while every observed step still passes.
const INSTANCE_KEYS = ['userOptions', 'version', 'options', 'logger'];
// The hooks of JavascriptModulesPlugin whose taps shape the text a chunk is
// rendered from, mirroring bootstrap-evidence.cjs: in the child compilation of
// the template nothing may tap them, because nothing observes that render.
const SHAPING = [
	'renderMain',
	'renderChunk',
	'render',
	'renderContent',
	'renderStartup',
	'renderRequire',
	'renderModuleContainer',
	'renderModulePackage',
	'inlineInRuntimeBailout',
	'embedInRuntimeBailout',
	'strictRuntimeBailout',
];
const MODULE_CONTENT = 'renderModuleContent';
// The taps webpack's own stock plugins register in the child compilation that
// the pinned child-compiler configures (node target, node template, var
// library), and the one APIPlugin tap of every compilation. Tap names are not
// identities - the same limit bootstrap-evidence.cjs lives with - but anything
// not named here writes the template bundle with code nothing observed.
const CHILD_TAPS = new Map([
	['render', ['AssignLibraryPlugin']],
	['renderStartup', ['AssignLibraryPlugin']],
	['embedInRuntimeBailout', ['AssignLibraryPlugin']],
	['strictRuntimeBailout', ['AssignLibraryPlugin']],
	['renderChunk', ['CommonJsChunkFormatPlugin']],
	[MODULE_CONTENT, ['APIPlugin']],
]);
const CANONICAL_SHA256 = /^sha256:[0-9a-f]{64}$/;
const BOM = Buffer.from([0xef, 0xbb, 0xbf]);
// The one entry the plugin adds to its child compilation beside the template.
const CHILD_ENTRY = 'data:text/javascript,__webpack_public_path__ = __webpack_base_uri__ = htmlWebpackPluginPublicPath;';
const CHILD_ENTRY_SOURCE = '__webpack_public_path__ = __webpack_base_uri__ = htmlWebpackPluginPublicPath;';
const HOOKS = ['beforeAssetTagGeneration', 'alterAssetTags', 'alterAssetTagGroups', 'afterTemplateExecution', 'beforeEmit', 'afterEmit'];
// Every file of the plugin that decides what the html is made of. The three
// that write html text themselves are claimed as sources of it.
const PLUGIN_FILES = ['index.js', 'lib/loader.js', 'lib/html-tags.js', 'lib/child-compiler.js', 'lib/cached-child-compiler.js', 'lib/hooks.js', 'lib/chunksorter.js', 'lib/errors.js'];
const PLUGIN_TEXT_FILES = new Set(['index.js', 'lib/loader.js', 'lib/html-tags.js']);
const MINIFIER_FILES = ['src/htmlminifier.js', 'src/htmlparser.js', 'src/tokenchain.js', 'src/utils.js'];
// The raw bytes of those files in the registry archives of these versions,
// whose sha512 are the integrity pinned in package-lock.json. A fork keeping
// the version string is not the implementation these fingerprints describe.
const FINGERPRINTS = new Map([
	[`${PLUGIN_NAME}/index.js`, 'sha256:a21ad81ac18caac0710bfd14ba5dfa6fa91e913d26141c7a321202ecbba7970c'],
	[`${PLUGIN_NAME}/lib/loader.js`, 'sha256:59fcbda4890ead89628a462490df69ba56b06b9be15a7150d774019549f8c0e6'],
	[`${PLUGIN_NAME}/lib/html-tags.js`, 'sha256:74755a5cbf4c6cfef8b6678aefabec1379d330c97757b80f6b8b803ac31e6379'],
	[`${PLUGIN_NAME}/lib/child-compiler.js`, 'sha256:fd532eec60d91b21a18066471d70d70a9a263ba3a92a6f60db6bbbcc1f261871'],
	[`${PLUGIN_NAME}/lib/cached-child-compiler.js`, 'sha256:63b9384f3ded53b8e1ab551615ea05ef946de621d0dce9b45ebf5211b90fdf94'],
	[`${PLUGIN_NAME}/lib/hooks.js`, 'sha256:9917ac9f7dd1843ceedea38c01f36ad5ed97d41cee5ccc6378ca2bec58707005'],
	[`${PLUGIN_NAME}/lib/chunksorter.js`, 'sha256:a9207500c870ce6b3918d64b8566f9730e4c5fbb0bdfd6244f6f22158755f735'],
	[`${PLUGIN_NAME}/lib/errors.js`, 'sha256:a88e8b3a04941e81ddc199f6627c1d17cab11c57b49d786158afde179d3f29d1'],
	[`${LODASH_NAME}/lodash.js`, 'sha256:71b4b7f5d2fc2d69399fd3edd7104fa10f9fd73fc600130825c3032ee8c50dad'],
	[`${MINIFIER_NAME}/src/htmlminifier.js`, 'sha256:6594bd37dd57ecaf70d9e1983c2ec5d20c5a8a73593af45fa157ce44f0f25921'],
	[`${MINIFIER_NAME}/src/htmlparser.js`, 'sha256:a8ccd04e7e8e90587f991ccc40b4f65fa55919fe924d2815bf4bc5bcc5864825'],
	[`${MINIFIER_NAME}/src/tokenchain.js`, 'sha256:4dbf09fba2035b0005194ccf845be72a11faab14c96e3320a5bc10f84d5755da'],
	[`${MINIFIER_NAME}/src/utils.js`, 'sha256:c288262014e0befe1fc4cfe024333310d1d91e7315f37149d2f2a15e19eb5518'],
	[`${ENTITIES_NAME}/he.js`, 'sha256:76c554d5bbfd032fe620595076a50abea5124b9cbd4e9ffe6ac94a4f855aeceb'],
]);
// The only option set nobody chose: the one the plugin itself builds for a
// production build that leaves its minification alone.
const DEFAULT_MINIFY_OPTIONS = {
	collapseWhitespace: true,
	keepClosingSlash: true,
	removeComments: true,
	removeRedundantAttributes: true,
	removeScriptTypeAttributes: true,
	removeStyleLinkTypeAttributes: true,
	useShortDoctype: true,
};
// What the plugin makes of a configuration that names nothing but its template.
const DESCRIBED_OPTIONS = {
	templateContent: false,
	filename: 'index.html',
	publicPath: 'auto',
	hash: false,
	inject: 'head',
	scriptLoading: 'defer',
	compile: true,
	favicon: false,
	minify: 'auto',
	cache: true,
	showErrors: true,
	chunks: 'all',
	excludeChunks: [],
	chunksSortMode: 'auto',
	meta: {},
	base: false,
	title: 'Webpack App',
	xhtml: false,
};

// One observer per html-webpack-plugin of this process: several compilers and
// collectors share the one wrapped template compilation and its records.
const observers = new WeakMap();

function installHtmlEvidence(compiler, verifyResource) {
	if (typeof verifyResource !== 'function') throw new TypeError(`${NAME}: verifyResource must be a function`);
	const prepared = prepare(compiler);
	const states = new WeakMap();
	const children = [];
	if (prepared.observer) tap(compiler, prepared, states, children);
	return async function evidenceFor(compilation, assetName) {
		if (prepared.none) return { status: 'none' };
		if (prepared.problem) return noData(prepared.problem);
		const state = states.get(compilation);
		if (!state) return noData('the html of this compilation was not observed');
		if (!state.analysis) state.analysis = analyse({ compiler, compilation, state, children, prepared, verifyResource });
		try {
			return (await state.analysis).get(assetName) || { status: 'none' };
		} catch (error) {
			return noData(`the html of this compilation could not be described: ${error.message}`);
		}
	};
}

function prepare(compiler) {
	const instances = (compiler.options.plugins || []).filter(isHtmlPlugin);
	if (instances.length === 0) return { none: true };
	const registry = globalThis[REGISTRY];
	if (!registry || typeof registry.findByExport !== 'function' || typeof registry.getByFile !== 'function' || typeof registry.snapshot !== 'function') {
		return { problem: 'the commonjs load registry is not installed in this process' };
	}
	const api = compiler.webpack;
	if (!api || typeof api.version !== 'string') return { problem: 'the compiler does not expose its webpack' };
	if (api.version !== SUPPORTED_WEBPACK) return { problem: `the html of webpack ${api.version} is not described, only ${SUPPORTED_WEBPACK}` };
	// Two instances write two files from two templates through one shared child
	// compiler; only the single-template configuration is described.
	if (instances.length > 1) return { problem: `${instances.length} ${PLUGIN_NAME} instances are configured in this compiler` };
	const entry = registry.findByExport(instances[0].constructor);
	if (!entry || !entry.usable || path.basename(entry.file) !== ENTRY_FILE) return { problem: `${PLUGIN_NAME} was not observed being loaded by this process` };
	const observer = observe(registry, entry);
	if (!observer) return { problem: `the template compilation of ${PLUGIN_NAME} could not be observed` };
	return { observer, plugin: instances[0] };
}

// Recognized before anything of this process is trusted: whether this object is
// the pinned plugin is decided by its recorded source, not by this shape.
function isHtmlPlugin(plugin) {
	if (plugin === null || typeof plugin !== 'object') return false;
	const constructor = plugin.constructor;
	return typeof constructor === 'function' && constructor.version === 5 && typeof constructor.getHooks === 'function' && typeof plugin.userOptions === 'object';
}

function observe(registry, entry) {
	const existing = observers.get(entry.exports);
	if (existing) return existing;
	const root = path.dirname(entry.file);
	const groups = packageGroups(registry, root);
	if (!groups) return null;
	const observer = {
		registry,
		groups,
		modules: groups.flatMap((group) => group.modules),
		plugin: entry,
		loaderFile: path.join(root, ...LOADER_FILE.split('/')),
		loaderCalls: [],
		evaluations: [],
		executions: [],
		postProcesses: [],
		minifications: [],
		allowed: new Map(),
	};
	if (!wrapLoader(observer) || !wrapPlugin(observer) || !wrapMinifier(observer) || !resolveHookClass(observer, root)) return null;
	observers.set(entry.exports, observer);
	return observer;
}

// The hook class the plugin builds its public hooks with: a hook that is not a
// plain waterfall of this tapable, or one carrying an interceptor, can hand the
// html to code no tap list names. The class is a factory whose instances carry
// it as their own constructor, so identity is what there is to compare.
function resolveHookClass(observer, root) {
	try {
		observer.waterfall = require(require.resolve('tapable', { paths: [root] })).AsyncSeriesWaterfallHook;
	} catch {
		return false;
	}
	return typeof observer.waterfall === 'function';
}

// The pinned files of the four distributions that make the html, resolved the
// way the plugin itself resolves them and loaded here when the plugin has not
// loaded them itself yet.
function packageGroups(registry, root) {
	let minifierRoot;
	let lodashFile;
	let entitiesFile;
	try {
		minifierRoot = path.dirname(require.resolve(`${MINIFIER_NAME}/package.json`, { paths: [root] }));
		lodashFile = require.resolve(LODASH_NAME, { paths: [root] });
		require(path.join(minifierRoot, ...MINIFIER_FILES[0].split('/')));
		require(path.join(root, ...LOADER_FILE.split('/')));
		entitiesFile = require.resolve(ENTITIES_NAME, { paths: [minifierRoot] });
	} catch {
		return null;
	}
	const groups = [
		{ name: PLUGIN_NAME, version: SUPPORTED_PLUGIN, root, files: PLUGIN_FILES, text: (file) => PLUGIN_TEXT_FILES.has(file) },
		{ name: LODASH_NAME, version: SUPPORTED_LODASH, root: path.dirname(lodashFile), files: [path.basename(lodashFile)], text: () => true },
		{ name: MINIFIER_NAME, version: SUPPORTED_MINIFIER, root: minifierRoot, files: MINIFIER_FILES, text: () => true, minifying: true },
		{ name: ENTITIES_NAME, version: SUPPORTED_ENTITIES, root: path.dirname(entitiesFile), files: [path.basename(entitiesFile)], text: () => false, minifying: true },
	];
	for (const group of groups) {
		group.modules = [];
		for (const file of group.files) {
			const absolute = path.join(group.root, ...file.split('/'));
			const loaded = registry.getByFile(absolute);
			if (!loaded || !loaded.usable || !('exports' in loaded)) return null;
			group.modules.push({ group, name: file, key: `${group.name}/${file}`, file: absolute, entry: loaded });
		}
	}
	return groups;
}

// What the loader was handed and what it made of it. The loader module exports
// the function itself and recognizes its own calls through that export, so the
// wrapper takes the place of the whole module export and the drift check holds
// it to the one this adapter installed.
function wrapLoader(observer) {
	const loaded = require.cache[observer.loaderFile];
	const entry = observer.registry.getByFile(observer.loaderFile);
	if (!loaded || !entry || typeof loaded.exports !== 'function' || loaded.exports !== entry.exports) return false;
	const original = loaded.exports;
	observer.loaderOriginal = original;
	observer.loaderWrapper = function (source) {
		const before = drift(observer);
		const call = {
			compilation: this._compilation,
			module: this._module,
			resourcePath: this.resourcePath,
			resourceQuery: this.resourceQuery,
			resourceFragment: this.resourceFragment,
			loaderIndex: this.loaderIndex,
			loaders: Array.isArray(this.loaders) ? this.loaders.map((loader) => loader && loader.path) : null,
			query: this.query,
			source,
		};
		call.output = original.call(this, source);
		call.problem = before || drift(observer) || loaderProblem(observer, call);
		observer.loaderCalls.push(call);
		return call.output;
	};
	loaded.exports = observer.loaderWrapper;
	return true;
}

// Only the plugin's own default loader chain is described: another loader in
// front of it, options of its own or a request that is not a plain file change
// what the template becomes.
function loaderProblem(observer, call) {
	if (typeof call.source !== 'string') return 'the template was not read as text';
	if (typeof call.output !== 'string') return 'the template was not compiled into text';
	if (!Array.isArray(call.loaders) || call.loaders.length !== 1 || call.loaders[0] !== observer.loaderFile || call.loaderIndex !== 0) {
		return 'the template was built by a loader chain this adapter does not describe';
	}
	if (call.resourceQuery || call.resourceFragment) return 'the template was built from a request this adapter does not describe';
	if (!plain(call.query)) return 'the template loader was given options of its own';
	return null;
}

function wrapPlugin(observer) {
	const prototype = prototypeOf(observer.plugin.exports);
	const wrappers = new Map();
	for (const method of ['evaluateCompilationResult', 'executeTemplate', 'postProcessHtml']) {
		const descriptor = prototype && Object.getOwnPropertyDescriptor(prototype, method);
		if (!descriptor || typeof descriptor.value !== 'function' || !descriptor.writable || !descriptor.configurable) return false;
		// What is about to be wrapped has to be what the file exported when it was
		// loaded: a replacement installed before this point is not that source.
		const loaded = observer.plugin.prototypeMembers && observer.plugin.prototypeMembers.get(method);
		if (!loaded || loaded.kind !== 'data' || !Object.is(loaded.value, descriptor.value)) return false;
		const original = descriptor.value;
		const wrapper = function (...args) {
			const record = { plugin: this, before: drift(observer) };
			return settle(observer, original.apply(this, args), record, method, args);
		};
		wrappers.set(method, wrapper);
		Object.defineProperty(prototype, method, { ...descriptor, value: wrapper });
	}
	observer.allowed.set(`${PLUGIN_NAME}/${ENTRY_FILE}`, { prototype: wrappers });
	return true;
}

// The three calls that hand the html on, each recorded with what it returned.
function settle(observer, running, record, method, args) {
	return Promise.resolve(running).then((value) => {
		record.problem = record.before || drift(observer);
		if (method === 'evaluateCompilationResult') {
			Object.assign(record, { source: args[0], publicPath: args[1], templateFilename: args[2], result: value });
			observer.evaluations.push(record);
		} else if (method === 'executeTemplate') {
			Object.assign(record, { templateFunction: args[0], compilation: args[3], html: value });
			observer.executions.push(record);
		} else {
			Object.assign(record, { compiler: args[0], input: args[1], output: value });
			observer.postProcesses.push(record);
		}
		return value;
	});
}

function wrapMinifier(observer) {
	const entry = observer.groups.find((group) => group.name === MINIFIER_NAME).modules[0].entry;
	const descriptor = Object.getOwnPropertyDescriptor(entry.exports, 'minify');
	if (!descriptor || typeof descriptor.value !== 'function' || !descriptor.writable || !descriptor.configurable) return false;
	const loaded = entry.members && entry.members.get('minify');
	if (!loaded || loaded.kind !== 'data' || !Object.is(loaded.value, descriptor.value)) return false;
	const original = descriptor.value;
	const wrapper = function (value, options) {
		const record = { input: value, options, before: drift(observer) };
		return Promise.resolve(original.call(this, value, options)).then((output) => {
			record.output = output;
			record.problem = record.before || drift(observer);
			observer.minifications.push(record);
			return output;
		});
	};
	observer.allowed.set(`${MINIFIER_NAME}/${MINIFIER_FILES[0]}`, { exports: new Map([['minify', wrapper]]) });
	Object.defineProperty(entry.exports, 'minify', { ...descriptor, value: wrapper });
	return true;
}

function tap(compiler, prepared, states, children) {
	const observer = prepared.observer;
	compiler.hooks.compilation.tap(NAME, (compilation) => {
		// A child compiler of this compiler inherits this tap; the template is
		// compiled in the one the plugin creates for it.
		const parent = compilation.compiler.parentCompilation;
		if (parent) {
			if (compilation.compiler.name === CHILD_COMPILER) tapChild(compilation, parent, children);
			return;
		}
		const api = compiler.webpack;
		const stage = api && api.Compilation && api.Compilation.PROCESS_ASSETS_STAGE_OPTIMIZE_INLINE;
		if (typeof stage !== 'number') return;
		const state = {};
		states.set(compilation, state);
		// Around the one stage the plugin generates its html in: the taps on its
		// hooks have to be counted while they could still have been used.
		compilation.hooks.processAssets.tap({ name: NAME, stage: stage - 1 }, () => {
			state.tapsBefore = hookTaps(observer, compilation);
		});
		compilation.hooks.processAssets.tap({ name: NAME, stage: stage + 1 }, () => {
			state.tapsAfter = hookTaps(observer, compilation);
			state.assets = snapshot(compilation);
		});
	});
}

// Everything the child compilation of the template held, taken before the
// plugin extracts its asset and deletes it again, and the taps that could have
// reached that asset: webpack copies the taps of this compiler into the child
// compiler (Compiler.js:1216-1239), so a plugin of the main build renders and
// processes the template bundle too.
function tapChild(compilation, parent, children) {
	const api = compilation.compiler.webpack;
	const stage = api && api.Compilation && api.Compilation.PROCESS_ASSETS_STAGE_ADDITIONS;
	if (typeof stage !== 'number') return;
	const taps = childTaps(api, compilation, stage);
	compilation.hooks.processAssets.tap({ name: NAME, stage: stage - 1 }, () => {
		const RuntimeModule = api.RuntimeModule;
		children.push({
			parent,
			compilation,
			taps,
			// Again once the bundle is rendered and the earlier stages have run.
			tapsAfter: childTaps(api, compilation, stage),
			assets: snapshot(compilation),
			chunks: compilation.chunks.size,
			errors: compilation.errors.length,
			modules: [...compilation.modules].map((module) => ({
				module,
				resource: module.resource,
				// The generated runtime of the child bundle is webpack's own: it is
				// executed to produce the template function, not written into html.
				runtime: typeof RuntimeModule === 'function' ? module instanceof RuntimeModule : null,
				loaders: Array.isArray(module.loaders) ? module.loaders.map((loader) => loader && loader.loader) : null,
				source: sourceOf(module),
			})),
		});
	});
}

// Who could have written the template bundle: a tap on a hook that shapes the
// render, or one processing the assets of the child compilation no later than
// the stage the plugin takes its asset out at. Anything after that stage cannot
// reach the source object the plugin already extracted.
function childTaps(api, compilation, additions) {
	const plugin = api && api.javascript && api.javascript.JavascriptModulesPlugin;
	if (typeof plugin !== 'function' || typeof plugin.getCompilationHooks !== 'function') return null;
	let hooks;
	try {
		hooks = plugin.getCompilationHooks(compilation);
	} catch {
		return null;
	}
	const foreign = [];
	for (const name of [...SHAPING, MODULE_CONTENT]) {
		const hook = hooks && hooks[name];
		if (!hook || !Array.isArray(hook.taps)) return null;
		const allowed = CHILD_TAPS.get(name) || [];
		for (const tap of hook.taps) {
			const tapped = String(tap && tap.name);
			if (!allowed.includes(tapped)) foreign.push(`${tapped} tapped ${name}`);
		}
	}
	const assets = compilation.hooks.processAssets;
	if (!assets || !Array.isArray(assets.taps)) return null;
	for (const tap of assets.taps) {
		const tapped = String(tap && tap.name);
		if (tapped === NAME || tapped === PLUGIN_TAP) continue;
		const tappedStage = tap && typeof tap.stage === 'number' ? tap.stage : 0;
		if (tappedStage <= additions) foreign.push(`${tapped} tapped processAssets at ${tappedStage}`);
	}
	return foreign;
}

function hookTaps(observer, compilation) {
	const plugin = observer.plugin.exports;
	if (typeof plugin !== 'function' || typeof plugin.getHooks !== 'function') return null;
	let hooks;
	try {
		hooks = plugin.getHooks(compilation);
	} catch {
		return null;
	}
	const counted = new Map();
	for (const name of HOOKS) {
		const hook = hooks && hooks[name];
		const plain =
			hook !== null && typeof hook === 'object' && hook.constructor === observer.waterfall && Array.isArray(hook.taps) && Array.isArray(hook.interceptors) && hook.interceptors.length === 0;
		counted.set(name, plain ? hook.taps.length : null);
	}
	return counted;
}

async function analyse(context) {
	const byName = new Map();
	const plugin = context.prepared.plugin;
	const described = await describe(context, plugin);
	const name = typeof plugin.options.filename === 'string' ? plugin.options.filename : null;
	if (described.name) byName.set(described.name, described.result);
	else if (name !== null) byName.set(name, described.result);
	// Nothing names the file this plugin would have written: the refusal belongs
	// to every html of the compilation rather than to none of them.
	else
		for (const asset of (context.state.assets || new Map()).keys()) {
			if (asset.endsWith('.html')) byName.set(asset, described.result);
		}
	return byName;
}

async function describe(context, plugin) {
	const observer = context.prepared.observer;
	const state = context.state;
	if (!state.assets || !state.tapsBefore || !state.tapsAfter) return { result: noData('the html of this compilation was not observed') };
	for (const name of HOOKS) {
		const before = state.tapsBefore.get(name);
		const after = state.tapsAfter.get(name);
		if (before === null || after === null) return { result: noData(`the ${name} hook of ${PLUGIN_NAME} is not the plain waterfall hook this adapter describes`) };
		if (before !== 0 || after !== 0) return { result: noData(`another plugin taps the ${name} hook of ${PLUGIN_NAME}`) };
	}
	const drifted = drift(observer);
	if (drifted) return { result: noData(drifted) };
	const instance = instanceProblem(observer, plugin);
	if (instance) return { result: noData(`${PLUGIN_NAME} ${instance}`) };
	const options = optionsProblem(plugin);
	if (options) return { result: noData(`${PLUGIN_NAME} ${options}`) };

	const chain = chained(context, plugin);
	if (chain.failure) return { result: chain };

	const emitted = state.assets.get(plugin.options.filename);
	if (!emitted) return { result: noData(`${plugin.options.filename} is not an asset of this compilation`) };
	const html = Buffer.from(chain.html, 'utf8');
	if (!emitted.equals(html)) {
		return { name: plugin.options.filename, result: failed('hash-mismatch', `${plugin.options.filename} is not the html ${PLUGIN_NAME} produced`) };
	}

	const units = await describeUnits(context, chain);
	if (units.failure) return { name: plugin.options.filename, result: units };
	return { name: plugin.options.filename, result: { units: units.units, requiredBytes: emitted } };
}

// The steps of one html, each bound to the next by the value it handed on.
function chained(context, plugin) {
	const observer = context.prepared.observer;
	const executions = observer.executions.filter((record) => record.compilation === context.compilation && record.plugin === plugin);
	if (executions.length !== 1) return noData(`the template of this compilation was executed ${executions.length} times`);
	const [execution] = executions;
	if (execution.problem) return noData(`the template was executed while ${execution.problem}`);
	if (typeof execution.html !== 'string') return noData('the executed template did not return text');

	const evaluations = observer.evaluations.filter((record) => record.plugin === plugin && record.result === execution.templateFunction);
	if (evaluations.length !== 1) return noData(`the executed template was evaluated ${evaluations.length} times`);
	const [evaluation] = evaluations;
	if (evaluation.problem) return noData(`the template was evaluated while ${evaluation.problem}`);
	if (evaluation.templateFilename !== plugin.options.template) return noData('the evaluated template is not the configured one');

	const compiled = compiledTemplate(context, plugin, evaluation);
	if (compiled.failure) return compiled;

	const postProcesses = observer.postProcesses.filter((record) => record.plugin === plugin && record.input === execution.html && record.compiler === context.compiler);
	if (postProcesses.length !== 1) return noData(`the executed template was post processed ${postProcesses.length} times`);
	const [post] = postProcesses;
	if (post.problem) return noData(`the html was post processed while ${post.problem}`);
	if (typeof post.output !== 'string') return noData('the post processed html is not text');

	// What the pinned post processing does with a production build and its own
	// default options: the minification it performed is observed, not repeated.
	const minifying = context.compiler.options.mode === 'production' || context.compiler.options.mode === undefined;
	if (!minifying) return { html: post.output, minified: false, loader: compiled.loader };
	const minifications = observer.minifications.filter((record) => record.output === post.output);
	if (minifications.length !== 1) return noData(`the html of this compilation was minified ${minifications.length} times`);
	const [minified] = minifications;
	if (minified.problem) return noData(`the html was minified while ${minified.problem}`);
	if (typeof minified.input !== 'string') return noData('the minified html was not text');
	if (!sameData(DEFAULT_MINIFY_OPTIONS, minified.options)) return noData('the html was minified with options of its own');
	return { html: post.output, minified: true, loader: compiled.loader };
}

// What the evaluated code was made of: one child compilation of this build,
// holding nothing but the plugin's own public path entry and the template
// module the pinned loader compiled.
function compiledTemplate(context, plugin, evaluation) {
	const observer = context.prepared.observer;
	const children = context.children.filter((child) => child.parent === context.compilation);
	if (children.length !== 1) return noData(`this compilation compiled ${children.length} html templates`);
	const [child] = children;
	if (child.errors !== 0) return noData('the template compilation reported errors');
	for (const taps of [child.taps, child.tapsAfter]) {
		if (taps === null) return noData('the taps that could reach the template bundle could not be observed');
		if (taps.length > 0) return noData(`the template bundle was open to foreign code: ${[...new Set(taps)].sort().join(', ')}`);
	}
	if (child.chunks !== 1 || child.assets.size !== 1) return noData('the template compilation produced more than one chunk');
	const [compiled] = [...child.assets.values()];
	if (compiled.toString('utf8') !== evaluation.source) return noData('the evaluated code is not what the template compilation produced');
	if (child.modules.some((module) => module.runtime === null)) return noData('the modules of the template compilation could not be told apart');
	const modules = child.modules.filter((module) => !module.runtime);
	if (modules.length !== 2) return noData(`the template was compiled with ${modules.length} modules`);
	const prefix = `${observer.loaderFile}!`;
	if (!plugin.options.template.startsWith(prefix)) return noData('the template is not the one the loader of this plugin compiles');
	const resource = plugin.options.template.slice(prefix.length);
	const template = modules.find((module) => module.resource === resource);
	const entry = modules.find((module) => module !== template);
	if (!template) return noData('the template compilation does not hold the configured template');
	if (entry.resource !== CHILD_ENTRY || !entry.source || entry.source.toString('utf8') !== CHILD_ENTRY_SOURCE) {
		return noData('the template compilation holds a public path entry of its own');
	}
	if (!Array.isArray(template.loaders) || template.loaders.length !== 1 || template.loaders[0] !== observer.loaderFile) {
		return noData('the template was not compiled by the loader of this plugin alone');
	}
	const calls = observer.loaderCalls.filter((call) => call.module === template.module && call.compilation === child.compilation);
	if (calls.length !== 1) return noData(`the template was compiled ${calls.length} times`);
	const [loader] = calls;
	if (loader.problem) return noData(`the template was compiled while ${loader.problem}`);
	if (loader.resourcePath !== resource) return noData('the loader read a file other than the configured template');
	if (!template.source || template.source.toString('utf8') !== loader.output) return noData('the compiled module is not what the loader returned');
	return { loader };
}

// The object in the configuration has to be an instance of the class this
// adapter recorded and carry nothing of its own: an own property shadowing one
// of the methods that were not wrapped - the tag generators, the template
// parameters, the whole generation - writes html no observation covers.
function instanceProblem(observer, plugin) {
	if (Object.getPrototypeOf(plugin) !== prototypeOf(observer.plugin.exports)) return 'is not an instance of the recorded plugin class';
	for (const key of Reflect.ownKeys(plugin)) {
		if (!INSTANCE_KEYS.includes(key)) return `carries ${String(key)} of its own`;
		const descriptor = Object.getOwnPropertyDescriptor(plugin, key);
		if (!('value' in descriptor) || typeof descriptor.value === 'function') return `carries a ${String(key)} of its own`;
	}
	return null;
}

// Only the plugin's own defaults are described: every option of it decides what
// the html holds, and none of that would be observed here.
function optionsProblem(plugin) {
	const user = plugin.userOptions;
	if (user === null || typeof user !== 'object' || typeof user.template !== 'string' || user.template === '') return 'was configured without a template of its own';
	const options = plugin.options;
	if (options === null || typeof options !== 'object') return 'carries no options of its own';
	const described = [...Object.keys(DESCRIBED_OPTIONS), 'template', 'templateParameters'];
	if (Reflect.ownKeys(options).length !== described.length || !described.every((key) => Object.prototype.hasOwnProperty.call(options, key))) {
		return 'was configured with options this adapter does not describe';
	}
	for (const [key, value] of Object.entries(DESCRIBED_OPTIONS)) {
		if (!sameData(value, options[key])) return `was configured with a ${key} of its own`;
	}
	// The default generator is the one the plugin builds for an instance that
	// chose no parameters; a function of the configuration is another one.
	const defaults = new plugin.constructor({});
	if (options.templateParameters !== defaults.options.templateParameters) return 'was configured with template parameters of its own';
	if (typeof options.template !== 'string') return 'was configured with a template this adapter does not describe';
	return null;
}

async function describeUnits(context, chain) {
	const observer = context.prepared.observer;
	const units = [];
	const template = await templateUnit(context, chain.loader);
	if (template.failure) return template;
	units.push(template.unit);
	for (const group of observer.groups) {
		if (group.minifying && !chain.minified) continue;
		const described = await groupUnits(context, group);
		if (described.failure) return described;
		units.push(...described.units);
	}
	return { units };
}

// The file the loader read, bound to its component by the same verification as
// any other source and to the bytes the loader was handed.
async function templateUnit(context, loader) {
	const resolution = await verified(context, loader.resourcePath);
	if (resolution.failure) return resolution;
	const unit = resolution.unit;
	if (!Buffer.isBuffer(unit.bytes)) return noData(`${unit.path} was verified without its bytes`);
	if (digest(unit.bytes) !== unit.sha256) return failed('invalid', `${unit.path} was verified as bytes other than the ones it carries`);
	// loader-runner hands a loader the file text with a byte order mark stripped:
	// those bytes would be described as read, and they were not.
	if (unit.bytes.length >= BOM.length && unit.bytes.subarray(0, BOM.length).equals(BOM)) {
		return noData(`${unit.path} starts with a byte order mark the loader does not pass on`);
	}
	if (unit.bytes.toString('utf8') !== loader.source) return failed('hash-mismatch', `${PLUGIN_NAME} did not read the verified bytes of ${unit.path}`);
	return { unit: { path: unit.path, sha256: unit.sha256, component: unit.component } };
}

// One distribution of the instrument: every file of it has to be the pinned
// source, has to still hold the bytes this process loaded from it, and has to
// belong to one component of the expected name and version. The files that
// write html text are claimed as sources of it; the others are the instrument
// that decided what was written and contribute nothing.
async function groupUnits(context, group) {
	const units = [];
	let component;
	for (const module of group.modules) {
		const resolution = await verified(context, module.file);
		if (resolution.failure) return resolution;
		const unit = resolution.unit;
		if (unit.sha256 !== module.entry.sha256) return failed('hash-mismatch', `${module.file} differs from the bytes this process loaded from it`);
		if (unit.sha256 !== FINGERPRINTS.get(module.key)) return failed('unsupported', `${module.key} is not the source of the pinned ${group.name} ${group.version}`);
		const bound = unit.component;
		if (bound === null || typeof bound !== 'object') return failed('invalid', `${module.key} is bound to no component`);
		if (component === undefined) component = bound;
		else if (!sameJSON(component, bound)) return failed('invalid', `the ${group.name} sources bind to conflicting components ${component.id} and ${bound.id}`);
		if (group.text(module.name)) units.push({ path: unit.path, sha256: unit.sha256, component: bound });
	}
	if (component === undefined || component.name !== group.name || component.version !== group.version) {
		return failed('invalid', `component ${component === undefined ? 'none' : component.id} is not ${group.name} ${group.version}`);
	}
	return { units };
}

async function verified(context, file) {
	let resolution;
	try {
		resolution = await context.verifyResource(file);
	} catch (error) {
		return noData(`${file} could not be verified: ${error.message}`);
	}
	if (!resolution || (!resolution.unit && !resolution.failure)) return noData(`${file} was not verified`);
	if (resolution.failure) return { failure: resolution.failure };
	const unit = resolution.unit;
	if (!unit || typeof unit.path !== 'string' || !CANONICAL_SHA256.test(String(unit.sha256)) || unit.component === null || typeof unit.component !== 'object') {
		return noData(`${file} was not verified as a described unit`);
	}
	return { unit };
}

function drift(observer) {
	if (require.cache[observer.loaderFile] === undefined || require.cache[observer.loaderFile].exports !== observer.loaderWrapper) {
		return `${LOADER_FILE} is no longer the loader this adapter wrapped`;
	}
	if (observer.loaderOriginal !== observer.registry.getByFile(observer.loaderFile).exports) {
		return `${LOADER_FILE} did not export what this adapter recorded`;
	}
	for (const module of observer.modules) {
		const allowed = observer.allowed.get(module.key) || {};
		const entry = module.entry;
		const changed =
			compareMembers(entry.members, observer.registry.snapshot(entry.exports), 'exports', allowed.exports) ||
			compareMembers(entry.prototypeMembers, observer.registry.snapshot(prototypeOf(entry.exports)), 'prototype', allowed.prototype);
		if (changed) return `${module.key} no longer exports what it exported when it was loaded: ${changed}`;
	}
	return null;
}

function compareMembers(snapshot, now, where, allowed) {
	if (snapshot === null || now === null) return snapshot === now ? null : `${where} is no longer an object`;
	for (const key of snapshot.keys()) {
		if (!now.has(key)) return `${where}.${String(key)} is gone`;
	}
	for (const [key, is] of now) {
		const was = snapshot.get(key);
		if (!was) return `${where}.${String(key)} was added`;
		if (allowed && allowed.has(key) && is.kind === 'data' && Object.is(is.value, allowed.get(key))) continue;
		if (was.kind !== is.kind) return `${where}.${String(key)} was replaced`;
		if (was.kind === 'data' ? !Object.is(was.value, is.value) : !Object.is(was.get, is.get) || !Object.is(was.set, is.set)) {
			return `${where}.${String(key)} was replaced`;
		}
	}
	return null;
}

function snapshot(compilation) {
	const assets = new Map();
	for (const { name, source } of compilation.getAssets()) assets.set(name, bytesOf(source));
	return assets;
}

function sourceOf(module) {
	try {
		const source = module.originalSource && module.originalSource();
		return source ? bytesOf(source) : null;
	} catch {
		return null;
	}
}

function bytesOf(source) {
	if (!source || (typeof source.buffer !== 'function' && typeof source.source !== 'function')) return null;
	try {
		return Buffer.from(typeof source.buffer === 'function' ? source.buffer() : source.source());
	} catch {
		return null;
	}
}

function prototypeOf(value) {
	const descriptor = typeof value === 'function' ? Object.getOwnPropertyDescriptor(value, 'prototype') : undefined;
	return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

// Only the options nobody chose: the loader is handed none of its own.
function plain(value) {
	if (value === undefined || value === null || value === '') return true;
	if (typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
	return Reflect.ownKeys(value).length === 0;
}

// Plain data compared by its own enumerable keys and values: nothing that
// serializes like an expected value while holding another one passes.
function sameData(left, right) {
	if (Array.isArray(left) || Array.isArray(right)) {
		if (!Array.isArray(left) || !Array.isArray(right) || Object.getPrototypeOf(right) !== Array.prototype || left.length !== right.length) return false;
		return left.every((value, index) => sameData(value, right[index]));
	}
	if (isPlainObject(left) || isPlainObject(right)) {
		if (!isPlainObject(left) || !isPlainObject(right)) return false;
		const keys = Object.keys(left);
		if (Reflect.ownKeys(right).length !== keys.length) return false;
		return keys.every((key) => {
			const descriptor = Object.getOwnPropertyDescriptor(right, key);
			return descriptor !== undefined && 'value' in descriptor && descriptor.enumerable && sameData(left[key], descriptor.value);
		});
	}
	return Object.is(left, right);
}

function isPlainObject(value) {
	return typeof value === 'object' && value !== null && Object.getPrototypeOf(value) === Object.prototype;
}

function sameJSON(left, right) {
	return JSON.stringify(left) === JSON.stringify(right);
}

function digest(bytes) {
	return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function failed(status, reason) {
	return { failure: { status, reason } };
}

function noData(reason) {
	return failed('no-data', reason);
}

module.exports = { installHtmlEvidence };
