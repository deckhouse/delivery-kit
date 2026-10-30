'use strict';

// Test-only fixture for code-split-evidence.test.cjs.
//
// The parent packs the installed webpack once and hands the child the paths it
// needs; this file is also the child entry point, run as
// `node --require runtime-preload.cjs code-split-fixture.cjs` so that the load
// registry is in place before webpack is required here.
//
// The build is the shape Argo has: a web entry that imports a chunk lazily,
// both named by their content hash.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { chunkEvidence } = require('./chunk-evidence.cjs');
const { runtimeEvidence } = require('./runtime-evidence.cjs');

const MARKER = 'DK-CODE-SPLIT-REPORT ';
const SOURCES = {
	'index.js': "import('./lazy.js').then(({ lazy }) => console.log(lazy()));\n",
	'lazy.js': 'export function lazy() { return "lazy"; }\n',
	// What a library written in the amd style asks for, which webpack answers
	// with two runtime modules of its own.
	// A commonjs module imported from an esm one, which is what makes webpack
	// carry its compatibility helper and its module decorator into the runtime.
	'legacy.js': "module.paths;\nmodule.exports = function legacy() { return 'legacy'; };\n",
	'interop.js': "import legacy from './legacy.js';\nimport('./lazy.js');\nconsole.log(legacy());\n",
	// A module in the esm style that asks for its own module object, and a lazy
	// import of a commonjs module: the first makes webpack carry the decorator
	// that gives an esm module one, the second the helper that turns what the
	// import answers with into a namespace.
	'decorated.js': 'export const own = module;\n',
	'esm-interop.js': "import { own } from './decorated.js';\nimport('./legacy.js').then((m) => console.log(m.default, own));\n",
	'amd.js':
		"import('./lazy.js');\nconsole.log(typeof define === 'function' && define.amd, typeof require === 'function' && require.amd);\n" +
		// Taken rather than called, which is what makes webpack carry its own
		// definition of it into the runtime.
		'var indirect = define;\nconsole.log(typeof indirect);\n',
};

function entryFile(scenario) {
	if (scenario.startsWith('amd') || scenario === 'forged-amd-options') return 'amd.js';
	if (scenario === 'interop' || scenario === 'forged-decorator' || scenario === 'foreign-decorator') return 'interop.js';
	if (scenario === 'esm-interop' || scenario === 'forged-harmony') return 'esm-interop.js';
	return null;
}

function writeSources(dir) {
	fs.mkdirSync(dir, { recursive: true });
	for (const [name, content] of Object.entries(SOURCES)) fs.writeFileSync(path.join(dir, name), content);
	return path.join(dir, 'index.js');
}

// The same binding the collector performs, for the one root these adapters
// read: the materialized file is bound to the component only when its bytes are
// the bytes of the original counterpart.
function verifier(setup) {
	return async (resource) => {
		const actual = path.resolve(resource);
		const prefix = setup.root.endsWith(path.sep) ? setup.root : setup.root + path.sep;
		if (!actual.startsWith(prefix)) return { failure: { status: 'no-data', reason: `outside the webpack root: ${actual}` } };
		const bytes = read(actual);
		if (bytes.failure) return bytes;
		const original = read(path.join(setup.originalRoot, path.relative(setup.root, actual)));
		if (original.failure) return original;
		const sha256 = digest(bytes.bytes);
		if (sha256 !== digest(original.bytes)) {
			return { failure: { status: 'hash-mismatch', reason: `materialized source differs from its original: ${actual}` } };
		}
		return { unit: { path: actual, sha256, bytes: bytes.bytes, component: setup.component } };
	};
}

function read(file) {
	try {
		return { bytes: fs.readFileSync(file) };
	} catch (error) {
		return { failure: { status: 'no-data', reason: `missing file ${file}: ${error.code || error.message}` } };
	}
}

function digest(bytes) {
	return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

// Each scenario is what some plugin of this compilation could do to the text
// these adapters describe.
function scenarioPlugin(setup, webpack) {
	const scenario = setup.scenario;
	return {
		apply(compiler) {
			compiler.hooks.compilation.tap('fixture', (compilation) => {
				const hooks = webpack.javascript.JavascriptModulesPlugin.getCompilationHooks(compilation);
				if (scenario === 'tapped-render') hooks.render.tap('fixture', (source) => source);
				if (scenario === 'tapped-chunk') hooks.renderChunk.tap('fixture', (source) => source);
				if (scenario === 'untapped') {
					// The chunk format taps this hook while it is applied to the
					// compilation; a plugin can take its wrapper away again.
					hooks.renderChunk.taps.length = 0;
					hooks.renderChunk._resetCompilation();
				}
				if (scenario === 'foreign-decorator') {
					// A class of a plugin's own, under the name of one webpack
					// declares, writing the very text webpack's own would write.
					compilation.hooks.runtimeModule.tap('fixture', (module) => {
						if (Object.getPrototypeOf(module).constructor.name !== 'NodeModuleDecoratorRuntimeModule') return;
						const text = module.generate();
						const NodeModuleDecoratorRuntimeModule = class extends Object.getPrototypeOf(Object.getPrototypeOf(module)).constructor {
							generate() {
								return text;
							}
						};
						Object.setPrototypeOf(module, NodeModuleDecoratorRuntimeModule.prototype);
					});
				}
				if (scenario === 'forged-decorator') {
					// The generator of a class nothing exports, replaced on the one
					// instance that was built with it.
					compilation.hooks.runtimeModule.tap('fixture', (module) => {
						if (Object.getPrototypeOf(module).constructor.name !== 'NodeModuleDecoratorRuntimeModule') return;
						const prototype = Object.getPrototypeOf(module);
						const original = prototype.generate;
						prototype.generate = function () {
							return `${original.call(this)}\n/* forged */`;
						};
					});
				}
				if (scenario === 'forged-amd-options') {
					// Options that are not plain data: what json writes of them is not
					// what stands here.
					compilation.hooks.runtimeModule.tap('fixture', (module) => {
						if (Object.getPrototypeOf(module).constructor.name !== 'AMDOptionsRuntimeModule') return;
						module.options = {
							get jQuery() {
								return true;
							},
						};
					});
				}
				if (scenario === 'forged-template' || scenario === 'forged-global' || scenario === 'no-filename') {
					compilation.hooks.runtimeModule.tap('fixture', (module) => {
						if (typeof module.getFilenameForChunk !== 'function') return;
						// A template of the plugin's own making, where the output
						// options are the only ones this adapter describes - or none at
						// all, so that no filename is built where one always is.
						if (scenario === 'forged-template') module.getFilenameForChunk = () => 'forged-[id].js';
						if (scenario === 'no-filename') module.getFilenameForChunk = () => undefined;
					});
					// The name the chunk format and the chunk loading runtime carry
					// into their text unquoted.
					if (scenario === 'forged-global') compilation.runtimeTemplate.globalObject = 'self["x"]';
				}
				if (scenario === 'own-path-builder') {
					// A compilation that builds its filenames with a method of its own,
					// installed before anything generates.
					const inherited = compilation.getAssetPath;
					compilation.getAssetPath = function (filename, data) {
						return inherited.call(this, filename, data);
					};
				}
				if (scenario === 'shadowed-path-builder') {
					// Not an own method: one shadowing the loaded implementation from a
					// prototype slipped in between.
					const prototype = Object.getPrototypeOf(compilation);
					const shadow = Object.create(prototype, {
						getAssetPath: {
							value: function (filename, data) {
								return prototype.getAssetPath.call(this, filename, data);
							},
							writable: true,
							configurable: true,
						},
					});
					Object.setPrototypeOf(compilation, shadow);
				}
				if (scenario === 'swap-while-building') {
					compilation.hooks.runtimeModule.tap('fixture', (module) => {
						if (typeof module.getFilenameForChunk !== 'function') return;
						const template = compilation.outputOptions.chunkFilename;
						// The function the module was built with, taking the recording
						// away in the middle of the generator call.
						module.getFilenameForChunk = () => {
							compilation.getAssetPath = () => 'forged.js';
							return template;
						};
					});
				}
				if (scenario === 'tapped-asset-path') compilation.hooks.assetPath.tap('fixture', (filename) => filename);
				if (scenario === 'second-render') {
					// A plugin rendering the same chunk again, from a context of its
					// own making.
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: webpack.Compilation.PROCESS_ASSETS_STAGE_REPORT }, () => {
						const plugin = new webpack.javascript.JavascriptModulesPlugin();
						for (const chunk of compilation.chunks) {
							if (chunk.hasRuntime()) continue;
							plugin.renderChunk(
								{
									chunk,
									chunkGraph: compilation.chunkGraph,
									codeGenerationResults: compilation.codeGenerationResults,
									runtimeTemplate: compilation.runtimeTemplate,
									moduleGraph: compilation.moduleGraph,
									dependencyTemplates: compilation.dependencyTemplates,
									strictMode: false,
								},
								hooks,
							);
						}
					});
				}
				if (scenario === 'tapped-create-script') {
					const LoadScriptRuntimeModule = require(path.join(setup.root, 'lib', 'runtime', 'LoadScriptRuntimeModule.js'));
					LoadScriptRuntimeModule.getCompilationHooks(compilation).createScript.tap('fixture', (code) => code);
				}
				if (scenario === 'tapped-link-preload') {
					const JsonpChunkLoadingRuntimeModule = require(path.join(setup.root, 'lib', 'web', 'JsonpChunkLoadingRuntimeModule.js'));
					JsonpChunkLoadingRuntimeModule.getCompilationHooks(compilation).linkPreload.tap('fixture', (source) => source);
				}
			});
		},
	};
}

function configuration(setup, webpack) {
	const plugins = [scenarioPlugin(setup, webpack)];
	// The production collector itself, bound to the originals the parent
	// verified, so the proof it writes is what the assertions read.
	if (setup.proofPath) plugins.unshift(new (require('./collector.cjs'))({ proofPath: setup.proofPath, originals: setup.originals }));
	return {
		mode: 'production',
		// What AMDPlugin writes into the runtime of a chunk that asks for it.
		...(setup.scenario === 'amd-options' ? { amd: { jQuery: true, name: 'argo' } } : {}),
		context: setup.context,
		// The entry the test installed, except where a scenario needs one of the
		// other sources beside it.
		entry: entryFile(setup.scenario) ? path.join(path.dirname(setup.entry), entryFile(setup.scenario)) : setup.entry,
		output: {
			path: setup.output,
			filename: setup.scenario === 'nested-output' ? 'js/[name].[contenthash].js' : '[name].[contenthash].js',
			chunkFilename: '[name].[contenthash].chunk.js',
			// Argo configures none, so the runtime works its own out; the other
			// scenario is the explicit one.
			...(setup.scenario === 'explicit-path' ? { publicPath: '/' } : {}),
			clean: true,
		},
		target: 'web',
		externals: { 'some-ext': 'commonjs some-ext' },
		resolve: setup.modules ? { modules: [setup.modules] } : {},
		optimization: {
			minimize: setup.scenario === 'minified' || setup.collect === true,
			concatenateModules: true,
			usedExports: true,
			// Moves the runtime out of the entry chunk, which then starts its own
			// entry modules without carrying the runtime.
			...(setup.scenario === 'runtime-chunk' ? { runtimeChunk: 'single' } : {}),
		},
		cache: false,
		plugins,
	};
}

async function describe(compilation, verify) {
	const chunks = [];
	for (const chunk of compilation.chunks) {
		const files = [...chunk.files].sort();
		if (chunk.hasRuntime()) {
			const modules = [];
			for (const module of compilation.chunkGraph.getChunkRuntimeModulesIterable(chunk)) {
				const result = await runtimeEvidence(compilation, chunk, module, verify);
				const observed = globalThis[Symbol.for('dk.sbom.webpack.cjs')].getGeneration(module);
				modules.push({
					class: Object.getPrototypeOf(module).constructor.name,
					runs: observed && Array.isArray(observed.runs) ? observed.runs.length : null,
					status: result.failure ? result.failure.status : 'present',
					reason: result.failure ? result.failure.reason : undefined,
					units: result.units.map((unit) => unit.path),
				});
			}
			modules.sort((a, b) => (a.class < b.class ? -1 : 1));
			chunks.push({ runtime: true, files, modules });
			continue;
		}
		const result = await chunkEvidence(compilation, chunk, verify);
		chunks.push({
			runtime: false,
			files,
			status: result.failure ? result.failure.status : 'present',
			reason: result.failure ? result.failure.reason : undefined,
			units: result.units.map((unit) => unit.path),
			rendered: result.rendered ? digest(result.rendered) : undefined,
		});
	}
	return chunks;
}

function run(compiler) {
	return new Promise((resolve, reject) => {
		compiler.run((error, stats) => {
			if (error) return reject(error);
			if (stats.hasErrors()) return reject(new Error(stats.toString({ all: false, errors: true })));
			resolve(stats);
		});
	});
}

async function main() {
	const setup = JSON.parse(process.env.DK_CODE_SPLIT_SETUP);
	const webpack = require(setup.root);
	const verify = verifier(setup);
	let chunks = [];
	const compiler = webpack(configuration(setup, webpack));
	compiler.hooks.afterEmit.tapPromise('fixture', async (compilation) => {
		chunks = await describe(compilation, verify);
	});
	await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	const emitted = {};
	for (const name of fs.readdirSync(setup.output, { recursive: true }).sort()) {
		const file = path.join(setup.output, name);
		if (fs.statSync(file).isFile()) emitted[name.split(path.sep).join('/')] = digest(fs.readFileSync(file));
	}
	const proof = setup.proofPath ? JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')) : undefined;
	process.stdout.write(`${MARKER}${JSON.stringify({ webpack: webpack.version, emitted, chunks, proof })}\n`);
}

module.exports = { MARKER, writeSources, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
