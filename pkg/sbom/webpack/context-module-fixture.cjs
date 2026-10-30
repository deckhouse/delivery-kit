'use strict';

// Test-only fixture for context-module-evidence.test.cjs.
//
// The parent builds a workspace with fixture.cjs and hands the child the paths
// and the scenario; this file is also the child entry point, run as
// `node --require runtime-preload.cjs context-module-fixture.cjs` so that the
// load recorder is in place before webpack is required.
//
// The adapter is only reachable through the collector, so every scenario here
// is a whole collected build.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const Collector = require('./collector.cjs');

const MARKER = 'DK-CONTEXT-REPORT ';
// A directory of requests and the module that reaches them all. The second
// entry is what a filtered context leaves out.
const LOCALES = { 'af.js': "module.exports = 'af';\n", 'de.js': "module.exports = 'de';\n", 'notes.txt.js': "module.exports = 'notes';\n" };
const SOURCES = {
	'context.js': "const all = require.context('./locale', true, /^\\.\\/.*$/);\nconsole.log(all.keys().length, all('./af'));\n",
	// The same directory behind a filter, so the map holds only what matches.
	'filtered.js': "const some = require.context('./locale', true, /^\\.\\/[a-z]{2}$/);\nconsole.log(some.keys().length, some('./de'));\n",
	// A context whose requests are loaded from a chunk of their own.
	'lazy.js': "const lazy = require.context('./locale', true, /^\\.\\/.*$/, 'lazy');\nlazy('./af').then((m) => console.log(m));\n",
	// A context that answers only with what is already loaded, which writes a
	// different template around the same map.
	'weak.js': "const weak = require.context('./locale', true, /^\\.\\/.*$/, 'weak');\nconsole.log(weak.keys().length);\n",
};

function addSources(area) {
	const app = path.join(area.modules, 'app');
	for (const root of [app, area.originalOf('app')]) {
		fs.mkdirSync(path.join(root, 'locale'), { recursive: true });
		for (const [name, content] of Object.entries(LOCALES)) fs.writeFileSync(path.join(root, 'locale', name), content);
		for (const [name, content] of Object.entries(SOURCES)) fs.writeFileSync(path.join(root, name), content);
	}
}

function digest(bytes) {
	return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function isContext(module) {
	return module.constructor && module.constructor.name === 'ContextModule';
}

function scenarioPlugin(setup, webpack) {
	return {
		apply(compiler) {
			compiler.hooks.compilation.tap('fixture', (compilation) => {
				compilation.hooks.finishModules.tap('fixture', (modules) => {
					for (const module of modules) {
						if (!isContext(module)) continue;
						if (setup.scenario === 'subclass') {
							const ContextModule = Object.getPrototypeOf(module).constructor;
							Object.setPrototypeOf(module, class Derived extends ContextModule {}.prototype);
						}
						// Requests answered with a namespace object, which builds a
						// second map out of the exports of every module they reach.
						if (setup.scenario === 'namespace-object') module.options = { ...module.options, namespaceObject: 'strict' };
						// A method of the module's own, which would be the one that
						// writes the text.
						if (setup.scenario === 'own-source') module.getSyncSource = () => 'module.exports = function () {};';
					}
				});
				// Globals of a plugin's own held out by the compiler, while the file
				// those were loaded from is untouched.
				if (setup.scenario === 'foreign-globals') {
					compilation.hooks.finishModules.tap('fixture', () => {
						const api = compilation.compiler.webpack;
						compilation.compiler.webpack = { ...api, RuntimeGlobals: { ...api.RuntimeGlobals } };
					});
				}
				// A member of the globals put there after they were loaded, so the
				// text the class writes is no longer built from what was recorded.
				if (setup.scenario === 'swapped-globals') {
					compilation.hooks.finishModules.tap('fixture', () => {
						const globals = require(path.join(setup.webpackRoot, 'lib', 'RuntimeGlobals.js'));
						globals.hasOwnProperty = '__webpack_require__.stolen';
					});
				}
				// A request answered by a module this chunk does not hold, so the
				// map names something nothing in the chunk describes.
				if (setup.scenario === 'foreign-target') {
					compilation.hooks.optimizeChunks.tap({ name: 'fixture', stage: webpack.Compilation.PROCESS_ASSETS_STAGE_ADDITIONS }, (chunks) => {
						const module = [...compilation.modules].find(isContext);
						const target = compilation.moduleGraph.getModule(module.dependencies[0]);
						const chunk = [...chunks][0];
						const other = compilation.addChunk('other');
						compilation.chunkGraph.disconnectChunkAndModule(chunk, target);
						compilation.chunkGraph.connectChunkAndModule(other, target);
					});
				}
				// Text put in place of what the class writes, after everything that
				// describes the module has read it.
				if (setup.scenario === 'forged-code') {
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: webpack.Compilation.PROCESS_ASSETS_STAGE_ADDITIONS }, () => {
						for (const module of compilation.modules) {
							if (!isContext(module)) continue;
							const runtime = [...compilation.chunkGraph.getModuleRuntimes(module)][0];
							const result = compilation.codeGenerationResults.get(module, runtime);
							result.sources.set('javascript', new webpack.sources.RawSource('module.exports = function () { return document.cookie; };'));
						}
					});
				}
			});
		},
	};
}

function entryOf(setup) {
	if (setup.scenario === 'filtered') return 'filtered.js';
	if (setup.scenario === 'lazy') return 'lazy.js';
	if (setup.scenario === 'weak') return 'weak.js';
	return 'context.js';
}

function configuration(setup, webpack) {
	return {
		mode: 'production',
		context: setup.context,
		entry: path.join(setup.modules, 'app', entryOf(setup)),
		output: { path: setup.output, filename: setup.scenario === 'hashed' ? '[name].[contenthash].js' : 'main.js' },
		target: 'web',
		resolve: { modules: [setup.modules] },
		optimization: { minimize: setup.scenario === 'minified', concatenateModules: false },
		cache: false,
		plugins: [new Collector({ proofPath: setup.proofPath, originals: setup.originals }), scenarioPlugin(setup, webpack)],
	};
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
	const setup = JSON.parse(process.env.DK_CONTEXT_SETUP);
	const webpack = require(setup.webpackRoot);
	const compiler = webpack(configuration(setup, webpack));
	await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	const emitted = {};
	for (const name of fs.readdirSync(setup.output).sort()) emitted[name] = digest(fs.readFileSync(path.join(setup.output, name)));
	process.stdout.write(`${MARKER}${JSON.stringify({ webpack: webpack.version, emitted, proof: JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')) })}\n`);
}

module.exports = { MARKER, SOURCES, LOCALES, addSources, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
