'use strict';

// Test-only fixture for child-evidence.test.cjs.
//
// The parent builds a workspace with fixture.cjs and hands the child the paths
// and the scenario; this file is also the child entry point, run as
// `node --require runtime-preload.cjs child-fixture.cjs` so that the load
// registry is in place before webpack is required here.
//
// The build is the shape a worker plugin produces: a web entry plus a child
// compilation of its own, compiled for a web worker and emitted into the
// parent under a name no chunk of the parent ever built.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const Collector = require('./collector.cjs');
const MARKER = 'DK-CHILD-REPORT ';
const WORKER = 'worker.js';
const SOURCES = {
	'main.js': "import { shared } from './shared.js';\nconsole.log(shared());\n",
	'shared.js': 'export function shared() { return "shared"; }\n',
	// A worker that uses the same module, so its bundle carries the interop
	// runtime modules a real worker carries, and one comment of the kind the
	// minifier writes to a file of its own.
	'worker-entry.js': "/*! worker-lib v2.0.0 | (c) 2024 | MIT */\nimport { shared } from './shared.js';\nself.onmessage = () => self.postMessage(shared());\n",
	// One that loads a chunk of its own, which needs the import-scripts loading
	// runtime no adapter of this set describes.
	'lazy-worker-entry.js': "self.onmessage = () => import('./shared.js').then(({ shared }) => self.postMessage(shared()));\n",
};

function addSources(area) {
	for (const [name, content] of Object.entries(SOURCES)) {
		fs.writeFileSync(path.join(area.modules, 'app', name), content);
		fs.writeFileSync(path.join(area.originalOf('app'), name), content);
	}
}

function digest(bytes) {
	return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

// What a worker plugin does: one child compilation per worker entry, compiled
// for a web worker, limited to a single chunk, emitted into this compilation.
function workerPlugin(setup, webpack, options) {
	return {
		apply(compiler) {
			compiler.hooks.make.tapAsync('fixture', (compilation, callback) => {
				const child = compilation.createChildCompiler(options.id, { filename: options.filename, publicPath: compilation.outputOptions.publicPath, globalObject: 'this' }, [
					new webpack.webworker.WebWorkerTemplatePlugin(),
					new webpack.LoaderTargetPlugin('webworker'),
				]);
				new webpack.EntryPlugin(compiler.context, path.join(setup.appDir, options.entry), 'main').apply(child);
				// What a worker plugin asks for, so that the worker is one file; the
				// other scenario lets the child split and load chunks of its own.
				if (setup.scenario !== 'split-worker') new webpack.optimize.LimitChunkCountPlugin({ maxChunks: 1 }).apply(child);
				if (setup.scenario === 'foreign-child' || setup.scenario === 'throwing-child') {
					// A compilation of the child's own, which the parent never made:
					// its assets reach the output through the child.
					child.hooks.compilation.tap('fixture', (childCompilation) => {
						if (childCompilation.compiler !== child) return;
						childCompilation.hooks.additionalAssets.tapAsync('fixture', (done) => {
							const grand = childCompilation.createChildCompiler('grand', { filename: 'grand.js' }, [new webpack.webworker.WebWorkerTemplatePlugin(), new webpack.LoaderTargetPlugin('webworker')]);
							new webpack.EntryPlugin(compiler.context, path.join(setup.appDir, 'worker-entry.js'), 'main').apply(grand);
							new webpack.optimize.LimitChunkCountPlugin({ maxChunks: 1 }).apply(grand);
							grand.runAsChild((error) => done(error));
						});
					});
				}
				if (setup.scenario === 'tapped-child-render') {
					child.hooks.compilation.tap('fixture', (childCompilation) => {
						webpack.javascript.JavascriptModulesPlugin.getCompilationHooks(childCompilation).render.tap('fixture', (source) => source);
					});
				}
				child.runAsChild((error) => callback(error));
			});
		},
	};
}

function scenarioPlugin(setup, webpack) {
	return {
		apply(compiler) {
			compiler.hooks.compilation.tap('fixture', (compilation) => {
				if (compilation.compiler.isChild()) return;
				if (setup.scenario === 'foreign-child' || setup.scenario === 'throwing-child') {
					// The plugin puts it among the compilations this one made, which
					// it is not.
					compilation.hooks.afterProcessAssets.tap('fixture', () => {
						for (const made of compilation.children) {
							for (const grand of made.children) {
								if (compilation.children.includes(grand)) continue;
								// One that cannot even be looked at.
								if (setup.scenario === 'throwing-child') {
									Object.defineProperty(grand, 'chunkGraph', {
										get() {
											throw new Error('this compilation is gone');
										},
										configurable: true,
									});
								}
								compilation.children.push(grand);
							}
						}
					});
				}
				if (setup.scenario === 'rewritten-by-parent') {
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: webpack.Compilation.PROCESS_ASSETS_STAGE_REPORT }, (assets) => {
						compilation.updateAsset(WORKER, new webpack.sources.RawSource(`${assets[WORKER].source()}\n// touched\n`));
					});
				}
			});
		},
	};
}

// What a template plugin does: a child compilation whose result it reads and
// then deletes, so nothing of it is emitted here - and whose chunk happens to
// be named like an asset of this compilation.
function templatePlugin(setup, webpack) {
	return {
		apply(compiler) {
			compiler.hooks.make.tapAsync('fixture', (compilation, callback) => {
				const child = compilation.createChildCompiler('template', { filename: '__child-template.js' }, []);
				new webpack.EntryPlugin(compiler.context, path.join(setup.appDir, 'worker-entry.js'), 'main').apply(child);
				child.runAsChild((error) => {
					if (error) return callback(error);
					compilation.deleteAsset('__child-template.js');
					callback();
				});
			});
		},
	};
}

function configuration(setup, webpack) {
	const lazy = setup.scenario === 'lazy-worker' || setup.scenario === 'split-worker';
	const workers = [{ id: 'worker', entry: lazy ? 'lazy-worker-entry.js' : 'worker-entry.js', filename: WORKER }];
	// Two plugins writing one and the same file: the asset is then the work of
	// neither child alone.
	if (setup.scenario === 'two-children') workers.push({ id: 'other', entry: 'worker-entry.js', filename: WORKER });
	return {
		mode: 'production',
		context: setup.context,
		entry: path.join(setup.appDir, 'main.js'),
		output: { path: setup.output, filename: '[name].js', clean: true },
		target: 'web',
		resolve: { modules: [setup.modules] },
		optimization: { minimize: setup.scenario === 'minified', concatenateModules: false, usedExports: true },
		cache: false,
		plugins: [
			new Collector({ proofPath: setup.proofPath, originals: setup.originals }),
			...workers.map((worker) => workerPlugin(setup, webpack, worker)),
			...(setup.scenario === 'template-child' ? [templatePlugin(setup, webpack)] : []),
			scenarioPlugin(setup, webpack),
		],
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
	const setup = JSON.parse(process.env.DK_CHILD_SETUP);
	const webpack = require(setup.webpackRoot);
	const compiler = webpack(configuration(setup, webpack));
	await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	const emitted = {};
	for (const name of fs.readdirSync(setup.output).sort()) emitted[name] = digest(fs.readFileSync(path.join(setup.output, name)));
	process.stdout.write(`${MARKER}${JSON.stringify({ webpack: webpack.version, emitted, proof: JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')) })}\n`);
}

module.exports = { MARKER, WORKER, addSources, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
