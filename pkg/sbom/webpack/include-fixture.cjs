'use strict';

// Test-only fixture for include-evidence.test.cjs.
//
// The parent hands the child the paths it needs; this file is also the child
// entry point, run as `node --require include-preload.cjs include-fixture.cjs`
// so that the loader recorder is in place before the monaco plugin requires
// its own loader.
//
// The build is the shape Argo has: a web entry importing monaco, with
// MonacoWebpackPlugin({ languages: ['yaml'] }).

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { installIncludeEvidence } = require('./include-evidence.cjs');
const Collector = require('./collector.cjs');

const MARKER = 'DK-INCLUDE-REPORT ';
const ENTRY = "import * as monaco from 'monaco-editor';\nconsole.log(monaco.editor);\n";
// The same build with monaco behind a dynamic import, so the module the loader
// pitched ends up in a chunk of its own.
const LAZY_ENTRY = "import('monaco-editor').then((monaco) => console.log(monaco.editor));\n";

function writeSources(dir) {
	fs.mkdirSync(dir, { recursive: true });
	fs.writeFileSync(path.join(dir, 'index.js'), ENTRY);
	return path.join(dir, 'index.js');
}

// The same binding the collector performs, over the roots this adapter reads.
function verifier(setup) {
	return async (resource) => {
		const actual = path.resolve(resource);
		const binding = setup.originals.find((candidate) => actual.startsWith(candidate.root.endsWith(path.sep) ? candidate.root : candidate.root + path.sep));
		if (!binding) return { failure: { status: 'no-data', reason: `outside the declared roots: ${actual}` } };
		const bytes = read(actual);
		if (bytes.failure) return bytes;
		const original = read(path.join(binding.originalRoot, path.relative(binding.root, actual)));
		if (original.failure) return original;
		const sha256 = digest(bytes.bytes);
		if (sha256 !== digest(original.bytes)) {
			return { failure: { status: 'hash-mismatch', reason: `materialized source differs from its original: ${actual}` } };
		}
		return { unit: { path: actual, sha256, bytes: bytes.bytes, component: binding.component } };
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

// Every way of being something other than the loader this adapter describes.
function scenarioPlugin(setup) {
	return {
		apply(compiler) {
			if (setup.scenario === 'second-loader') {
				compiler.hooks.afterPlugins.tap('fixture', () => {
					for (const rule of compiler.options.module.rules) {
						if (Array.isArray(rule.use) && rule.use[0] && String(rule.use[0].loader).includes('monaco-editor-webpack-plugin')) {
							rule.use.push({ loader: path.join(setup.fixtureDir, 'include-noop-loader.cjs') });
						}
					}
				});
			}
			if (setup.scenario === 'mutated-options') {
				// The very options the loader ran with, changed after it ran: what it
				// wrote can no longer be rebuilt from them. The value chosen is one
				// the loader writes literally, so every request it asked for is still
				// one it wrote.
				compiler.hooks.compilation.tap('fixture', (compilation) => {
					// Once every module has been built, so that no later pitch is given
					// the changed options.
					compilation.hooks.finishModules.tap('fixture', (modules) => {
						for (const module of modules) {
							const item = (Array.isArray(module.loaders) ? module.loaders : []).find((candidate) => String(candidate.loader).includes('monaco-editor-webpack-plugin'));
							if (item && item.options && item.options.globals) item.options.globals.MonacoEnvironment = '(function () { return {}; })()';
						}
					});
				});
			}
			if (setup.scenario === 'injected-global' || setup.scenario === 'forged-worker-paths' || setup.scenario === 'extra-global' || setup.scenario === 'two-faced-global') {
				compiler.hooks.afterPlugins.tap('fixture', () => {
					for (const rule of compiler.options.module.rules) {
						const item = Array.isArray(rule.use) ? rule.use[0] : undefined;
						if (!item || !String(item.loader).includes('monaco-editor-webpack-plugin')) continue;
						const globals = item.options.globals;
						// Code in a slot the plugin fills with data, a worker map that
						// is not the one the plugin writes, and a second global the
						// plugin never authors.
						if (setup.scenario === 'injected-global') globals.MonacoEnvironment = globals.MonacoEnvironment.replace('globalAPI: false', 'globalAPI: (window.stolen = document.cookie, false)');
						if (setup.scenario === 'forged-worker-paths') globals.MonacoEnvironment = globals.MonacoEnvironment.replace(/\)$/, ', evil())');
						if (setup.scenario === 'extra-global') globals.OtherGlobal = 'window.stolen = document.cookie';
						// The published text for whoever checks it, code of its own for
						// the loader that writes it out and for anyone rebuilding what
						// the loader wrote.
						if (setup.scenario === 'two-faced-global') {
							const published = globals.MonacoEnvironment;
							const stolen = published.replace('globalAPI: false', 'globalAPI: (window.stolen = document.cookie, false)');
							Object.defineProperty(globals, 'MonacoEnvironment', {
								// Whoever is describing this build is shown the text the
								// plugin publishes; the loader that writes it into the
								// bundle is given the other one.
								get: () => (new Error().stack.includes('include-evidence.cjs') ? published : stolen),
								enumerable: true,
								configurable: true,
							});
						}
					}
				});
			}
			if (setup.scenario === 'replaced-pitch') {
				// A plugin putting its own function where the loader published one.
				compiler.hooks.afterPlugins.tap('fixture', () => {
					const loader = require(path.join(setup.pluginRoot, 'out', 'loaders', 'include.js'));
					const published = loader.pitch;
					loader.pitch = function (...args) {
						return published.apply(this, args);
					};
				});
			}
			if (setup.scenario === 'forged-source') {
				compiler.hooks.compilation.tap('fixture', (compilation) => {
					compilation.hooks.succeedModule.tap('fixture', (module) => {
						const loaders = Array.isArray(module.loaders) ? module.loaders : [];
						if (!loaders.some((item) => String(item.loader).includes('monaco-editor-webpack-plugin'))) return;
						module._source = new (require(setup.webpackRoot).sources.RawSource)(`${module._source.source()}\n// forged\n`);
					});
				});
			}
			if (setup.scenario === 'extra-option') {
				compiler.hooks.afterPlugins.tap('fixture', () => {
					for (const rule of compiler.options.module.rules) {
						if (Array.isArray(rule.use) && rule.use[0] && String(rule.use[0].loader).includes('monaco-editor-webpack-plugin')) {
							rule.use[0].options = { ...rule.use[0].options, pre: [...rule.use[0].options.pre, setup.extraInclude] };
						}
					}
				});
			}
		},
	};
}

function configuration(setup, webpack, rows) {
	const MonacoWebpackPlugin = require(setup.pluginRoot);
	return {
		// What Argo builds; the development mode adds a plugin that writes module
		// headers into every chunk, which is a different question entirely.
		mode: 'production',
		devtool: false,
		context: setup.context,
		entry: setup.entry,
		output: { path: setup.output, filename: '[name].js', clean: true },
		target: 'web',
		resolve: { modules: [setup.modules] },
		// Monaco carries stylesheets and a font. The stylesheet chain is the one
		// Argo configures, which the stylesheet adapter describes.
		module: {
			rules: [
				// The chain Argo configures, except where a test needs monaco's
				// stylesheets out of the way of what it is about.
				setup.cssAsAsset ? { test: /\.css$/, type: 'asset/source' } : { test: /\.css$/, use: [{ loader: setup.styleLoader }, { loader: setup.rawLoader }] },
				{ test: /\.ttf$/, type: 'asset/resource' },
			],
		},
		optimization: { minimize: Boolean(setup.proofPath), concatenateModules: false },
		cache: false,
		plugins: [
			new MonacoWebpackPlugin({ languages: ['yaml'] }),
			...(setup.proofPath ? [new Collector({ proofPath: setup.proofPath, originals: setup.originals })] : [evidencePlugin(setup, rows)]),
			scenarioPlugin(setup),
		],
	};
}

function evidencePlugin(setup, rows) {
	return {
		apply(compiler) {
			const evidenceFor = installIncludeEvidence(compiler, verifier(setup));
			compiler.hooks.afterEmit.tapPromise('fixture', async (compilation) => {
				if (compilation.compiler.isChild()) return;
				for (const module of compilation.modules) {
					const loaders = Array.isArray(module.loaders) ? module.loaders : [];
					if (!loaders.some((item) => String(item.loader).includes('monaco-editor-webpack-plugin'))) continue;
					const result = await evidenceFor(module);
					rows.push({
						identifier: module.identifier(),
						resource: module.resource,
						status: result.failure ? result.failure.status : 'present',
						reason: result.failure ? result.failure.reason : undefined,
						units: result.units.map((unit) => unit.path),
						components: result.units.map((unit) => unit.component && unit.component.id),
						source: module.originalSource ? String(module.originalSource().source()) : undefined,
					});
				}
				rows.sort((a, b) => (a.identifier < b.identifier ? -1 : 1));
			});
		},
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
	const setup = JSON.parse(process.env.DK_INCLUDE_SETUP);
	const webpack = require(setup.webpackRoot);
	const rows = [];
	const compiler = webpack(configuration(setup, webpack, rows));
	await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	const emitted = {};
	for (const name of fs.readdirSync(setup.output, { recursive: true }).sort()) {
		const file = path.join(setup.output, name);
		if (fs.statSync(file).isFile()) emitted[name.split(path.sep).join('/')] = digest(fs.readFileSync(file));
	}
	const proof = setup.proofPath ? JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')) : undefined;
	process.stdout.write(`${MARKER}${JSON.stringify({ webpack: webpack.version, emitted, rows, proof })}\n`);
}

module.exports = { MARKER, ENTRY, LAZY_ENTRY, writeSources, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
