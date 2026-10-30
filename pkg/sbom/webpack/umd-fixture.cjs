'use strict';

// Test-only fixture for umd-evidence.test.cjs.
//
// The parent builds a workspace with fixture.cjs and hands the child the paths
// and the scenario; this file is also the child entry point, run as
// `node --require runtime-preload.cjs umd-fixture.cjs` so that the load
// recorder is in place before webpack is required.
//
// The adapter is driven directly: it rebuilds the wrapper of one chunk, and
// this slice does not yet wire it into the collector.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const Collector = require('./collector.cjs');
const { umdEvidence } = require('./umd-evidence.cjs');

const MARKER = 'DK-UMD-REPORT ';
const SOURCES = {
	// A bundle that exports something and references a library it does not
	// carry, the way redoc's standalone bundle does.
	'umd.js': "import yaml from 'yaml';\nexport function render() { return yaml; }\n",
	// The same bundle without anything of the environment in it.
	'alone.js': 'export function render() { return "alone"; }\n',
	// The shape redoc builds: a library wrapper, a banner, constants defined
	// for the parser and a source map beside the bundle.
	'redoc.js': "import yaml from 'yaml';\nexport function render() { return [__REDOC_VERSION__, yaml]; }\n",
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

function verifier(setup) {
	return async (resource) => {
		const actual = path.resolve(resource);
		const binding = setup.originals.find((candidate) => actual.startsWith(candidate.root.endsWith(path.sep) ? candidate.root : candidate.root + path.sep));
		if (!binding) return { failure: { status: 'no-data', reason: `outside the declared roots: ${actual}` } };
		const bytes = read(actual);
		if (bytes.failure) return bytes;
		const original = read(path.join(binding.originalRoot, path.relative(binding.root, actual)));
		if (original.failure) return original;
		if (!bytes.bytes.equals(original.bytes)) return { failure: { status: 'hash-mismatch', reason: `${actual} differs from its original` } };
		return { unit: { path: actual, sha256: digest(bytes.bytes), bytes: bytes.bytes, component: binding.component } };
	};
}

function read(file) {
	try {
		return { bytes: fs.readFileSync(file) };
	} catch (error) {
		return { failure: { status: 'no-data', reason: `missing file ${file}: ${error.code || error.message}` } };
	}
}

function library(scenario) {
	switch (scenario) {
		case 'named-object':
			return { name: { root: 'Redoc', amd: 'redoc', commonjs: 'redoc-cjs' }, type: 'umd' };
		case 'named-define':
			return { name: 'Redoc', type: 'umd', umdNamedDefine: true };
		case 'comment':
			return { name: 'Redoc', type: 'umd', auxiliaryComment: 'built by the fixture' };
		case 'templated-name':
			return { name: 'Redoc_[name]', type: 'umd' };
		case 'umd2':
			return { name: 'Redoc', type: 'umd2' };
		case 'assigned':
			return { name: 'Redoc', type: 'var' };
		default:
			return { name: 'Redoc', type: 'umd' };
	}
}

// A plugin shaping the rendered code of the chunk beside the library wrapper.
function scenarioPlugin(setup, webpack) {
	return {
		apply(compiler) {
			if (setup.scenario !== 'company') return;
			compiler.hooks.compilation.tap('fixture', (compilation) => {
				webpack.javascript.JavascriptModulesPlugin.getCompilationHooks(compilation).render.tap('fixture', (source) => new webpack.sources.ConcatSource('/* fixture */\n', source));
			});
		},
	};
}

function evidencePlugin(setup, reports) {
	return {
		apply(compiler) {
			compiler.hooks.afterEmit.tapPromise('fixture', async (compilation) => {
				for (const chunk of compilation.chunks) {
					const result = await umdEvidence(compilation, chunk, verifier(setup));
					reports.push({
						chunk: chunk.name || String(chunk.id),
						files: [...chunk.files],
						status: result.failure ? result.failure.status : 'present',
						reason: result.failure ? result.failure.reason : undefined,
						prefix: result.prefix,
						suffix: result.suffix,
						externals: result.externals,
						units: (result.units || []).map((unit) => unit.path),
					});
				}
			});
		},
	};
}

// Everything redoc's own configuration asks for, over one entry.
function redocConfiguration(setup, webpack) {
	return {
		mode: 'production',
		context: setup.context,
		entry: path.join(path.dirname(setup.entry), 'redoc.js'),
		output: {
			path: setup.output,
			filename: 'redoc.standalone.js',
			library: { name: 'Redoc', type: 'umd' },
			globalObject: 'this',
		},
		devtool: 'source-map',
		target: 'web',
		externals: { yaml: 'null' },
		resolve: { modules: [setup.modules] },
		optimization: { minimize: true, concatenateModules: false },
		cache: false,
		plugins: [
			new Collector({ proofPath: setup.proofPath, originals: setup.originals }),
			{
				apply(compiler) {
					if (setup.scenario !== 'mutated-global') return;
					// The wrapper is rebuilt from the build, so a build that says
					// something else about itself afterwards no longer accounts for
					// the text that was rendered.
					compiler.hooks.compilation.tap('fixture', (compilation) => {
						compilation.hooks.afterProcessAssets.tap('fixture', () => {
							compilation.outputOptions.globalObject = 'self';
						});
					});
				},
			},
			new webpack.BannerPlugin('ReDoc - OpenAPI/Swagger-generated API Reference Documentation\n  Version: "2.4.0"'),
			new webpack.DefinePlugin({ __REDOC_VERSION__: '"2.4.0"', 'process.env': '{}' }),
		],
	};
}

function configuration(setup, webpack, reports) {
	if (setup.scenario === 'redoc' || setup.scenario === 'mutated-global') return redocConfiguration(setup, webpack);
	return {
		mode: 'production',
		context: setup.context,
		entry: setup.scenario === 'no-externals' ? path.join(path.dirname(setup.entry), 'alone.js') : setup.entry,
		output: {
			path: setup.output,
			filename: 'bundle.js',
			library: library(setup.scenario),
			globalObject: setup.scenario === 'expression-global' ? 'this.window || this' : 'this',
			environment: setup.scenario === 'no-arrow' ? { arrowFunction: false } : undefined,
		},
		target: 'web',
		externals: setup.scenario === 'no-externals' ? {} : { yaml: 'null' },
		resolve: { modules: [setup.modules] },
		optimization: { minimize: false, concatenateModules: false },
		cache: false,
		plugins: [evidencePlugin(setup, reports), scenarioPlugin(setup, webpack)],
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
	const setup = JSON.parse(process.env.DK_UMD_SETUP);
	const webpack = require(setup.webpackRoot);
	const reports = [];
	const compiler = webpack(configuration(setup, webpack, reports));
	await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	const emitted = {};
	for (const name of fs.readdirSync(setup.output).sort()) emitted[name] = fs.readFileSync(path.join(setup.output, name), 'utf8');
	const proof = fs.existsSync(setup.proofPath) ? JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')) : undefined;
	process.stdout.write(`${MARKER}${JSON.stringify({ webpack: webpack.version, emitted, rows: reports, proof })}\n`);
}

module.exports = { MARKER, SOURCES, addSources, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
