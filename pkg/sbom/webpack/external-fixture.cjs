'use strict';

// Test-only fixture for external-evidence.test.cjs.
//
// The parent builds a workspace with fixture.cjs and hands the child the paths
// and the scenario; this file is also the child entry point, run as
// `node --require runtime-preload.cjs external-fixture.cjs` so that the load
// recorder is in place before webpack is required.
//
// The adapter is only reachable through the collector, so every scenario here
// is a whole collected build.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const Collector = require('./collector.cjs');

const MARKER = 'DK-EXTERNAL-REPORT ';
const SOURCES = {
	'external.js': "const outside = require('outside');\nconsole.log(outside);\n",
	// Imported rather than required, so scope hoisting can pull the module that
	// reaches it into the entry.
	'hoisted.js': "import outside from 'outside';\nconsole.log(outside);\n",
	// A request the build can do without, which webpack guards with a check of
	// its own in front of the line that reaches it.
	'optional.js': "let value = null;\ntry {\n\tvalue = require('outside');\n} catch (error) {}\nconsole.log(value);\n",
};

function addSources(area) {
	for (const root of [path.join(area.modules, 'app'), area.originalOf('app')]) {
		for (const [name, content] of Object.entries(SOURCES)) fs.writeFileSync(path.join(root, name), content);
	}
}

function digest(bytes) {
	return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

// What the build says about the request it answers from outside. Only the two
// forms that hold no expression of the build's own are described.
function externals(scenario) {
	if (scenario === 'variable' || scenario === 'hoisted-variable') return { outside: 'null' };
	if (scenario === 'many-names') return { outside: ['outside', 'parse'] };
	// One name per way of reaching the package, which webpack hands the class
	// as an object rather than as a request.
	if (scenario === 'request-object') return { outside: { root: 'Outside', commonjs: 'outside', amd: 'outside' } };
	return { outside: 'outside' };
}

function externalsType(scenario) {
	if (scenario === 'variable' || scenario === 'hoisted-variable') return 'var';
	if (scenario === 'amd' || scenario === 'optional') return 'amd';
	if (scenario === 'request-object') return 'umd';
	// What a build targeting node asks for, where the module is a script unless
	// the output is an esm module.
	if (scenario === 'node-commonjs' || scenario === 'node-commonjs-module') return 'node-commonjs';
	return 'commonjs';
}

function entryOf(scenario) {
	if (scenario === 'hoisted' || scenario === 'hoisted-variable' || scenario === 'node-commonjs-module') return 'hoisted.js';
	if (scenario === 'optional') return 'optional.js';
	return 'external.js';
}

function scenarioPlugin(setup, webpack) {
	return {
		apply(compiler) {
			if (setup.scenario !== 'forged-code') return;
			// Another line put in place of the one the class writes, after
			// everything that describes the module has read it.
			compiler.hooks.compilation.tap('fixture', (compilation) => {
				compilation.hooks.processAssets.tap({ name: 'fixture', stage: webpack.Compilation.PROCESS_ASSETS_STAGE_ADDITIONS }, () => {
					for (const module of compilation.modules) {
						if (typeof module.externalType !== 'string') continue;
						const runtime = [...compilation.chunkGraph.getModuleRuntimes(module)][0];
						compilation.codeGenerationResults.get(module, runtime).sources.set('javascript', new webpack.sources.RawSource('module.exports = document.cookie;'));
					}
				});
			});
		},
	};
}

function configuration(setup, webpack) {
	return {
		mode: 'production',
		context: setup.context,
		entry: path.join(setup.modules, 'app', entryOf(setup.scenario)),
		// Built as an esm module, where the same external type reaches the request
		// through a fragment of its own instead of a plain require.
		...(setup.scenario === 'node-commonjs-module' ? { experiments: { outputModule: true } } : {}),
		output: setup.scenario === 'node-commonjs-module' ? { path: setup.output, filename: 'main.js', module: true, chunkFormat: 'module', library: { type: 'module' } } : { path: setup.output, filename: 'main.js' },
		target: setup.scenario.startsWith('node-commonjs') ? 'node' : 'web',
		externals: externals(setup.scenario),
		externalsType: externalsType(setup.scenario),
		resolve: { modules: [setup.modules] },
		optimization: { minimize: false, concatenateModules: setup.scenario === 'hoisted' || setup.scenario === 'hoisted-variable' },
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
	const setup = JSON.parse(process.env.DK_EXTERNAL_SETUP);
	const webpack = require(setup.webpackRoot);
	const compiler = webpack(configuration(setup, webpack));
	await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	const emitted = {};
	for (const name of fs.readdirSync(setup.output).sort()) emitted[name] = digest(fs.readFileSync(path.join(setup.output, name)));
	process.stdout.write(`${MARKER}${JSON.stringify({ webpack: webpack.version, emitted, proof: JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')) })}\n`);
}

module.exports = { MARKER, SOURCES, addSources, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
