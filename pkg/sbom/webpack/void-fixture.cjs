'use strict';

// Test-only fixture for void-evidence.test.cjs.
//
// The parent builds a workspace with fixture.cjs and hands the child the paths
// and the scenario; this file is also the child entry point, run as
// `node --require runtime-preload.cjs void-fixture.cjs` so that the load
// recorder is in place before webpack is required.
//
// The adapter is only reachable through the collector, so every scenario here
// is a whole collected build.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const Collector = require('./collector.cjs');

const MARKER = 'DK-VOID-REPORT ';
const VOID_SOURCE = '/* (ignored) */';
const SOURCES = {
	// A request webpack is told to answer with nothing, and one it is told to
	// drop before it is even resolved.
	'void.js': "import http from 'http';\nimport ignored from './optional.js';\nconsole.log(http, ignored);\n",
	'optional.js': 'export default 1;\n',
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

function scenarioPlugin(setup) {
	return {
		apply(compiler) {
			compiler.hooks.compilation.tap('fixture', (compilation) => {
				if (setup.scenario === 'plain' || setup.scenario === 'dropped') return;
				compilation.hooks.finishModules.tap('fixture', (modules) => {
					for (const module of modules) {
						if (!/^ignored\|/.test(module.identifier())) continue;
						if (setup.scenario === 'forged-text') module.sourceStr = 'globalThis.stolen = document.cookie;';
						if (setup.scenario === 'renamed') module.identifierStr = 'provided|http';
						// Code of its own in the bundle, and the fixed comment back in
						// place by the time anyone looks at the module.
						if (setup.scenario === 'forged-code') module.sourceStr = 'globalThis.stolen = document.cookie;';
						if (setup.scenario === 'subclass') {
							const RawModule = Object.getPrototypeOf(module).constructor;
							Object.setPrototypeOf(module, class Derived extends RawModule {}.prototype);
						}
					}
				});
				if (setup.scenario === 'forged-code') {
					compilation.hooks.afterProcessAssets.tap('fixture', () => {
						for (const module of compilation.modules) {
							if (/^ignored\|/.test(module.identifier())) module.sourceStr = VOID_SOURCE;
						}
					});
				}
			});
		},
	};
}

function configuration(setup, webpack) {
	return {
		mode: 'production',
		context: setup.context,
		entry: setup.entry,
		output: { path: setup.output, filename: 'main.js' },
		target: 'web',
		resolve: {
			modules: [setup.modules],
			// The request answered with nothing. The other one is dropped before
			// resolution, which builds no module at all.
			fallback: { http: false },
		},
		optimization: { minimize: false, concatenateModules: false },
		cache: false,
		plugins: [
			new Collector({ proofPath: setup.proofPath, originals: setup.originals }),
			...(setup.scenario === 'dropped' ? [new webpack.IgnorePlugin({ resourceRegExp: /optional\.js$/ })] : []),
			scenarioPlugin(setup),
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
	const setup = JSON.parse(process.env.DK_VOID_SETUP);
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
