'use strict';

// Test-only fixture for define-evidence.test.cjs.
//
// The parent builds a workspace with fixture.cjs and hands the child the paths
// and the scenario; this file is also the child entry point, run as
// `node --require runtime-preload.cjs define-fixture.cjs` so that the load
// recorder is in place before webpack is required.
//
// The build is the shape redoc has: constants defined for the parser, and one
// identifier provided from a module of the graph.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const Collector = require('./collector.cjs');

const MARKER = 'DK-DEFINE-REPORT ';
const SOURCES = {
	'define.js': "console.log(__REDOC_VERSION__, process.platform, Provided.name);\n",
	// What an identifier is provided from.
	'provided.js': 'export const Provided = { name: "provided" };\n',
	// What a compiler this one makes compiles.
	'child.js': "console.log(__CHILD_CONSTANT__);\n",
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

function definitions(scenario) {
	const data = { __REDOC_VERSION__: '"2.4.0"', 'process.platform': '"browser"', 'process.env': '{}', 'process.stdout': 'null' };
	switch (scenario) {
		case 'code':
			return { ...data, __REDOC_VERSION__: 'globalThis.stolen = document.cookie' };
		case 'function':
			return { ...data, __REDOC_VERSION__: () => '"2.4.0"' };
		case 'regexp':
			return { ...data, __REDOC_VERSION__: /2\.4\.0/ };
		case 'nested-code':
			return { ...data, __REDOC_VERSION__: { version: 'globalThis.stolen = 1' } };
		case 'undefined-value':
			return { ...data, __REDOC_REVISION__: undefined };
		default:
			return data;
	}
}

// A compiler of this one's own, given a definer after it was made - after the
// taps of this one were copied into it.
function childPlugin(setup, webpack) {
	return {
		apply(compiler) {
			if (setup.scenario !== 'child-define' && setup.scenario !== 'child-plain') return;
			compiler.hooks.make.tapAsync('fixture', (compilation, callback) => {
				const child = compilation.createChildCompiler('fixture-child', { filename: 'child.js' }, []);
				new webpack.EntryPlugin(setup.context, path.join(setup.modules, 'app', 'child.js'), { name: 'child' }).apply(child);
				if (setup.scenario === 'child-define') new webpack.DefinePlugin({ __CHILD_CONSTANT__: 'globalThis.stolen = document.cookie' }).apply(child);
				child.runAsChild((error) => callback(error));
			});
		},
	};
}

function plugins(setup, webpack) {
	const { DefinePlugin, ProvidePlugin } = webpack;
	const provide = new ProvidePlugin({ Provided: [path.join(setup.modules, 'app', 'provided.js'), 'Provided'] });
	if (setup.scenario === 'applied-inside') {
		return [
			provide,
			{
				apply(compiler) {
					// A plugin of someone else's defining constants of its own.
					new DefinePlugin(definitions('code')).apply(compiler);
				},
			},
		];
	}
	if (setup.scenario === 'derived') {
		class Derived extends DefinePlugin {}
		return [provide, new Derived(definitions('plain'))];
	}
	if (setup.scenario === 'no-define') return [provide];
	return [provide, new DefinePlugin(definitions(setup.scenario))];
}

function configuration(setup, webpack) {
	return {
		mode: 'production',
		context: setup.context,
		entry: setup.entry,
		output: { path: setup.output, filename: 'main.js' },
		target: 'web',
		resolve: { modules: [setup.modules] },
		optimization: { minimize: false, concatenateModules: false, nodeEnv: setup.scenario === 'no-node-env' ? false : 'production' },
		cache: false,
		plugins: [new Collector({ proofPath: setup.proofPath, originals: setup.originals }), ...plugins(setup, webpack), childPlugin(setup, webpack)],
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
	const setup = JSON.parse(process.env.DK_DEFINE_SETUP);
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
