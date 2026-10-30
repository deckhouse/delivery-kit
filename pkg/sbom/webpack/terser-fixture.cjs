'use strict';

// Test-only fixture for terser-evidence.test.cjs.
//
// The parent builds a workspace with fixture.cjs and hands the child the paths
// and the scenario; this file is also the child entry point, run as
// `node --require runtime-preload.cjs terser-fixture.cjs` so that the load
// recorder is in place before webpack and its minimizer are required.

const fs = require('node:fs');
const path = require('node:path');

const MARKER = 'DK-TERSER-REPORT ';
// A production build changes the hash of every chunk when this salt changes,
// while the bytes it renders stay the same: the asset cache of the compilation
// misses and the cache of the minifier does not.
const SALTS = ['first', 'second'];

function minimizer(setup, webpack) {
	const TerserPlugin = require(setup.terserPlugin);
	const defaults = { compress: { passes: 2 } };
	if (setup.scenario === 'serial') return [new TerserPlugin({ parallel: false, terserOptions: defaults })];
	if (setup.scenario === 'custom-options') return [new TerserPlugin({ terserOptions: userOptions() })];
	if (setup.scenario === 'no-extract') return [new TerserPlugin({ extractComments: false, terserOptions: defaults })];
	if (setup.scenario === 'custom-minimizer') {
		return [
			{
				apply: (compiler) => {
					compiler.hooks.compilation.tap('fixture', (compilation) => {
						compilation.hooks.processAssets.tap({ name: 'fixture', stage: webpack.Compilation.PROCESS_ASSETS_STAGE_OPTIMIZE_SIZE }, (assets) => {
							for (const name of Object.keys(assets)) {
								compilation.updateAsset(name, new webpack.sources.RawSource(`${assets[name].source()}//x\n`), { minimized: true });
							}
						});
					});
				},
			},
		];
	}
	return undefined;
}

// Kept as one object so the child can report whether the adapter left the
// options the user wrote alone.
let options;
function userOptions() {
	if (!options) options = { mangle: false };
	return options;
}

// Another plugin that rewrites the asset, before or after the minifier runs.
function rewritePlugin(webpack, stage) {
	return {
		apply: (compiler) => {
			compiler.hooks.compilation.tap('fixture', (compilation) => {
				compilation.hooks.processAssets.tap({ name: 'fixture', stage }, (assets) => {
					for (const name of Object.keys(assets)) {
						if (!name.endsWith('.js')) continue;
						compilation.updateAsset(name, new webpack.sources.RawSource(`${assets[name].source()}\nglobalThis.injected = 1;\n`));
					}
				});
			});
		},
	};
}

// Another plugin that rewrites the emitted file itself, after the compiler has
// written it and before anything reads it back.
function diskPlugin(setup) {
	return {
		apply: (compiler) => {
			compiler.hooks.afterEmit.tap('fixture', (compilation) => {
				for (const asset of compilation.getAssets()) {
					if (asset.name.endsWith('.js')) fs.appendFileSync(path.join(setup.output, asset.name), '\nglobalThis.appended = 1;\n');
				}
			});
		},
	};
}

function configuration(setup, webpack) {
	const plugins = [new (require('./collector.cjs'))({ proofPath: setup.proofPath, originals: setup.originals })];
	// Before the collector, so that its own afterEmit runs first and the bytes it
	// compares are the ones that stayed on disk.
	if (setup.scenario === 'disk-rewrite') plugins.unshift(diskPlugin(setup));
	const stages = { 'late-rewrite': webpack.Compilation.PROCESS_ASSETS_STAGE_REPORT, 'early-rewrite': webpack.Compilation.PROCESS_ASSETS_STAGE_ADDITIONS };
	if (stages[setup.scenario] !== undefined) plugins.push(rewritePlugin(webpack, stages[setup.scenario]));
	const minimize = setup.scenario !== 'unminified';
	return {
		mode: 'production',
		context: setup.context,
		entry: setup.entry,
		output: { path: setup.output, filename: setup.filename || 'main.js', iife: false, hashSalt: SALTS[0] },
		externals: { 'some-ext': 'commonjs some-ext' },
		target: 'node',
		resolve: { modules: [setup.modules] },
		optimization: { minimize, minimizer: minimizer(setup, webpack), concatenateModules: true, usedExports: true },
		cache: setup.cacheDirectory ? { type: 'filesystem', cacheDirectory: setup.cacheDirectory, name: 'terser-fixture' } : false,
		plugins,
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

async function compile(setup, webpack, salt) {
	const configured = configuration(setup, webpack);
	if (salt) configured.output.hashSalt = salt;
	for (const key of Object.keys(configured.optimization)) {
		if (configured.optimization[key] === undefined) delete configured.optimization[key];
	}
	const compiler = webpack(configured);
	await run(compiler);
	// Also what writes the filesystem cache this compiler was given.
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	return configured;
}

async function main() {
	const setup = JSON.parse(process.env.DK_TERSER_SETUP);
	const webpack = require(setup.webpackRoot);
	const proofs = [];
	const configured = await compile(setup, webpack, setup.salt);
	proofs.push(JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')));
	// A second compilation of this process, with every chunk hashed differently
	// and rendered identically: the asset cache of the compilation misses, and
	// the minifier finds the output of the first one waiting for it.
	if (setup.scenario === 'warm') {
		await compile(setup, webpack, SALTS[1]);
		proofs.push(JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')));
	}
	await new Promise((resolve) => setTimeout(resolve, 0));
	process.stdout.write(
		`${MARKER}${JSON.stringify({
			terserPlugin: require(path.join(path.dirname(path.dirname(setup.terserPlugin)), 'package.json')).version,
			terser: require(path.join(path.dirname(path.dirname(setup.terserEntry)), 'package.json')).version,
			userOptions: options === undefined ? undefined : { shared: configured.optimization.minimizer[0].options.minimizer.options === options, keys: Object.keys(options).sort() },
			// False when the parallel workers did the minifying: terser is then never
			// loaded by this process at all.
			terserLoadedHere: Boolean(globalThis[Symbol.for('dk.sbom.webpack.cjs')].getByFile(setup.terserEntry)),
			emitted: fs.readdirSync(setup.output).sort(),
			proofs,
		})}\n`,
	);
}

module.exports = { MARKER, SALTS, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
