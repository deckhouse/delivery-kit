'use strict';

// Test-only fixture for license-evidence.test.cjs.
//
// The parent builds a workspace with fixture.cjs and hands the child the paths
// and the scenario; this file is also the child entry point, run as
// `node --require runtime-preload.cjs license-fixture.cjs` so that the load
// recorder is in place before webpack and its minimizer are required.
//
// The sources carry the two comment shapes the default minifier takes out of an
// asset, so the build really writes a comments file of its own.

const fs = require('node:fs');
const path = require('node:path');

const MARKER = 'DK-LICENSE-REPORT ';
const SUFFIX = '.LICENSE.txt';
const COMMENTS = ['/*! pkg-a v1.2.3 | (c) 2024 | MIT */', '/** @license pkg-b 4.5.6 Apache-2.0 */'];
const SOURCES = {
	'licensed.js': `${COMMENTS[0]}\nimport { a } from 'pkg-a';\n${COMMENTS[1]}\nexport const licensed = () => a();\n`,
	'with-license.js': "import { licensed } from './licensed.js';\nconsole.log(licensed());\n",
};

function addSources(area) {
	for (const [name, content] of Object.entries(SOURCES)) {
		fs.writeFileSync(path.join(area.modules, 'app', name), content);
		fs.writeFileSync(path.join(area.originalOf('app'), name), content);
	}
}

// Every way of putting something else where the minifier writes its comments.
// The plugin keeps an asset that is already there (its own index.js, where it
// returns the existing asset instead of emitting), so a file written before it
// runs is the file that stays.
function forged(scenario) {
	if (scenario === 'forged-comment') return '/*! not a comment of this asset */\n';
	if (scenario === 'unsorted-comments') return `${COMMENTS[1]}\n\n${COMMENTS[0]}\n`;
	if (scenario === 'repeated-comments') return `${COMMENTS[0]}\n\n${COMMENTS[0]}\n`;
	// Text the asset was minified from, but no comment.
	if (scenario === 'not-a-comment') return 'console\n';
	return null;
}

function scenarioPlugin(setup, webpack) {
	const text = forged(setup.scenario);
	return {
		apply(compiler) {
			compiler.hooks.compilation.tap('fixture', (compilation) => {
				if (text !== null) {
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: webpack.Compilation.PROCESS_ASSETS_STAGE_ADDITIONS }, () => {
						for (const asset of compilation.getAssets()) {
							if (asset.name.endsWith('.js')) compilation.emitAsset(`${asset.name}${SUFFIX}`, new webpack.sources.RawSource(text), { extractedComments: true });
						}
					});
				}
				if (setup.scenario === 'foreign-comments') {
					// Before the minifier and before the hashes, so that it is an asset
					// of this compilation like any other.
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: webpack.Compilation.PROCESS_ASSETS_STAGE_ADDITIONS }, () => {
						compilation.emitAsset(`nothing.js${SUFFIX}`, new webpack.sources.RawSource('/*! nobody wrote this */\n'), { extractedComments: true });
					});
				}
				if (setup.scenario === 'orphan-owner') {
					// A licensed file of its own, emitted before the minifier runs: it
					// is minified and gets a comments file like any asset, but no chunk
					// of this compilation ever built it.
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: webpack.Compilation.PROCESS_ASSETS_STAGE_ADDITIONS }, () => {
						compilation.emitAsset('orphan.js', new webpack.sources.RawSource(`${COMMENTS[0]}\nconsole.log('orphan');\n`));
					});
				}
				if (setup.scenario === 'undescribed-owner') {
					webpack.javascript.JavascriptModulesPlugin.getCompilationHooks(compilation).render.tap('fixture', (source) => source);
				}
				if (setup.scenario === 'rewritten-comments') {
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: webpack.Compilation.PROCESS_ASSETS_STAGE_REPORT }, (assets) => {
						for (const name of Object.keys(assets)) {
							if (name.endsWith(SUFFIX)) compilation.updateAsset(name, new webpack.sources.RawSource(`${assets[name].source()}/*! appended */\n`));
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
		output: { path: setup.output, filename: setup.filename || 'main.js', iife: false, clean: true },
		externals: { 'some-ext': 'commonjs some-ext' },
		target: 'node',
		resolve: { modules: [setup.modules] },
		// Whether the comments survive as far as the minifier depends on how the
		// modules holding them are concatenated, so both shapes are built.
		optimization: { minimize: true, concatenateModules: setup.scenario === 'concatenated', usedExports: true },
		cache: false,
		plugins: [new (require('./collector.cjs'))({ proofPath: setup.proofPath, originals: setup.originals }), scenarioPlugin(setup, webpack)],
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
	const setup = JSON.parse(process.env.DK_LICENSE_SETUP);
	const webpack = require(setup.webpackRoot);
	const compiler = webpack(configuration(setup, webpack));
	await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	const emitted = {};
	for (const name of fs.readdirSync(setup.output).sort()) emitted[name] = fs.readFileSync(path.join(setup.output, name), 'utf8');
	process.stdout.write(`${MARKER}${JSON.stringify({ emitted, proof: JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')) })}\n`);
}

module.exports = { MARKER, SUFFIX, COMMENTS, addSources, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
