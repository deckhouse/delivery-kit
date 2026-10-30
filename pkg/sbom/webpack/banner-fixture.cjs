'use strict';

// Test-only fixture for banner-evidence.test.cjs.
//
// The parent builds a workspace with fixture.cjs and hands the child the paths
// and the scenario; this file is also the child entry point, run as
// `node --require runtime-preload.cjs banner-fixture.cjs` so that the load
// recorder is in place before webpack is required.
//
// The adapter is only reachable through the collector, so every scenario here
// is a whole collected build, in the shape redoc builds: a banner of several
// lines in front of a minified bundle.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const Collector = require('./collector.cjs');

const MARKER = 'DK-BANNER-REPORT ';
const BANNER = `ReDoc - OpenAPI/Swagger-generated API Reference Documentation
-------------------------------------------------------------
  Version: "2.4.0"
  Repo: https://github.com/Redocly/redoc`;
const SOURCES = {
	'banner.js': "import('./lazy.js').then(({ lazy }) => console.log(lazy()));\n",
	'lazy.js': 'export function lazy() { return "lazy"; }\n',
	'worker-entry.js': 'self.onmessage = () => self.postMessage("worked");\n',
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

function banners(setup, webpack) {
	const { BannerPlugin } = webpack;
	switch (setup.scenario) {
		case 'single-line':
			return [new BannerPlugin('ReDoc 2.4.0')];
		case 'function':
			return [new BannerPlugin(() => BANNER)];
		case 'raw':
			return [new BannerPlugin({ banner: `/* ${BANNER.split('\n')[0]} */`, raw: true })];
		case 'footer':
			return [new BannerPlugin({ banner: BANNER, footer: true })];
		case 'twice':
			return [new BannerPlugin(BANNER), new BannerPlugin('and one more')];
		case 'templated':
			return [new BannerPlugin('built into [name]')];
		case 'derived': {
			class Derived extends BannerPlugin {}
			return [new Derived(BANNER)];
		}
		case 'none':
			return [];
		case 'mutated-banner': {
			// The plugin wraps its banner once, when it is built; options read
			// afterwards are not the text that was added.
			const plugin = new BannerPlugin(BANNER);
			plugin.options = { ...plugin.options, banner: 'a banner nobody added' };
			return [plugin];
		}
		case 'applied-inside':
			// A plugin of someone else's that adds a banner of its own choosing:
			// the options this adapter would read are not the ones that were used.
			return [
				{
					apply(compiler) {
						new BannerPlugin('a banner of my own').apply(compiler);
					},
				},
			];
		default:
			return [new BannerPlugin(BANNER)];
	}
}

// What a worker plugin does: a compilation of its own, whose asset is emitted
// into this one. A child compiler copies the taps of the compiler that made it,
// so the banner of this build is put in front of that asset too.
function childPlugin(setup, webpack) {
	return {
		apply(compiler) {
			if (setup.scenario !== 'child') return;
			compiler.hooks.make.tapAsync('fixture', (compilation, callback) => {
				const child = compilation.createChildCompiler('worker', { filename: 'worker.js' }, [
					new webpack.webworker.WebWorkerTemplatePlugin(),
					new webpack.LoaderTargetPlugin('webworker'),
				]);
				new webpack.EntryPlugin(compiler.context, path.join(setup.modules, 'app', 'worker-entry.js'), 'main').apply(child);
				new webpack.optimize.LimitChunkCountPlugin({ maxChunks: 1 }).apply(child);
				child.runAsChild((error) => callback(error));
			});
		},
	};
}

// Another plugin working in the very stage the banners are added in.
function scenarioPlugin(setup, webpack) {
	const stage = setup.scenario === 'before-banner' ? webpack.Compilation.PROCESS_ASSETS_STAGE_PRE_PROCESS : webpack.Compilation.PROCESS_ASSETS_STAGE_ADDITIONS;
	return {
		apply(compiler) {
			if (setup.scenario !== 'company' && setup.scenario !== 'before-banner') return;
			compiler.hooks.compilation.tap('fixture', (compilation) => {
				compilation.hooks.processAssets.tap({ name: 'fixture', stage }, (assets) => {
					for (const name of Object.keys(assets)) {
						compilation.updateAsset(name, (old) => new webpack.sources.ConcatSource('/* fixture */\n', old));
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
		entry: setup.entry,
		output: { path: setup.output, filename: 'main.[contenthash].js', chunkFilename: 'chunk.[contenthash].js' },
		target: 'web',
		resolve: { modules: [setup.modules] },
		optimization: { minimize: setup.scenario !== 'unminified', realContentHash: true, concatenateModules: false },
		cache: false,
		plugins: [new Collector({ proofPath: setup.proofPath, originals: setup.originals }), ...banners(setup, webpack), scenarioPlugin(setup, webpack), childPlugin(setup, webpack)],
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
	const setup = JSON.parse(process.env.DK_BANNER_SETUP);
	const webpack = require(setup.webpackRoot);
	const compiler = webpack(configuration(setup, webpack));
	await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	const emitted = {};
	for (const name of fs.readdirSync(setup.output).sort()) emitted[name] = digest(fs.readFileSync(path.join(setup.output, name)));
	process.stdout.write(`${MARKER}${JSON.stringify({ webpack: webpack.version, emitted, proof: JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')) })}\n`);
}

module.exports = { MARKER, BANNER, SOURCES, addSources, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
