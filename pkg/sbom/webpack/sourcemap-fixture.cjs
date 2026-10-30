'use strict';

// Test-only fixture for sourcemap-evidence.test.cjs.
//
// The parent builds a workspace with fixture.cjs and hands the child the paths
// and the scenario; this file is also the child entry point, run as
// `node --require runtime-preload.cjs sourcemap-fixture.cjs` so that the load
// recorder is in place before webpack is required.
//
// The adapter is driven directly: it describes one asset at a time, and this
// slice does not yet wire it into the collector.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { installSourcemapEvidence } = require('./sourcemap-evidence.cjs');

const MARKER = 'DK-SOURCEMAP-REPORT ';
const SOURCES = {
	'map.js': "import { lazy } from './lazy.js';\nconsole.log(lazy());\n",
	'lazy.js': 'export function lazy() { return "lazy"; }\n',
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

// The same binding the collector performs: a materialized file is bound to its
// component only when its bytes are the bytes of its original counterpart.
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

// Another plugin working in the very stage the source maps are written in, and
// one writing an asset of its own there.
function scenarioPlugin(setup, webpack) {
	const stage = webpack.Compilation.PROCESS_ASSETS_STAGE_DEV_TOOLING;
	return {
		apply(compiler) {
			compiler.hooks.compilation.tap('fixture', (compilation) => {
				if (setup.scenario === 'company') {
					compilation.hooks.processAssets.tap({ name: 'fixture', stage }, (assets) => {
						for (const name of Object.keys(assets)) {
							if (name.endsWith('.js')) compilation.updateAsset(name, (old) => new webpack.sources.ConcatSource(old, '\n/* fixture */'));
						}
					});
				}
				if (setup.scenario === 'extra-asset') {
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: stage + 0.5 }, () => {
						compilation.emitAsset('extra.txt', new webpack.sources.RawSource('written beside the maps'));
					});
				}
				if (setup.scenario === 'forged-url') {
					// The comment of a map that was never written.
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: stage + 0.5 }, (assets) => {
						for (const name of Object.keys(assets)) {
							if (!name.endsWith('.js')) continue;
							const text = assets[name].source().toString().replace(/\n\/\/# sourceMappingURL=.*$/, '\n//# sourceMappingURL=https://example.test/x.map');
							compilation.updateAsset(name, new webpack.sources.RawSource(text));
						}
					});
				}
			});
		},
	};
}

// A plugin of someone else's, derived from the one that writes source maps.
function derivedPlugin(setup, webpack) {
	if (setup.scenario !== 'derived-plugin') return [];
	class Derived extends webpack.SourceMapDevToolPlugin {}
	return [new Derived({ filename: '[file].map' })];
}

function evidencePlugin(setup, reports) {
	return {
		apply(compiler) {
			const evidenceFor = installSourcemapEvidence(compiler, verifier(setup));
			compiler.hooks.afterEmit.tapPromise('fixture', async (compilation) => {
				const rows = [];
				for (const asset of compilation.getAssets()) {
					const result = await evidenceFor(compilation, asset.name);
					rows.push({
						name: asset.name,
						status: result.failure ? result.failure.status : result.status === 'none' ? 'none' : 'present',
						reason: result.failure ? result.failure.reason : undefined,
						input: result.input ? digest(result.input) : undefined,
						output: result.output ? digest(result.output) : undefined,
						trailer: result.input && result.output ? result.output.slice(result.input.length).toString('utf8') : undefined,
						units: (result.units || []).map((unit) => unit.path),
					});
				}
				rows.sort((a, b) => (a.name < b.name ? -1 : 1));
				reports.push(rows);
			});
		},
	};
}

function configuration(setup, webpack, reports) {
	return {
		mode: 'production',
		context: setup.context,
		entry: setup.entry,
		output: { path: setup.output, filename: setup.scenario === 'nested' ? 'scripts/main.js' : 'main.js' },
		target: 'web',
		devtool: setup.scenario === 'no-maps' || setup.scenario === 'derived-plugin' ? false : 'source-map',
		resolve: { modules: [setup.modules] },
		optimization: { minimize: setup.scenario !== 'unminified', concatenateModules: false },
		cache: false,
		plugins: [evidencePlugin(setup, reports), scenarioPlugin(setup, webpack), ...derivedPlugin(setup, webpack)],
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
	const setup = JSON.parse(process.env.DK_SOURCEMAP_SETUP);
	const webpack = require(setup.webpackRoot);
	const reports = [];
	const compiler = webpack(configuration(setup, webpack, reports));
	await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	const emitted = {};
	for (const name of fs.readdirSync(setup.output, { recursive: true }).sort()) {
		const file = path.join(setup.output, name);
		if (fs.statSync(file).isFile()) emitted[name.split(path.sep).join('/')] = digest(fs.readFileSync(file));
	}
	process.stdout.write(`${MARKER}${JSON.stringify({ webpack: webpack.version, emitted, rows: reports[0] || [] })}\n`);
}

module.exports = { MARKER, SOURCES, addSources, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
