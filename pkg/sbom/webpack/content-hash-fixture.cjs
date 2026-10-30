'use strict';

// Test-only fixture for content-hash-evidence.test.cjs.
//
// The parent builds a workspace with fixture.cjs and hands the child the paths
// and the scenario; this file is also the child entry point, run as
// `node --require runtime-preload.cjs content-hash-fixture.cjs` so that the load
// recorder is in place before webpack is required.
//
// The adapter is driven directly: it describes one asset at a time, and this
// slice does not yet wire it into the collector.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { installContentHashEvidence } = require('./content-hash-evidence.cjs');

const MARKER = 'DK-CONTENT-HASH-REPORT ';
const SOURCES = {
	// Imported lazily, so that the main chunk carries the hashed name of the
	// chunk it loads and both files are rewritten for their real content.
	'split.js': "import('./lazy.js').then(({ lazy }) => console.log(lazy()));\n",
	'lazy.js': 'export function lazy() { return "lazy"; }\n',
};

function addSources(area) {
	for (const [name, content] of Object.entries(SOURCES)) {
		fs.writeFileSync(path.join(area.modules, 'app', name), content);
		fs.writeFileSync(path.join(area.originalOf('app'), name), content);
	}
}

// The same binding the collector performs: a materialized file is bound to its
// component only when its bytes are the bytes of its original counterpart.
function verifier(setup) {
	return async (resource) => {
		const actual = path.resolve(resource);
		// The one file this adapter checks, refused the way an unverifiable
		// instrument source is refused.
		if (setup.scenario === 'unverified' && actual.endsWith('RealContentHashPlugin.js')) {
			return { failure: { status: 'no-data', reason: `outside the declared roots: ${actual}` } };
		}
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

// Another plugin working in the very stage the content hashes are replaced in.
function scenarioPlugin(setup, webpack) {
	const stage = webpack.Compilation.PROCESS_ASSETS_STAGE_OPTIMIZE_HASH;
	return {
		apply(compiler) {
			compiler.hooks.compilation.tap('fixture', (compilation) => {
				if (setup.scenario === 'altered') {
					compilation.hooks.processAssets.tap({ name: 'fixture', stage }, (assets) => {
						for (const name of Object.keys(assets)) {
							if (name.endsWith('.js')) compilation.updateAsset(name, new webpack.sources.RawSource(`${assets[name].source()}\nglobalThis.altered = 1;\n`));
						}
					});
				}
				if (setup.scenario === 'renamed' || setup.scenario === 'late-rename') {
					// Before the plugin in the one case and after it in the other, both
					// inside the window this adapter watches.
					const when = setup.scenario === 'renamed' ? stage : stage + 0.5;
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: when }, () => {
						for (const asset of compilation.getAssets()) {
							if (asset.name.endsWith('.js')) compilation.renameAsset(asset.name, `extra-${asset.name}`);
						}
					});
				}
				if (setup.scenario === 'injected') {
					// After the plugin, a tap that consistently swaps one new hash for
					// text that is not a hash: in names, bytes and the recorded hashes.
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: stage + 0.5 }, () => {
						const chunk = compilation.getAssets().find((asset) => /chunk/.test(asset.name) && asset.info.contenthash);
						const hash = [].concat(chunk.info.contenthash)[0];
						const text = 'aa;globalThis.injected=1;aa';
						for (const asset of compilation.getAssets()) {
							const hashes = [].concat(asset.info.contenthash || []).map((value) => (value === hash ? text : value));
							const bytes = asset.source.source().toString().split(hash).join(text);
							compilation.updateAsset(asset.name, new webpack.sources.RawSource(bytes), { contenthash: hashes });
							if (asset.name.includes(hash)) compilation.renameAsset(asset.name, asset.name.split(hash).join(text));
						}
					});
				}
				if (setup.scenario === 'between') {
					// After the minifier is done with the asset and before the content
					// hashes of the compilation are replaced.
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: stage - 2 }, (assets) => {
						for (const name of Object.keys(assets)) {
							if (name.endsWith('.js')) compilation.updateAsset(name, new webpack.sources.RawSource(`${assets[name].source()}\nglobalThis.between = 1;\n`));
						}
					});
				}
				if (setup.scenario === 'updatehash') {
					// A tap that decides the new hashes itself, returning the one the
					// plugin would have computed is not the point: nothing may tap it.
					const RealContentHashPlugin = require(path.join(setup.webpackRoot, 'lib', 'optimize', 'RealContentHashPlugin.js'));
					RealContentHashPlugin.getCompilationHooks(compilation).updateHash.tap('fixture', (content, oldHash) => `${oldHash.slice(0, oldHash.length - 1)}f`);
				}
			});
		},
	};
}

function evidencePlugin(setup, reports) {
	return {
		apply(compiler) {
			const evidenceFor = installContentHashEvidence(compiler, verifier(setup));
			compiler.hooks.afterEmit.tapPromise('fixture', async (compilation) => {
				const rows = [];
				for (const asset of compilation.getAssets()) {
					const result = await evidenceFor(compilation, asset.name);
					rows.push({
						name: asset.name,
						status: result.failure ? result.failure.status : result.status === 'none' ? 'none' : 'present',
						reason: result.failure ? result.failure.reason : undefined,
						was: result.name,
						input: result.input ? digest(result.input) : undefined,
						output: result.output ? digest(result.output) : undefined,
					});
				}
				rows.sort((a, b) => (a.name < b.name ? -1 : 1));
				reports.push(rows);
			});
		},
	};
}

function configuration(setup, webpack, reports) {
	const collecting = typeof setup.proofPath === 'string';
	return {
		mode: 'production',
		context: setup.context,
		entry: setup.split ? setup.entry : setup.plainEntry,
		output: { path: setup.output, filename: '[contenthash].js', chunkFilename: 'chunk.[contenthash].js', iife: false },
		externals: { 'some-ext': 'commonjs some-ext' },
		target: 'node',
		resolve: { modules: [setup.modules] },
		optimization: { minimize: setup.minimize === true || setup.scenario === 'minified', realContentHash: true, concatenateModules: true, usedExports: true },
		cache: false,
		plugins: collecting
			? [new (require('./collector.cjs'))({ proofPath: setup.proofPath, originals: setup.originals }), scenarioPlugin(setup, webpack)]
			: [evidencePlugin(setup, reports), scenarioPlugin(setup, webpack)],
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
	const setup = JSON.parse(process.env.DK_CONTENT_HASH_SETUP);
	const webpack = require(setup.webpackRoot);
	const reports = [];
	const compiler = webpack(configuration(setup, webpack, reports));
	await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	const emitted = {};
	for (const name of fs.readdirSync(setup.output).sort()) emitted[name] = digest(fs.readFileSync(path.join(setup.output, name)));
	process.stdout.write(
		`${MARKER}${JSON.stringify({
			webpack: webpack.version,
			emitted,
			rows: reports[0] || [],
			proof: typeof setup.proofPath === 'string' ? JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')) : undefined,
		})}\n`,
	);
}

module.exports = { MARKER, SOURCES, addSources, digest, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
