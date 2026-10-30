'use strict';

// Test-only fixture for copy-evidence.test.cjs.
//
// The parent packs the installed copy-webpack-plugin once and hands each child
// the paths it needs; this file is also the child entry point, run as
// `node --require runtime-preload.cjs copy-fixture.cjs` so that the load
// registry is in place before the plugin is required here.

const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { installCopyEvidence } = require('./copy-evidence.cjs');

const MARKER = 'DK-COPY-REPORT ';

// The original root is extracted from the archive npm produced out of the
// installed distribution, never copied from it, and is bound to the integrity
// npm reported and this code recomputed from the archive bytes.
function packPackage(root, installed) {
	const tarballs = path.join(root, 'tarballs');
	fs.mkdirSync(tarballs, { recursive: true });
	const report = JSON.parse(
		execFileSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', tarballs, installed], {
			encoding: 'utf8',
			env: { ...process.env, NPM_CONFIG_UPDATE_NOTIFIER: 'false', NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_FUND: 'false', GIT_TERMINAL_PROMPT: '0' },
		}),
	)[0];
	const tarball = path.join(tarballs, report.filename);
	const integrity = `sha512-${crypto.createHash('sha512').update(fs.readFileSync(tarball)).digest('base64')}`;
	if (integrity !== report.integrity) throw new Error(`npm reported a different integrity for ${installed}`);
	const original = path.join(root, 'original');
	fs.mkdirSync(original, { recursive: true });
	execFileSync('tar', ['-xzf', tarball, '-C', original, '--strip-components=1']);
	const manifest = JSON.parse(fs.readFileSync(path.join(original, 'package.json'), 'utf8'));
	return {
		root: fs.realpathSync(installed),
		original,
		tarball,
		integrity,
		component: {
			id: `node:${manifest.name}@${manifest.version}`,
			name: manifest.name,
			version: manifest.version,
			source: { kind: 'node', locator: `file://${tarball}`, checksum: integrity },
		},
	};
}

// The same binding the collector performs: the materialized file is bound to
// the component only when its bytes are the bytes of the original counterpart.
function verifier(setup) {
	return async (resource) => {
		const actual = path.resolve(resource);
		const binding = setup.originals.find((candidate) => actual.startsWith(candidate.root.endsWith(path.sep) ? candidate.root : candidate.root + path.sep));
		if (!binding) return { failure: { status: 'no-data', reason: `outside the declared roots: ${actual}` } };
		const bytes = read(actual);
		if (bytes.failure) return bytes;
		const originalBytes = read(path.join(binding.originalRoot, path.relative(binding.root, actual)));
		if (originalBytes.failure) return originalBytes;
		const sha256 = digest(bytes.bytes);
		if (sha256 !== digest(originalBytes.bytes)) {
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

// What some copy plugin instance of this compiler is configured to copy; the
// report then says what the adapter makes of the assets it produced.
function patterns(setup) {
	const asset = (relative) => path.join(setup.context, 'assets', relative);
	switch (setup.scenario) {
		case 'directory':
		case 'warm':
			return [{ from: asset('a'), to: 'dir' }];
		case 'glob':
			return [{ from: '**/*.txt', context: asset('a'), to: 'glob' }];
		case 'collide':
			return [
				{ from: asset('a/one.txt'), to: 'same.txt' },
				{ from: asset('b/one.txt'), to: 'same.txt' },
			];
		case 'duplicate':
			// The same file copied to the same target twice: one copy of one file,
			// observed twice.
			return [
				{ from: asset('a/one.txt'), to: 'same.txt' },
				{ from: asset('a/one.txt'), to: 'same.txt' },
			];
		case 'force':
			return [
				{ from: asset('a/one.txt'), to: 'same.txt' },
				{ from: asset('b/one.txt'), to: 'same.txt', force: true },
			];
		case 'transform':
			// The transform hands back the very buffer it was given, so only the
			// configured transformation itself can keep this copy undescribed.
			return [
				{ from: asset('a/one.txt'), to: 'transformed.txt', transform: (content) => content },
				{ from: asset('a/two.txt'), to: 'plain.txt' },
			];
		case 'missing':
			return [
				{ from: 'missing.txt', context: asset('a'), to: 'missing.txt', noErrorOnMissing: true },
				{ from: asset('a/two.txt'), to: 'plain.txt' },
			];
		default:
			return [{ from: asset('a/one.txt'), to: 'late.txt' }];
	}
}

function scenarioPlugin(setup) {
	return {
		apply(compiler) {
			const { RawSource } = compiler.webpack.sources;
			if (setup.scenario === 'changed-after-load') {
				// Both copies change the same way, so the verifier still binds the file
				// to its original; only the bytes this process loaded are now stale.
				for (const root of [setup.pluginRoot, setup.originals[0].originalRoot]) {
					fs.appendFileSync(path.join(root, 'dist', 'processPattern.js'), '\n// appended after loading\n');
				}
			}
			if (setup.scenario === 'swapped-module') {
				// A forwarding replacement of one of the modules that decide what is
				// copied where, in place while the copy runs.
				compiler.hooks.thisCompilation.tap('fixture', () => {
					const preProcess = require(path.join(setup.pluginRoot, 'dist', 'preProcessPattern.js'));
					const original = preProcess.default;
					if (original.swapped) return;
					preProcess.default = Object.assign((...args) => original(...args), { swapped: true });
				});
			}
			if (setup.scenario === 'pre-install-swap') {
				// A forwarding replacement of the copy step, installed before the
				// evidence adapter: whatever it does, the copies no longer come from
				// the function the loaded file exported.
				const post = require(path.join(setup.pluginRoot, 'dist', 'postProcessPattern.js'));
				const original = post.default;
				post.default = (...args) => original(...args);
			}
			if (setup.scenario === 'unknown') {
				compiler.hooks.thisCompilation.tap('fixture', (compilation) => {
					compilation.hooks.additionalAssets.tap('fixture', () => {
						compilation.emitAsset('unknown.txt', new RawSource(Buffer.from('one\n')), { copied: true });
					});
				});
			}
			if (setup.scenario === 'late-replacement') {
				compiler.hooks.compilation.tap('fixture', (compilation) => {
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: compiler.webpack.Compilation.PROCESS_ASSETS_STAGE_REPORT }, (assets) => {
						// The same bytes in a source of its own: indistinguishable from the
						// copy for anything that compares content.
						const existing = assets['late.txt'];
						compilation.updateAsset('late.txt', new RawSource(Buffer.from(existing.buffer())));
					});
				});
			}
		},
	};
}

function evidencePlugin(setup, reports) {
	return {
		apply(compiler) {
			const evidenceFor = installCopyEvidence(compiler, verifier(setup));
			compiler.hooks.afterEmit.tap('fixture', (compilation) => {
				const rows = [];
				for (const asset of compilation.getAssets()) {
					rows.push(describe(evidenceFor(compilation, asset.name), asset.name, asset.info && asset.info.copied === true, false));
				}
				for (const name of setup.probe || []) rows.push(describe(evidenceFor(compilation, name), name, false, true));
				rows.sort((a, b) => (a.name < b.name ? -1 : 1));
				reports.push(rows);
			});
		},
	};
}

function describe(result, name, copied, probe) {
	return {
		name,
		copied,
		probe,
		from: result.from,
		rewritten: result.rewritten,
		status: result.failure ? result.failure.status : 'present',
		reason: result.failure ? result.failure.reason : undefined,
	};
}

function configuration(setup, plugins) {
	return {
		mode: 'production',
		context: setup.context,
		entry: setup.entry,
		output: { path: setup.output, filename: 'main.js', iife: false },
		target: 'node',
		optimization: { minimize: false },
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

async function main() {
	const setup = JSON.parse(process.env.DK_COPY_SETUP);
	const webpack = require(setup.webpackRoot);
	const CopyPlugin = require(setup.pluginRoot);
	const reports = [];
	const compiler = webpack(configuration(setup, [new CopyPlugin({ patterns: patterns(setup) }), scenarioPlugin(setup), evidencePlugin(setup, reports)]));
	await run(compiler);
	if (setup.scenario === 'warm') await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	process.stdout.write(`${MARKER}${JSON.stringify({ plugin: require(path.join(setup.pluginRoot, 'package.json')).version, builds: reports })}\n`);
}

module.exports = { MARKER, packPackage, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
