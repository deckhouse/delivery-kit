'use strict';

// Ahead of every webpack require of this file: the bootstrap evidence of the
// collector is a recording of the sources this process loads.
require('./runtime-preload.cjs');

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test, before, after } = require('node:test');

const DkSbomWebpackCollector = require('./collector.cjs');
const { PACKAGES, createFixture, configuration, run, readProof, sha256 } = require('./fixture.cjs');
const webpack = require('webpack');
const CopyPlugin = require('copy-webpack-plugin');

let fixture;
let scratch;
let distributions;

before(() => {
	scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-collector-')));
	fixture = createFixture(scratch, { bootstrap: true });
	distributions = fixture.distributions;
});

after(() => {
	fs.rmSync(scratch, { recursive: true, force: true });
});

function asset(proof, assetPath) {
	const row = proof.assets.find((candidate) => candidate.path === assetPath);
	assert.ok(row, `no row for ${assetPath} in ${proof.assets.map((candidate) => candidate.path).join(', ')}`);
	return row;
}

test('binds an emitted chunk to the concatenated modules it really contains', async () => {
	const { area, proof } = await fixture.buildPrimary('primary');

	assert.equal(proof.version, 1);
	assert.equal(proof.sourceRoot, area.output);
	assert.ok(!area.proofPath.startsWith(`${area.output}${path.sep}`), 'proof must live outside the output root');
	assert.deepEqual(
		proof.assets.map((row) => row.path).sort(),
		['main.js', 'notice.txt', 'undeclared.txt', 'vendor.js'],
	);
	for (const row of proof.assets) {
		for (const field of ['includedComponents', 'components', 'inputs', 'tools']) {
			assert.ok(Array.isArray(row[field]), `${row.path} must carry ${field}`);
		}
		assert.match(row.sha256, /^sha256:[0-9a-f]{64}$/);
		assert.equal(row.size, fs.statSync(path.join(area.output, row.path)).size);
		assert.equal(row.sha256, sha256(path.join(area.output, row.path)));
	}

	const main = asset(proof, 'main.js');
	assert.equal(main.status, 'present');
	assert.equal(main.reason, undefined);
	assert.deepEqual(main.includedComponents, ['node:app@0.1.0', 'node:pkg-a@1.2.3', 'node:pkg-b@4.5.6', 'node:webpack@5.94.0']);
	// The bootstrap this chunk was rendered from: the chunk renderer of the pinned
	// webpack, the three helper modules it reads, the stock APIPlugin tap that
	// shaped its module content, and the class that wrote the line reaching the
	// external this bundle references.
	const bootstrapSources = ['lib/javascript/JavascriptModulesPlugin.js', 'lib/RuntimeGlobals.js', 'lib/RuntimeTemplate.js', 'lib/Template.js', 'lib/APIPlugin.js', 'lib/ExternalModule.js'].map((relative) =>
		path.join(fixture.bootstrap.binding.root, relative),
	);
	assert.deepEqual(
		main.inputs,
		[
			{ kind: 'source', path: area.installed('app/index.js'), sha256: sha256(area.installed('app/index.js')), components: ['node:app@0.1.0'], disposition: 'included' },
			{ kind: 'source', path: area.installed('pkg-a/index.js'), sha256: sha256(area.installed('pkg-a/index.js')), components: ['node:pkg-a@1.2.3'], disposition: 'included' },
			{ kind: 'source', path: area.installed('pkg-b/index.js'), sha256: sha256(area.installed('pkg-b/index.js')), components: ['node:pkg-b@4.5.6'], disposition: 'included' },
			...bootstrapSources.map((source) => ({ kind: 'source', path: source, sha256: sha256(source), components: ['node:webpack@5.94.0'], disposition: 'included' })),
		].sort((left, right) => (left.path < right.path ? -1 : 1)),
	);
	assert.deepEqual(main.components, [
		distributions.app.component,
		distributions['pkg-a'].component,
		distributions['pkg-b'].component,
		fixture.bootstrap.binding.component,
	]);
	for (const component of main.components) {
		assert.match(component.source.checksum, /^sha512-[A-Za-z0-9+/]+={0,2}$/);
	}
	assert.equal(JSON.stringify(proof).includes('pkg-c'), false, 'the unused installed package must not be claimed');
	assert.equal(JSON.stringify(proof).includes('some-ext'), false, 'an external is referenced, not bundled');
});

test('binds a declared plain copied asset to its own component only', async () => {
	const { area, proof } = await fixture.buildPrimary('copied');

	const notice = asset(proof, 'notice.txt');
	assert.equal(notice.status, 'present');
	assert.deepEqual(notice.includedComponents, ['node:pkg-a@1.2.3']);
	assert.deepEqual(notice.components, [distributions['pkg-a'].component]);
	assert.deepEqual(notice.inputs, [
		{
			kind: 'source',
			path: area.installed('pkg-a/NOTICE.txt'),
			sha256: sha256(area.installed('pkg-a/NOTICE.txt')),
			components: ['node:pkg-a@1.2.3'],
			disposition: 'included',
		},
	]);
	assert.deepEqual(notice.tools, []);
});

test('refuses a copied bundle and binds an undeclared copy to its observed source', async () => {
	const { area, proof } = await fixture.buildPrimary('opaque');

	const vendor = asset(proof, 'vendor.js');
	assert.equal(vendor.status, 'no-data');
	assert.match(vendor.reason, /copied \.js carries an unsupplied nested composition/);
	assert.deepEqual(vendor.components, []);
	assert.deepEqual(vendor.includedComponents, []);

	// Nothing declares this copy: the observed one is what binds it.
	const undeclared = asset(proof, 'undeclared.txt');
	assert.equal(undeclared.status, 'present');
	assert.deepEqual(undeclared.includedComponents, ['node:pkg-a@1.2.3']);
	assert.deepEqual(undeclared.inputs, [
		{
			kind: 'source',
			path: area.installed('pkg-a/LICENSE'),
			sha256: sha256(area.installed('pkg-a/LICENSE')),
			components: ['node:pkg-a@1.2.3'],
			disposition: 'included',
		},
	]);
});

test('reports hash-mismatch when a materialized source differs from its original', async () => {
	const { area, proof } = await fixture.buildPrimary('tampered', {
		// A same-length edit: only the bytes themselves can tell this one apart.
		beforeRun: (area) => fs.writeFileSync(area.installed('pkg-b/index.js'), PACKAGES['pkg-b'].files['index.js'].replace('"b"', '"B"')),
	});

	const main = asset(proof, 'main.js');
	assert.equal(main.status, 'hash-mismatch');
	assert.equal(main.reason, `materialized source differs from its original: ${area.installed('pkg-b/index.js')}`);
	assert.deepEqual(main.includedComponents, []);
	assert.deepEqual(main.inputs, []);
	assert.equal(main.sha256, sha256(path.join(area.output, 'main.js')));
	assert.equal(
		fs.readFileSync(path.join(distributions['pkg-b'].original, 'index.js'), 'utf8'),
		PACKAGES['pkg-b'].files['index.js'],
		'the original counterpart must stay untouched',
	);
	assert.equal(asset(proof, 'notice.txt').status, 'present', 'an unrelated asset keeps its own binding');
});

// A commonjs2 library taps the chunk renderer, so the bootstrap of the chunk
// carries code of a plugin this collector cannot attribute to a source.
test('reports no-data for a chunk whose library shaping it cannot attribute', async () => {
	const area = fixture.workspace('runtime');
	await run(
		configuration(area, {
			entry: area.installed('app/lib.js'),
			output: { path: area.output, filename: 'lib.js', library: { type: 'commonjs2' } },
			plugins: [new DkSbomWebpackCollector({ proofPath: area.proofPath, originals: area.originals })],
		}),
	);

	const lib = asset(readProof(area), 'lib.js');
	assert.equal(lib.status, 'no-data');
	assert.match(lib.reason, /AssignLibraryPlugin tapped render while renderMain ran/);
	assert.deepEqual(lib.includedComponents, []);
	assert.deepEqual(lib.components, []);
});

test('reports invalid when one copied asset has conflicting declared origins', async () => {
	const area = fixture.workspace('conflict');
	await run(
		configuration(area, {
			plugins: [
				new CopyPlugin({ patterns: [{ from: area.installed('pkg-a/NOTICE.txt'), to: 'notice.txt' }] }),
				new DkSbomWebpackCollector({
					proofPath: area.proofPath,
					originals: area.originals,
					copied: [
						{ from: area.installed('pkg-a/NOTICE.txt'), to: 'notice.txt' },
						{ from: area.installed('pkg-c/index.js'), to: 'notice.txt' },
					],
				}),
			],
		}),
	);

	const notice = asset(readProof(area), 'notice.txt');
	assert.equal(notice.status, 'invalid');
	assert.match(notice.reason, /conflicting declared origins/);
	assert.deepEqual(notice.components, []);
});

// A transforming pattern hands the asset content the plugin made up on the way,
// not the bytes any observed copy read.
test('reports no-data for an asset a transforming copy pattern produced', async () => {
	const area = fixture.workspace('transformed');
	await run(
		configuration(area, {
			plugins: [
				new CopyPlugin({
					patterns: [{ from: area.installed('pkg-a/NOTICE.txt'), to: 'notice.txt', transform: (content) => `${content}appended by the build\n` }],
				}),
				new DkSbomWebpackCollector({
					proofPath: area.proofPath,
					originals: area.originals,
					copied: [{ from: area.installed('pkg-a/NOTICE.txt'), to: 'notice.txt' }],
				}),
			],
		}),
	);

	const notice = asset(readProof(area), 'notice.txt');
	assert.equal(notice.status, 'no-data');
	// The pattern that rewrote the file is named, which says more about why
	// nothing is claimed than its bytes alone could.
	assert.match(notice.reason, /notice\.txt was copied while the pattern transforms the copied content/);
	assert.deepEqual(notice.includedComponents, []);
	assert.equal(notice.sha256, sha256(path.join(area.output, 'notice.txt')));
	assert.match(fs.readFileSync(path.join(area.output, 'notice.txt'), 'utf8'), /appended by the build/, 'the transformed bytes must be what the asset really carries');
});

test('reports invalid for a materialized source reached through a symlink', async () => {
	const area = fixture.workspace('symlinked');
	const installed = area.installed('pkg-b/index.js');
	fs.rmSync(installed);
	fs.symlinkSync(path.join(distributions['pkg-b'].original, 'index.js'), installed);
	await run(
		configuration(area, {
			resolve: { modules: [area.modules], symlinks: false },
			plugins: [new DkSbomWebpackCollector({ proofPath: area.proofPath, originals: area.originals })],
		}),
	);

	const main = asset(readProof(area), 'main.js');
	assert.equal(main.status, 'invalid');
	assert.equal(main.reason, `not a regular file: ${installed}`);
	assert.deepEqual(main.components, []);
});

test('reports no-data when a materialized source has no original counterpart', async () => {
	const area = fixture.workspace('uncovered', { isolateOriginals: true });
	fs.rmSync(area.originalOf('pkg-b/index.js'));
	await run(configuration(area, { plugins: [new DkSbomWebpackCollector({ proofPath: area.proofPath, originals: area.originals })] }));

	const main = asset(readProof(area), 'main.js');
	assert.equal(main.status, 'no-data');
	assert.equal(main.reason, `missing file ${area.originalOf('pkg-b/index.js')}`);
	assert.deepEqual(main.inputs, []);
});

test('refuses a proof path inside the output root', () => {
	const area = fixture.workspace('selfcontained');
	assert.throws(
		() =>
			webpack(
				configuration(area, {
					plugins: [new DkSbomWebpackCollector({ proofPath: path.join(area.output, 'proof.json'), originals: area.originals })],
				}),
			),
		/proofPath .* is inside the output root/,
	);
});

test('refuses conflicting identities for one component id', () => {
	const area = fixture.workspace('identity');
	const conflicting = { ...distributions['pkg-b'].component, id: distributions['pkg-a'].component.id };
	assert.throws(
		() => new DkSbomWebpackCollector({ proofPath: area.proofPath, originals: [...area.originals, { ...area.originals[1], component: conflicting }] }),
		/conflicting identities for component node:pkg-a@1\.2\.3/,
	);
});

test('refuses a webpack other than the supported one', () => {
	const area = fixture.workspace('version');
	const compiler = webpack(configuration(area, {}));
	Object.defineProperty(compiler, 'webpack', { value: { ...compiler.webpack, version: '5.93.0' } });
	assert.throws(() => new DkSbomWebpackCollector({ proofPath: area.proofPath, originals: area.originals }).apply(compiler), /unsupported webpack 5\.93\.0, expected 5\.94\.0/);
});
test('reports no-data for a chunk whose module went through a loader', async () => {
	const area = fixture.workspace('loaded');
	const extra = path.join(area.root, 'appended.txt');
	fs.writeFileSync(extra, '\nexport const appended = true;\n');
	const loader = path.join(area.root, 'append-loader.cjs');
	fs.writeFileSync(loader, `module.exports = function (content) { return content + require('node:fs').readFileSync(${JSON.stringify(extra)}, 'utf8'); };\n`);
	await run(
		configuration(area, {
			module: { rules: [{ test: /pkg-b[\\/]index\.js$/, use: loader }] },
			plugins: [new DkSbomWebpackCollector({ proofPath: area.proofPath, originals: area.originals })],
		}),
	);

	const main = asset(readProof(area), 'main.js');
	assert.equal(main.status, 'no-data');
	assert.match(main.reason, /loader-transformed module: .*pkg-b[\\/]index\.js/);
	assert.deepEqual(main.includedComponents, []);
});

test('reports no-data for every asset of a chunk emitting more than one file', async () => {
	const area = fixture.workspace('multifile');
	await run(
		configuration(area, {
			entry: area.installed('app/styled.js'),
			target: 'web',
			experiments: { css: true },
			plugins: [new DkSbomWebpackCollector({ proofPath: area.proofPath, originals: area.originals })],
		}),
	);

	const proof = readProof(area);
	assert.ok(proof.assets.length > 1, `expected a multi-file chunk, got ${proof.assets.map((row) => row.path).join(', ')}`);
	for (const row of proof.assets) {
		assert.equal(row.status, 'no-data', row.path);
		assert.match(row.reason, /emits 2 files/);
		assert.deepEqual(row.components, []);
	}
});

test('refuses a declared copy origin that is not the configured one, even with identical bytes', async () => {
	const area = fixture.workspace('miscopied');
	assert.deepEqual(fs.readFileSync(area.installed('pkg-a/LICENSE')), fs.readFileSync(area.installed('pkg-c/LICENSE')));
	await run(
		configuration(area, {
			plugins: [
				new CopyPlugin({ patterns: [{ from: area.installed('pkg-c/LICENSE'), to: 'license.txt' }] }),
				new DkSbomWebpackCollector({
					proofPath: area.proofPath,
					originals: area.originals,
					copied: [{ from: area.installed('pkg-a/LICENSE'), to: 'license.txt' }],
				}),
			],
		}),
	);

	const license = asset(readProof(area), 'license.txt');
	assert.equal(license.status, 'invalid');
	assert.equal(license.reason, `declared origin of license.txt is not the configured ${area.installed('pkg-c/LICENSE')}`);
	assert.deepEqual(license.includedComponents, []);
});

test('refuses a module whose consumed source is not the bytes on disk', async () => {
	const area = fixture.workspace('virtualized');
	const replace = {
		apply(compiler) {
			compiler.hooks.compilation.tap('replace', (compilation) => {
				compilation.hooks.afterProcessAssets.tap('replace', () => {
					for (const module of compilation.modules) {
						for (const inner of Array.isArray(module.modules) ? module.modules : [module]) {
							if (typeof inner.resource === 'string' && inner.resource === area.installed('pkg-b/index.js')) {
								inner.originalSource = () => new webpack.sources.RawSource('export function b() { return "virtual"; }\n');
							}
						}
					}
				});
			});
		},
	};
	await run(
		configuration(area, {
			plugins: [replace, new DkSbomWebpackCollector({ proofPath: area.proofPath, originals: area.originals })],
		}),
	);

	const main = asset(readProof(area), 'main.js');
	assert.equal(main.status, 'hash-mismatch');
	assert.equal(main.reason, `consumed module source differs from its file: ${area.installed('pkg-b/index.js')}`);
	assert.deepEqual(main.inputs, []);
});

// A directory pattern copies files nothing declared, one by one: each emitted
// asset carries the package the file it was read from belongs to.
test('binds every file of a directory copy pattern to the package it was read from', async () => {
	const area = fixture.workspace('directory');
	await run(
		configuration(area, {
			plugins: [
				new CopyPlugin({ patterns: [{ from: area.installed('pkg-c'), to: 'bundled' }] }),
				new DkSbomWebpackCollector({ proofPath: area.proofPath, originals: area.originals, copied: [] }),
			],
		}),
	);

	const proof = readProof(area);
	assert.deepEqual(
		proof.assets.filter((row) => row.path.startsWith('bundled/')).map((row) => [row.path, row.status, row.includedComponents]),
		[
			['bundled/LICENSE', 'present', ['node:pkg-c@7.8.9']],
			['bundled/index.js', 'no-data', []],
			['bundled/package.json', 'present', ['node:pkg-c@7.8.9']],
			['bundled/vendor.js', 'no-data', []],
		],
	);
	for (const name of ['LICENSE', 'package.json']) {
		const row = asset(proof, `bundled/${name}`);
		assert.deepEqual(row.inputs, [
			{
				kind: 'source',
				path: area.installed(`pkg-c/${name}`),
				sha256: sha256(area.installed(`pkg-c/${name}`)),
				components: ['node:pkg-c@7.8.9'],
				disposition: 'included',
			},
		]);
	}
});

test('binds a copy pattern whose context is relative to the compiler context', async () => {
	const area = fixture.workspace('relativecontext');
	assert.notEqual(area.root, process.cwd(), 'the compiler context must differ from the working directory');
	await run(
		configuration(area, {
			plugins: [
				new CopyPlugin({ patterns: [{ from: 'pkg-c/LICENSE', context: 'node_modules', to: 'license.txt' }] }),
				new DkSbomWebpackCollector({
					proofPath: area.proofPath,
					originals: area.originals,
					copied: [{ from: area.installed('pkg-c/LICENSE'), to: 'license.txt' }],
				}),
			],
		}),
	);

	const license = asset(readProof(area), 'license.txt');
	assert.equal(license.status, 'present');
	assert.deepEqual(license.includedComponents, ['node:pkg-c@7.8.9']);
});

test('refuses a wrong origin for a relative-context copy pattern with identical bytes', async () => {
	const area = fixture.workspace('relativecontextwrong');
	assert.deepEqual(fs.readFileSync(area.installed('pkg-a/LICENSE')), fs.readFileSync(area.installed('pkg-c/LICENSE')));
	await run(
		configuration(area, {
			plugins: [
				new CopyPlugin({ patterns: [{ from: 'pkg-c/LICENSE', context: 'node_modules', to: 'license.txt' }] }),
				new DkSbomWebpackCollector({
					proofPath: area.proofPath,
					originals: area.originals,
					copied: [{ from: area.installed('pkg-a/LICENSE'), to: 'license.txt' }],
				}),
			],
		}),
	);

	const license = asset(readProof(area), 'license.txt');
	assert.equal(license.status, 'invalid');
	assert.equal(license.reason, `declared origin of license.txt is not the configured ${area.installed('pkg-c/LICENSE')}`);
});

test('refuses a root that overlaps another binding original root', () => {
	const area = fixture.workspace('overlap', { isolateOriginals: true });
	const [first, second] = area.originals;
	const nested = path.join(first.originalRoot, 'nested');
	fs.mkdirSync(nested);
	assert.throws(
		() =>
			new DkSbomWebpackCollector({
				proofPath: area.proofPath,
				originals: [first, { ...second, root: nested }],
			}),
		/root overlaps the original root/,
	);
	assert.doesNotThrow(
		() => new DkSbomWebpackCollector({ proofPath: area.proofPath, originals: area.originals.map((entry) => ({ ...entry, originalRoot: first.originalRoot })) }),
		'sharing one original root is allowed',
	);
});
