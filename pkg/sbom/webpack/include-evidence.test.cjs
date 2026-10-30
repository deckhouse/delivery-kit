'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture, bootstrapOriginal } = require('./fixture.cjs');
const { MARKER, ENTRY, LAZY_ENTRY, writeSources, child } = require('./include-fixture.cjs');

// Both recorders, the way the activation installs them for a real build.
const PRELOADS = ['stylesheet-preload.cjs', 'include-preload.cjs'].flatMap((name) => ['--require', path.join(__dirname, name)]);
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));
const PLUGIN = path.dirname(require.resolve('monaco-editor-webpack-plugin/package.json'));
const MONACO = path.join(path.dirname(require.resolve('monaco-editor/package.json')), 'esm', 'vs', 'editor', 'editor.main.js');
// The published loader, as packed in the npm archive of 7.1.0.
const LOADER_SHA256 = 'sha256:5bb553fd45212f2f3e08f87dddea60bb83aa7dd92583113a35248a9338ec8a69';

let scratch;
let fixture;
let originals;
let builds = 0;

before(
	() => {
		assert.equal(sha256(path.join(PLUGIN, 'out', 'loaders', 'include.js')), LOADER_SHA256, 'the installed plugin is not the published 7.1.0 artifact');
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-include-')));
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
		originals = [
			bootstrapOriginal(path.join(scratch, 'plugin'), 'monaco-editor-webpack-plugin').binding,
			bootstrapOriginal(path.join(scratch, 'style-loader'), 'style-loader').binding,
			bootstrapOriginal(path.join(scratch, 'raw-loader'), 'raw-loader').binding,
			bootstrapOriginal(path.join(scratch, 'monaco'), 'monaco-editor').binding,
			bootstrapOriginal(path.join(scratch, 'terser-webpack-plugin'), 'terser-webpack-plugin').binding,
			bootstrapOriginal(path.join(scratch, 'terser'), 'terser').binding,
		];
	},
	{ timeout: 600000 },
);

after(() => fs.rmSync(scratch, { recursive: true, force: true }));

function sha256(file) {
	return `sha256:${crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')}`;
}

// One real webpack build per scenario, in its own process whose loader
// recorder is in place before the plugin requires its own loader.
function build(scenario, options = {}) {
	const root = path.join(scratch, `${scenario}-${builds++}`);
	// A collected build binds every module to a declared original, so it runs in
	// a workspace of the shared fixture.
	const area = options.collect ? fixture.workspace(`${scenario}-${builds}`, { isolateOriginals: true }) : undefined;
	if (area) {
		const entry = options.lazy ? LAZY_ENTRY : ENTRY;
		fs.writeFileSync(path.join(area.modules, 'app', 'index.js'), entry);
		fs.writeFileSync(path.join(area.originalOf('app'), 'index.js'), entry);
	}
	const setup = {
		scenario,
		context: area ? area.root : root,
		entry: area ? area.installed('app/index.js') : writeSources(path.join(root, 'src')),
		output: area ? area.output : path.join(root, 'out'),
		proofPath: area ? area.proofPath : undefined,
		fixtureDir: __dirname,
		extraInclude: MONACO,
		webpackRoot: WEBPACK,
		pluginRoot: PLUGIN,
		cssAsAsset: options.cssAsAsset === true,
		styleLoader: require.resolve('style-loader'),
		rawLoader: require.resolve('raw-loader'),
		modules: path.join(path.dirname(require.resolve('monaco-editor/package.json')), '..'),
		originals: area ? [...area.originals, ...originals] : originals,
	};
	const output = execFileSync(process.execPath, [...PRELOADS, child], {
		cwd: setup.context,
		encoding: 'utf8',
		timeout: 600000,
		maxBuffer: 64 * 1024 * 1024,
		env: { ...process.env, DK_INCLUDE_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output.slice(-4000)}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.webpack, '5.94.0');
	if (options.collect) return { setup, report };
	// The rule the plugin adds matches both monaco entries, so the loader builds
	// a module for each of them.
	assert.equal(report.rows.length, 2, report.rows.map((row) => row.identifier).join(', '));
	const row = report.rows.find((candidate) => candidate.resource === MONACO);
	assert.ok(row, `no module for ${MONACO}`);
	return { setup, report, row };
}

// The module the plugin builds for the monaco entry is the loader's own text,
// and nothing of the file it was asked for.
test('describes the module the include loader pitched', () => {
	const result = build('plain');
	for (const row of result.report.rows) assert.equal(row.status, 'present', `${row.identifier}: ${row.reason}`);
	// The loader that wrote the text, and the plugin source that authored the
	// one global it writes out unquoted.
	assert.deepEqual(result.row.units.map((unit) => path.relative(PLUGIN, unit)), [path.join('out', 'loaders', 'include.js'), path.join('out', 'index.js')]);
	assert.deepEqual(result.row.components, ['node:monaco-editor-webpack-plugin@7.1.0', 'node:monaco-editor-webpack-plugin@7.1.0']);
	// What it wrote: the environment the plugin configured, the feature imports,
	// the re-export of the file it was given, and the language imports.
	assert.match(result.row.source, /^self\["MonacoEnvironment"\] = \(function/);
	assert.match(result.row.source, /import \* as monaco from "[^"]*editor\.main\.js";/);
	assert.ok(
		result.row.source.includes('yaml'),
		'the language the plugin was configured with is not among the imports',
	);
	// The file it was asked for is the monaco entry the rule matched.
	assert.equal(result.row.resource, MONACO);
});

// A second loader on the same module is a chain this adapter does not describe.
test('reports no data for a module another loader also built', () => {
	const result = build('second-loader');
	for (const row of result.report.rows) {
		assert.equal(row.status, 'no-data', row.reason);
		assert.match(row.reason, /was not built by the include loader alone/);
		assert.deepEqual(row.units, []);
	}
});

// The text is recomputed from what the loader was given, so an include added
// behind its back is text that no longer matches.
test('describes a module whose includes a plugin changed, from the options it really had', () => {
	const result = build('extra-option');
	for (const row of result.report.rows) assert.equal(row.status, 'present', `${row.identifier}: ${row.reason}`);
	// The added import is in the text, and what was recomputed from the options
	// the loader really ran with has it too.
	assert.ok(result.row.source.includes(`import "./${path.basename(MONACO)}";`), result.row.source.slice(0, 400));
});

// What the loader wrote is rebuilt from the options it really ran with; options
// that changed afterwards no longer account for the text. The global is the one
// the plugin authors, so a changed one is refused before anything else.
test('reports no data when the globals of the loader changed after it ran', () => {
	const result = build('mutated-options');
	for (const row of result.report.rows) {
		assert.equal(row.status, 'no-data', row.reason);
		assert.match(row.reason, /the MonacoEnvironment it was given is not the text the plugin builds/);
		assert.deepEqual(row.units, []);
	}
});

// Every character of that global but its three data slots is the plugin's own
// code, so code smuggled into it is not code this adapter attributes to it.
test('reports no data for a global carrying code the plugin did not author', () => {
	// The last of them answers with the published text the first time it is
	// asked and with code of its own afterwards.
	for (const scenario of ['injected-global', 'forged-worker-paths', 'extra-global', 'two-faced-global']) {
		const result = build(scenario);
		for (const row of result.report.rows) {
			assert.equal(row.status, 'no-data', `${scenario}: ${row.reason}`);
			assert.match(row.reason, /MonacoEnvironment|globals other than|is not a value of its own/);
			assert.deepEqual(row.units, []);
		}
	}
});

// The function that ran has to be the one the loader published.
test('reports no data when a plugin replaced the published pitch', () => {
	const result = build('replaced-pitch');
	for (const row of result.report.rows) {
		assert.equal(row.status, 'no-data', row.reason);
		assert.match(row.reason, /did not export what this adapter recorded|was replaced after this adapter recorded it/);
		assert.deepEqual(row.units, []);
	}
});

// The source webpack kept for the module has to be what the loader pitched.
test('reports a hash mismatch when the source webpack kept was not what the loader pitched', () => {
	const result = build('forged-source');
	for (const row of result.report.rows) {
		assert.equal(row.status, 'hash-mismatch', row.reason);
		assert.match(row.reason, /is not what the include loader pitched/);
		assert.deepEqual(row.units, []);
	}
});

// The whole collector on the shape Argo builds: an entry importing monaco with
// the plugin configured for one language. Every emitted asset is described, or
// says precisely what is missing.
test('writes a proof for every asset of a monaco build', () => {
	const result = build('plain', { collect: true });
	const proof = result.report.proof;
	assert.ok(proof, 'the child wrote no proof');
	assert.deepEqual(
		proof.assets.map((row) => row.path).sort(),
		Object.keys(result.report.emitted).sort(),
		'the proof does not account for every emitted file',
	);
	const described = proof.assets.filter((row) => row.status === 'present');
	const refused = proof.assets.filter((row) => row.status !== 'present');
	// Whatever is described is bound to the bytes on disk.
	for (const row of described) assert.equal(row.sha256, result.report.emitted[row.path], row.path);
	// Nothing of this build is left undescribed.
	assert.deepEqual(
		refused.map((row) => `${row.path}: ${row.reason}`),
		[],
	);
	assert.ok(described.length > 100, `only ${described.length} assets described`);
	// The worker bundle of the child compilation, and a lazy chunk, carry the
	// monaco sources and are described down to them.
	const worker = proof.assets.find((row) => row.path === 'editor.worker.js');
	assert.ok(worker, proof.assets.map((row) => row.path).join(', '));
	assert.equal(worker.status, 'present', worker.reason);
	assert.ok(worker.includedComponents.includes('node:monaco-editor@0.33.0'), worker.includedComponents.join(', '));
});

// With monaco behind a dynamic import, the module the loader pitched is in a
// chunk of its own, which is described only because that loader is. Monaco's
// stylesheets are kept out of the loader chain here, so that what this test is
// about is the only thing it can fail on.
test('describes the chunk carrying the module the include loader pitched', () => {
	const result = build('plain', { collect: true, lazy: true, cssAsAsset: true });
	const carrying = result.report.proof.assets.filter((row) => row.includedComponents.includes('node:monaco-editor-webpack-plugin@7.1.0'));
	// The chunk itself and the comments the minifier took out of it.
	assert.deepEqual(
		carrying.map((row) => row.path.endsWith('.LICENSE.txt')).sort(),
		[false, true],
		carrying.map((row) => row.path).join(', '),
	);
	for (const row of carrying) {
		assert.equal(row.status, 'present', `${row.path}: ${row.reason}`);
		assert.equal(row.sha256, result.report.emitted[row.path]);
		assert.ok(
			row.inputs.some((input) => input.path.endsWith(path.join('out', 'loaders', 'include.js'))),
			row.inputs.map((input) => input.path).join(', '),
		);
		assert.ok(row.includedComponents.includes('node:monaco-editor@0.33.0'), row.includedComponents.join(', '));
	}
});
