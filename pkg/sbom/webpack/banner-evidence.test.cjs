'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture, bootstrapOriginal } = require('./fixture.cjs');
const { MARKER, BANNER, addSources, child } = require('./banner-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));
const BANNER_PLUGIN = path.join(WEBPACK, 'lib', 'BannerPlugin.js');

let scratch;
let fixture;
let toolOriginals;
let builds = 0;

before(
	() => {
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-banner-')));
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
		toolOriginals = [bootstrapOriginal(path.join(scratch, 'terser-webpack-plugin'), 'terser-webpack-plugin').binding, bootstrapOriginal(path.join(scratch, 'terser'), 'terser').binding];
	},
	{ timeout: 300000 },
);

after(() => fs.rmSync(scratch, { recursive: true, force: true }));

// One real collected webpack build per scenario, in its own process whose
// commonjs loader is recorded from the very first module on.
function build(scenario) {
	const area = fixture.workspace(`${scenario}-${builds++}`, { isolateOriginals: true });
	addSources(area);
	const setup = {
		scenario,
		context: area.root,
		entry: area.installed('app/banner.js'),
		modules: area.modules,
		output: area.output,
		proofPath: area.proofPath,
		originals: [...area.originals, ...toolOriginals],
		webpackRoot: WEBPACK,
	};
	const output = execFileSync(process.execPath, ['--require', PRELOAD, child], {
		cwd: setup.context,
		encoding: 'utf8',
		timeout: 60000,
		env: { ...process.env, DK_BANNER_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.webpack, '5.94.0');
	const rows = report.proof.assets;
	assert.ok(rows.length >= 2, rows.map((row) => row.path).join(', '));
	return { setup, report, rows, main: rows.find((row) => row.path.startsWith('main.')) };
}

// The comment the plugin puts in front of an asset is webpack's own wrapper
// around text the build was configured with: the asset keeps the composition it
// had, and the file webpack wrote that wrapper with is claimed with it.
test('describes the assets a banner was put in front of', () => {
	const result = build('plain');
	for (const row of result.rows) {
		assert.equal(row.status, 'present', `${row.path}: ${row.reason}`);
		assert.equal(row.sha256, result.report.emitted[row.path]);
	}
	assert.ok(
		result.main.inputs.some((input) => input.path === BANNER_PLUGIN),
		result.main.inputs.map((input) => input.path).join(', '),
	);
	// The banner really is in front of the minified bundle, wrapped the way the
	// plugin wraps text of several lines.
	const text = fs.readFileSync(path.join(result.setup.output, result.main.path), 'utf8');
	assert.ok(text.startsWith('/*!\n * ReDoc - OpenAPI'), text.slice(0, 80));
	for (const line of BANNER.split('\n')) assert.ok(text.includes(line.trimEnd()), line);
});

// The same for a banner of one line, which the plugin wraps differently.
test('describes an asset carrying a banner of a single line', () => {
	const result = build('single-line');
	assert.equal(result.main.status, 'present', result.main.reason);
	assert.equal(result.main.sha256, result.report.emitted[result.main.path]);
	assert.ok(fs.readFileSync(path.join(result.setup.output, result.main.path), 'utf8').startsWith('/*! ReDoc 2.4.0 */\n'));
});

// A build with no banner at all is described as it was before.
test('describes a build without a banner', () => {
	const result = build('none');
	assert.equal(result.main.status, 'present', result.main.reason);
	assert.ok(
		result.main.inputs.every((input) => input.path !== BANNER_PLUGIN),
		'no banner was added, so its source is claimed by nothing',
	);
});

// What this adapter describes is one comment in front of every asset, built out
// of text the build was configured with.
test('reports no data for banners this adapter does not describe', () => {
	for (const [scenario, pattern] of [
		['function', /is not text of its own/],
		['raw', /configured with raw/],
		['footer', /configured with footer/],
		// Two of them tap that stage, and the second is as unaccounted as any
		// other plugin writing there.
		['twice', /BannerPlugin, BannerPlugin added to the assets of this compilation/],
		['templated', /carries a path template/],
		['derived', /derived from BannerPlugin/],
	]) {
		const row = build(scenario).main;
		assert.equal(row.status, 'no-data', `${scenario}: ${row.reason}`);
		assert.match(row.reason, pattern);
		assert.deepEqual(row.inputs, []);
	}
});

// The plugin wraps its banner when it is built, so what its options say
// afterwards is not necessarily what it added.
test('reports no data when the configured banner is not the one that was added', () => {
	const row = build('mutated-banner').main;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /is not the asset the banner of this compilation was put in front of/);
	assert.deepEqual(row.inputs, []);
});

// The banner is read off the plugin the build is configured with; one some
// other plugin applied by itself carries text this adapter never saw.
test('reports no data for a banner added by a plugin of someone else', () => {
	const row = build('applied-inside').main;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /configured with 0 banner plugins/);
	assert.deepEqual(row.inputs, []);
});

// The banner is described for the bytes the render produced; anything written
// into the asset before it is unaccounted.
test('reports no data when the asset was changed before its banner', () => {
	const row = build('before-banner').main;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /was changed between its render and its banner/);
	assert.deepEqual(row.inputs, []);
});

// Another plugin writing into the assets in that very stage adds bytes this
// adapter cannot attribute to the banner.
test('reports no data when another plugin writes in the stage the banner is added in', () => {
	const row = build('company').main;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /fixture added to the assets of this compilation in the stage the banner is added in/);
	assert.deepEqual(row.inputs, []);
});
