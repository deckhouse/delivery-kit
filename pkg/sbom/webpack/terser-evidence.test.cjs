'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture, bootstrapOriginal } = require('./fixture.cjs');
const { MARKER, child } = require('./terser-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));
const TERSER_PLUGIN = require.resolve('terser-webpack-plugin');
const TERSER_ENTRY = require.resolve('terser', { paths: [path.dirname(TERSER_PLUGIN)] });
// The published artifacts, as packed in the npm archives of these versions.
const PLUGIN_FILES = {
	'index.js': 'sha256:c4954a793da40e7c1e3812b7f3d7e61badb7758910272029f8ff7ddee32d1012',
	'minify.js': 'sha256:83fc302758585ede630d112b5e18742fda0980e85c143281318a295ec89f6742',
	'utils.js': 'sha256:8d5b9d5c8b7826c6d26e78b75c17f16ff6ab998618bed9194298daeb48bc3b1e',
};
const TERSER_SHA256 = 'sha256:38af5a0fb14c73bc49acc03cb5e1187ff45470b7dec04571aea44525aa063ce8';
const APP_COMPONENT = 'node:app@0.1.0';
const WEBPACK_COMPONENT = 'node:webpack@5.94.0';

let scratch;
let fixture;
let toolOriginals;
let areas = 0;

before(
	() => {
		for (const [name, expected] of Object.entries(PLUGIN_FILES)) {
			assert.equal(sha256(path.join(path.dirname(TERSER_PLUGIN), name)), expected, `the installed terser-webpack-plugin is not the published 5.3.10 artifact: ${name}`);
		}
		assert.equal(sha256(TERSER_ENTRY), TERSER_SHA256, 'the installed terser is not the published 5.31.6 artifact');
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-terser-')));
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
		toolOriginals = [
			bootstrapOriginal(path.join(scratch, 'terser-webpack-plugin'), 'terser-webpack-plugin').binding,
			bootstrapOriginal(path.join(scratch, 'terser'), 'terser').binding,
		];
	},
	{ timeout: 300000 },
);

after(() => fs.rmSync(scratch, { recursive: true, force: true }));

function sha256(file) {
	return `sha256:${crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')}`;
}

// One real webpack build per scenario, in its own process whose commonjs loader
// is recorded from the very first module on.
function build(scenario, options = {}) {
	const area = options.area || fixture.workspace(`${scenario}-${areas++}`);
	const setup = {
		scenario,
		context: area.root,
		modules: area.modules,
		entry: area.installed(options.entry || 'app/index.js'),
		output: area.output,
		filename: options.filename,
		proofPath: area.proofPath,
		webpackRoot: WEBPACK,
		terserPlugin: TERSER_PLUGIN,
		terserEntry: TERSER_ENTRY,
		originals: [...area.originals, ...toolOriginals],
		cacheDirectory: options.cacheDirectory,
		salt: options.salt,
	};
	const output = execFileSync(process.execPath, ['--require', PRELOAD, child], {
		cwd: area.root,
		encoding: 'utf8',
		timeout: 60000,
		env: { ...process.env, DK_TERSER_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.terserPlugin, '5.3.10');
	assert.equal(report.terser, '5.31.6');
	return { area, report };
}

function rowOf(report, index = 0, name = 'main.js') {
	const row = report.proofs[index].assets.find((candidate) => candidate.path === name);
	assert.ok(row, `no ${name} row in proof ${index}`);
	return row;
}

function inputsOf(row) {
	return row.inputs.map((input) => `${input.path} ${input.sha256}`).sort();
}

// The minified bundle keeps the claim of the sources it was rendered from, and
// the bytes it is bound to are the ones the minifier left on disk.
test('describes a production bundle the default minifier rewrote in its workers', () => {
	const minified = build('minified');
	const row = rowOf(minified.report);
	assert.equal(row.status, 'present', row.reason);
	assert.equal(minified.report.terserLoadedHere, false, 'the default minifier did not run in its workers');
	const emitted = path.join(minified.area.output, 'main.js');
	assert.equal(row.sha256, sha256(emitted));
	assert.equal(row.size, fs.statSync(emitted).size);
	assert.deepEqual(minified.report.emitted, ['main.js']);
	const plain = build('unminified', { area: minified.area });
	const unminified = rowOf(plain.report);
	assert.equal(unminified.status, 'present', unminified.reason);
	assert.ok(row.size < unminified.size, `the minified bundle is not smaller: ${row.size} >= ${unminified.size}`);
	assert.deepEqual(inputsOf(row), inputsOf(unminified));
	assert.deepEqual(row.includedComponents, unminified.includedComponents);
	assert.ok(row.includedComponents.includes(APP_COMPONENT) && row.includedComponents.includes(WEBPACK_COMPONENT), row.includedComponents.join(', '));
	// The minifier rewrites what it is given; it is no part of what it produced.
	assert.ok(!row.includedComponents.some((id) => /terser/.test(id)), `a terser component was claimed: ${row.includedComponents.join(', ')}`);
	assert.equal(row.inputs.find((input) => /node_modules[/\\]terser/.test(input.path)), undefined, 'a terser source was claimed as an input');
});

test('describes a bundle minified in this very process', () => {
	const result = build('serial');
	const row = rowOf(result.report);
	assert.equal(row.status, 'present', row.reason);
	assert.equal(result.report.terserLoadedHere, true, 'the minifier did not run in this process');
	assert.equal(row.sha256, sha256(path.join(result.area.output, 'main.js')));
});

// The second compilation renders the same bytes and finds them minified in the
// cache of this process: what was observed once is observed for that input.
test('describes a rebuild whose minification came from a cache this process filled', () => {
	const area = fixture.workspace(`warm-${areas++}`);
	const result = build('warm', { area, cacheDirectory: path.join(area.root, 'cache') });
	assert.equal(result.report.proofs.length, 2);
	for (const index of [0, 1]) {
		const row = rowOf(result.report, index);
		assert.equal(row.status, 'present', `proof ${index}: ${row.reason}`);
		assert.equal(row.sha256, sha256(path.join(result.area.output, 'main.js')));
	}
	assert.deepEqual(inputsOf(rowOf(result.report, 0)), inputsOf(rowOf(result.report, 1)));
});

// A stored output is not an observation: another process minified it, and this
// one neither reruns the minifier nor takes the cache's word for it.
test('reports no data for a minification restored from a cache another process filled', () => {
	const area = fixture.workspace(`persist-${areas++}`);
	const cacheDirectory = path.join(area.root, 'cache');
	const first = build('minified', { area, cacheDirectory });
	assert.equal(rowOf(first.report).status, 'present', rowOf(first.report).reason);
	const second = build('minified', { area, cacheDirectory, salt: 'second' });
	const row = rowOf(second.report);
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /came from a cache this process did not fill/);
	assert.deepEqual(row.inputs, []);
});

// Every one of these changes what the minifier does with the bytes it is given,
// and the user's own options object is never touched.
test('reports no data for a minifier configured in its own way', () => {
	for (const [scenario, expected] of [
		['custom-options', /configured with terser options of its own/],
		['no-extract', /configured to extract comments in its own way/],
		['custom-minimizer', /changed between its render and its emit/],
	]) {
		const result = build(scenario);
		const row = rowOf(result.report);
		assert.equal(row.status, 'no-data', `${scenario}: ${row.reason}`);
		assert.match(row.reason, expected);
		assert.deepEqual(row.inputs, []);
		if (scenario === 'custom-options') assert.deepEqual(result.report.userOptions, { shared: true, keys: ['mangle'] }, 'the user options were not left alone');
	}
});

// The observed minification is not the end of the story, and neither is the
// render: what another plugin does to the asset on either side of it is nothing
// this adapter can attribute.
test('reports no data for an asset rewritten around its minification', () => {
	for (const [scenario, expected] of [
		['late-rewrite', /was changed between its render and its emit/],
		['early-rewrite', /was changed between its render and its minification/],
	]) {
		const result = build(scenario);
		const row = rowOf(result.report);
		assert.equal(row.status, 'no-data', `${scenario}: ${row.reason}`);
		assert.match(row.reason, expected);
		assert.deepEqual(row.inputs, []);
	}
});

// The minified bytes the adapter observed are not the proof: what stayed on the
// output file system is.
test('reports a hash mismatch when the minified file on disk is not what was minified', () => {
	const result = build('disk-rewrite');
	const row = rowOf(result.report);
	assert.equal(row.status, 'hash-mismatch');
	assert.match(row.reason, /emitted asset differs from the bytes it was described from/);
	assert.deepEqual(row.inputs, []);
	assert.equal(row.sha256, sha256(path.join(result.area.output, 'main.js')));
});

// A real-content-hashed name is replaced after the minification, by bytes and
// by name alike: this adapter describes neither, and says so.
// The minified asset is renamed for its real content hash after the
// minification this adapter observed; the content-hash adapter describes that
// step, so the chain reaches the file that was emitted under the new name.
test('describes a minified asset whose name carries its content hash', () => {
	const result = build('minified', { filename: '[contenthash].js' });
	const name = result.report.emitted.find((candidate) => candidate.endsWith('.js'));
	const row = rowOf(result.report, 0, name);
	assert.equal(row.status, 'present', row.reason);
	assert.equal(row.sha256, sha256(path.join(result.area.output, name)));
	assert.ok(row.inputs.length > 0);
});

// The default minifier moves preserved comments into a LICENSE file and leaves a
// pointer to it at the top of the bundle: that pointer is formatting the plugin
// writes, not a contribution, so the bundle keeps its claim; the extracted file
// itself belongs to no chunk and stays undescribed.
test('describes a minified bundle whose preserved comment the minifier extracted', () => {
	const area = fixture.workspace(`banner-${areas++}`, { isolateOriginals: true });
	const source = '/*! preserved notice of the application */\nconsole.log(require("pkg-a").a());\n';
	for (const file of [area.installed('app/banner.js'), area.originalOf('app/banner.js')]) fs.writeFileSync(file, source);
	const result = build('minified', { area, entry: 'app/banner.js' });
	const row = rowOf(result.report);
	assert.equal(row.status, 'present', row.reason);
	const emitted = fs.readFileSync(path.join(area.output, 'main.js'), 'utf8');
	assert.match(emitted, /^\/\*! For license information please see main\.js\.LICENSE\.txt \*\//);
	assert.equal(row.sha256, sha256(path.join(area.output, 'main.js')));
	assert.match(fs.readFileSync(path.join(area.output, 'main.js.LICENSE.txt'), 'utf8'), /preserved notice of the application/);
	const license = rowOf(result.report, 0, 'main.js.LICENSE.txt');
	assert.equal(license.status, 'no-data');
	assert.ok(row.inputs.some((input) => input.path === area.installed('app/banner.js')), 'the entry is not an input');
});
