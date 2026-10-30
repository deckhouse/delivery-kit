'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture, bootstrapOriginal } = require('./fixture.cjs');
const { MARKER, addSources, child } = require('./umd-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));
const UMD = path.join(WEBPACK, 'lib', 'library', 'UmdLibraryPlugin.js');
const ABSTRACT = path.join(WEBPACK, 'lib', 'library', 'AbstractLibraryPlugin.js');
// Installed beside the wrapper for every library that can export a member of
// its own; it adds nothing to one that exports none.
const EXPORT_PROPERTY = path.join(WEBPACK, 'lib', 'library', 'ExportPropertyLibraryPlugin.js');

let scratch;
let fixture;
let toolOriginals;
let builds = 0;

before(
	() => {
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-umd-')));
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
		toolOriginals = [bootstrapOriginal(path.join(scratch, 'terser-webpack-plugin'), 'terser-webpack-plugin').binding, bootstrapOriginal(path.join(scratch, 'terser'), 'terser').binding];
	},
	{ timeout: 300000 },
);

after(() => fs.rmSync(scratch, { recursive: true, force: true }));

// One real webpack build per scenario, in its own process whose commonjs loader
// is recorded from the very first module on.
function build(scenario) {
	const area = fixture.workspace(`${scenario}-${builds++}`, { isolateOriginals: true });
	addSources(area);
	const setup = {
		scenario,
		context: area.root,
		entry: area.installed('app/umd.js'),
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
		env: { ...process.env, DK_UMD_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.webpack, '5.94.0');
	if (scenario === 'redoc' || scenario === 'mutated-global') return { setup, report };
	assert.equal(report.rows.length, 1, 'one chunk is wrapped');
	return { setup, report, row: report.rows[0], bundle: report.emitted['bundle.js'] };
}

// The wrapper really is what stands around the code of the chunk: the text
// rebuilt here from the name, the externals and the global object of the build
// is the text webpack wrote, to the byte.
test('rebuilds the wrapper of a library of type umd', () => {
	const result = build('plain');
	assert.equal(result.row.status, 'present', result.row.reason);
	assert.ok(result.bundle.startsWith(result.row.prefix), `${JSON.stringify(result.bundle.slice(0, 400))}\n${JSON.stringify(result.row.prefix)}`);
	// The chunk render puts a semicolon of its own after the wrapper, which the
	// adapter describing the render accounts for.
	assert.ok(result.bundle.endsWith(`${result.row.suffix};`), JSON.stringify(result.bundle.slice(-20)));
	// The data of the build stands in that text: the name of the library, the
	// global object, and the request the configuration maps the external to -
	// named as a reference rather than carried as code.
	assert.match(result.row.prefix, /exports\["Redoc"\] = factory\(require\("null"\)\)/);
	assert.match(result.row.prefix, /\}\)\(this, \(__WEBPACK_EXTERNAL_MODULE_\w+__\) =>/);
	assert.deepEqual(result.row.externals, ['null']);
	assert.deepEqual(result.row.units, [UMD, ABSTRACT, EXPORT_PROPERTY]);
});

// A bundle that references nothing of the environment is wrapped with empty
// lists, and the same recomputation has to produce it.
test('rebuilds the wrapper of a library without externals', () => {
	const result = build('no-externals');
	assert.equal(result.row.status, 'present', result.row.reason);
	assert.ok(result.bundle.startsWith(result.row.prefix), JSON.stringify(result.bundle.slice(0, 400)));
	assert.deepEqual(result.row.externals, []);
	assert.match(result.row.prefix, /define\(\[\], factory\)/);
});

// The wrapper is written with a function rather than an arrow when the build
// says its environment has none.
test('rebuilds the wrapper of a build without arrow functions', () => {
	const result = build('no-arrow');
	assert.equal(result.row.status, 'present', result.row.reason);
	assert.ok(result.bundle.startsWith(result.row.prefix), JSON.stringify(result.bundle.slice(0, 400)));
	assert.match(result.row.prefix, /\}\)\(this, function\(__WEBPACK_EXTERNAL_MODULE_\w+__\)/);
});

// The shapes of a umd library this adapter does not write out again.
test('reports no data for libraries this adapter does not describe', () => {
	for (const [scenario, pattern] of [
		['named-object', /not named with a name of its own/],
		['named-define', /names itself to its amd loader/],
		['comment', /carries comments of its own/],
		['templated-name', /named with a template/],
		['umd2', /is not wrapped as a library of type umd/],
		// A library of another type is not wrapped by this plugin at all, so its
		// source is never even loaded.
		['assigned', /UmdLibraryPlugin\.js was not observed being loaded by this process/],
		['expression-global', /reaches its global object by something other than a name/],
	]) {
		const row = build(scenario).row;
		assert.equal(row.status, 'no-data', `${scenario}: ${row.reason}`);
		assert.match(row.reason, pattern);
		assert.deepEqual(row.units, []);
	}
});

// Another plugin shaping the rendered code leaves bytes between the wrapper and
// the chunk that this adapter cannot attribute.
test('reports no data when another plugin shapes the rendered chunk', () => {
	const row = build('company').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /fixture shaped the chunks of this compilation besides its library wrapper/);
	assert.deepEqual(row.units, []);
});

// Everything redoc's configuration asks for at once, collected whole: a library
// of type umd around a minified bundle, a banner in front of it, constants
// spliced into its modules and the line naming the source map beside it.
test('describes a redoc-shaped build whole', () => {
	const result = build('redoc');
	const rows = new Map(result.report.proof.assets.map((row) => [row.path, row]));
	const bundle = rows.get('redoc.standalone.js');
	assert.equal(bundle.status, 'present', bundle.reason);
	// Every stage really happened to those bytes. The banner is a comment the
	// minifier takes out into a file of its own, exactly as it does in redoc's
	// published bundle, leaving the pointer to it in front.
	const text = result.report.emitted['redoc.standalone.js'];
	assert.ok(text.startsWith('/*! For license information please see redoc.standalone.js.LICENSE.txt */'), text.slice(0, 80));
	assert.match(result.report.emitted['redoc.standalone.js.LICENSE.txt'], /ReDoc - OpenAPI/);
	assert.equal(rows.get('redoc.standalone.js.LICENSE.txt').status, 'present', rows.get('redoc.standalone.js.LICENSE.txt').reason);
	// The wrapper, minified: the library named three ways and the external kept
	// as a reference.
	assert.match(text, /exports\.Redoc=r\(require\("null"\)\)/);
	assert.match(text, /"2\.4\.0"/);
	assert.ok(text.endsWith('\n//# sourceMappingURL=redoc.standalone.js.map'), JSON.stringify(text.slice(-60)));
	// The wrapper, the banner and the source map line are claimed with the
	// webpack sources that wrote them.
	const claimed = bundle.inputs.map((input) => path.basename(input.path));
	for (const file of ['UmdLibraryPlugin.js', 'AbstractLibraryPlugin.js', 'BannerPlugin.js', 'SourceMapDevToolPlugin.js']) {
		assert.ok(claimed.includes(file), `${file} is not claimed: ${claimed.join(', ')}`);
	}
	// The map itself is the one asset this collector refuses, in its own words.
	const map = rows.get('redoc.standalone.js.map');
	assert.equal(map.status, 'no-data', map.reason);
	assert.match(map.reason, /is the source map of an asset of this build, which this collector does not describe/);
	assert.deepEqual(
		result.report.proof.assets.filter((row) => row.status !== 'present').map((row) => row.path),
		['redoc.standalone.js.map'],
	);
});

// The wrapper is accounted for by rebuilding it, not by trusting whoever
// rendered it: a build whose own answers changed after the render no longer
// accounts for the text that stands in the asset.
test('reports no data when the rebuilt wrapper is not the one that was rendered', () => {
	const result = build('mutated-global');
	const bundle = result.report.proof.assets.find((row) => row.path === 'redoc.standalone.js');
	assert.equal(bundle.status, 'no-data', bundle.reason);
	assert.match(bundle.reason, /is not wrapped in the library its wrapper describes/);
	assert.deepEqual(bundle.inputs, []);
});
