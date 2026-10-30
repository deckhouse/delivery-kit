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

let scratch;
let fixture;
let webpackOriginal;
let builds = 0;

before(
	() => {
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-umd-')));
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
		webpackOriginal = bootstrapOriginal(path.join(scratch, 'webpack'), 'webpack').binding;
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
		originals: [...area.originals, webpackOriginal],
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
	assert.deepEqual(result.row.units, [UMD, ABSTRACT]);
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
