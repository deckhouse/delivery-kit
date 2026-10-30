'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture } = require('./fixture.cjs');
const { MARKER, addSources, child } = require('./define-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));

let scratch;
let fixture;
let builds = 0;

before(
	() => {
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-define-')));
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
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
		entry: area.installed('app/define.js'),
		modules: area.modules,
		output: area.output,
		proofPath: area.proofPath,
		originals: area.originals,
		webpackRoot: WEBPACK,
	};
	const output = execFileSync(process.execPath, ['--require', PRELOAD, child], {
		cwd: setup.context,
		encoding: 'utf8',
		timeout: 60000,
		env: { ...process.env, DK_DEFINE_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.webpack, '5.94.0');
	const row = report.proof.assets.find((candidate) => candidate.path === 'main.js');
	assert.ok(row, report.proof.assets.map((candidate) => candidate.path).join(', '));
	return { setup, report, row, rows: new Map(report.proof.assets.map((candidate) => [candidate.path, candidate])) };
}

// Constants the build defines as data are spliced into the modules as literals:
// they carry no component, and the modules they were spliced into keep their
// claim. What is provided comes from a module of the graph, and is described as
// the module it is.
test('describes a build that defines constants and provides an identifier', () => {
	const result = build('plain');
	assert.equal(result.row.status, 'present', result.row.reason);
	assert.equal(result.row.sha256, result.report.emitted['main.js']);
	const text = fs.readFileSync(path.join(result.setup.output, 'main.js'), 'utf8');
	// The defined value really is in the bundle, as the literal it was written
	// as, and the provided module really was pulled in beside it.
	assert.match(text, /"2\.4\.0"/);
	assert.match(text, /provided/);
	assert.ok(
		result.row.inputs.some((input) => path.basename(input.path) === 'provided.js'),
		result.row.inputs.map((input) => input.path).join(', '),
	);
});

// A value the plugin would splice as code stands in the asset while the module
// it was spliced into still matches its file, so nothing else here can see it.
test('reports no data for constants defined as code', () => {
	for (const [scenario, pattern] of [
		['code', /defines __REDOC_VERSION__ = "globalThis\.stolen = document\.cookie" as code/],
		['function', /defines __REDOC_VERSION__ as code/],
		['regexp', /defines __REDOC_VERSION__ as code/],
		['nested-code', /defines __REDOC_VERSION__\.version = "globalThis\.stolen = 1" as code/],
	]) {
		const row = build(scenario).row;
		assert.equal(row.status, 'no-data', `${scenario}: ${row.reason}`);
		assert.match(row.reason, pattern);
		assert.deepEqual(row.inputs, []);
	}
});

// A constant defined as nothing at all is a literal like any other.
test('describes a build defining a constant with no value', () => {
	const row = build('undefined-value').row;
	assert.equal(row.status, 'present', row.reason);
});

// Webpack defines one constant of its own when the build names an environment,
// and that one is accounted for rather than refused.
test('describes a build whose only constant is the one webpack defines', () => {
	const row = build('no-define').row;
	assert.equal(row.status, 'present', row.reason);
});

// The same build without that environment defines nothing at all.
test('describes a build that defines no constants at all', () => {
	const row = build('no-node-env').row;
	assert.equal(row.status, 'present', row.reason);
});

// The constants are read off the plugins the build is configured with; ones
// some other plugin applied by itself were never seen.
test('reports no data for constants defined by a plugin of someone else', () => {
	const row = build('applied-inside').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /2 plugins define constants in this compilation and 1 of them are accounted for/);
	assert.deepEqual(row.inputs, []);
});

// The class webpack loaded, not something derived from it.
test('reports no data for constants defined by a derived plugin', () => {
	const row = build('derived').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /derived from DefinePlugin/);
	assert.deepEqual(row.inputs, []);
});

// A compiler this one makes is given the definers of this one, and may be given
// more of its own afterwards: what its modules were spliced with is decided for
// its own compilation.
test('reports no data for a child compilation with a definer of its own', () => {
	const result = build('child-define');
	const child = result.rows.get('child.js');
	assert.ok(child, [...result.rows.keys()].join(', '));
	assert.equal(child.status, 'no-data', child.reason);
	assert.match(child.reason, /the compilation of fixture-child: 3 plugins define constants in this compilation and 2 of them are accounted for/);
	assert.deepEqual(child.inputs, []);
	// The asset of this compilation keeps its own answer.
	assert.equal(result.row.status, 'present', result.row.reason);
});

// The same child without one is described like any other.
test('describes a child compilation defining nothing of its own', () => {
	const result = build('child-plain');
	const child = result.rows.get('child.js');
	assert.ok(child, [...result.rows.keys()].join(', '));
	assert.equal(child.status, 'present', child.reason);
});
