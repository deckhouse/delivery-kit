'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture, forkedWebpack } = require('./fixture.cjs');
const { MARKER, addSources, child } = require('./void-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));
const RAW_MODULE = path.join(WEBPACK, 'lib', 'RawModule.js');

let scratch;
let fixture;
let builds = 0;

before(
	() => {
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-void-')));
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
	},
	{ timeout: 300000 },
);

after(() => fs.rmSync(scratch, { recursive: true, force: true }));

// One real webpack build per scenario, collected whole, in its own process
// whose commonjs loader is recorded from the very first module on.
function build(scenario, options = {}) {
	const area = fixture.workspace(`${scenario}-${builds++}`, { isolateOriginals: true });
	addSources(area);
	// A distribution of its own, patched in the live copy and in the original
	// alike: every file still binds to its component, and the one that was
	// rewritten is no longer the pinned webpack.
	const fork = options.fork ? forkedWebpack(path.join(area.root, 'fork'), (copy) => fs.appendFileSync(path.join(copy, 'lib', 'RawModule.js'), '\n// patched fork\n')) : undefined;
	const setup = {
		scenario,
		context: area.root,
		entry: area.installed('app/void.js'),
		modules: area.modules,
		output: area.output,
		proofPath: area.proofPath,
		// The forked distribution stands in place of the installed one: two roots
		// of one identity would be two answers about the same component.
		originals: fork ? [...area.originals.filter((original) => original.component.id !== fork.binding.component.id), fork.binding] : area.originals,
		webpackRoot: fork ? fork.root : WEBPACK,
	};
	const output = execFileSync(process.execPath, ['--require', PRELOAD, child], {
		cwd: setup.context,
		encoding: 'utf8',
		timeout: 60000,
		env: { ...process.env, DK_VOID_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.webpack, '5.94.0');
	const row = report.proof.assets.find((candidate) => candidate.path === 'main.js');
	assert.ok(row, report.proof.assets.map((candidate) => candidate.path).join(', '));
	return { setup, report, row };
}

// A request webpack was told to answer with nothing leaves a module in the
// chunk that reads no file: it carries one fixed comment of webpack's own, so
// it is described with the webpack source that holds it.
test('describes a module built for a request that resolves to nothing', () => {
	const result = build('plain');
	assert.equal(result.row.status, 'present', result.row.reason);
	assert.equal(result.row.sha256, result.report.emitted['main.js']);
	assert.ok(
		result.row.inputs.some((input) => input.path === RAW_MODULE),
		result.row.inputs.map((input) => input.path).join(', '),
	);
	// The comment really is in the bundle, and no source of the project stands
	// behind it.
	assert.match(fs.readFileSync(path.join(result.setup.output, 'main.js'), 'utf8'), /\/\* \(ignored\) \*\//);
});

// A request dropped before it is resolved builds no module at all: what the
// referencing module gets instead is webpack's own generated code, which the
// render of the chunk already accounts for.
test('describes a build whose request was dropped before resolution', () => {
	const result = build('dropped');
	assert.equal(result.row.status, 'present', result.row.reason);
	assert.equal(result.row.sha256, result.report.emitted['main.js']);
	assert.match(fs.readFileSync(path.join(result.setup.output, 'main.js'), 'utf8'), /webpackMissingModule/);
});

// Only the one fixed comment is text no project stands behind.
test('reports no data for a void module carrying text of its own', () => {
	const row = build('forged-text').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /carries text other than the comment webpack writes for a dropped request/);
	assert.deepEqual(row.inputs, []);
});

// What the chunk was given for the module, not what the module says afterwards.
test('reports a hash mismatch when the generated code is not the comment', () => {
	const row = build('forged-code').row;
	assert.equal(row.status, 'hash-mismatch', row.reason);
	assert.match(row.reason, /the generated source of .* is not the comment it carries/);
	assert.deepEqual(row.inputs, []);
});

// The class webpack loaded, not something derived from it.
test('reports no data for a module of a class derived from the loaded one', () => {
	const row = build('subclass').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /is not built by the loaded RawModule\.js/);
	assert.deepEqual(row.inputs, []);
});

// A distribution that is byte-for-byte its own original and still not the
// webpack this adapter was pinned against: its file verifies, and the text it
// writes is not the text that was read when the pin was taken.
test('refuses a patched distribution that verifies against its own original', () => {
	const row = build('plain', { fork: true }).row;
	assert.equal(row.status, 'unsupported', row.reason);
	assert.match(row.reason, /RawModule\.js is not the source of the pinned webpack 5\.94\.0/);
	assert.deepEqual(row.inputs, []);
});

// Webpack builds such a module for a dropped request and says so in its name;
// anything else of that class was built for another reason entirely.
test('reports no data for a module of that class built for something else', () => {
	const row = build('renamed').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /is not a module webpack built for a request it dropped/);
	assert.deepEqual(row.inputs, []);
});
