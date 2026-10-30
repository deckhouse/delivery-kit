'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture } = require('./fixture.cjs');
const { MARKER, addSources, child } = require('./external-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));
const EXTERNAL_MODULE = path.join(WEBPACK, 'lib', 'ExternalModule.js');
const TEMPLATE = path.join(WEBPACK, 'lib', 'Template.js');

let scratch;
let fixture;
let builds = 0;

before(
	() => {
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-external-')));
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
	},
	{ timeout: 300000 },
);

after(() => fs.rmSync(scratch, { recursive: true, force: true }));

// One real webpack build per scenario, collected whole, in its own process
// whose commonjs loader is recorded from the very first module on.
function build(scenario) {
	const area = fixture.workspace(`${scenario}-${builds++}`, { isolateOriginals: true });
	addSources(area);
	const setup = {
		scenario,
		context: area.root,
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
		env: { ...process.env, DK_EXTERNAL_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.webpack, '5.94.0');
	const row = report.proof.assets.find((candidate) => candidate.path === 'main.js');
	assert.ok(row, report.proof.assets.map((candidate) => candidate.path).join(', '));
	return { setup, area, report, row };
}

function inputPaths(row) {
	return row.inputs.map((input) => input.path);
}

// The package is not in the bundle: what stands in the chunk is one line
// webpack writes to reach it, with the request in it as a string literal. The
// file that writes that line is what the module is described with.
test('describes a bundle that reaches a package from outside it', () => {
	const result = build('commonjs');
	assert.equal(result.row.status, 'present', result.row.reason);
	assert.equal(result.row.sha256, result.report.emitted['main.js']);
	assert.ok(inputPaths(result.row).includes(EXTERNAL_MODULE), inputPaths(result.row).join(', '));
	// The request is in the bundle, and nothing of the package it names is.
	assert.match(fs.readFileSync(path.join(result.setup.output, 'main.js'), 'utf8'), /require\("outside"\)/);
});

// Reached through the loader of the chunk instead: the line names a variable
// built from the module's id, and the request is not written at all. The
// identifier comes from Template, so Template is described with it.
test('describes a bundle that reaches a package through its loader', () => {
	const result = build('amd');
	assert.equal(result.row.status, 'present', result.row.reason);
	for (const file of [EXTERNAL_MODULE, TEMPLATE]) assert.ok(inputPaths(result.row).includes(file), `${file} is not an input of ${inputPaths(result.row).join(', ')}`);
	assert.match(fs.readFileSync(path.join(result.setup.output, 'main.js'), 'utf8'), /__WEBPACK_EXTERNAL_MODULE_/);
});

// Hoisted into the module that uses it, where the line declares a binding of
// that scope: the module holding it answers for those bytes, and the shape of
// the external is still what keeps the build's own configuration out of them.
test('describes an external hoisted into the module that reaches it', () => {
	const result = build('hoisted');
	assert.equal(result.row.status, 'present', result.row.reason);
	assert.equal(result.row.sha256, result.report.emitted['main.js']);
	assert.ok(inputPaths(result.row).includes(EXTERNAL_MODULE), inputPaths(result.row).join(', '));
});

// The dangerous shape: `externals: { outside: 'null' }` with no library puts
// the configured text into the chunk as an expression, and nothing describes
// what that text is.
test('reports no data for an external written into the chunk as an expression', () => {
	const result = build('variable');
	assert.equal(result.row.status, 'no-data', result.row.reason);
	assert.match(result.row.reason, /it is reached as var, which writes the configured request into the chunk as an expression/);
	assert.deepEqual(result.row.inputs, []);
	// The configured expression really is the text of that module.
	assert.match(fs.readFileSync(path.join(result.setup.output, 'main.js'), 'utf8'), /module\.exports = null/);
});

// A request of several names reaches into a member of what it found, which is
// written into the chunk as an expression too.
test('reports no data for an external reaching into what its name found', () => {
	const row = build('many-names').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /it is requested by a name reaching into what that name found/);
	assert.deepEqual(row.inputs, []);
});

// One name per way of reaching the package: webpack hands the class an object,
// and which of its names the line is built from is the loader's business.
test('reports no data for an external named once per way of reaching it', () => {
	const row = build('request-object').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /it is requested by one name per way of reaching it/);
	assert.deepEqual(row.inputs, []);
});

// Hoisting changes where the line stands, not what it is built from: a shape
// this adapter refuses is refused there too.
test('reports no data for an expression-shaped external that was hoisted', () => {
	const result = build('hoisted-variable');
	assert.equal(result.row.status, 'no-data', result.row.reason);
	assert.match(result.row.reason, /it is reached as var, which writes the configured request into the chunk as an expression/);
	assert.deepEqual(result.row.inputs, []);
	assert.match(fs.readFileSync(path.join(result.setup.output, 'main.js'), 'utf8'), /null/);
});

// A build targeting node asks for the request by that name, and for a module
// built as a script the line is the commonjs one, byte for byte.
test('describes an external a script reaches by the node commonjs name', () => {
	const result = build('node-commonjs');
	assert.equal(result.row.status, 'present', result.row.reason);
	assert.ok(inputPaths(result.row).includes(EXTERNAL_MODULE), inputPaths(result.row).join(', '));
	assert.match(fs.readFileSync(path.join(result.setup.output, 'main.js'), 'utf8'), /require\("outside"\)/);
});

// The same external type in a build whose output is an esm module reaches the
// request through an import fragment of its own, which stands outside the line.
test('reports no data for a node commonjs external of a module build', () => {
	const row = build('node-commonjs-module').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /it is reached as node-commonjs from a module, which reaches the request through a fragment of its own/);
	assert.deepEqual(row.inputs, []);
});

// A request the build can do without carries a guard of webpack's own in front
// of the line, which this adapter does not account for.
test('reports no data for an external the build can do without', () => {
	const result = build('optional');
	assert.equal(result.row.status, 'no-data', result.row.reason);
	assert.match(result.row.reason, /it is an external the build can do without/);
	assert.deepEqual(result.row.inputs, []);
	assert.match(fs.readFileSync(path.join(result.setup.output, 'main.js'), 'utf8'), /MODULE_NOT_FOUND/);
});

// What the chunk was given for the module, not what the class would write now.
test('reports a hash mismatch when the generated line is not the one the class writes', () => {
	const row = build('forged-code').row;
	assert.equal(row.status, 'hash-mismatch', row.reason);
	assert.match(row.reason, /is not the line ExternalModule\.js writes to reach it/);
	assert.deepEqual(row.inputs, []);
});
