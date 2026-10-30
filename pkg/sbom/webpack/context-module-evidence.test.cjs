'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture, forkedWebpack } = require('./fixture.cjs');
const { MARKER, LOCALES, addSources, child } = require('./context-module-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));
const CONTEXT_MODULE = path.join(WEBPACK, 'lib', 'ContextModule.js');
const RUNTIME_GLOBALS = path.join(WEBPACK, 'lib', 'RuntimeGlobals.js');
const APP_COMPONENT = 'node:app@0.1.0';
const WEBPACK_COMPONENT = 'node:webpack@5.94.0';

let scratch;
let fixture;
let builds = 0;

before(
	() => {
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-context-')));
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true, minifier: true });
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
	const fork = options.fork ? forkedWebpack(path.join(area.root, 'fork'), (copy) => fs.appendFileSync(path.join(copy, 'lib', 'ContextModule.js'), '\n// patched fork\n')) : undefined;
	const setup = {
		scenario,
		context: area.root,
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
		env: { ...process.env, DK_CONTEXT_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.webpack, '5.94.0');
	const row = report.proof.assets.find((candidate) => candidate.path.startsWith('main.') && candidate.path.endsWith('.js'));
	assert.ok(row, report.proof.assets.map((candidate) => candidate.path).join(', '));
	return { setup, area, report, row };
}

function inputPaths(row) {
	return row.inputs.map((input) => input.path);
}

// A `require.context` leaves a module in the chunk that reads no file: its text
// is a map of the requests it answers, written by webpack around a fixed
// function body. It is described with the webpack sources that write it, and
// every file it can reach is described as a module of its own.
test('describes a bundle built around a required context', () => {
	const result = build('plain');
	assert.equal(result.row.status, 'present', result.row.reason);
	assert.equal(result.row.sha256, result.report.emitted['main.js']);
	const paths = inputPaths(result.row);
	for (const file of [CONTEXT_MODULE, RUNTIME_GLOBALS]) assert.ok(paths.includes(file), `${file} is not an input of ${paths.join(', ')}`);
	// The files the context reaches are claimed where they are described.
	for (const name of Object.keys(LOCALES)) {
		const file = result.area.installed(path.join('app', 'locale', name));
		assert.ok(paths.includes(file), `${file} is not an input of ${paths.join(', ')}`);
	}
	for (const id of [APP_COMPONENT, WEBPACK_COMPONENT]) assert.ok(result.row.includedComponents.includes(id), `${id} is not included in ${result.row.includedComponents.join(', ')}`);
	// The map really is in the bundle, and the files it names really are there.
	const bundle = fs.readFileSync(path.join(result.setup.output, 'main.js'), 'utf8');
	assert.match(bundle, /webpackContext/);
	assert.match(bundle, /\.\/af/);
});

// Which files the directory holds is data: a filter leaves some of them out of
// the map, and the text is still what the class writes for that graph.
test('describes a context whose requests are filtered', () => {
	const result = build('filtered');
	assert.equal(result.row.status, 'present', result.row.reason);
	assert.equal(result.row.sha256, result.report.emitted['main.js']);
	const paths = inputPaths(result.row);
	assert.ok(paths.includes(result.area.installed(path.join('app', 'locale', 'de.js'))), paths.join(', '));
	// Nothing the filter rejected is claimed: it is in no chunk.
	assert.ok(!paths.includes(result.area.installed(path.join('app', 'locale', 'notes.txt.js'))), paths.join(', '));
});

// The stages that follow leave the module alone, so a minified bundle with a
// content-hashed name is described exactly as the plain one is.
test('describes a required context through minification and a content hash', () => {
	for (const scenario of ['minified', 'hashed']) {
		const result = build(scenario);
		assert.equal(result.row.status, 'present', `${scenario}: ${result.row.reason}`);
		assert.equal(result.row.sha256, result.report.emitted[result.row.path], scenario);
		assert.ok(inputPaths(result.row).includes(CONTEXT_MODULE), scenario);
	}
});

// Every other mode writes a different template, with chunk loading in it.
test('reports no data for a context whose requests are loaded from another chunk', () => {
	const row = build('lazy').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /its requests are resolved lazy, and only sync is described/);
	assert.deepEqual(row.inputs, []);
});

// Only what is already loaded, which the class writes a different template for.
test('reports no data for a context that answers only with what is loaded', () => {
	const row = build('weak').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /its requests are resolved weak, and only sync is described/);
	assert.deepEqual(row.inputs, []);
});

// A namespace object builds a second map out of the exports of every module the
// context reaches, which this adapter does not account for.
test('reports no data for a context whose requests answer with a namespace object', () => {
	const row = build('namespace-object').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /its requests answer with a namespace object/);
	assert.deepEqual(row.inputs, []);
});

// The globals the class writes into the text have to be the ones that were
// recorded when they were loaded, and the ones the compiler is using.
test('reports no data when the globals it writes have drifted since they were loaded', () => {
	const row = build('swapped-globals').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /RuntimeGlobals\.js no longer exports what it exported when it was loaded/);
	assert.deepEqual(row.inputs, []);
});

// Globals the compiler holds out that are not the ones loaded from its own lib
// directory: the text would be written from values nothing here recorded.
test('reports no data when the compiler exposes globals of its own', () => {
	const row = build('foreign-globals').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /the compiler exposes a RuntimeGlobals\.js other than the one loaded from its lib directory/);
	assert.deepEqual(row.inputs, []);
});

// The class webpack loaded, not something derived from it.
test('reports no data for a context module of a class derived from the loaded one', () => {
	const row = build('subclass').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /is not built by the loaded ContextModule\.js/);
	assert.deepEqual(row.inputs, []);
});

// A method of the module's own would be the one that wrote the text.
test('reports no data for a context module carrying an implementation of its own', () => {
	const row = build('own-source').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /carries an implementation of its own: getSyncSource implementation/);
	assert.deepEqual(row.inputs, []);
});

// The check the description rests on: every request the map answers is a module
// of this chunk, which the collector describes on its own. One that is not
// leaves text naming something nothing here accounts for.
test('reports no data for a context whose request is answered outside the chunk', () => {
	const row = build('foreign-target').row;
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /it names .*, which this chunk does not hold/);
	assert.deepEqual(row.inputs, []);
});

// A distribution that is byte-for-byte its own original and still not the
// webpack this adapter was pinned against: its files verify, and the text they
// write is not the text that was read when the pin was taken.
test('refuses a patched distribution that verifies against its own original', () => {
	const row = build('plain', { fork: true }).row;
	assert.equal(row.status, 'unsupported', row.reason);
	assert.match(row.reason, /ContextModule\.js is not the source of the pinned webpack 5\.94\.0/);
	assert.deepEqual(row.inputs, []);
});

// What the chunk was given for the module, not what the class would write now.
test('reports a hash mismatch when the generated code is not what the class writes', () => {
	const row = build('forged-code').row;
	assert.equal(row.status, 'hash-mismatch', row.reason);
	assert.match(row.reason, /is not what ContextModule\.js writes for this graph/);
	assert.deepEqual(row.inputs, []);
});
