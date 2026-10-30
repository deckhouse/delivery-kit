'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture, bootstrapOriginal } = require('./fixture.cjs');
const { MARKER, WORKER, addSources, child } = require('./child-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));

let scratch;
let fixture;
let toolOriginals;
let builds = 0;

before(
	() => {
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-child-')));
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
function build(scenario) {
	const area = fixture.workspace(`${scenario}-${builds++}`, { isolateOriginals: true });
	addSources(area);
	const setup = {
		scenario,
		context: area.root,
		modules: area.modules,
		appDir: path.join(area.modules, 'app'),
		output: area.output,
		proofPath: area.proofPath,
		webpackRoot: WEBPACK,
		originals: [...area.originals, ...toolOriginals],
	};
	const output = execFileSync(process.execPath, ['--require', PRELOAD, child], {
		cwd: area.root,
		encoding: 'utf8',
		timeout: 60000,
		env: { ...process.env, DK_CHILD_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.webpack, '5.94.0');
	return { setup, area, report };
}

function workerRow(report) {
	const row = report.proof.assets.find((candidate) => candidate.path === WORKER);
	assert.ok(row, `no row for ${WORKER}: ${report.proof.assets.map((candidate) => candidate.path).join(', ')}`);
	return row;
}

// The worker bundle belongs to no chunk of the compilation that emits it, and
// is described through the chunk of the compilation that built it, down to the
// modules of that chunk.
test('describes an asset a child compilation built', () => {
	for (const scenario of ['plain', 'minified']) {
		const result = build(scenario);
		const row = workerRow(result.report);
		assert.equal(row.status, 'present', `${scenario}: ${row.reason}`);
		// The bytes it is bound to are the ones that stayed on disk under that
		// name: the compilation that emitted it changed nothing.
		assert.equal(row.sha256, result.report.emitted[WORKER]);
		assert.equal(row.sha256, sha256(path.join(result.setup.output, WORKER)));
		// The modules of the child chunk, and the sources of the webpack that
		// rendered it.
		for (const name of ['shared.js', 'worker-entry.js']) {
			assert.ok(
				row.inputs.some((input) => path.basename(input.path) === name),
				`${name} is not an input of ${WORKER}: ${row.inputs.map((input) => input.path).join(', ')}`,
			);
		}
		assert.ok(row.includedComponents.includes('node:webpack@5.94.0'), row.includedComponents.join(', '));
		// The parent's own asset is described as before, from its own chunk.
		const main = result.report.proof.assets.find((candidate) => candidate.path === 'main.js');
		assert.equal(main.status, 'present', main.reason);
		assert.ok(
			main.inputs.every((input) => path.basename(input.path) !== 'worker-entry.js'),
			'the worker entry leaked into the asset of the parent chunk',
		);
	}
});

// Two children writing one file: the asset is the work of neither alone.
test('reports no data for an asset two child compilations built', () => {
	const row = workerRow(build('two-children').report);
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /is emitted by 2 chunks of this compilation and the ones it made/);
	assert.deepEqual(row.inputs, []);
});

// What the child handed over has to be what this compilation holds: a rewrite
// in between is bytes this adapter cannot attribute.
test('reports no data for a child asset the compilation rewrote', () => {
	const row = workerRow(build('rewritten-by-parent').report);
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /is not the asset the child compilation handed over/);
	assert.deepEqual(row.inputs, []);
});

// The chunk of the child is described exactly as a chunk of any compilation is,
// refusals included.
test('reports no data for a child chunk another plugin shaped', () => {
	const row = workerRow(build('tapped-child-render').report);
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /fixture tapped render/);
	assert.deepEqual(row.inputs, []);
});

// A worker plugin asks for a single chunk, so an import inside the worker is
// folded into it and no chunk loading is needed.
test('describes a worker whose own import was folded into its single chunk', () => {
	const row = workerRow(build('lazy-worker').report);
	assert.equal(row.status, 'present', row.reason);
});

// Without that limit the worker loads a chunk of its own, which needs the
// import-scripts loading runtime no adapter of this set describes yet.
test('reports no data for a worker that loads chunks of its own', () => {
	const report = build('split-worker').report;
	const row = workerRow(report);
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /ImportScriptsChunkLoadingRuntimeModule\.js, which is not a described webpack runtime module/);
	assert.deepEqual(row.inputs, []);
	// The chunk it loads is an asset of a child compilation too, and is
	// described like any other.
	const loaded = report.proof.assets.filter((candidate) => candidate.path !== WORKER && candidate.path !== 'main.js');
	assert.equal(loaded.length, 1, report.proof.assets.map((candidate) => candidate.path).join(', '));
	assert.equal(loaded[0].status, 'present', loaded[0].reason);
	assert.equal(loaded[0].sha256, report.emitted[loaded[0].path]);
});

// A compilation this one did not make describes nothing here, however its
// assets reached the output.
test('reports no data for a chunk of a compilation this one did not make', () => {
	const report = build('foreign-child').report;
	const row = report.proof.assets.find((candidate) => candidate.path === 'grand.js');
	assert.ok(row, report.proof.assets.map((candidate) => candidate.path).join(', '));
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /belongs to a compilation that is not a child of this one/);
	assert.deepEqual(row.inputs, []);
});
