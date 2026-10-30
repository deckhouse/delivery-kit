'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { available, prepare, area, build } = require('./worker-wiring-fixture.cjs');

// A worker that itself embeds a worker: the modules of the inner one are
// described through the outer compilation's walk, which has to carry the
// stages of the build with it.
const NESTED_WORKER = "import makeInner from 'workerize-loader?inline&fallback=false!./inner.js';\n\nconst inner = makeInner();\n\nexport function add(a, b) {\n\treturn inner.twice(a + b);\n}\n";
const INNER_WORKER = 'export function twice(n) {\n\treturn n * 2;\n}\n';

const SKIP = available();
const TAIL_SKIP = SKIP || (process.env.DK_ESBUILD_SOURCE ? false : 'DK_ESBUILD_SOURCE is not set to the instrumented esbuild');

let scratch;

before(
	() => {
		if (SKIP) return;
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-worker-wiring-')));
		prepare(scratch);
	},
	{ timeout: 900000 },
);

after(() => scratch && fs.rmSync(scratch, { recursive: true, force: true }));

function rowOf(report, name) {
	const row = report.proof.assets.find((asset) => asset.path === name);
	assert.ok(row, report.proof.assets.map((asset) => asset.path).join(', '));
	return row;
}

// The module workerize-loader pitched has to reach the worker adapter through
// the collector's own dispatch, and what it claims has to carry the loader that
// wrote it and the worker's own sources.
test('describes a build whose worker is embedded in the bundle', { skip: SKIP }, () => {
	const where = area(scratch, 'inline');
	const result = build(where);
	assert.ok(!result.report.error, result.report.error);
	const row = rowOf(result.report, 'main.js');
	assert.equal(row.status, 'present', row.reason);
	const claimed = row.inputs.map((input) => path.basename(input.path));
	for (const file of ['index.js', 'worker.js', 'rpc-wrapper.js']) assert.ok(claimed.includes(file), `${file} is not claimed: ${claimed.join(', ')}`);
	// The worker is really inside the bundle rather than beside it, with both of
	// the exports it was asked for.
	assert.deepEqual(result.report.assets, ['main.js']);
	assert.match(result.report.bundle, /function add/);
	assert.match(result.report.bundle, /function mul/);
	for (const method of ['add', 'mul']) assert.ok(result.report.bundle.includes(`"${method}"`), `${method} is not an rpc method of the wrapper`);
});

// A worker built with no fallback is an asset of nobody: the child compilation
// it was built in emits nothing here, so the collector does not walk it, and
// the only account of its modules is the wrapper's.
test('claims the modules of a fallback-less worker through the wrapper alone', { skip: SKIP }, () => {
	const result = build(area(scratch, 'no-fallback'));
	assert.ok(!result.report.error, result.report.error);
	// The child really was compiled, and really holds the worker.
	const child = result.report.children.find((candidate) => candidate.modules.includes('worker.js'));
	assert.ok(child, JSON.stringify(result.report.children));
	// And nothing it emitted is an asset of the build.
	for (const name of child.assets) assert.ok(!result.report.assets.includes(name), `${name} is an asset of the parent as well`);
	const row = rowOf(result.report, 'main.js');
	assert.equal(row.status, 'present', row.reason);
	// The worker's own source is claimed once, and by the one asset there is.
	assert.equal(
		row.inputs.filter((input) => path.basename(input.path) === 'worker.js').length,
		1,
	);
});

// A worker emitted beside the bundle is an asset of this build, and the child
// compilation that made it is walked for that asset like any other: its modules
// are claimed there, not through the wrapper.
test('describes the worker a build emits beside its bundle', { skip: SKIP }, () => {
	const result = build(area(scratch, 'fallback', { query: '' }), { query: '' });
	assert.ok(!result.report.error, result.report.error);
	const worker = result.report.assets.find((name) => name !== 'main.js');
	assert.ok(worker, result.report.assets.join(', '));
	const emitted = rowOf(result.report, worker);
	assert.equal(emitted.status, 'present', emitted.reason);
	assert.ok(
		emitted.inputs.some((input) => path.basename(input.path) === 'worker.js'),
		emitted.inputs.map((input) => input.path).join(', '),
	);
	// The bundle itself carries the wrapper, and this is the shape of it the
	// worker adapter does not read: the loader was given other options than the
	// ones it describes. The dispatch is what put that reason there.
	const bundle = rowOf(result.report, 'main.js');
	assert.equal(bundle.status, 'no-data', bundle.reason);
	assert.match(bundle.reason, /workerize-loader was given options this version cannot read/);
	assert.deepEqual(bundle.inputs, []);
});

// Redoc's shape: the worker is TypeScript behind esbuild-loader, so the entry
// loader appends to a text no file holds, and the tail the collector hands the
// worker adapter is the one that produced it.
test('describes a worker whose entry was built by an esbuild tail', { skip: TAIL_SKIP }, () => {
	const where = area(scratch, 'ts-worker', { tail: 'esbuild' });
	const result = build(where, { tail: 'esbuild' });
	assert.ok(!result.report.error, result.report.error);
	const row = rowOf(result.report, 'main.js');
	assert.equal(row.status, 'present', row.reason);
	const claimed = row.inputs.map((input) => path.basename(input.path));
	for (const file of ['worker.ts', 'rpc-wrapper.js']) assert.ok(claimed.includes(file), `${file} is not claimed: ${claimed.join(', ')}`);
	// The types really were compiled away, and the worker really is embedded.
	assert.match(result.report.bundle, /function add/);
	assert.ok(!result.report.bundle.includes(': number'), 'the typescript stands in the bundle');
});

// The worker's own asset went through the stages of the compilation that made
// it, so the adapter has to be handed the evidence of those stages: with a
// minifier in the build, the embedded bytes are the minified ones.
test('describes a minified worker embedded in a minified bundle', { skip: SKIP }, () => {
	const result = build(area(scratch, 'minimized'), { minimize: true });
	assert.ok(!result.report.error, result.report.error);
	const row = rowOf(result.report, 'main.js');
	assert.equal(row.status, 'present', row.reason);
	const claimed = row.inputs.map((input) => path.basename(input.path));
	for (const file of ['worker.js', 'rpc-wrapper.js']) assert.ok(claimed.includes(file), `${file} is not claimed: ${claimed.join(', ')}`);
	// Minified: the worker's own source no longer stands in the bundle as it was
	// written.
	assert.ok(!result.report.bundle.includes('export function add'), 'the worker was not minified');
});

// The worker's modules are described by the account of the compilation that
// built them: a definer its own compiler was given after it was made splices
// code the parent never saw, and the wrapper that embeds those modules owes
// that refusal.
test('refuses a worker whose own compilation defines constants as code', { skip: SKIP }, () => {
	const result = build(area(scratch, 'child-define'), { childDefine: true });
	assert.ok(!result.report.error, result.report.error);
	const row = rowOf(result.report, 'main.js');
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /plugins define constants in this compilation/);
	assert.deepEqual(row.inputs, []);
});

// A worker asked for inline without saying anything about its fallback is
// emitted beside the bundle as well as embedded in it: the asset is described
// by the compilation that made it, and the wrapper the adapter does not read
// claims none of it.
test('describes the worker of a build that keeps its fallback', { skip: SKIP }, () => {
	const result = build(area(scratch, 'inline-fallback', { query: '?inline' }), { query: '?inline' });
	assert.ok(!result.report.error, result.report.error);
	const worker = result.report.assets.find((name) => name !== 'main.js');
	assert.ok(worker, result.report.assets.join(', '));
	const emitted = rowOf(result.report, worker);
	assert.equal(emitted.status, 'present', emitted.reason);
	assert.ok(
		emitted.inputs.some((input) => path.basename(input.path) === 'worker.js'),
		emitted.inputs.map((input) => input.path).join(', '),
	);
	// The wrapper of such a build loads the worker from that asset when the
	// browser cannot take the embedded one, which this adapter does not read.
	const bundle = rowOf(result.report, 'main.js');
	assert.equal(bundle.status, 'no-data', bundle.reason);
	assert.match(bundle.reason, /only a worker without a fallback asset is described/);
	// The worker is claimed by the asset that holds it, and by nothing else.
	assert.deepEqual(bundle.inputs, []);
});

// A worker inside a worker: the inner one is a module of the outer worker's
// chunk, and the account of it goes through the same stages as every other
// asset of this build.
test('describes a minified worker that embeds a worker of its own', { skip: SKIP }, () => {
	const where = area(scratch, 'nested', { workerSource: NESTED_WORKER });
	fs.writeFileSync(path.join(where.src, 'inner.js'), INNER_WORKER);
	const result = build(where, { minimize: true });
	assert.ok(!result.report.error, result.report.error);
	const row = rowOf(result.report, 'main.js');
	assert.equal(row.status, 'present', row.reason);
	const claimed = row.inputs.map((input) => path.basename(input.path));
	for (const file of ['worker.js', 'inner.js', 'rpc-wrapper.js']) assert.ok(claimed.includes(file), `${file} is not claimed: ${claimed.join(', ')}`);
	// Both workers really are inside the one asset this build emits.
	assert.deepEqual(result.report.assets, ['main.js']);
});
