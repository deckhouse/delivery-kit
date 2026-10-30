'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test, before, after } = require('node:test');

const fixture = require('./worker-fixture.cjs');

const SKIP = fixture.available();
// The chain redoc builds its worker with needs the instrumented esbuild too.
const ESBUILD_SKIP = process.env.DK_ESBUILD_SOURCE ? false : 'DK_ESBUILD_SOURCE is not set to a checkout of the instrumented esbuild';

let scratch;

before(() => {
	scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-worker-evidence-')));
	if (SKIP) return;
	fixture.prepare(scratch);
}, { timeout: 600000 });

after(() => {
	fs.rmSync(scratch, { recursive: true, force: true });
});

function build(id, options = {}) {
	const where = fixture.area(scratch, id, options);
	return { where, ...fixture.build(where, options) };
}

function rowOf(report, kind) {
	const row = report.modules.find((candidate) => candidate.kind === kind);
	assert.ok(row, `the build described no ${kind} module:\n${JSON.stringify(report, null, 1)}`);
	return row;
}

function unitOf(row, file) {
	return row.units.find((unit) => unit.path.endsWith(file));
}

test('describes the module workerize-loader writes and the worker it embeds', { skip: SKIP }, () => {
	const result = build('inline');
	assert.deepEqual(result.report.assets, ['main.js'], 'an inline worker without a fallback emits no asset of its own');

	const wrapper = rowOf(result.report, 'wrapper');
	assert.equal(wrapper.status, 'present', wrapper.reason);

	// The loader's own published file authored the text, and it is bound to the
	// Git-pinned distribution rather than to a registry archive.
	const loader = unitOf(wrapper, path.join('workerize-loader', 'dist', 'index.js'));
	assert.ok(loader, 'the loader that wrote the module must be a unit of it');
	assert.equal(loader.sha256, fixture.PINNED['dist/index.js']);
	assert.equal(loader.component, fixture.COMPONENT.id);

	// The worker's own bytes are described by the compilation that built them:
	// its runtime comes from webpack, its entry from the worker source.
	// The worker's own bytes are described by the compilation that built them,
	// so its render, its runtime and the modules it was built from are all units
	// of the module that embeds it: nothing else in the parent build claims them.
	assert.ok(unitOf(wrapper, path.join('webpack', 'lib', 'javascript', 'JavascriptModulesPlugin.js')), 'the worker asset must carry its own render evidence');
	assert.ok(unitOf(wrapper, path.join('webpack', 'lib', 'RuntimeTemplate.js')), 'the worker asset must carry the runtime it was rendered with');
	const source = unitOf(wrapper, path.join('src', 'worker.js'));
	assert.ok(source, 'the module the worker was built from must be claimed by the module that embeds it');
	assert.equal(source.component, 'project');
	assert.ok(unitOf(wrapper, 'rpc-worker-loader.js'), 'the loader that built the worker entry must be claimed too');
	// The runtime webpack generated for the worker is code of the worker: the
	// classes that wrote it are claimed, not only the helpers that rendered it.
	assert.ok(unitOf(wrapper, 'HasOwnPropertyRuntimeModule.js'), 'the runtime modules generated for the worker must be claimed');
	assert.ok(unitOf(wrapper, 'DefinePropertyGettersRuntimeModule.js'), 'the exports runtime the worker needs must be claimed');
});

test('describes the worker entry as its source with the recomputed setup script', { skip: SKIP }, () => {
	const entry = rowOf(build('entry').report, 'entry');
	assert.equal(entry.status, 'present', entry.reason);
	assert.deepEqual(
		entry.units.map((unit) => [path.basename(unit.path), unit.component]).sort(),
		[['rpc-worker-loader.js', fixture.COMPONENT.id], ['worker.js', 'project']],
	);
	assert.equal(unitOf(entry, 'rpc-worker-loader.js').sha256, fixture.PINNED['dist/rpc-worker-loader.js']);
});

// The appended script is built at run time from the loader's own function
// source; describing it means recomputing it from the verified file, so a file
// that no longer holds that function is refused instead of trusted.
test('refuses a worker entry whose loader file is not the pinned one', { skip: SKIP }, () => {
	const root = path.join(scratch, 'tampered-entry-loader');
	const loaderRoot = copyLoader(root);
	const target = path.join(loaderRoot, 'dist', 'rpc-worker-loader.js');
	fs.writeFileSync(target, `${fs.readFileSync(target, 'utf8')}\n// not the published file\n`);

	const entry = rowOf(build('tampered-entry-loader-build', { loaderRoot }).report, 'entry');
	assert.equal(entry.status, 'hash-mismatch', entry.reason);
	assert.match(entry.reason, /is not the loader that builds the worker entry this version describes/);
	assert.deepEqual(entry.units, []);
});

test('refuses the wrapper when the loader that wrote it is not the pinned one', { skip: SKIP }, () => {
	const root = path.join(scratch, 'tampered-loader');
	const loaderRoot = copyLoader(root);
	const target = path.join(loaderRoot, 'dist', 'index.js');
	fs.writeFileSync(target, `${fs.readFileSync(target, 'utf8')}\n// not the published file\n`);

	const result = build('tampered-loader-build', { loaderRoot });
	const wrapper = rowOf(result.report, 'wrapper');
	// The recorder refuses the file outright, so nothing it pitched is described.
	assert.equal(wrapper.status, 'no-data', wrapper.reason);
	assert.match(wrapper.reason, /the workerize loader was not loaded in this process/);
	assert.deepEqual(wrapper.units, []);
});

// The rpc wrapper is required by the text, not loaded by node, so nothing but
// this adapter's own check stands between it and the module it is named in.
test('refuses the wrapper when the file it requires is not the pinned rpc wrapper', { skip: SKIP }, () => {
	const root = path.join(scratch, 'tampered-rpc-wrapper');
	const loaderRoot = copyLoader(root);
	const target = path.join(loaderRoot, 'dist', 'rpc-wrapper.js');
	fs.writeFileSync(target, `${fs.readFileSync(target, 'utf8')}\n// not the published file\n`);

	const wrapper = rowOf(build('tampered-rpc-wrapper-build', { loaderRoot }).report, 'wrapper');
	assert.equal(wrapper.status, 'hash-mismatch', wrapper.reason);
	assert.match(wrapper.reason, /is not the rpc wrapper this module requires this version describes/);
	assert.deepEqual(wrapper.units, []);
});

test('refuses the wrapper when the compilation kept a source the loader did not write', { skip: SKIP }, () => {
	const wrapper = rowOf(build('tampered-wrapper-source', { tamper: 'wrapper-source' }).report, 'wrapper');
	assert.equal(wrapper.status, 'hash-mismatch', wrapper.reason);
	assert.match(wrapper.reason, /was changed between the loader and the compilation/);
	assert.deepEqual(wrapper.units, []);
});

test('refuses a worker entry whose source changed between the build and the description', { skip: SKIP }, () => {
	const entry = rowOf(build('tampered-source', { tamper: 'worker-source' }).report, 'entry');
	assert.equal(entry.status, 'hash-mismatch', entry.reason);
	assert.match(entry.reason, /is not .*worker\.js with the recomputed worker setup appended/);
	assert.deepEqual(entry.units, []);
});

// Only the shape redoc builds is described: the bytes of the worker are in the
// module, and nothing else was asked of the loader.
test('refuses the options this version does not describe', { skip: SKIP }, () => {
	for (const [id, query, match] of [
		['an emitted worker', '?inline&fallback=true', /only a worker without a fallback asset is described/],
		['a worker loaded by url', '?fallback=false', /only an inline worker is described/],
		['a ready promise', '?inline&fallback=false&ready', /was given ready, which this version does not describe/],
		['a public path', '?inline&fallback=false&publicPath=true', /was given publicPath, which this version does not describe/],
	]) {
		const wrapper = rowOf(build(`options-${id.replace(/\W/g, '-')}`, { query }).report, 'wrapper');
		assert.equal(wrapper.status, 'no-data', `${id}: ${wrapper.reason}`);
		assert.match(wrapper.reason, match, id);
		assert.deepEqual(wrapper.units, [], id);
	}
});

test('describes nothing without the recorder that watched the loader run', { skip: SKIP }, () => {
	const result = build('no-preload', { preload: false });
	for (const kind of ['wrapper', 'entry']) {
		const row = rowOf(result.report, kind);
		assert.equal(row.status, 'no-data', row.reason);
		assert.match(row.reason, /the worker load recorder is not installed in this process/);
		assert.deepEqual(row.units, []);
	}
});

function copyLoader(root) {
	const loaderRoot = path.join(root, 'node_modules', 'workerize-loader');
	fs.mkdirSync(path.dirname(loaderRoot), { recursive: true });
	fs.cpSync(fixture.loaderRoot(), loaderRoot, { recursive: true });
	for (const sibling of fs.readdirSync(fixture.modulesRoot())) {
		// The loader is the copy under test, and webpack is linked below, to the
		// one that runs the build.
		if (sibling === 'workerize-loader' || sibling === 'webpack') continue;
		fs.cpSync(path.join(fixture.modulesRoot(), sibling), path.join(root, 'node_modules', sibling), { recursive: true });
	}
	// The loader loads webpack's own plugins from where it sits, and it must be
	// the webpack that runs the build.
	fs.symlinkSync(path.join(__dirname, 'node_modules', 'webpack'), path.join(root, 'node_modules', 'webpack'));
	return loaderRoot;
}

// Redoc's own shape: the worker is TypeScript behind an esbuild-loader, so the
// pitched module has a chain behind the pitch and the worker entry appends to
// a text no file holds.
test('describes the chain redoc builds its worker with', { skip: SKIP || ESBUILD_SKIP }, () => {
	const result = build('esbuild-tail', { tail: 'esbuild', query: '?inline&fallback=false' });

	const wrapper = rowOf(result.report, 'wrapper');
	assert.equal(wrapper.status, 'present', wrapper.reason);
	assert.match(wrapper.identifier, /workerize-loader\/dist\/index\.js\?inline&fallback=false!.*esbuild-loader/, 'the pitched module must carry the chain the pitch short-circuited');
	assert.ok(unitOf(wrapper, path.join('workerize-loader', 'dist', 'index.js')), 'the loader that wrote the module must be a unit of it');
	// The worker's own inputs are claimed here, and the TypeScript file is one.
	assert.ok(unitOf(wrapper, path.join('src', 'worker.ts')), 'the module the worker was built from must be claimed');

	const entry = rowOf(result.report, 'entry');
	assert.equal(entry.status, 'present', entry.reason);
	assert.match(entry.identifier, /rpc-worker-loader\.js!.*esbuild-loader/);
	assert.ok(unitOf(entry, path.join('src', 'worker.ts')), 'the entry must claim what esbuild transformed');
	assert.ok(unitOf(entry, 'rpc-worker-loader.js'), 'the entry must claim the loader that appended to it');
});

test('refuses a worker entry built by a chain whose tail is not described', { skip: SKIP || ESBUILD_SKIP }, () => {
	const result = build('esbuild-tail-undescribed', { tail: 'esbuild', withoutTail: true });
	const entry = rowOf(result.report, 'entry');
	assert.equal(entry.status, 'no-data', entry.reason);
	assert.match(entry.reason, /was built by a chain this collector describes no tail for/);
	assert.deepEqual(entry.units, []);

	// An input of the worker that cannot be described leaves the bytes the
	// wrapper embeds unaccounted for, so the wrapper is refused for that very
	// reason rather than claiming a composition with a hole in it.
	const wrapper = rowOf(result.report, 'wrapper');
	assert.equal(wrapper.status, 'no-data', wrapper.reason);
	assert.equal(wrapper.reason, entry.reason);
	assert.deepEqual(wrapper.units, []);
});

// The two comparisons of the wrapper are separate claims: that the loader wrote
// the text its inputs imply, and that the compilation kept what it wrote.
test('refuses the wrapper when the bytes it embeds are not the ones the worker emitted', { skip: SKIP }, () => {
	const wrapper = rowOf(build('observed-worker', { tamper: 'observed-worker' }).report, 'wrapper');
	assert.equal(wrapper.status, 'hash-mismatch', wrapper.reason);
	assert.match(wrapper.reason, /is not the text workerize-loader writes for what it was given/);
	assert.deepEqual(wrapper.units, []);
});

// A minified worker with a banner: the embedded bytes are no longer the plain
// render, and whether they can be described is the asset evidence's business,
// not this adapter's.
test('leaves a minified, bannered worker to the evidence of the compilation that built it', { skip: SKIP }, () => {
	const wrapper = rowOf(build('minimized-worker', { minimize: true, banner: 'dk worker banner' }).report, 'wrapper');
	assert.equal(wrapper.status, 'no-data', wrapper.reason);
	// The refusal is the asset evidence's: the bytes are no longer the render it
	// observed. Nothing about the wrapper itself is claimed or denied.
	assert.match(wrapper.reason, /worker\.js was changed between its render and its emit/);
	assert.deepEqual(wrapper.units, []);
});
