'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture } = require('./fixture.cjs');
const { MARKER, SOURCES, addSources, resolveRuntimeModule, writeCorruptingClient, child } = require('./esbuild-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));
// The checkout of the instrumented esbuild of esbuild/README.md, whose
// executable and Node client must already be built from the pinned commit and
// the patch. It is an explicit input of this file: an ordinary install has no
// such checkout, and nothing here ever downloads or builds a compiler.
const TOOL_SOURCE = process.env.DK_ESBUILD_SOURCE;
const EVIDENCE = process.env.DK_ESBUILD_EVIDENCE;
const SKIP = TOOL_SOURCE === undefined || TOOL_SOURCE === '' ? 'DK_ESBUILD_SOURCE is not set to a checkout of the instrumented esbuild' : false;
const COMMIT = 'e9174d671b1882758cd32ac5e146200f5bee3e45';
const ENTRY = SKIP ? '' : path.join(TOOL_SOURCE, 'npm', 'esbuild', 'lib', 'main.js');
const BINARY = SKIP ? '' : path.join(TOOL_SOURCE, 'esbuild');
const LOADER = require.resolve('esbuild-loader');
// The published esbuild-loader 4.3.0 artifact, as packed in its npm archive.
const LOADER_SHA256 = 'sha256:64b2b3f0adaadc963e115caa4f0aeb137bf721eca2d0b7386fbe71cbe88f473e';
const STOCK_ENTRY = require.resolve('esbuild');
const STOCK_BINARY = path.join(path.dirname(require.resolve('esbuild/package.json')), '..', '@esbuild', `${process.platform}-${process.arch}`, 'bin', 'esbuild');
const APP_COMPONENT = 'node:app@0.1.0';
const WEBPACK_COMPONENT = 'node:webpack@5.94.0';
const ESBUILD_COMPONENT = 'pm:esbuild-runtime-source';

let scratch;
let fixture;
let runtime;
let corrupting;
let passThrough;
let areas = 0;

before(() => {
	if (SKIP) return;
	for (const file of [ENTRY, BINARY]) {
		assert.ok(fs.existsSync(file), `${file} must be the instrumented esbuild built from ${COMMIT} and the transform evidence patch`);
	}
	assert.equal(fs.readFileSync(path.join(TOOL_SOURCE, 'version.txt'), 'utf8').trim(), '0.25.0');
	assert.equal(sha256(LOADER), LOADER_SHA256, 'the installed esbuild-loader is not the published 4.3.0 artifact');
	scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-esbuild-')));
	fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
	// The published Go module of the pinned version, verified by the Go
	// toolchain and byte-compared with the commit the tool was built from.
	runtime = resolveRuntimeModule(scratch, TOOL_SOURCE, COMMIT);
	assert.equal(runtime.module.sum, 'h1:jRR9D1pfdb669VzdN4w0jwsDfrKE098nKMaDMKvMPyU=');
	assert.ok(runtime.module.origin === null || runtime.module.origin === COMMIT, `the module was built from ${runtime.module.origin}`);
	assert.deepEqual(runtime.module.checked.pinnedCommitBytes && runtime.module.checked.toolCheckoutBytes, true);
	// The component is the package the Go helper really packed and read back.
	assert.equal(runtime.packet.component.id, ESBUILD_COMPONENT);
	assert.match(runtime.packet.component.source.checksum, /^sha256:[0-9a-f]{64}$/);
	corrupting = { file: path.join(scratch, 'corrupting-client.cjs') };
	corrupting.sha256 = writeCorruptingClient(corrupting.file, ENTRY);
	passThrough = path.join(scratch, 'pass-through-loader.cjs');
	fs.writeFileSync(passThrough, 'module.exports = (source) => source;\n');
}, { timeout: 120000 });

after(() => {
	if (scratch) fs.rmSync(scratch, { recursive: true, force: true });
});

function sha256(file) {
	return `sha256:${crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')}`;
}

// One real webpack build per scenario, in its own process whose commonjs loader
// is recorded from the very first module on and whose environment already names
// the executable the collector is configured for.
function build(scenario, options = {}) {
	const area = fixture.workspace(`${scenario}-${areas++}`, { isolateOriginals: true });
	addSources(area);
	const app = path.join(area.modules, 'app');
	const tool = {
		entry: ENTRY,
		binary: BINARY,
		loader: LOADER,
		entrySHA256: sha256(ENTRY),
		binarySHA256: sha256(BINARY),
		loaderSHA256: sha256(LOADER),
		runtimeSource: runtime.file,
		runtimeSourceSHA256: runtime.sha256,
		...options.tool,
	};
	for (const key of options.without || []) delete tool[key];
	const setup = {
		scenario,
		context: area.root,
		modules: area.modules,
		entry: path.join(app, options.entry || 'index.ts'),
		output: area.output,
		proofPath: options.collect ? area.proofPath : undefined,
		webpackRoot: WEBPACK,
		tool,
		originals: [...area.originals, runtime.binding],
		appRoots: [app, area.originalOf('app')],
		passThroughLoader: passThrough,
		otherBinary: STOCK_BINARY,
	};
	const output = execFileSync(process.execPath, ['--require', PRELOAD, child], {
		cwd: area.root,
		encoding: 'utf8',
		timeout: 60000,
		env: { ...process.env, DK_ESBUILD_SETUP: JSON.stringify(setup), ESBUILD_BINARY_PATH: options.binaryPath || tool.binary },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.loader, '4.3.0');
	if (options.collect) {
		assert.ok(report.proof, 'the collector wrote no proof');
		// For a canonical validation of these proofs elsewhere; the directory is
		// the caller's and has to exist already.
		if (EVIDENCE !== undefined) {
			assert.ok(path.isAbsolute(EVIDENCE) && fs.statSync(EVIDENCE).isDirectory(), 'DK_ESBUILD_EVIDENCE must be an existing absolute directory');
			fs.writeFileSync(path.join(EVIDENCE, `${scenario}.json`), `${JSON.stringify(report.proof, null, 2)}\n`);
		}
		return { area, app, report };
	}
	assert.deepEqual(
		report.rows.map((row) => row.name).sort(),
		Object.keys(SOURCES).sort(),
	);
	return { area, app, report };
}

function rowOf(report, name) {
	const row = report.rows.find((candidate) => candidate.name === name);
	assert.ok(row, `no row for ${name}`);
	return row;
}

// A described module names the file esbuild really read, with the bytes that
// file carries and the component it is bound to.
function assertRawUnit(result, row) {
	assert.equal(row.status, 'present', row.reason);
	const file = path.join(result.app, row.name);
	assert.deepEqual(row.units[0], { path: file, sha256: sha256(file), component: APP_COMPONENT });
}

test('describes a transform that selected no runtime with the raw source alone', { skip: SKIP }, () => {
	const result = build('positive');
	for (const name of ['plain.ts', 'index.ts']) {
		const row = rowOf(result.report, name);
		assertRawUnit(result, row);
		assert.equal(row.units.length, 1, `${name} must not claim a runtime unit`);
	}
});

// The flag comes from the linker of this very transform, and the source it
// names is verified against the pinned checkout like any other input.
test('adds the verified esbuild runtime source to a transform that selected it', { skip: SKIP }, () => {
	const result = build('positive');
	const row = rowOf(result.report, 'runtime.ts');
	assertRawUnit(result, row);
	assert.equal(row.units.length, 2);
	assert.deepEqual(row.units[1], { path: runtime.file, sha256: runtime.sha256, component: ESBUILD_COMPONENT });
	assert.equal(sha256(runtime.file), runtime.sha256, 'the runtime source of the checkout is not the one of the pinned commit');
});

test('reports no data for a selected runtime whose source the collector was not given', { skip: SKIP }, () => {
	const result = build('no-runtime-source', { without: ['runtimeSource', 'runtimeSourceSHA256'] });
	const row = rowOf(result.report, 'runtime.ts');
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /selected the esbuild runtime, whose source this collector was not given/);
	assert.deepEqual(row.units, []);
	assertRawUnit(result, rowOf(result.report, 'plain.ts'));
});

// The file and its original change together, so the verification against the
// original still passes: only the bytes esbuild really read say otherwise.
test('reports a hash mismatch when the verified source is not what esbuild read', { skip: SKIP }, () => {
	const result = build('tamper');
	const row = rowOf(result.report, 'plain.ts');
	assert.equal(row.status, 'hash-mismatch');
	assert.match(row.reason, /esbuild did not read the verified bytes of/);
	assert.deepEqual(row.units, []);
	assert.equal(fs.readFileSync(path.join(result.app, 'plain.ts'), 'utf8').length, SOURCES['plain.ts'].length);
	assertRawUnit(result, rowOf(result.report, 'runtime.ts'));
});

test('reports a hash mismatch when the module source is not the code the transform returned', { skip: SKIP }, () => {
	const result = build('late-source');
	const row = rowOf(result.report, 'plain.ts');
	assert.equal(row.status, 'hash-mismatch');
	assert.match(row.reason, /is not the code the transform returned/);
	assert.deepEqual(row.units, []);
	assertRawUnit(result, rowOf(result.report, 'runtime.ts'));
});

// An unpatched esbuild of the same version produces the same code and no
// evidence at all; absent evidence is never read as a runtime that was not
// selected.
test('reports no data for a stock esbuild client and executable', { skip: SKIP }, () => {
	const result = build('stock', { tool: { entry: STOCK_ENTRY, entrySHA256: sha256(STOCK_ENTRY), binary: STOCK_BINARY, binarySHA256: sha256(STOCK_BINARY) }, binaryPath: STOCK_BINARY });
	for (const row of result.report.rows) {
		assert.equal(row.status, 'no-data');
		assert.match(row.reason, /produced no evidence/);
		assert.deepEqual(row.units, []);
	}
});

// The evidence is checked against the text and the code of the call it came
// with, so a client that runs the verified one and reports something else is a
// contradiction, not a described module.
test('reports an invalid result when the evidence does not describe the code that was returned', { skip: SKIP }, () => {
	const result = build('corrupting-client', { tool: { entry: corrupting.file, entrySHA256: corrupting.sha256 } });
	for (const row of result.report.rows) {
		assert.equal(row.status, 'invalid');
		assert.match(row.reason, /does not describe the code it returned/);
		assert.deepEqual(row.units, []);
	}
});

test('refuses to run when the executable is not the one the collector is configured for', { skip: SKIP }, () => {
	const result = build('wrong-binary', { tool: { binarySHA256: `sha256:${'0'.repeat(64)}` } });
	for (const row of result.report.rows) {
		assert.equal(row.status, 'hash-mismatch');
		assert.match(row.reason, /is not the binary this collector is configured for/);
		assert.deepEqual(row.units, []);
	}
});

// Another loader of the chain decides what esbuild reads or what the module
// becomes, and the adapter takes no part in the build.
test('takes no part in a loader chain of more than the esbuild loader', { skip: SKIP }, () => {
	const result = build('chain');
	for (const row of result.report.rows) {
		assert.equal(row.status, 'no-data');
		assert.match(row.reason, /was not built by an observed esbuild transform/);
		assert.deepEqual(row.units, []);
	}
});

test('leaves a loader configured with an implementation of its own untouched', { skip: SKIP }, () => {
	const result = build('foreign');
	assert.equal(result.report.userOptions.foreignIntact, true);
	assert.deepEqual(result.report.userOptions.keys, ['implementation', 'loader', 'target', 'tsconfigRaw']);
	for (const row of result.report.rows) {
		assert.equal(row.status, 'no-data');
		assert.match(row.reason, /was not built by an observed esbuild transform/);
		assert.deepEqual(row.units, []);
	}
});

function mainRow(result) {
	const row = result.report.proof.assets.find((candidate) => candidate.path === 'main.js');
	assert.ok(row, 'no main.js row in the proof');
	assert.equal(row.status, 'present', row.reason);
	assert.equal(row.sha256, sha256(path.join(result.area.output, 'main.js')));
	return row;
}

function inputOf(row, file) {
	return row.inputs.find((input) => input.path === file);
}

// The production call site: the collector installs the adapter from its own
// option and the described bundle carries the transformed source, the esbuild
// runtime source it selected and the webpack sources that rendered it.
test('describes a whole bundle whose module selected the esbuild runtime', { skip: SKIP }, () => {
	const result = build('collector-runtime', { collect: true, entry: 'only-runtime.ts' });
	const row = mainRow(result);
	const subject = path.join(result.app, 'only-runtime.ts');
	assert.deepEqual(inputOf(row, subject), { kind: 'source', path: subject, sha256: sha256(subject), components: [APP_COMPONENT], disposition: 'included' });
	assert.deepEqual(inputOf(row, runtime.file), { kind: 'source', path: runtime.file, sha256: runtime.sha256, components: [ESBUILD_COMPONENT], disposition: 'included' });
	for (const id of [APP_COMPONENT, ESBUILD_COMPONENT, WEBPACK_COMPONENT]) assert.ok(row.includedComponents.includes(id), `${id} is not an included component of ${row.includedComponents.join(', ')}`);
	// The identity of the runtime source is the published module the Go
	// toolchain verified, not a digest this fixture made up.
	assert.deepEqual(row.components.find((component) => component.id === ESBUILD_COMPONENT).source, {
		kind: 'pm',
		locator: runtime.packet.registry,
		checksum: runtime.packet.component.source.checksum,
	});
});

test('describes a whole bundle whose module selected no runtime without an esbuild component', { skip: SKIP }, () => {
	const result = build('collector-plain', { collect: true, entry: 'only-plain.ts' });
	const row = mainRow(result);
	const subject = path.join(result.app, 'only-plain.ts');
	assert.deepEqual(inputOf(row, subject), { kind: 'source', path: subject, sha256: sha256(subject), components: [APP_COMPONENT], disposition: 'included' });
	assert.equal(inputOf(row, runtime.file), undefined, 'a transform that selected no runtime must contribute no runtime source');
	assert.ok(!row.includedComponents.includes(ESBUILD_COMPONENT), `${ESBUILD_COMPONENT} must not be an included component of ${row.includedComponents.join(', ')}`);
	assert.ok(row.includedComponents.includes(APP_COMPONENT) && row.includedComponents.includes(WEBPACK_COMPONENT));
});

// The executable a client will run is fixed in the environment of its first
// load, and nothing in its bytes says which one that was.
test('reports no data when the esbuild client was already loaded in this process', { skip: SKIP }, () => {
	const result = build('preloaded-client');
	for (const row of result.report.rows) {
		assert.equal(row.status, 'no-data');
		assert.match(row.reason, /was already loaded in this process/);
		assert.deepEqual(row.units, []);
	}
});

// The client drops this one path from its environment and runs an executable of
// its own, so a declaration naming it describes nothing - whether or not a file
// is there.
test('refuses the executable path the esbuild client ignores', { skip: SKIP }, () => {
	const binary = '/usr/bin/esbuild';
	const result = build('ignored-binary', { tool: { binary, binarySHA256: `sha256:${'0'.repeat(64)}` }, binaryPath: binary });
	for (const row of result.report.rows) {
		assert.equal(row.status, 'no-data');
		assert.match(row.reason, /is the path the esbuild client ignores/);
		assert.deepEqual(row.units, []);
	}
});
