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
// The second described pair: the instrumented esbuild 0.17.19 of
// esbuild/0002-transform-runtime-evidence-v0.17.19.patch and the
// esbuild-loader 3.0.1 that depends on it, installed under an alias and
// recognized by the digest of its published artifact rather than by that name.
const OLD_TOOL_SOURCE = process.env.DK_ESBUILD_0_17_SOURCE;
const OLD_SKIP = SKIP || (OLD_TOOL_SOURCE === undefined || OLD_TOOL_SOURCE === '' ? 'DK_ESBUILD_0_17_SOURCE is not set to a checkout of the instrumented esbuild 0.17.19' : false);
const OLD_COMMIT = 'd47ab43980c457db27d2671ab618cd5c40a618a7';
const OLD_ENTRY = OLD_SKIP ? '' : path.join(OLD_TOOL_SOURCE, 'npm', 'esbuild', 'lib', 'main.js');
const OLD_BINARY = OLD_SKIP ? '' : path.join(OLD_TOOL_SOURCE, 'esbuild');
const OLD_LOADER = require.resolve('esbuild-loader-3.0.1');
const OLD_LOADER_SHA256 = 'sha256:95888f5eda79612e84c2c5723b2fee45d1acbde7fd979e8f42ede582c913b723';
const PAIR = { esbuild: '0.25.0', esbuildLoader: '4.3.0' };
const OLD_PAIR = { esbuild: '0.17.19', esbuildLoader: '3.0.1' };
const STOCK_ENTRY = require.resolve('esbuild');
const STOCK_BINARY = path.join(path.dirname(require.resolve('esbuild/package.json')), '..', '@esbuild', `${process.platform}-${process.arch}`, 'bin', 'esbuild');
const APP_COMPONENT = 'node:app@0.1.0';
const WEBPACK_COMPONENT = 'node:webpack@5.94.0';
const ESBUILD_COMPONENT = 'pm:esbuild-runtime-source';

let scratch;
let fixture;
let runtime;
let oldRuntime;
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
	if (OLD_SKIP) return;
	for (const file of [OLD_ENTRY, OLD_BINARY]) {
		assert.ok(fs.existsSync(file), `${file} must be the instrumented esbuild built from ${OLD_COMMIT} and the ported transform evidence patch`);
	}
	assert.equal(fs.readFileSync(path.join(OLD_TOOL_SOURCE, 'version.txt'), 'utf8').trim(), '0.17.19');
	assert.equal(sha256(OLD_LOADER), OLD_LOADER_SHA256, 'the aliased esbuild-loader is not the published 3.0.1 artifact');
	assert.equal(require(path.join(path.dirname(path.dirname(OLD_LOADER)), 'package.json')).name, 'esbuild-loader', 'the alias holds another package');
	oldRuntime = resolveRuntimeModule(scratch, OLD_TOOL_SOURCE, OLD_COMMIT, 'v0.17.19');
	assert.equal(oldRuntime.module.sum, 'h1:JdzNCvfFEoUCXKHhdP326Vn2mhCu8PybXeBDHaSRyWo=');
	assert.deepEqual(oldRuntime.module.checked.pinnedCommitBytes && oldRuntime.module.checked.toolCheckoutBytes, true);
}, { timeout: 240000 });

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
	const old = options.pair === OLD_PAIR;
	const source = old ? oldRuntime : runtime;
	const tool = {
		versions: options.pair || PAIR,
		entry: old ? OLD_ENTRY : ENTRY,
		binary: old ? OLD_BINARY : BINARY,
		loader: old ? OLD_LOADER : LOADER,
		entrySHA256: sha256(old ? OLD_ENTRY : ENTRY),
		binarySHA256: sha256(old ? OLD_BINARY : BINARY),
		runtimeSource: source.file,
		runtimeSourceSHA256: source.sha256,
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
		originals: [...area.originals, source.binding, ...(options.originals || [])],
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
	assert.equal(report.loader, options.expectLoader || tool.versions.esbuildLoader);
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

// The second pair, proved against the real instrumented esbuild 0.17.19 and the
// esbuild-loader 3.0.1 installed under an alias.
test('describes transforms of the second pinned esbuild and loader pair', { skip: OLD_SKIP }, () => {
	const result = build('pair-0-17', { pair: OLD_PAIR });
	for (const name of ['plain.ts', 'index.ts']) {
		const row = rowOf(result.report, name);
		assertRawUnit(result, row);
		assert.equal(row.units.length, 1, `${name} must not claim a runtime unit`);
	}
	const selected = rowOf(result.report, 'runtime.ts');
	assertRawUnit(result, selected);
	assert.equal(selected.units.length, 2);
	assert.deepEqual(selected.units[1], { path: oldRuntime.file, sha256: oldRuntime.sha256, component: oldRuntime.packet.component.id });
	assert.notEqual(oldRuntime.sha256, runtime.sha256, 'the two pinned versions must not share a runtime source');
});

// The loader is recognized by the digest of its published artifact: the 3.0.1
// file on disk is simply not the 4.3.0 this build declares, and the name of the
// directory it sits in — an alias here — takes no part in that.
test('refuses a loader that is not the published artifact of the declared pair', { skip: OLD_SKIP }, () => {
	const result = build('pair-loader-mismatch', {
		tool: { loader: OLD_LOADER, entry: OLD_ENTRY, binary: OLD_BINARY, entrySHA256: sha256(OLD_ENTRY), binarySHA256: sha256(OLD_BINARY) },
		binaryPath: OLD_BINARY,
		expectLoader: '3.0.1',
	});
	for (const name of Object.keys(SOURCES)) {
		const row = rowOf(result.report, name);
		assert.equal(row.status, 'hash-mismatch', row.reason);
		assert.match(row.reason, /is not the published esbuild-loader 4\.3\.0 this build declares/);
		assert.deepEqual(row.units, []);
	}
});

// Everything on disk is what the pair pins except the compiler that ran: its
// evidence names another producer, which is not described by this pair.
test('refuses evidence of an esbuild other than the one the pair pins', { skip: OLD_SKIP }, () => {
	const result = build('pair-producer-mismatch', { tool: { entry: OLD_ENTRY, binary: OLD_BINARY, entrySHA256: sha256(OLD_ENTRY), binarySHA256: sha256(OLD_BINARY) }, binaryPath: OLD_BINARY });
	for (const name of Object.keys(SOURCES)) {
		const row = rowOf(result.report, name);
		assert.equal(row.status, 'unsupported', row.reason);
		assert.match(row.reason, /transformed by dk-sbom\/1 esbuild 0\.17\.19 evidence version 1, not dk-sbom\/1 esbuild 0\.25\.0/);
		assert.deepEqual(row.units, []);
	}
});

// The runtime source is the one of the declared esbuild. The pair supplies the
// digest, so a build that hands over the other version's file is refused where
// a unit would have been claimed against it — and only there: a module that
// selects no runtime is unaffected.
test('refuses the runtime source of the other pinned esbuild', { skip: OLD_SKIP }, () => {
	const crossed = path.join(OLD_TOOL_SOURCE, 'internal', 'runtime', 'runtime.go');
	assert.notEqual(sha256(crossed), sha256(path.join(TOOL_SOURCE, 'internal', 'runtime', 'runtime.go')));
	// Declaring nothing about its digest is possible only because the pair pins
	// one; the file itself is the other version's.
	// The other tree is a verified original too, so the crossed file resolves to
	// a unit and the comparison that refuses it is the digest one.
	const result = build('pair-runtime-crossed', { tool: { runtimeSource: crossed, runtimeSourceSHA256: undefined }, originals: [oldRuntime.binding] });
	for (const name of ['plain.ts', 'index.ts']) {
		const row = rowOf(result.report, name);
		assert.equal(row.status, 'present', row.reason);
	}
	const selected = rowOf(result.report, 'runtime.ts');
	assert.equal(selected.status, 'hash-mismatch', selected.reason);
	assert.match(selected.reason, /is not the runtime source of esbuild 0\.25\.0/);
	assert.deepEqual(selected.units, []);
});

// The declaration itself, with no build: a pair this adapter does not describe
// is a programming error, not a result.
test('refuses a tool declaration that names no described pair', () => {
	const { installEsbuildEvidence } = require('./esbuild-evidence.cjs');
	const compiler = { hooks: { compilation: { tap() {} } }, webpack: { version: '5.94.0', NormalModule: { getCompilationHooks: () => ({ beforeLoaders: { tap() {} } }) } } };
	const base = {
		versions: PAIR,
		entry: '/tool/main.js',
		binary: '/tool/esbuild',
		loader: '/tool/loader.cjs',
		entrySHA256: `sha256:${'a'.repeat(64)}`,
		binarySHA256: `sha256:${'b'.repeat(64)}`,
	};
	for (const [id, versions, message] of [
		['missing', undefined, /tool\.versions must name the esbuild and esbuild-loader of this build/],
		['not an object', 'esbuild 0.25.0', /tool\.versions must name the esbuild and esbuild-loader of this build/],
		['unknown esbuild', { esbuild: '0.24.0', esbuildLoader: '4.3.0' }, /esbuild 0\.24\.0 with esbuild-loader 4\.3\.0 is not a described pair/],
		['unknown loader', { esbuild: '0.25.0', esbuildLoader: '3.0.1' }, /esbuild 0\.25\.0 with esbuild-loader 3\.0\.1 is not a described pair/],
		['crossed pair', { esbuild: '0.17.19', esbuildLoader: '4.3.0' }, /esbuild 0\.17\.19 with esbuild-loader 4\.3\.0 is not a described pair/],
	]) {
		assert.throws(() => installEsbuildEvidence(compiler, { ...base, versions }, () => {}), TypeError, id);
		assert.throws(() => installEsbuildEvidence(compiler, { ...base, versions }, () => {}), message, id);
	}
	// A declared digest may repeat what the pair pins and may not contradict it.
	assert.throws(
		() => installEsbuildEvidence(compiler, { ...base, loaderSHA256: `sha256:${'c'.repeat(64)}` }, () => {}),
		/tool.loaderSHA256 is not the published esbuild-loader 4\.3\.0/,
	);
	const crossedRuntime = OLD_SKIP ? null : path.join(OLD_TOOL_SOURCE, 'internal', 'runtime', 'runtime.go');
	assert.throws(
		() => installEsbuildEvidence(compiler, { ...base, runtimeSource: crossedRuntime || '/tool/runtime.go', runtimeSourceSHA256: crossedRuntime ? sha256(crossedRuntime) : `sha256:${'d'.repeat(64)}` }, () => {}),
		/tool.runtimeSourceSHA256 is not the runtime source of esbuild 0\.25\.0/,
	);
	// The pinned digest itself is accepted, and so is leaving it out.
	for (const loaderSHA256 of [undefined, LOADER_SHA256]) {
		const evidence = installEsbuildEvidence(compiler, { ...base, loaderSHA256 }, () => {});
		assert.equal(typeof evidence, 'function');
	}
});
