'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');
const { createFixture } = require('./fixture.cjs');
const { createArea, writeManifest, run, HEAP_LIMIT_MB, GIT_PACKAGE } = require('./activate-fixture.cjs');

let root, fixture;
before(() => {
	root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-activate-')));
	fixture = createFixture(root);
});
after(() => fs.rmSync(root, { recursive: true, force: true }));

function emitted(area) {
	return fs.existsSync(path.join(area.output, 'main.js'));
}

// Every recorder an adapter of this set reads has to be in place before the
// first file of the build is compiled, which is what the activation is for.
test('installs every load recorder of this adapter set', () => {
	const area = createArea(fixture, 'recorders');
	const result = run(area, {});
	assert.equal(result.status, 0, result.stderr);
	assert.deepEqual(result.probe.recorders, [
		'dk.sbom.webpack.cjs',
		'dk.sbom.webpack.include',
		'dk.sbom.webpack.stylesheet',
		'dk.sbom.webpack.stylesheet3',
		'dk.sbom.webpack.worker',
	]);
});

test('attaches the collector to the named configuration of a real CLI build', () => {
	const area = createArea(fixture, 'object');
	const result = run(area);
	assert.equal(result.status, 0, result.stderr);
	assert.ok(emitted(area));
	assert.equal(result.probe.exportsIsConfig, false, 'the loaded configuration must be the attached copy');
	assert.deepEqual(result.probe.declaredPlugins, ['DkFixtureProbe'], 'the configuration file must keep its own plugins array');
	assert.deepEqual(result.probe.compilerPlugins, ['CLIPlugin', 'DkFixtureProbe', 'DkSbomWebpackActivation']);
	assert.equal(result.proof.version, 1);
	assert.equal(result.proof.sourceRoot, fs.realpathSync(area.output));
	assert.deepEqual(
		result.proof.assets.map((asset) => asset.path),
		['main.js'],
	);
	// This fixture installs no verified original of webpack itself, so the
	// bootstrap of the only chunk has no evidence: the activation is proven by
	// the proof it produced for the actual build, not by a present row.
	assert.equal(result.proof.assets[0].status, 'no-data');
	assert.ok(result.proof.assets[0].reason);
	// A proof without evidence would look the same if the originals had never
	// been resolved at all, so the resolver the activation really loaded has to
	// have answered for the selected packages and to have delegated the primary
	// source it does not own.
	const answers = new Map(result.probe.originalsCalls.map((call) => [call.resource, call]));
	assert.deepEqual(answers.get('node_modules/pkg-a/index.js'), { resource: 'node_modules/pkg-a/index.js', component: 'pkg-a' });
	assert.deepEqual(answers.get('node_modules/pkg-b/index.js'), { resource: 'node_modules/pkg-b/index.js', component: 'pkg-b' });
	assert.deepEqual(answers.get('src/main.js'), { resource: 'src/main.js', component: null }, 'the primary source must be an answered Yarn miss, not an unasked one');
	assert.equal(result.proof.assets[0].sha256, `sha256:${require('node:crypto').createHash('sha256').update(fs.readFileSync(path.join(area.output, 'main.js'))).digest('hex')}`);
	assert.deepEqual(result.scratch, [], 'the activation must remove the originals it extracted');
});

test('preserves the env, argv and node options of a function configuration', () => {
	const area = createArea(fixture, 'function', { shape: 'function' });
	const result = run(area, { args: ['--env', 'fixture=on'] });
	assert.equal(result.status, 0, result.stderr);
	assert.equal(result.probe.exportsType, 'function');
	assert.equal(result.probe.call.env.fixture, 'on');
	assert.deepEqual(result.probe.call.argv, { mode: 'production' });
	assert.ok(result.probe.compilerPlugins.includes('DkSbomWebpackActivation'));
	assert.equal(result.proof.version, 1);
	assert.match(result.probe.nodeOptions, new RegExp(`^--max_old_space_size=${HEAP_LIMIT_MB} --require .*activate\\.cjs$`));
	const heapLimit = result.probe.heapLimit / 1048576;
	assert.ok(heapLimit > HEAP_LIMIT_MB * 0.9 && heapLimit < HEAP_LIMIT_MB * 2, `heap limit ${heapLimit}MB must come from the forwarded option`);
	assert.deepEqual(result.scratch, []);
});

// A typescript or esm configuration reaches the CLI transpiled, as a namespace
// whose default the CLI unwraps; the attachment belongs on what it unwraps to.
test('attaches the collector to a transpiled configuration the CLI unwraps', () => {
	const area = createArea(fixture, 'transpiled', { shape: 'transpiled' });
	const result = run(area, {});
	assert.equal(result.status, 0, result.stderr);
	assert.equal(result.probe.exportsIsConfig, false, 'the namespace is not the configuration itself');
	// The flag a transpiler marks non-enumerable survives the attachment.
	assert.deepEqual(result.probe.esModule, { value: true, writable: false, enumerable: false, configurable: false });
	assert.ok(result.probe.compilerPlugins.includes('DkSbomWebpackActivation'), result.probe.compilerPlugins.join(', '));
	assert.equal(result.proof.version, 1);
	assert.equal(result.proof.assets.length, 1);
	// The same proof an ordinary configuration of this fixture produces, over
	// the asset the build really wrote.
	assert.equal(result.proof.assets[0].sha256, `sha256:${require('node:crypto').createHash('sha256').update(fs.readFileSync(path.join(area.output, 'main.js'))).digest('hex')}`);
});

test('fails the build before any output when the primary-source manifest is missing', () => {
	const area = createArea(fixture, 'no-manifest');
	fs.rmSync(area.manifestPath);
	const result = run(area);
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /verified primary-source inputs are missing/);
	assert.equal(emitted(area), false);
	assert.equal(result.proof, undefined);
	assert.deepEqual(result.scratch, []);
});

test('leaves a build of another configuration alone and writes no proof', () => {
	const area = createArea(fixture, 'other-config');
	const result = run(area, { configPath: area.unmatchedConfigPath });
	assert.equal(result.status, 0, result.stderr);
	assert.ok(emitted(area));
	assert.equal(result.probe.exportsIsConfig, true);
	assert.deepEqual(result.probe.compilerPlugins, ['CLIPlugin', 'DkFixtureProbe']);
	assert.equal(result.proof, undefined, 'an unloaded configuration must produce no proof');
	assert.deepEqual(result.scratch, []);
});

test('observes nothing at all when the activation is not configured', () => {
	const area = createArea(fixture, 'inactive');
	const result = run(area, { active: false });
	assert.equal(result.status, 0, result.stderr);
	assert.ok(emitted(area));
	assert.equal(result.probe.exportsIsConfig, true);
	assert.deepEqual(result.probe.compilerPlugins, ['CLIPlugin', 'DkFixtureProbe']);
	assert.equal(result.probe.observer, false, 'a build without the activation must load no load recorder');
	assert.deepEqual(result.probe.recorders, [], 'a build without the activation must load no recorder at all');
	assert.equal(result.proof, undefined);
	assert.deepEqual(result.scratch, []);
});

test('resolves a Git-locked dependency through the build context it was given', () => {
	const area = createArea(fixture, 'git-listed', { git: 'listed' });
	const result = run(area);
	assert.equal(result.status, 0, result.stderr);
	assert.ok(emitted(area));
	const answers = new Map(result.probe.originalsCalls.map((call) => [call.resource, call]));
	// The Yarn resolver itself answered for the Git-locked package, which it can
	// only do through the manifest beside the build context: its cache holds no
	// archive for that entry at all.
	assert.deepEqual(answers.get(`node_modules/${GIT_PACKAGE}/index.js`), { resource: `node_modules/${GIT_PACKAGE}/index.js`, component: GIT_PACKAGE });
	assert.deepEqual(result.scratch, [], 'a Git original extracts nothing');
});

test('does not attribute a Git-locked dependency the build context does not list', () => {
	const area = createArea(fixture, 'git-unlisted', { git: 'unlisted' });
	const result = run(area);
	assert.equal(result.status, 0, result.stderr);
	const answers = new Map(result.probe.originalsCalls.map((call) => [call.resource, call]));
	assert.deepEqual(answers.get(`node_modules/${GIT_PACKAGE}/index.js`), { resource: `node_modules/${GIT_PACKAGE}/index.js`, status: 'no-data' });
	assert.equal(result.proof.assets[0].status, 'no-data');
});

// The same project installed by the other package manager: the activation
// chooses its resolver by the lockfile the project was built from, and that
// resolver answers for the installed packages.
test('resolves the originals of an npm-installed project', () => {
	const area = createArea(fixture, 'npm-project', { manager: 'npm' });
	const result = run(area);
	assert.equal(result.status, 0, result.stderr);
	assert.ok(emitted(area));
	const answers = new Map(result.probe.originalsCalls.map((call) => [call.resource, call]));
	assert.deepEqual(answers.get('node_modules/pkg-a/index.js'), { resource: 'node_modules/pkg-a/index.js', component: 'pkg-a' });
	assert.deepEqual(answers.get('node_modules/pkg-b/index.js'), { resource: 'node_modules/pkg-b/index.js', component: 'pkg-b' });
	assert.deepEqual(answers.get('src/main.js'), { resource: 'src/main.js', component: null }, 'the primary source must be an answered miss, not an unasked one');
	assert.deepEqual(result.scratch, [], 'the activation must remove the originals it extracted');
});

// Which package manager installed the project has to be unambiguous: with two
// lockfiles beside each other, or none, there is no single account of where the
// installed bytes came from.
test('refuses a project whose package manager cannot be told', () => {
	for (const [name, lockfiles, pattern] of [
		['two-lockfiles', ['yarn.lock', 'package-lock.json'], /carries yarn\.lock and package-lock\.json/],
		['no-lockfile', [], /carries no lockfile/],
		// Shipped by the project rather than written by its install, with rules
		// of its own that nothing here reads.
		['shrinkwrap', ['npm-shrinkwrap.json'], /carries npm-shrinkwrap\.json, whose installs this collector does not resolve/],
		['shrinkwrap-beside-lock', ['yarn.lock', 'npm-shrinkwrap.json'], /carries yarn\.lock and npm-shrinkwrap\.json/],
	]) {
		const area = createArea(fixture, name);
		for (const lockfile of ['yarn.lock', 'package-lock.json', 'npm-shrinkwrap.json']) {
			const file = path.join(area.root, lockfile);
			if (lockfiles.includes(lockfile)) fs.writeFileSync(file, fs.existsSync(file) ? fs.readFileSync(file) : '{}\n');
			else fs.rmSync(file, { force: true });
		}
		const result = run(area);
		assert.notEqual(result.status, 0, `${name} built anyway`);
		assert.match(result.stderr, pattern);
		assert.ok(!emitted(area), `${name} emitted an asset`);
	}
});

// The instrumented esbuild a stage transforms its modules with has to be
// declared to the activation, or every module it built stays unaccounted for.
const ESBUILD_SKIP = process.env.DK_ESBUILD_0_17_SOURCE ? false : 'DK_ESBUILD_0_17_SOURCE is not set to a checkout of the instrumented esbuild';

// The asset of this workspace is never described whole - the webpack that runs
// it stands outside the project and is nobody's original here - so what the
// declaration changes is read where it shows: in what the asset is still
// missing an account of.
function reasonsFor(result, file) {
	const asset = result.proof.assets.find((row) => row.path === 'main.js');

	return (asset.reason || '').split('; ').filter((reason) => reason.includes(file));
}

test('describes a module an esbuild the environment declares transformed', { skip: ESBUILD_SKIP }, () => {
	const area = createArea(fixture, 'esbuild-declared', { esbuild: '0.17.19' });
	const result = run(area);
	assert.equal(result.status, 0, result.stderr);
	assert.deepEqual(reasonsFor(result, 'typed.ts'), [], 'the transformed module must leave nothing unaccounted for');
	// The module really was transformed by the declared loader, and the resolver
	// was asked for the file behind it.
	const answers = new Map(result.probe.originalsCalls.map((call) => [call.resource, call]));
	assert.deepEqual(answers.get(path.join('src', 'typed.ts')), { resource: path.join('src', 'typed.ts'), component: null });
});

// Without it the build is the same build, and the module is simply not
// described: a tool nobody declared is not one this collector may assume.
test('leaves a module of an undeclared esbuild unaccounted for', { skip: ESBUILD_SKIP }, () => {
	const area = createArea(fixture, 'esbuild-undeclared', { esbuild: '0.17.19' });
	const result = run(area, { env: { DK_SBOM_ESBUILD_VERSION: '', DK_SBOM_ESBUILD_LOADER_VERSION: '', DK_SBOM_ESBUILD_ENTRY: '', DK_SBOM_ESBUILD_BINARY: '', DK_SBOM_ESBUILD_LOADER: '', DK_SBOM_ESBUILD_RUNTIME_SOURCE: '' } });
	assert.equal(result.status, 0, result.stderr);
	const reasons = reasonsFor(result, 'typed.ts');
	assert.equal(reasons.length, 1, reasons.join('; '));
	assert.match(reasons[0], /loader-transformed module/);
});

test('refuses a half-declared instrumented esbuild', { skip: ESBUILD_SKIP }, () => {
	const area = createArea(fixture, 'esbuild-partial', { esbuild: '0.17.19' });
	const result = run(area, { env: { DK_SBOM_ESBUILD_BINARY: '' } });
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /declared by DK_SBOM_ESBUILD_ENTRY.*together, or by none of them/s);
	assert.equal(emitted(area), false);
});

// The digests of the two files this build made itself are the context's to
// answer for: what the environment names, it does not vouch for.
test('refuses an instrumented esbuild the build context does not carry', { skip: ESBUILD_SKIP }, () => {
	const area = createArea(fixture, 'esbuild-unlisted', { esbuild: '0.17.19' });
	area.esbuildUnlisted = true;
	writeManifest(area, false);
	const result = run(area);
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /DK_SBOM_ESBUILD_ENTRY names .*which the verified build context does not carry/);
	assert.equal(emitted(area), false);
});

test('refuses a version pair this collector does not describe', { skip: ESBUILD_SKIP }, () => {
	const area = createArea(fixture, 'esbuild-pair', { esbuild: '0.17.19' });
	const result = run(area, { env: { DK_SBOM_ESBUILD_LOADER_VERSION: '4.3.0' } });
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /is not a described pair/);
	assert.equal(emitted(area), false);
});
