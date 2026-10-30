'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');
const { createFixture } = require('./fixture.cjs');
const { createArea, run, HEAP_LIMIT_MB, GIT_PACKAGE } = require('./activate-fixture.cjs');

let root, fixture;
before(() => {
	root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-activate-')));
	fixture = createFixture(root);
});
after(() => fs.rmSync(root, { recursive: true, force: true }));

function emitted(area) {
	return fs.existsSync(path.join(area.output, 'main.js'));
}

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
	const answers = new Map(result.probe.yarnCalls.map((call) => [call.resource, call]));
	assert.deepEqual(answers.get('node_modules/pkg-a/index.js'), { resource: 'node_modules/pkg-a/index.js', component: 'pkg-a' });
	assert.deepEqual(answers.get('node_modules/pkg-b/index.js'), { resource: 'node_modules/pkg-b/index.js', component: 'pkg-b' });
	assert.deepEqual(answers.get('src/main.js'), { resource: 'src/main.js', component: null }, 'the primary source must be an answered Yarn miss, not an unasked one');
	assert.equal(result.proof.assets[0].sha256, `sha256:${require('node:crypto').createHash('sha256').update(fs.readFileSync(path.join(area.output, 'main.js'))).digest('hex')}`);
	assert.deepEqual(result.scratch, [], 'the activation must remove the originals it extracted');
});

test('preserves the env, argv and node options of a function configuration', () => {
	const area = createArea(fixture, 'function', { asFunction: true });
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
	assert.equal(result.proof, undefined);
	assert.deepEqual(result.scratch, []);
});

test('resolves a Git-locked dependency through the build context it was given', () => {
	const area = createArea(fixture, 'git-listed', { git: 'listed' });
	const result = run(area);
	assert.equal(result.status, 0, result.stderr);
	assert.ok(emitted(area));
	const answers = new Map(result.probe.yarnCalls.map((call) => [call.resource, call]));
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
	const answers = new Map(result.probe.yarnCalls.map((call) => [call.resource, call]));
	assert.deepEqual(answers.get(`node_modules/${GIT_PACKAGE}/index.js`), { resource: `node_modules/${GIT_PACKAGE}/index.js`, status: 'no-data' });
	assert.equal(result.proof.assets[0].status, 'no-data');
});
