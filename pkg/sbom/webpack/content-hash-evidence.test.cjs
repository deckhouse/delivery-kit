'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture, bootstrapOriginal } = require('./fixture.cjs');
const { MARKER, addSources, child } = require('./content-hash-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));
// The published artifact, as packed in the npm archive of webpack 5.94.0.
const PLUGIN_SHA256 = 'sha256:a831672c978182b4f5d22cec43606187e165f0684395f349219bab036685ba58';
const HASHED = /^(chunk\.)?[0-9a-f]+\.js$/;

let scratch;
let fixture;
let minifierOriginals;
let areas = 0;

before(
	() => {
		assert.equal(sha256(path.join(WEBPACK, 'lib', 'optimize', 'RealContentHashPlugin.js')), PLUGIN_SHA256, 'the installed webpack is not the published 5.94.0 artifact');
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-contenthash-')));
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
		// The minified cases run webpack's default minimizer, which is an instrument
		// of this compilation like webpack itself.
		minifierOriginals = [bootstrapOriginal(path.join(scratch, 'terser-webpack-plugin'), 'terser-webpack-plugin').binding, bootstrapOriginal(path.join(scratch, 'terser'), 'terser').binding];
	},
	{ timeout: 300000 },
);

after(() => fs.rmSync(scratch, { recursive: true, force: true }));

function sha256(file) {
	return `sha256:${crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')}`;
}

// One real webpack build per scenario, in its own process whose commonjs loader
// is recorded from the very first module on.
function build(scenario, options = {}) {
	const area = fixture.workspace(`${scenario}-${areas++}`, { isolateOriginals: true });
	addSources(area);
	const setup = {
		scenario,
		context: area.root,
		modules: area.modules,
		entry: area.installed('app/split.js'),
		plainEntry: area.installed('app/index.js'),
		output: area.output,
		proofPath: options.collect ? area.proofPath : undefined,
		minimize: options.minimize === true,
		split: options.split !== false,
		webpackRoot: WEBPACK,
		originals: [...area.originals, ...minifierOriginals],
	};
	const output = execFileSync(process.execPath, ['--require', PRELOAD, child], {
		cwd: area.root,
		encoding: 'utf8',
		timeout: 60000,
		env: { ...process.env, DK_CONTENT_HASH_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.webpack, '5.94.0');
	return { area, report };
}

function hashedRows(report) {
	const rows = report.rows.filter((row) => HASHED.test(row.name));
	assert.equal(rows.length, 2, `expected the entry and its lazy chunk, got ${report.rows.map((row) => row.name).join(', ')}`);
	return rows;
}

// Both files are renamed and rewritten: the entry carries the hashed name of
// the chunk it loads, so its own hash changes with that substitution too.
test('describes both assets a real-content-hash build renamed and rewrote', () => {
	for (const scenario of ['plain', 'minified']) {
		const result = build(scenario);
		const rows = hashedRows(result.report);
		for (const row of rows) {
			assert.equal(row.status, 'present', `${scenario} ${row.name}: ${row.reason}`);
			assert.notEqual(row.was, row.name, `${scenario}: ${row.name} was not renamed`);
			assert.match(row.was, HASHED);
			// What the asset ends as is what stayed on disk under its new name.
			assert.equal(row.output, result.report.emitted[row.name], `${scenario}: ${row.name}`);
		}
		// The lazy chunk carries no hash of its own in its bytes; the entry that
		// loads it by its hashed name does, and is rewritten for it.
		assert.equal(rows.filter((row) => row.input !== row.output).length, 1, `${scenario}: no asset was rewritten`);
		assert.deepEqual(Object.keys(result.report.emitted).sort(), rows.map((row) => row.name).sort());
	}
});

function proofRows(report) {
	assert.ok(report.proof, 'the child wrote no proof');
	return report.proof.assets;
}

// The whole collector: the asset is bound to the file it was renamed to, and
// the bytes of that file are the ones the described chain ends with.
test('describes a bundle the content hashes renamed, with and without the minifier', () => {
	for (const minimize of [false, true]) {
		const result = build('plain', { collect: true, minimize, split: false });
		const rows = proofRows(result.report);
		assert.equal(rows.length, 1, rows.map((row) => row.path).join(', '));
		const [row] = rows;
		assert.equal(row.status, 'present', `minimize=${minimize}: ${row.reason}`);
		assert.match(row.path, HASHED);
		assert.deepEqual(Object.keys(result.report.emitted), [row.path]);
		assert.equal(row.sha256, result.report.emitted[row.path]);
		assert.equal(row.size, fs.statSync(path.join(result.area.output, row.path)).size);
		assert.ok(row.inputs.length > 0);
	}
});

// A lazy chunk is rendered by a chunk renderer this adapter does not describe,
// and the runtime chunk that loads it carries chunk-loading runtime modules it
// does not describe either: the content hashes of such a build are observed,
// but its composition is not.
test('reports no data for the assets of a code-splitting build it cannot describe', () => {
	const result = build('plain', { collect: true });
	const rows = proofRows(result.report);
	assert.equal(rows.length, 2);
	for (const row of rows) {
		assert.equal(row.status, 'no-data', row.reason);
		assert.match(row.path, HASHED);
		assert.equal(row.sha256, result.report.emitted[row.path]);
		assert.deepEqual(row.inputs, []);
	}
});

// What the content hashes were replaced in has to be what the minifier left
// behind: a plugin working between those two stages breaks the chain even
// though the substitution itself is a valid one.
test('reports no data when an asset changed between its minification and its content hash', () => {
	const result = build('between', { collect: true, split: false, minimize: true });
	for (const row of proofRows(result.report)) {
		assert.equal(row.status, 'no-data');
		assert.match(row.reason, /was changed before its content hash was replaced/);
		assert.deepEqual(row.inputs, []);
	}
});

// A plugin working in that same stage leaves bytes no substitution accounts for.
// A hash token is not code only while it is a hash: text that replaces one
// consistently everywhere is still an injection.
test('reports no data when a replacement content hash is not a hash', () => {
	const result = build('injected');
	const rows = result.report.rows.filter((row) => row.name.endsWith('.js'));
	assert.equal(rows.length, 2);
	assert.ok(rows.some((row) => row.name.includes('injected')), rows.map((row) => row.name).join(', '));
	for (const row of rows) {
		assert.equal(row.status, 'no-data', `${row.name}: ${row.reason}`);
		assert.match(row.reason, /is not a content hash/);
	}
});

test('reports no data when another plugin changes an asset while the hashes are replaced', () => {
	const result = build('altered');
	for (const row of hashedRows(result.report)) {
		assert.equal(row.status, 'no-data');
		assert.match(row.reason, /is not the content-hash substitution of the asset it was made from/);
		assert.equal(row.input, undefined);
	}
});

// The collector refuses the whole asset when the content hashes were not
// replaced the way the pinned plugin replaces them.
test('reports no data in the proof for an asset altered while the hashes are replaced', () => {
	const result = build('altered', { collect: true, split: false });
	for (const row of proofRows(result.report)) {
		assert.equal(row.status, 'no-data');
		assert.deepEqual(row.inputs, []);
		assert.equal(row.sha256, result.report.emitted[row.path]);
	}
});

// A rename of its own is not a content-hash substitution either, before the
// plugin runs or after it.
test('reports no data for an asset another plugin renamed while the hashes are replaced', () => {
	for (const scenario of ['renamed', 'late-rename']) {
		const result = build(scenario);
		const rows = result.report.rows.filter((row) => row.name.endsWith('.js'));
		assert.ok(rows.length > 0);
		for (const row of rows) {
			assert.equal(row.status, 'no-data', `${scenario}: ${row.reason}`);
			assert.match(row.reason, /which is not its content-hash substitution/);
			assert.equal(row.input, undefined);
		}
	}
});

// The plugin that performed the substitution is an instrument that has to be
// verified like any other, against the pinned webpack source.
test('reports no data when the plugin that replaced the hashes cannot be verified', () => {
	const result = build('unverified');
	for (const row of hashedRows(result.report)) {
		assert.equal(row.status, 'no-data');
		assert.match(row.reason, /RealContentHashPlugin\.js/);
		assert.equal(row.input, undefined);
	}
});

// The new hashes have to be the ones the pinned plugin computes, and nothing
// else may decide them.
test('reports no data when a tap decides the new content hashes', () => {
	const result = build('updatehash');
	for (const row of hashedRows(result.report)) {
		assert.equal(row.status, 'no-data');
		assert.match(row.reason, /another plugin decides the new content hashes/);
		assert.equal(row.input, undefined);
	}
});
