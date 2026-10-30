'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture, bootstrapOriginal } = require('./fixture.cjs');
const { MARKER, SUFFIX, COMMENTS, addSources, child } = require('./license-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));

let scratch;
let fixture;
let toolOriginals;
let builds = 0;

before(
	() => {
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-license-')));
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
		toolOriginals = [
			bootstrapOriginal(path.join(scratch, 'terser-webpack-plugin'), 'terser-webpack-plugin').binding,
			bootstrapOriginal(path.join(scratch, 'terser'), 'terser').binding,
		];
	},
	{ timeout: 300000 },
);

after(() => fs.rmSync(scratch, { recursive: true, force: true }));

function sha256(bytes) {
	return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

// One real webpack build per scenario, in its own process whose commonjs loader
// is recorded from the very first module on.
function build(scenario, options = {}) {
	const area = fixture.workspace(`${scenario}-${builds++}`, { isolateOriginals: true });
	addSources(area);
	const setup = {
		scenario,
		context: area.root,
		modules: area.modules,
		entry: area.installed('app/with-license.js'),
		output: area.output,
		filename: options.filename,
		proofPath: area.proofPath,
		webpackRoot: WEBPACK,
		originals: [...area.originals, ...toolOriginals],
	};
	const output = execFileSync(process.execPath, ['--require', PRELOAD, child], {
		cwd: area.root,
		encoding: 'utf8',
		timeout: 60000,
		env: { ...process.env, DK_LICENSE_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	return { area, report: JSON.parse(line.slice(MARKER.length)) };
}

function rows(report) {
	const comments = report.proof.assets.filter((row) => row.path.endsWith(SUFFIX) && !row.path.startsWith('nothing') && !row.path.startsWith('orphan'));
	assert.equal(comments.length, 1, report.proof.assets.map((row) => row.path).join(', '));
	const [row] = comments;
	const owner = report.proof.assets.find((candidate) => candidate.path === row.path.slice(0, -SUFFIX.length));
	assert.ok(owner, `no owner asset for ${row.path}`);
	return { row, owner };
}

// The comments file is the comments of one asset and nothing else, so it is
// claimed with the sources that asset was built from.
test('describes the comments a minification took out of an asset', () => {
	const result = build('plain');
	const { row, owner } = rows(result.report);
	assert.equal(row.status, 'present', row.reason);
	assert.equal(owner.status, 'present', owner.reason);
	assert.equal(row.sha256, sha256(result.report.emitted[row.path]));
	assert.equal(row.size, Buffer.byteLength(result.report.emitted[row.path]));
	// Sorted, one blank line between them, one newline at the end.
	assert.equal(result.report.emitted[row.path], `${[...COMMENTS].sort().join('\n\n')}\n`);
	// The same claim as the asset the comments came out of, and no claim of its
	// own: no per-comment attribution is attempted.
	assert.deepEqual(row.inputs, owner.inputs);
	assert.deepEqual(row.includedComponents, owner.includedComponents);
	// What stayed in the asset is the line pointing at this file.
	assert.match(result.report.emitted[owner.path], /^\/\*! For license information please see main\.js\.LICENSE\.txt \*\//);
});

// Both files are renamed for the real content hash, the comments file after the
// asset it is named for.
test('describes the comments of an asset whose name carries its content hash', () => {
	const result = build('plain', { filename: '[contenthash].js' });
	const { row, owner } = rows(result.report);
	assert.equal(row.status, 'present', row.reason);
	assert.match(row.path, /^[0-9a-f]+\.js\.LICENSE\.txt$/);
	assert.equal(row.path, `${owner.path}${SUFFIX}`);
	assert.equal(row.sha256, sha256(result.report.emitted[row.path]));
	assert.deepEqual(row.inputs, owner.inputs);
});

// The production default concatenates what it can; whether a comment survives
// that far is the build's business, and whatever reaches the minifier is
// described the same way.
test('describes the comments of a bundle built with the production defaults', () => {
	const result = build('concatenated');
	const { row, owner } = rows(result.report);
	assert.equal(row.status, 'present', row.reason);
	assert.equal(row.sha256, sha256(result.report.emitted[row.path]));
	assert.deepEqual(row.inputs, owner.inputs);
});

// A file put where the minifier writes its comments is kept by the minifier, so
// what it holds has to be the comments of the asset it is named for: in that
// order, each of them once, and each of them in the bytes that were minified.
test('reports no data for comments that are not the ones taken out of the asset', () => {
	for (const [scenario, expected] of [
		['forged-comment', /holds a comment that is not in the bytes main\.js was minified from/],
		['unsorted-comments', /not sorted, or holds one of them twice/],
		['repeated-comments', /not sorted, or holds one of them twice/],
		['not-a-comment', /holds text that is not a comment/],
		['trailing-separator', /holds text that is not a comment/],
	]) {
		const { row } = rows(build(scenario).report);
		assert.equal(row.status, 'no-data', `${scenario}: ${row.reason}`);
		assert.match(row.reason, expected);
		assert.deepEqual(row.inputs, []);
	}
});

// The comments of an asset this adapter cannot describe are not described
// either: not when the asset was never built by a chunk of this compilation,
// and not when the chunk that built it is refused.
test('reports no data for the comments of an asset that is not described', () => {
	const orphan = build('orphan-owner').report.proof.assets.find((row) => row.path === `orphan.js${SUFFIX}`);
	assert.ok(orphan, 'no comments file for the orphan asset');
	assert.equal(orphan.status, 'no-data');
	assert.match(orphan.reason, /orphan\.js belongs to no chunk of this compilation/);
	assert.deepEqual(orphan.inputs, []);
	const { row, owner } = rows(build('undescribed-owner').report);
	assert.equal(owner.status, 'no-data', owner.reason);
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /fixture tapped render/);
	assert.deepEqual(row.inputs, []);
});

// A comments file no described minification wrote is nobody's claim.
test('reports no data for a comments file a plugin wrote itself', () => {
	const result = build('foreign-comments');
	const row = result.report.proof.assets.find((candidate) => candidate.path === `nothing.js${SUFFIX}`);
	assert.ok(row, result.report.proof.assets.map((candidate) => candidate.path).join(', '));
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /no described minification wrote nothing\.js\.LICENSE\.txt/);
	assert.deepEqual(row.inputs, []);
});

// The bytes that were written are not the end of the story either.
test('reports a hash mismatch when the comments file on disk was rewritten', () => {
	const { row } = rows(build('rewritten-comments').report);
	assert.equal(row.status, 'hash-mismatch');
	assert.match(row.reason, /emitted asset differs from the bytes it was described from/);
	assert.deepEqual(row.inputs, []);
});
