'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { MARKER, packPackage, child } = require('./copy-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const MODULES = path.join(__dirname, 'node_modules');
const WEBPACK = path.join(MODULES, 'webpack');
const ASSETS = {
	'a/one.txt': 'one\n',
	'a/two.txt': 'two\n',
	'a/skip.md': 'skip\n',
	// The same bytes as a/one.txt, in a file of its own.
	'b/one.txt': 'one\n',
};
const PROBES = { glob: ['glob/skip.md'], missing: ['missing.txt'] };

let scratch;
let distribution;
let areas = 0;

before(() => {
	scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-copy-')));
	distribution = packPackage(path.join(scratch, 'plugin-dist'), path.join(MODULES, 'copy-webpack-plugin'));
}, { timeout: 120000 });

after(() => fs.rmSync(scratch, { recursive: true, force: true }));

// One real webpack build per scenario, in its own process whose commonjs loader
// is recorded from the very first module on.
function build(scenario, options = {}) {
	const context = path.join(scratch, `${scenario}-${areas++}`);
	fs.mkdirSync(path.join(context, 'src'), { recursive: true });
	fs.writeFileSync(path.join(context, 'src', 'entry.js'), 'module.exports = 1;\n');
	for (const [relative, content] of Object.entries(ASSETS)) {
		const file = path.join(context, 'assets', ...relative.split('/'));
		fs.mkdirSync(path.dirname(file), { recursive: true });
		fs.writeFileSync(file, content);
	}
	let pluginRoot = distribution.root;
	let originalRoot = distribution.original;
	if (options.isolate) {
		// A distribution of its own, extracted from the archive like the original it
		// is verified against, so the scenario may rewrite it; its dependencies are
		// not part of any claim, so they are taken from the installed ones.
		const modules = path.join(context, 'node_modules');
		fs.mkdirSync(modules, { recursive: true });
		pluginRoot = path.join(modules, 'copy-webpack-plugin');
		fs.cpSync(distribution.original, pluginRoot, { recursive: true });
		for (const entry of fs.readdirSync(MODULES)) {
			if (entry.startsWith('.') || fs.existsSync(path.join(modules, entry))) continue;
			fs.symlinkSync(path.join(MODULES, entry), path.join(modules, entry));
		}
		originalRoot = path.join(context, 'plugin-original');
		fs.cpSync(distribution.original, originalRoot, { recursive: true });
	}
	if (options.fork) {
		// A distribution that is byte-for-byte its own original and still not the
		// pinned plugin: patched before anything loaded it.
		assert.ok(options.isolate, 'a fork must not patch the shared distribution');
		for (const target of [pluginRoot, originalRoot]) fs.appendFileSync(path.join(target, 'dist', ...options.fork.split('/')), '\n// patched fork\n');
	}
	const setup = {
		scenario,
		context,
		entry: path.join(context, 'src', 'entry.js'),
		output: path.join(context, 'out'),
		webpackRoot: WEBPACK,
		pluginRoot,
		probe: PROBES[scenario] || [],
		originals: [{ root: pluginRoot, originalRoot, component: distribution.component }],
	};
	const output = execFileSync(process.execPath, [...(options.preload === false ? [] : ['--require', PRELOAD]), child], {
		cwd: context,
		encoding: 'utf8',
		timeout: 60000,
		env: { ...process.env, DK_COPY_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.plugin, distribution.component.version);
	return { context, output: setup.output, report };
}

function rowsOf(report, index = 0) {
	const rows = report.builds[index];
	assert.ok(rows, `no build ${index} in the report`);
	return rows;
}

function rowOf(rows, name) {
	const row = rows.find((candidate) => candidate.name === name);
	assert.ok(row, `no row for ${name} in ${rows.map((candidate) => candidate.name).join(', ')}`);
	return row;
}

// A described copy has to name the file the bytes really came from.
function assertCopiedFrom(result, row, relative) {
	assert.equal(row.status, 'present', row.reason);
	assert.equal(row.copied, true);
	assert.equal(row.from, path.join(result.context, 'assets', ...relative.split('/')));
	assert.ok(fs.readFileSync(row.from).equals(fs.readFileSync(path.join(result.output, row.name))), `${row.name} does not carry the bytes of ${row.from}`);
}

test('names the source file of every asset copied out of a directory', () => {
	const result = build('directory');
	const rows = rowsOf(result.report);
	assert.deepEqual(rows.map((row) => row.name).sort(), ['dir/one.txt', 'dir/skip.md', 'dir/two.txt', 'main.js']);
	for (const name of ['one.txt', 'two.txt', 'skip.md']) assertCopiedFrom(result, rowOf(rows, `dir/${name}`), `a/${name}`);
	const bundle = rowOf(rows, 'main.js');
	assert.equal(bundle.status, 'no-data');
	assert.equal(bundle.copied, false);
});

test('names the source file of every asset a glob selected and nothing it excluded', () => {
	const result = build('glob');
	const rows = rowsOf(result.report);
	assert.deepEqual(rows.map((row) => row.name).sort(), ['glob/one.txt', 'glob/skip.md', 'glob/two.txt', 'main.js']);
	for (const name of ['one.txt', 'two.txt']) assertCopiedFrom(result, rowOf(rows, `glob/${name}`), `a/${name}`);
	const excluded = rowOf(rows, 'glob/skip.md');
	assert.equal(excluded.probe, true, 'the excluded file must not be an emitted asset');
	assert.equal(excluded.status, 'no-data');
	assert.equal(excluded.from, undefined);
	assert.ok(!fs.existsSync(path.join(result.output, 'glob', 'skip.md')));
});

// Both files hold the same bytes, so only the identity of the buffer the copy
// read can say which one the asset really carries.
test('names the file of the copy that won a collision of identical sources', () => {
	const result = build('collide');
	const sources = ['a/one.txt', 'b/one.txt'].map((relative) => fs.readFileSync(path.join(result.context, 'assets', ...relative.split('/'))));
	assert.ok(sources[0].equals(sources[1]), 'the colliding sources must be byte-identical');
	assertCopiedFrom(result, rowOf(rowsOf(result.report), 'same.txt'), 'a/one.txt');
});

test('names the file of the forced copy that replaced an earlier one', () => {
	const result = build('force');
	assertCopiedFrom(result, rowOf(rowsOf(result.report), 'same.txt'), 'b/one.txt');
});

test('reports no data for a copy whose content the pattern transforms', () => {
	const result = build('transform');
	const transformed = rowOf(rowsOf(result.report), 'transformed.txt');
	assert.equal(transformed.status, 'no-data');
	assert.match(transformed.reason, /transforms the copied content/);
	assert.equal(transformed.from, undefined);
	assertCopiedFrom(result, rowOf(rowsOf(result.report), 'plain.txt'), 'a/two.txt');
});

// The replacement carries exactly the bytes of the copy, so nothing that
// compares content could tell it apart from the copied asset.
// This observer says which file was copied to a target and whether the asset
// still holds what the copy put there. An asset rewritten afterwards - by
// another plugin, or by a stage of the build this observer knows nothing of -
// is named as one still to be accounted for, and it is the caller following
// those stages that accepts or refuses it.
test('names a copied asset another plugin replaced with the same bytes as rewritten', () => {
	const result = build('late-replacement');
	const row = rowOf(rowsOf(result.report), 'late.txt');
	assert.equal(row.status, 'present', row.reason);
	assert.equal(row.rewritten, true);
	assert.ok(row.from.endsWith(path.join('assets', 'a', 'one.txt')));
	assert.ok(fs.readFileSync(path.join(result.output, 'late.txt')).equals(fs.readFileSync(path.join(result.context, 'assets', 'a', 'one.txt'))));
});

test('reports no data for an asset another plugin marked as copied', () => {
	const row = rowOf(rowsOf(build('unknown').report), 'unknown.txt');
	assert.equal(row.copied, true);
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /does not carry the bytes of an observed copy/);
	assert.equal(row.from, undefined);
});

test('reports no data for a target no copy produced', () => {
	const result = build('missing');
	const rows = rowsOf(result.report);
	assert.deepEqual(rows.map((row) => row.name).sort(), ['main.js', 'missing.txt', 'plain.txt']);
	const absent = rowOf(rows, 'missing.txt');
	assert.equal(absent.probe, true);
	assert.equal(absent.status, 'no-data');
	assert.match(absent.reason, /no observed copy produced missing\.txt/);
	assert.ok(!fs.existsSync(path.join(result.output, 'missing.txt')));
	assertCopiedFrom(result, rowOf(rows, 'plain.txt'), 'a/two.txt');
});

test('describes a warm second build of the same compiler exactly like the first', () => {
	const result = build('warm');
	assert.equal(result.report.builds.length, 2);
	for (const name of ['one.txt', 'two.txt', 'skip.md']) assertCopiedFrom(result, rowOf(rowsOf(result.report, 1), `dir/${name}`), `a/${name}`);
	assert.deepEqual(rowsOf(result.report, 1), rowsOf(result.report, 0));
});

test('reports no data for the copied assets of a build that was not recorded', () => {
	const rows = rowsOf(build('directory', { preload: false }).report);
	for (const row of rows) {
		assert.equal(row.status, 'no-data');
		assert.match(row.reason, /registry is not installed/);
		assert.equal(row.from, undefined);
	}
});

test('refuses a patched copy plugin that verifies against its own original', () => {
	const rows = rowsOf(build('directory', { isolate: true, fork: 'processPattern.js' }).report);
	for (const row of rows.filter((candidate) => candidate.copied)) {
		assert.equal(row.status, 'unsupported');
		assert.match(row.reason, /processPattern\.js is not the source of the pinned copy-webpack-plugin 6\.1\.1/);
		assert.equal(row.from, undefined);
	}
});

// The helper that reads the copied bytes decides as much as the stages do.
test('refuses a patched helper of the copy plugin', () => {
	const rows = rowsOf(build('directory', { isolate: true, fork: 'utils/promisify.js' }).report);
	for (const row of rows.filter((candidate) => candidate.copied)) {
		assert.equal(row.status, 'unsupported');
		assert.match(row.reason, /utils\/promisify\.js is not the source of the pinned copy-webpack-plugin 6\.1\.1/);
		assert.equal(row.from, undefined);
	}
});

test('describes the copies of an unpatched distribution of its own', () => {
	const result = build('directory', { isolate: true });
	for (const name of ['one.txt', 'two.txt', 'skip.md']) assertCopiedFrom(result, rowOf(rowsOf(result.report), `dir/${name}`), `a/${name}`);
});

test('reports a hash mismatch when a plugin source is not the one this process loaded', () => {
	const result = build('changed-after-load', { isolate: true });
	const row = rowOf(rowsOf(result.report), 'late.txt');
	assert.equal(row.status, 'hash-mismatch');
	assert.match(row.reason, /processPattern\.js differs from the bytes this process loaded/);
	assert.equal(row.from, undefined);
});

test('reports no data when a module deciding the copy is replaced while it runs', () => {
	const row = rowOf(rowsOf(build('swapped-module').report), 'late.txt');
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /preProcessPattern\.js no longer exports/);
	assert.equal(row.from, undefined);
});

// The adapter would otherwise wrap and describe the replacement as the plugin.
test('reports no data when the copy step was replaced before the adapter was installed', () => {
	const rows = rowsOf(build('pre-install-swap').report);
	const row = rowOf(rows, 'late.txt');
	assert.equal(row.copied, true);
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /no observable copy-webpack-plugin instance/);
	assert.equal(row.from, undefined);
});

// Two patterns, one file, one target: an observation seen twice is still one copy.
test('names the source file a duplicated pattern copied twice', () => {
	const result = build('duplicate');
	assertCopiedFrom(result, rowOf(rowsOf(result.report), 'same.txt'), 'a/one.txt');
});
