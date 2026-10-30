'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture, bootstrapOriginal } = require('./fixture.cjs');
const { MARKER, addSources, child } = require('./sourcemap-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));
const PLUGIN = path.join(WEBPACK, 'lib', 'SourceMapDevToolPlugin.js');

let scratch;
let fixture;
let webpackOriginal;
let builds = 0;

before(
	() => {
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-sourcemap-')));
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
		webpackOriginal = bootstrapOriginal(path.join(scratch, 'webpack'), 'webpack').binding;
	},
	{ timeout: 300000 },
);

after(() => fs.rmSync(scratch, { recursive: true, force: true }));

// One real webpack build per scenario, in its own process whose commonjs loader
// is recorded from the very first module on.
function build(scenario) {
	const area = fixture.workspace(`${scenario}-${builds++}`, { isolateOriginals: true });
	addSources(area);
	const setup = {
		scenario,
		context: area.root,
		entry: area.installed('app/map.js'),
		modules: area.modules,
		output: area.output,
		originals: [...area.originals, webpackOriginal],
		webpackRoot: WEBPACK,
	};
	const output = execFileSync(process.execPath, ['--require', PRELOAD, child], {
		cwd: setup.context,
		encoding: 'utf8',
		timeout: 60000,
		env: { ...process.env, DK_SOURCEMAP_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.webpack, '5.94.0');
	return { setup, report, rows: new Map(report.rows.map((row) => [row.name, row])) };
}

// The published bundle of a build that writes source maps ends with the line
// naming its map; that line is webpack's own, and what it is added to is the
// asset as the minifier left it.
test('describes the source map comment at the end of an asset', () => {
	const result = build('plain');
	const row = result.rows.get('main.js');
	assert.equal(row.status, 'present', row.reason);
	assert.equal(row.output, result.report.emitted['main.js']);
	assert.equal(row.trailer, '\n//# sourceMappingURL=main.js.map');
	assert.deepEqual(row.units, [PLUGIN]);
	// What the published file really ends with.
	assert.ok(fs.readFileSync(path.join(result.setup.output, 'main.js'), 'utf8').endsWith('\n//# sourceMappingURL=main.js.map'));
});

// The map itself is a document webpack builds out of every module of the chunk;
// nothing here recomputes it, and it is refused in those words.
// A worker compiled in a compilation of its own: the devtool plugin writes a
// map for its asset too, because a child compiler copies the taps of the
// compiler that made it. Undescribed, the line naming that map is a change to
// the worker's bytes that nothing can account for.
test('describes the source map comment of an asset of a child compilation', () => {
	const rows = build('child').rows;
	const worker = rows.get('child:worker.js');
	assert.ok(worker, [...rows.keys()].join(', '));
	assert.equal(worker.status, 'present', worker.reason);
	assert.equal(worker.trailer, '\n//# sourceMappingURL=worker.js.map');
	// The map of the child is an asset of the child, and is refused there for
	// the same reason the parent's own map is.
	assert.equal(rows.get('child:worker.js.map').status, 'no-data');
	assert.equal(rows.get('main.js').status, 'present', rows.get('main.js').reason);
});

test('refuses the source map itself with a reason of its own', () => {
	const row = build('plain').rows.get('main.js.map');
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /main\.js\.map is the source map of an asset of this build, which this collector does not describe/);
	assert.deepEqual(row.units, []);
});

// The map is named from the directory the asset it belongs to stands in.
test('describes the comment of an asset in a directory of its own', () => {
	const row = build('nested').rows.get('scripts/main.js');
	assert.equal(row.status, 'present', row.reason);
	assert.equal(row.trailer, '\n//# sourceMappingURL=main.js.map');
});

// A build that writes no source maps has nothing for this adapter to describe.
test('describes nothing when the build writes no source maps', () => {
	const rows = build('no-maps').rows;
	for (const row of rows.values()) assert.equal(row.status, 'none', `${row.name}: ${row.reason}`);
});

// Another plugin writing into the assets in that very stage adds bytes this
// adapter cannot attribute to the source map comment.
test('reports no data when another plugin writes in the stage the maps are written in', () => {
	const row = build('company').rows.get('main.js');
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /fixture, SourceMapDevToolPlugin wrote into the assets of this compilation in the stage the source maps are written in/);
	assert.deepEqual(row.units, []);
});

// The maps are the only assets that stage is allowed to have written.
test('reports no data for another asset written while the maps were', () => {
	const row = build('extra-asset').rows.get('extra.txt');
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /extra\.txt was written while the source maps of this compilation were/);
});

// The comment has to name the map that was really emitted beside the asset.
test('reports no data for a comment naming a map of its own', () => {
	const row = build('forged-url').rows.get('main.js');
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /main\.js is not the asset the source map comment was added to/);
	assert.deepEqual(row.units, []);
});

// The class webpack loaded, not something derived from it.
test('reports no data for source maps written by a derived plugin', () => {
	const row = build('derived-plugin').rows.get('main.js');
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /derived from SourceMapDevToolPlugin/);
	assert.deepEqual(row.units, []);
});
