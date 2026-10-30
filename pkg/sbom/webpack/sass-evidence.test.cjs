'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture, bootstrapOriginal } = require('./fixture.cjs');
const { MARKER, SOURCES, MUTATION, addSources, child } = require('./sass-fixture.cjs');

const PRELOAD = path.join(__dirname, 'stylesheet-preload.cjs');
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));
const STYLE_LOADER = require.resolve('style-loader');
const STYLE_INDEX = path.join(path.dirname(STYLE_LOADER), 'index.js');
const STYLE_RUNTIME = path.join(path.dirname(STYLE_LOADER), 'runtime', 'injectStylesIntoStyleTag.js');
const RAW_LOADER = require.resolve('raw-loader');
const SASS_LOADER = require.resolve('sass-loader');
const SASS_ENTRY = require.resolve('sass');
// The published artifacts, as packed in the npm archives of these versions.
const RAW_LOADER_SHA256 = 'sha256:caa83fec5bfb9c0544967fb0ce9b94d10e984c97bd427c7b69a8fb23771cf5c0';
const STYLE_INDEX_SHA256 = 'sha256:ca8bd425c4b174b307cd98525514c088a04dca73ae8e476066ddffa79d317f41';
const SASS_LOADER_FILES = {
	'dist/cjs.js': 'sha256:a45bce1d967c168463dd71645f57b95e1541ee18db961014f48559eecaae5e32',
	'dist/index.js': 'sha256:91440b3eca176f7b3656b8dcad7e5523154d6fd8ff2544d524c0fc932b976296',
	'dist/utils.js': 'sha256:4d0948db6eab79ab87776b929b3e374b51d394065a80dd3e5d5c14b703d57598',
};
const SASS_FILES = {
	'sass.default.dart.js': 'sha256:146019ec68f94ef65359450094c4d8ac7af37ba02c324f2314555374977e9b92',
	'sass.dart.js': 'sha256:bed180ba1d59efe0bcfb0d27862f30766995acd3a393a242a17031766561439d',
};
const APP_COMPONENT = 'node:app@0.1.0';
const STYLE_COMPONENT = 'node:style-loader@1.3.0';
const RAW_COMPONENT = 'node:raw-loader@0.5.1';
const WEBPACK_COMPONENT = 'node:webpack@5.94.0';

let scratch;
let fixture;
let loaderOriginals;
let areas = 0;

before(
	() => {
		for (const [relative, expected] of Object.entries(SASS_LOADER_FILES)) {
			assert.equal(sha256(path.join(path.dirname(path.dirname(SASS_LOADER)), ...relative.split('/'))), expected, `the installed sass-loader is not the published 14.2.1 artifact: ${relative}`);
		}
		for (const [name, expected] of Object.entries(SASS_FILES)) {
			assert.equal(sha256(path.join(path.dirname(SASS_ENTRY), name)), expected, `the installed sass is not the published 1.49.9 artifact: ${name}`);
		}
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-sass-')));
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
		loaderOriginals = [bootstrapOriginal(path.join(scratch, 'style-loader'), 'style-loader').binding, bootstrapOriginal(path.join(scratch, 'raw-loader'), 'raw-loader').binding];
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
	const app = path.join(area.modules, 'app');
	const setup = {
		scenario,
		context: area.root,
		modules: area.modules,
		entry: path.join(app, options.entry || 'styled.js'),
		output: area.output,
		proofPath: options.collect ? area.proofPath : undefined,
		webpackRoot: WEBPACK,
		styleLoader: STYLE_LOADER,
		rawLoader: RAW_LOADER,
		sassLoader: SASS_LOADER,
		sassEntry: SASS_ENTRY,
		originals: [...area.originals, ...loaderOriginals],
		appRoots: [app, area.originalOf('app')],
	};
	const output = execFileSync(process.execPath, ['--require', PRELOAD, child], {
		cwd: area.root,
		encoding: 'utf8',
		timeout: 120000,
		env: { ...process.env, DK_SASS_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.sassLoader, '14.2.1');
	assert.equal(report.sass, '1.49.9');
	return { area, app, report };
}

function rowOf(report, name, loaderCount) {
	const row = report.rows.find((candidate) => candidate.name === name && candidate.loaders.length === loaderCount);
	assert.ok(row, `no row for ${name} built by ${loaderCount} loaders`);
	return row;
}

function compiledRow(report, name = 'main.scss') {
	return rowOf(report, name, 2);
}

function unitsOf(row) {
	return row.units.map((unit) => ({ path: unit.path, sha256: unit.sha256, component: unit.component }));
}

function sources(app, ...names) {
	return names.map((name) => ({ path: path.join(app, name), sha256: sha256(path.join(app, name)), component: APP_COMPONENT }));
}

// The stylesheet sass was given and the one partial it really read, in the
// order sass reported them, and nothing of the sass distribution itself.
test('describes the scss sources one render consumed and the loader that returned its css', () => {
	const result = build('basic');
	const row = compiledRow(result.report);
	assert.equal(row.status, 'present', row.reason);
	assert.deepEqual(unitsOf(row), [...sources(result.app, 'main.scss', '_colors.scss'), { path: RAW_LOADER, sha256: RAW_LOADER_SHA256, component: RAW_COMPONENT }]);
	assert.ok(!row.units.some((unit) => /unused\.scss|other/.test(unit.path)), `a source no render consumed was claimed: ${row.units.map((unit) => unit.path).join(', ')}`);
	assert.match(row.source, /^module\.exports = ".app\{color:red\}"$/);
	// The pitched parent of the three-loader chain contributes its own loader
	// file alone; the css and its sources belong to the module behind it.
	const parent = rowOf(result.report, 'main.scss', 3);
	assert.equal(parent.status, 'present', parent.reason);
	assert.deepEqual(unitsOf(parent), [{ path: STYLE_INDEX, sha256: STYLE_INDEX_SHA256, component: STYLE_COMPONENT }]);
});

test('describes a stylesheet compiled by the raw and sass chain alone', () => {
	const result = build('raw-only');
	const row = compiledRow(result.report);
	assert.equal(row.status, 'present', row.reason);
	assert.deepEqual(unitsOf(row), [...sources(result.app, 'main.scss', '_colors.scss'), { path: RAW_LOADER, sha256: RAW_LOADER_SHA256, component: RAW_COMPONENT }]);
	assert.equal(result.report.rows.filter((candidate) => candidate.loaders.length === 3).length, 0);
});

// Two renders share one recorder in one build; this fixture renders them one
// after another, so it does not exercise overlapping windows.
test('tells the partials of two stylesheets rendered in one build apart', () => {
	const result = build('basic', { entry: 'two-sheets.js' });
	const main = compiledRow(result.report, 'main.scss');
	const other = compiledRow(result.report, 'other.scss');
	assert.equal(main.status, 'present', main.reason);
	assert.equal(other.status, 'present', other.reason);
	assert.deepEqual(unitsOf(main).slice(0, 2), sources(result.app, 'main.scss', '_colors.scss'));
	assert.deepEqual(unitsOf(other).slice(0, 2), sources(result.app, 'other.scss', '_other-colors.scss'));
});

// The partial and its original change together, so the verification against the
// original still passes: only the bytes sass really read say otherwise.
test('reports a hash mismatch when the verified partial is not what sass read', () => {
	const result = build('mutate');
	const row = compiledRow(result.report);
	assert.equal(row.status, 'hash-mismatch');
	assert.match(row.reason, /sass did not read the verified bytes of .*_colors\.scss/);
	assert.deepEqual(row.units, []);
	const partial = fs.readFileSync(path.join(result.app, '_colors.scss'), 'utf8');
	assert.equal(partial.length, SOURCES['_colors.scss'].length);
	assert.ok(partial.includes(MUTATION[1]), 'the fixture did not rewrite the partial');
});

// What the next loader was handed has to be the css this very render returned.
test('refuses a module whose css is not what the observed render returned', () => {
	const result = build('direct');
	const returned = result.report.rows.find((row) => row.label === 'returned');
	const changed = result.report.rows.find((row) => row.label === 'changed');
	assert.equal(returned.status, 'present', returned.reason);
	assert.deepEqual(unitsOf(returned), sources(result.app, 'main.scss', '_colors.scss'));
	assert.equal(changed.status, 'hash-mismatch');
	assert.match(changed.reason, /is not what sass returned for it/);
	assert.deepEqual(changed.units, []);
});

// Every option of this loader changes what sass is given or which
// implementation produces the css, and the user's own object is never touched.
test('reports no data for a sass-loader configured with options of its own', () => {
	for (const [scenario, keys] of [
		['additional-data', ['additionalData']],
		['custom-importer', ['sassOptions']],
		['custom-implementation', ['implementation']],
	]) {
		const result = build(scenario);
		const row = compiledRow(result.report);
		assert.equal(row.status, 'no-data', `${scenario}: ${row.reason}`);
		assert.match(row.reason, /was not built by an observed sass render/);
		assert.deepEqual(row.units, []);
		assert.deepEqual(result.report.userOptions, { shared: true, keys }, `${scenario} left other options behind`);
	}
});

// A reader another plugin puts in front of the one this adapter installed sees
// reads this process never did.
test('reports no data when the file reader is replaced while sass runs', () => {
	const result = build('replaced');
	const row = compiledRow(result.report);
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /fs\.readFileSync was replaced while sass ran/);
	assert.deepEqual(row.units, []);
});

test('reports no data for a stylesheet whose byte order mark the loader stripped', () => {
	const result = build('basic', { entry: 'bom-entry.js' });
	const row = compiledRow(result.report, 'bom.scss');
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /byte order mark the loader does not pass on/);
	assert.deepEqual(row.units, []);
});

function inputOf(row, file) {
	return row.inputs.find((input) => input.path === file);
}

// The production call site: the collector routes the chain to the stylesheet
// adapter, which hands the compiled module to this one.
test('describes a whole bundle built through the style, raw and sass chain', () => {
	const result = build('collector-style', { collect: true, entry: 'styled.js' });
	const row = result.report.proof.assets.find((candidate) => candidate.path === 'main.js');
	assert.ok(row, 'no main.js row in the proof');
	assert.equal(row.status, 'present', row.reason);
	assert.equal(row.sha256, sha256(path.join(result.area.output, 'main.js')));
	for (const [file, component] of [
		[path.join(result.app, 'main.scss'), APP_COMPONENT],
		[path.join(result.app, '_colors.scss'), APP_COMPONENT],
		[path.join(result.app, 'styled.js'), APP_COMPONENT],
		[RAW_LOADER, RAW_COMPONENT],
		[STYLE_INDEX, STYLE_COMPONENT],
		[STYLE_RUNTIME, STYLE_COMPONENT],
	]) {
		assert.deepEqual(inputOf(row, file), { kind: 'source', path: file, sha256: sha256(file), components: [component], disposition: 'included' }, `missing input ${file}`);
	}
	for (const name of ['unused.scss', 'other.scss', '_other-colors.scss']) {
		assert.equal(inputOf(row, path.join(result.app, name)), undefined, `${name} was claimed without being consumed`);
	}
	assert.equal(inputOf(row, SASS_LOADER), undefined, 'the sass-loader distribution is an instrument, not an input');
	assert.equal(inputOf(row, SASS_ENTRY), undefined, 'the sass distribution is an instrument, not an input');
	for (const id of [APP_COMPONENT, STYLE_COMPONENT, RAW_COMPONENT, WEBPACK_COMPONENT]) {
		assert.ok(row.includedComponents.includes(id), `${id} is not an included component of ${row.includedComponents.join(', ')}`);
	}
	assert.ok(!row.includedComponents.some((id) => /sass/i.test(id)), `no sass component may be claimed: ${row.includedComponents.join(', ')}`);
});
