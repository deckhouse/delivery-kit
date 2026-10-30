'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture, bootstrapOriginal } = require('./fixture.cjs');
const { MARKER, SOURCES, addSources, child } = require('./stylesheet-fixture.cjs');

const PRELOAD = path.join(__dirname, 'stylesheet-preload.cjs');
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));
const STYLE_LOADER = require.resolve('style-loader');
const STYLE_INDEX = path.join(path.dirname(STYLE_LOADER), 'index.js');
const STYLE_RUNTIME = path.join(path.dirname(STYLE_LOADER), 'runtime', 'injectStylesIntoStyleTag.js');
const RAW_LOADER = require.resolve('raw-loader');
// The published artifacts, as packed in the npm archives of these two versions.
const STYLE_INDEX_SHA256 = 'sha256:ca8bd425c4b174b307cd98525514c088a04dca73ae8e476066ddffa79d317f41';
const RAW_LOADER_SHA256 = 'sha256:caa83fec5bfb9c0544967fb0ce9b94d10e984c97bd427c7b69a8fb23771cf5c0';
const APP_COMPONENT = 'node:app@0.1.0';
const STYLE_COMPONENT = 'node:style-loader@1.3.0';
const RAW_COMPONENT = 'node:raw-loader@0.5.1';
const WEBPACK_COMPONENT = 'node:webpack@5.94.0';
const EVIDENCE = process.env.DK_STYLESHEET_EVIDENCE;

let scratch;
let fixture;
let loaderOriginals;
let passThrough;
let aliasedRuntime;
let areas = 0;

before(() => {
	assert.equal(sha256(STYLE_INDEX), STYLE_INDEX_SHA256, 'the installed style-loader is not the published 1.3.0 artifact');
	assert.equal(sha256(RAW_LOADER), RAW_LOADER_SHA256, 'the installed raw-loader is not the published 0.5.1 artifact');
	scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-stylesheet-')));
	fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
	// The loaders are bound where they are installed, to an original extracted
	// from an archive of that very installation, exactly as the bootstrap of a
	// rendered chunk is bound to the webpack this process runs.
	loaderOriginals = [bootstrapOriginal(path.join(scratch, 'style-loader'), 'style-loader').binding, bootstrapOriginal(path.join(scratch, 'raw-loader'), 'raw-loader').binding];
	passThrough = path.join(scratch, 'pass-through-loader.cjs');
	fs.writeFileSync(passThrough, 'module.exports = (source) => source;\n');
	aliasedRuntime = path.join(scratch, 'aliased-runtime.js');
	fs.writeFileSync(aliasedRuntime, 'module.exports = function () { return function () {}; };\n');
}, { timeout: 180000 });

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
		entry: path.join(app, options.entry || 'one.js'),
		output: area.output,
		proofPath: options.collect ? area.proofPath : undefined,
		webpackRoot: WEBPACK,
		styleLoader: STYLE_LOADER,
		rawLoader: RAW_LOADER,
		passThroughLoader: passThrough,
		styleRuntime: STYLE_RUNTIME,
		aliasedRuntime: aliasedRuntime,
		originals: [...area.originals, ...loaderOriginals],
		appRoots: [app, area.originalOf('app')],
	};
	const output = execFileSync(process.execPath, [...(options.withoutPreload ? [] : ['--require', PRELOAD]), child], {
		cwd: area.root,
		encoding: 'utf8',
		timeout: 60000,
		env: { ...process.env, DK_STYLESHEET_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.styleLoader, '1.3.0');
	assert.equal(report.rawLoader, '0.5.1');
	if (options.collect) {
		assert.ok(report.proof, 'the collector wrote no proof');
		// For a canonical validation of these proofs elsewhere; the directory is
		// the caller's and has to exist already.
		if (EVIDENCE !== undefined) {
			assert.ok(path.isAbsolute(EVIDENCE) && fs.statSync(EVIDENCE).isDirectory(), 'DK_STYLESHEET_EVIDENCE must be an existing absolute directory');
			fs.writeFileSync(path.join(EVIDENCE, `${scenario}.json`), `${JSON.stringify(report.proof, null, 2)}\n`);
		}
	}
	return { area, app, report };
}

// Parent and child are both built from the stylesheet itself; what tells them
// apart is the chain each was built by.
function rowOf(report, name, loaderCount) {
	const row = report.rows.find((candidate) => candidate.name === name && candidate.loaders.length === loaderCount);
	assert.ok(row, `no row for ${name} built by ${loaderCount} loaders`);
	return row;
}

function styleRow(report, name = 'a.css') {
	return rowOf(report, name, 2);
}

function rawRow(report, name = 'a.css') {
	return rowOf(report, name, 1);
}

function unitsOf(row) {
	return row.units.map((unit) => ({ path: unit.path, sha256: unit.sha256, component: unit.component }));
}

test('describes the stylesheet raw-loader read and the loader file that returned it', () => {
	const result = build('basic');
	const row = rawRow(result.report);
	assert.equal(row.status, 'present', row.reason);
	const file = path.join(result.app, 'a.css');
	assert.deepEqual(unitsOf(row), [
		{ path: file, sha256: sha256(file), component: APP_COMPONENT },
		{ path: RAW_LOADER, sha256: RAW_LOADER_SHA256, component: RAW_COMPONENT },
	]);
	assert.equal(row.source, `module.exports = ${JSON.stringify(SOURCES['a.css'])}`);
});

// The pitched module never read the stylesheet: its source is the template of
// the loader file, and that file is the only unit it contributes.
test('describes the pitched module with the style-loader source alone', () => {
	const result = build('basic');
	const row = styleRow(result.report);
	assert.equal(row.status, 'present', row.reason);
	assert.deepEqual(unitsOf(row), [{ path: STYLE_INDEX, sha256: STYLE_INDEX_SHA256, component: STYLE_COMPONENT }]);
	assert.ok(!row.units.some((unit) => unit.path.endsWith('a.css')), 'the pitched module must claim no stylesheet of its own');
	assert.match(row.source, /^var api = require\("[^"]+injectStylesIntoStyleTag\.js"\);\n {12}var content = require\("!!/);
	assert.match(row.source, /\nmodule\.exports = content\.locals \|\| \{\};$/);
});

// The physical runtime the pitched code requires is an ordinary module of the
// graph, described where every other source module is, not here.
test('leaves the style-loader runtime module to the ordinary graph', () => {
	const result = build('basic');
	const row = rowOf(result.report, 'injectStylesIntoStyleTag.js', 0);
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /was not built by an observed stylesheet loader/);
	assert.deepEqual(row.units, []);
	assert.equal(row.resource, STYLE_RUNTIME);
	assert.equal(rowOf(result.report, 'one.js', 0).status, 'no-data');
});

test('describes a stylesheet built by raw-loader alone', () => {
	const result = build('raw-only');
	const row = rawRow(result.report);
	assert.equal(row.status, 'present', row.reason);
	const file = path.join(result.app, 'a.css');
	assert.deepEqual(unitsOf(row), [
		{ path: file, sha256: sha256(file), component: APP_COMPONENT },
		{ path: RAW_LOADER, sha256: RAW_LOADER_SHA256, component: RAW_COMPONENT },
	]);
	assert.equal(result.report.rows.filter((candidate) => candidate.loaders.length === 2).length, 0);
});

// The file and its original change together, so the verification against the
// original still passes: only the bytes raw-loader really read say otherwise.
test('reports a hash mismatch when the verified stylesheet is not what raw-loader read', () => {
	const result = build('tamper');
	const row = rawRow(result.report);
	assert.equal(row.status, 'hash-mismatch');
	assert.match(row.reason, /did not read the verified bytes of/);
	assert.deepEqual(row.units, []);
	assert.equal(fs.readFileSync(path.join(result.app, 'a.css'), 'utf8').length, SOURCES['a.css'].length);
	assert.equal(styleRow(result.report).status, 'present');
});

test('reports a hash mismatch when the raw module source is not what the loader returned', () => {
	const result = build('late-child');
	const row = rawRow(result.report);
	assert.equal(row.status, 'hash-mismatch');
	assert.match(row.reason, /is not what raw-loader returned/);
	assert.deepEqual(row.units, []);
	assert.equal(styleRow(result.report).status, 'present');
});

test('reports a hash mismatch when the pitched module source is not what was pitched', () => {
	const result = build('late-parent');
	const row = styleRow(result.report);
	assert.equal(row.status, 'hash-mismatch');
	assert.match(row.reason, /is not what style-loader pitched/);
	assert.deepEqual(row.units, []);
	assert.equal(rawRow(result.report).status, 'present');
});

// Another plugin that wraps the published pitch for itself decides what the
// module becomes; the recorded call is no longer the whole of it.
test('reports no data for a pitch replaced after this adapter recorded it', () => {
	const result = build('repitch');
	const row = styleRow(result.report);
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /pitch of .* was replaced after this adapter recorded it/);
	assert.deepEqual(row.units, []);
	assert.match(row.source, /added by another plugin/);
	assert.equal(rawRow(result.report).status, 'present');
});

// Every option of style-loader changes the code it pitches, and an insert
// function is printed into that code: none of it is described here.
test('reports no data for a style-loader configured with an insert function', () => {
	const result = build('insert');
	const row = styleRow(result.report);
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /options this adapter does not describe/);
	assert.deepEqual(row.units, []);
	assert.deepEqual(result.report.userOptions, { shared: true, keys: ['insert'] });
	assert.equal(rawRow(result.report).status, 'present');
});

// Two stylesheets through one rule: the adapter installs nothing into the
// options the user configured, so the object both modules were built with is
// the one the configuration still holds.
test('describes two stylesheets of one rule and leaves its options object alone', () => {
	const result = build('shared-options', { entry: 'two.js' });
	assert.deepEqual(result.report.userOptions, { shared: true, keys: [] });
	for (const name of ['a.css', 'b.css']) {
		assert.equal(styleRow(result.report, name).status, 'present', styleRow(result.report, name).reason);
		const row = rawRow(result.report, name);
		assert.equal(row.status, 'present', row.reason);
		assert.equal(row.units[0].sha256, sha256(path.join(result.app, name)));
	}
});

// A chain of more than the two known loaders is another transformation
// altogether - a sass chain among them - and nothing of it is described.
test('takes no part in a chain of more than the two known loaders', () => {
	const result = build('chain');
	const style = rowOf(result.report, 'a.css', 3);
	assert.equal(style.status, 'no-data');
	assert.match(style.reason, /was not pitched by style-loader at the head of its chain/);
	const row = rowOf(result.report, 'a.css', 2);
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /was not built by raw-loader alone/);
	assert.deepEqual(style.units, []);
	assert.deepEqual(row.units, []);
});

// Without the recorder nothing of what the loaders did was observed, and the
// adapter claims nothing from the built modules alone.
test('reports no data for a build this process did not record', () => {
	const result = build('basic', { withoutPreload: true });
	for (const row of result.report.rows) {
		assert.equal(row.status, 'no-data');
		assert.match(row.reason, /recorder is not installed in this process/);
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

// The production call site: the collector dispatches the chain to this adapter
// and the described bundle carries the stylesheet, both loader files and the
// style-loader runtime webpack bundled as an ordinary module.
test('describes a whole bundle built through the style-loader chain', () => {
	const result = build('collector-style', { collect: true, entry: 'required.js' });
	const row = mainRow(result);
	const css = path.join(result.app, 'a.css');
	for (const [file, component] of [
		[css, APP_COMPONENT],
		[path.join(result.app, 'required.js'), APP_COMPONENT],
		[RAW_LOADER, RAW_COMPONENT],
		[STYLE_INDEX, STYLE_COMPONENT],
		[STYLE_RUNTIME, STYLE_COMPONENT],
	]) {
		assert.deepEqual(inputOf(row, file), { kind: 'source', path: file, sha256: sha256(file), components: [component], disposition: 'included' }, `missing input ${file}`);
	}
	for (const id of [APP_COMPONENT, STYLE_COMPONENT, RAW_COMPONENT, WEBPACK_COMPONENT]) {
		assert.ok(row.includedComponents.includes(id), `${id} is not an included component of ${row.includedComponents.join(', ')}`);
	}
	assert.ok(!row.includedComponents.some((id) => /sass|scss/i.test(id)), `no sass component may be claimed: ${row.includedComponents.join(', ')}`);
});

test('describes a whole bundle whose stylesheet is built by raw-loader alone', () => {
	const result = build('raw-only', { collect: true, entry: 'required.js' });
	const row = mainRow(result);
	const css = path.join(result.app, 'a.css');
	assert.deepEqual(inputOf(row, css), { kind: 'source', path: css, sha256: sha256(css), components: [APP_COMPONENT], disposition: 'included' });
	assert.deepEqual(inputOf(row, RAW_LOADER), { kind: 'source', path: RAW_LOADER, sha256: RAW_LOADER_SHA256, components: [RAW_COMPONENT], disposition: 'included' });
	assert.equal(inputOf(row, STYLE_INDEX), undefined, 'a raw-loader chain must contribute no style-loader source');
	for (const id of [APP_COMPONENT, RAW_COMPONENT, WEBPACK_COMPONENT]) {
		assert.ok(row.includedComponents.includes(id), `${id} is not an included component of ${row.includedComponents.join(', ')}`);
	}
	assert.ok(!row.includedComponents.includes(STYLE_COMPONENT), `${STYLE_COMPONENT} must not be an included component of ${row.includedComponents.join(', ')}`);
});

// The loader writes the request for its shared runtime relative to the
// directory of each stylesheet it pitches over, so stylesheets at different
// depths are pitched different text.
test('describes pitched modules whose stylesheets lie at different depths', () => {
	const result = build('depths', { entry: 'depths.js' });
	const shallow = styleRow(result.report, 'a.css');
	const deep = styleRow(result.report, 'c.css');
	for (const row of [shallow, deep]) {
		assert.equal(row.status, 'present', `${row.resource}: ${row.reason}`);
		assert.deepEqual(unitsOf(row), [{ path: STYLE_INDEX, sha256: STYLE_INDEX_SHA256, component: STYLE_COMPONENT }]);
	}
	// The one runtime both of them load, named from where each of them stands.
	const requestOf = (row) => row.source.match(/^var api = require\("([^"]*)"\);/)[1];
	assert.notEqual(requestOf(shallow), requestOf(deep));
	for (const row of [shallow, deep]) {
		assert.equal(path.resolve(path.dirname(row.resource), requestOf(row).slice(1)), STYLE_RUNTIME);
	}
});

// The claim is that the code loads the runtime of the loader file it claims, so
// a build that resolves that request to a file of its own is not described.
test('reports no data when the runtime of the request is not the one the loader names', () => {
	const row = styleRow(build('aliased-runtime').report);
	assert.equal(row.status, 'no-data', row.reason);
	assert.match(row.reason, /also requires .*aliased-runtime\.js$/);
	assert.deepEqual(row.units, []);
});
