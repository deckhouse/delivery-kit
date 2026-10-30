'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture, bootstrapOriginal } = require('./fixture.cjs');
const { MARKER, TEMPLATE, FORK_DEPENDENCIES, addSources, child } = require('./html-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const PLUGIN = path.dirname(require.resolve('html-webpack-plugin/package.json'));
const WEBPACK = path.dirname(require.resolve('webpack/package.json')); // The published artifacts, as packed in the npm archives of these versions.
const PINS = new Map([
	['html-webpack-plugin/index.js', 'sha256:a21ad81ac18caac0710bfd14ba5dfa6fa91e913d26141c7a321202ecbba7970c'],
	['html-webpack-plugin/lib/loader.js', 'sha256:59fcbda4890ead89628a462490df69ba56b06b9be15a7150d774019549f8c0e6'],
	['html-webpack-plugin/lib/html-tags.js', 'sha256:74755a5cbf4c6cfef8b6678aefabec1379d330c97757b80f6b8b803ac31e6379'],
	['lodash/lodash.js', 'sha256:71b4b7f5d2fc2d69399fd3edd7104fa10f9fd73fc600130825c3032ee8c50dad'],
	['html-minifier-terser/src/htmlminifier.js', 'sha256:6594bd37dd57ecaf70d9e1983c2ec5d20c5a8a73593af45fa157ce44f0f25921'],
	['he/he.js', 'sha256:76c554d5bbfd032fe620595076a50abea5124b9cbd4e9ffe6ac94a4f855aeceb'],
]);
// Every file the adapter claims as a source of the html it describes.
const TEXT_FILES = [
	'html-webpack-plugin/index.js',
	'html-webpack-plugin/lib/loader.js',
	'html-webpack-plugin/lib/html-tags.js',
	'lodash/lodash.js',
	'html-minifier-terser/src/htmlminifier.js',
	'html-minifier-terser/src/htmlparser.js',
	'html-minifier-terser/src/tokenchain.js',
	'html-minifier-terser/src/utils.js',
];

let scratch;
let fixture;
let tools;
let dependencyRoots;
let areas = 0;

before(
	() => {
		for (const [file, sha256] of PINS) {
			assert.equal(sha256of(require.resolve(file)), sha256, `${file} is not the published artifact this adapter pins`);
		}
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-html-')));
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
		// The plugin and the three distributions whose code writes html text are
		// instruments of this compilation, like webpack itself.
		tools = ['html-webpack-plugin', 'lodash', 'html-minifier-terser', 'he', 'terser-webpack-plugin', 'terser'].map((name) => bootstrapOriginal(path.join(scratch, name), name).binding);
		dependencyRoots = Object.fromEntries(FORK_DEPENDENCIES.map((name) => [name, path.dirname(require.resolve(`${name}/package.json`))]));
	},
	{ timeout: 300000 }
);

after(() => fs.rmSync(scratch, { recursive: true, force: true }));

function sha256of(file) {
	return `sha256:${crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')}`;
}

// One real webpack build per scenario, in its own process whose commonjs loader
// is recorded from the very first module on.
function build(scenario, options = {}) {
	const area = fixture.workspace(`${scenario}-${areas++}`, { isolateOriginals: true });
	addSources(area, { argo: options.argo === true });
	const setup = {
		scenario,
		mode: options.mode,
		context: area.root,
		modules: area.modules,
		entry: area.installed('app/index.js'),
		output: area.output,
		proofPath: options.collect ? area.proofPath : undefined,
		webpackRoot: WEBPACK,
		pluginRoot: PLUGIN,
		dependencyRoots,
		originals: [...area.originals, ...tools],
	};
	const output = execFileSync(process.execPath, ['--require', PRELOAD, child], {
		cwd: area.root,
		encoding: 'utf8',
		timeout: 60000,
		env: { ...process.env, DK_HTML_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.webpack, '5.94.0');
	assert.equal(report.plugin, '5.6.0');
	return { area, report };
}

function htmlRow(report) {
	const row = report.rows.find((candidate) => candidate.name === 'index.html');
	assert.ok(row, `no index.html row in ${report.rows.map((candidate) => candidate.name).join(', ')}`);
	return row;
}

// The emitted html, the template it was compiled from and the code that wrote
// the rest of it, bound to the bytes that stayed on disk.
test('describes the html of a production build with the plugin default options', () => {
	const result = build('plain');
	const row = htmlRow(result.report);
	assert.equal(row.status, 'present', row.reason);
	assert.equal(row.requiredBytes, result.report.emitted['index.html']);
	assert.equal(row.requiredBytes, sha256of(path.join(result.area.output, 'index.html')));

	const paths = row.units.map((unit) => unit.path);
	assert.ok(paths.includes(path.join(result.area.modules, 'app', TEMPLATE)), paths.join('\n'));
	for (const file of TEXT_FILES) assert.ok(paths.includes(require.resolve(file)), `${file} is not a described source: ${paths.join('\n')}`);
	assert.equal(paths.length, TEXT_FILES.length + 1);
	assert.deepEqual([...new Set(row.units.map((unit) => unit.component))].sort(), ['node:app@0.1.0', 'node:html-minifier-terser@6.1.0', 'node:html-webpack-plugin@5.6.0', 'node:lodash@4.17.23']);

	// The production minification really ran, and the tags really name the asset
	// this compilation produced.
	assert.doesNotMatch(result.report.html, /the comment a production build removes/);
	assert.doesNotMatch(result.report.html, /\n/);
	assert.match(result.report.html, /<script defer="defer" src="main\.js"><\/script>/);
	assert.match(result.report.html, /<title>Webpack App<\/title>/);

	// Nothing else of the compilation is this adapter's to describe.
	assert.equal(result.report.rows.find((candidate) => candidate.name === 'main.js').status, 'none');
});

// The file the loader read has to be the file that was verified: bytes that
// changed after the read describe an html nobody can reproduce from them.
test('reports a hash mismatch when the template changed after it was read', () => {
	const row = htmlRow(build('retemplate').report);
	assert.equal(row.status, 'hash-mismatch');
	assert.match(row.reason, /did not read the verified bytes of .*index\.html/);
	assert.equal(row.units, undefined);
});

// Every one of the plugin's public hooks is a seam for text this adapter never
// sees - whether the tap changes the html or not, and an interceptor registers
// taps no tap list of a later reading has to show.
test('reports no data when another plugin taps or intercepts a hook of the html plugin', () => {
	for (const [scenario, hook] of [
		['tap-before-emit', 'beforeEmit'],
		['tap-alter-tags', 'alterAssetTags'],
	]) {
		const row = htmlRow(build(scenario).report);
		assert.equal(row.status, 'no-data', `${scenario}: ${row.reason}`);
		assert.equal(row.reason, `another plugin taps the ${hook} hook of html-webpack-plugin`);
		assert.equal(row.requiredBytes, undefined);
	}
	const intercepted = htmlRow(build('intercepted').report);
	assert.equal(intercepted.status, 'no-data');
	assert.equal(intercepted.reason, 'the beforeEmit hook of html-webpack-plugin is not the plain waterfall hook this adapter describes');
});

// Only the options the plugin itself builds for a configuration that names
// nothing but its template are described.
test('reports no data for options this adapter does not describe', () => {
	for (const [scenario, reason] of [
		['custom-minify', /a minify of its own/],
		['parameters', /template parameters of its own/],
		['no-inject', /a inject of its own/],
	]) {
		const row = htmlRow(build(scenario).report);
		assert.equal(row.status, 'no-data', `${scenario}: ${row.reason}`);
		assert.match(row.reason, reason);
		assert.equal(row.units, undefined);
	}
});

// A fork keeping the version of the plugin it was made from is not that plugin,
// however well its own bytes verify.
test('refuses a plugin source that is not the pinned one', () => {
	const row = htmlRow(build('forked').report);
	assert.equal(row.status, 'unsupported');
	assert.match(row.reason, /html-webpack-plugin\/lib\/html-tags\.js is not the source of the pinned html-webpack-plugin 5\.6\.0/);
	assert.equal(row.units, undefined);
});

// What is emitted has to be what the described steps produced: an asset
// another plugin rewrote afterwards is no longer that html.
test('reports a hash mismatch when the emitted html was rewritten after it was made', () => {
	const row = htmlRow(build('rewritten').report);
	assert.equal(row.status, 'hash-mismatch');
	assert.equal(row.reason, 'index.html is not the html html-webpack-plugin produced');
	assert.equal(row.units, undefined);
});

// A loader of the project in front of the plugin's own writes html out of
// code this adapter never observed reading anything.
test('reports no data when another loader compiled the template', () => {
	const result = build('extra-loader');
	const row = htmlRow(result.report);
	assert.equal(row.status, 'no-data');
	assert.equal(row.reason, 'the template was not compiled by the loader of this plugin alone');
	assert.match(result.report.html, /from another loader/);
});

// The plugin object of the configuration has to be an instance of the recorded
// class and nothing more: the methods this adapter does not wrap are reached
// through it, and an own property shadowing one of them writes html nobody saw.
test('reports no data for a plugin object carrying members of its own', () => {
	const shadowed = build('shadowed');
	const row = htmlRow(shadowed.report);
	assert.equal(row.status, 'no-data');
	assert.equal(row.reason, 'html-webpack-plugin carries generatedScriptTags of its own');
	// The shadowing really did write the html it was refused for.
	assert.match(shadowed.report.html, /integrity="from an own tag generator"/);

	const borrowed = htmlRow(build('borrowed').report);
	assert.equal(borrowed.status, 'no-data');
	assert.equal(borrowed.reason, 'html-webpack-plugin is not an instance of the recorded plugin class');
});

// Webpack copies the taps of this compiler into the child compiler of the
// template (Compiler.js:1216-1239), so a plugin of the main build can render
// and rewrite the template bundle where nothing observes it.
test('reports no data when foreign code could reach the template bundle', () => {
	for (const [scenario, reason] of [
		['child-render', /fixture tapped render/],
		['child-assets', /fixture tapped processAssets at -102/],
	]) {
		const row = htmlRow(build(scenario).report);
		assert.equal(row.status, 'no-data', `${scenario}: ${row.reason}`);
		assert.match(row.reason, reason);
		assert.equal(row.units, undefined);
	}
});

// The whole collector on the shape Argo builds with: the real Argo template,
// content-hashed chunk names the html refers to and the default minimizer. The
// html is rewritten by the content hash substitution after the plugin emitted
// it, so the proof has to follow it through that stage down to the file.
test('describes the Argo html through the whole collector', () => {
	const result = build('argo', { collect: true, argo: true });
	const proof = result.report.proof;
	assert.ok(proof, 'the child wrote no proof');
	const rows = Object.fromEntries(proof.assets.map((row) => [row.path, row]));
	assert.deepEqual(Object.keys(rows).sort(), Object.keys(result.report.emitted).sort());

	const html = rows['index.html'];
	assert.equal(html.status, 'present', html.reason);
	assert.equal(html.sha256, result.report.emitted['index.html']);
	assert.equal(html.size, fs.statSync(path.join(result.area.output, 'index.html')).size);
	assert.ok(
		html.inputs.some((input) => input.path === path.join(result.area.modules, 'app', TEMPLATE)),
		html.inputs.map((input) => input.path).join('\n')
	);
	for (const file of TEXT_FILES)
		assert.ok(
			html.inputs.some((input) => input.path === require.resolve(file)),
			`${file} is not an input of the html`
		);

	// The emitted html is Argo's template, minified, naming the hashed bundle the
	// content hash substitution gave its final name to.
	const bundle = Object.keys(result.report.emitted).find((name) => name.endsWith('.js'));
	assert.match(bundle, /^main\.[0-9a-f]+\.js$/);
	assert.match(result.report.html, new RegExp(`src="${bundle.replace(/\./g, '\\.')}"`));
	assert.match(result.report.html, /<title>Argo CD<\/title>/);
	assert.match(result.report.html, /<base href="\/">/);
	assert.equal(rows[bundle].status, 'present', rows[bundle].reason);
});

// An instrument file nobody can verify is not an instrument this adapter may
// describe an asset from.
test('reports no data when a file of the plugin cannot be verified', () => {
	const row = htmlRow(build('unverified').report);
	assert.equal(row.status, 'no-data');
	assert.match(row.reason, /html-tags\.js/);
	assert.equal(row.units, undefined);
});
