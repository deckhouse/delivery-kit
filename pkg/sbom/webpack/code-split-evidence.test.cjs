'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture, bootstrapOriginal } = require('./fixture.cjs');
const { addSources } = require('./content-hash-fixture.cjs');
const { packWebpack } = require('./runtime-fixture.cjs');
const { MARKER, writeSources, child } = require('./code-split-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const WEBPACK = path.dirname(require.resolve('webpack/package.json'));
// The classes a web build with one lazy import carries, in the shape Argo
// builds: no public path of its own, so the runtime works it out itself.
const DESCRIBED = [
	'AutoPublicPathRuntimeModule',
	'DefinePropertyGettersRuntimeModule',
	'EnsureChunkRuntimeModule',
	'GetChunkFilenameRuntimeModule',
	'GlobalRuntimeModule',
	'HasOwnPropertyRuntimeModule',
	'JsonpChunkLoadingRuntimeModule',
	'LoadScriptRuntimeModule',
	'MakeNamespaceObjectRuntimeModule',
];

let scratch;
let webpackSource;
let fixture;
let toolOriginals;
let builds = 0;

before(
	() => {
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-split-')));
		webpackSource = packWebpack(path.join(scratch, 'webpack'), WEBPACK);
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true });
		toolOriginals = [bootstrapOriginal(path.join(scratch, 'terser-webpack-plugin'), 'terser-webpack-plugin').binding, bootstrapOriginal(path.join(scratch, 'terser'), 'terser').binding];
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
	const root = path.join(scratch, `${scenario}-${builds++}`);
	// A collected build needs every module bound to a declared original, so it
	// runs in a workspace of the shared fixture instead of a bare source dir.
	const area = options.collect ? fixture.workspace(`${scenario}-${builds}`, { isolateOriginals: true }) : undefined;
	if (area) addSources(area);
	const setup = {
		scenario,
		collect: Boolean(options.collect),
		context: area ? area.root : root,
		entry: area ? area.installed('app/split.js') : writeSources(path.join(root, 'src')),
		modules: area ? area.modules : undefined,
		output: area ? area.output : path.join(root, 'out'),
		proofPath: area ? area.proofPath : undefined,
		originals: area ? [...area.originals, ...toolOriginals] : undefined,
		root: webpackSource.root,
		originalRoot: webpackSource.original,
		component: webpackSource.component,
	};
	const output = execFileSync(process.execPath, ['--require', PRELOAD, child], {
		cwd: setup.context,
		encoding: 'utf8',
		timeout: 60000,
		env: { ...process.env, DK_CODE_SPLIT_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.webpack, '5.94.0');
	assert.equal(report.chunks.length, options.chunks || 2, report.chunks.map((candidate) => candidate.files.join('+')).join(', '));
	return { setup, report };
}

function lazyChunk(report) {
	const chunk = report.chunks.find((candidate) => !candidate.runtime);
	assert.ok(chunk, 'no lazy chunk in the report');
	return chunk;
}

function runtimeModules(report) {
	const chunk = report.chunks.find((candidate) => candidate.runtime);
	assert.ok(chunk, 'no runtime chunk in the report');
	return new Map(chunk.modules.map((module) => [module.class, module]));
}

function relative(unit) {
	return path.relative(path.join(WEBPACK, 'lib'), unit).split(path.sep).join('/');
}

// The lazy chunk is the array-push wrapper of its modules: the renderer and the
// chunk format that produced it are the pinned sources, and the bytes the
// render returned are the file that was emitted.
test('describes the lazy chunk of a code-splitting build', () => {
	const result = build('plain');
	const chunk = lazyChunk(result.report);
	assert.equal(chunk.status, 'present', chunk.reason);
	assert.equal(chunk.files.length, 1);
	assert.match(chunk.files[0], /\.chunk\.js$/);
	assert.equal(chunk.rendered, result.report.emitted[chunk.files[0]]);
	assert.equal(chunk.rendered, sha256(path.join(result.setup.output, chunk.files[0])));
	assert.deepEqual(chunk.units.map(relative).sort(), ['APIPlugin.js', 'RuntimeGlobals.js', 'RuntimeTemplate.js', 'Template.js', 'javascript/ArrayPushCallbackChunkFormatPlugin.js', 'javascript/JavascriptModulesPlugin.js']);
});

// With the minifier the rendered bytes are no longer the emitted ones; what the
// render produced is still described, and the caller chains the two.
test('describes the lazy chunk of a minified code-splitting build', () => {
	const result = build('minified');
	const chunk = lazyChunk(result.report);
	assert.equal(chunk.status, 'present', chunk.reason);
	assert.notEqual(chunk.rendered, result.report.emitted[chunk.files[0]]);
});

// Every runtime module a lazy import pulls in, including the three that build
// a filename out of the output options.
test('describes the chunk-loading runtime modules a lazy import pulls in', () => {
	const modules = runtimeModules(build('plain').report);
	assert.deepEqual([...modules.keys()].sort(), [...DESCRIBED].sort());
	for (const name of DESCRIBED) {
		const module = modules.get(name);
		assert.equal(module.status, 'present', `${name}: ${module.reason}`);
		assert.ok(module.units.length >= 4, `${name} claims ${module.units.length} sources`);
	}
	assert.deepEqual(
		modules.get('JsonpChunkLoadingRuntimeModule').units.map(relative).sort(),
		['RuntimeGlobals.js', 'RuntimeModule.js', 'RuntimeTemplate.js', 'Template.js', 'javascript/JavascriptModulesPlugin.js', 'javascript/StartupHelpers.js', 'util/compileBooleanMatcher.js', 'web/JsonpChunkLoadingRuntimeModule.js'],
	);
	// The chunk filename map is generated a second time while the chunk hashes
	// are computed; both runs are observed and the used one is bound.
	assert.equal(modules.get('GetChunkFilenameRuntimeModule').runs, 2);
	assert.equal(modules.get('EnsureChunkRuntimeModule').runs, 1);
	assert.deepEqual(
		modules.get('GetChunkFilenameRuntimeModule').units.map(relative).sort(),
		['Compilation.js', 'RuntimeGlobals.js', 'RuntimeModule.js', 'RuntimeTemplate.js', 'Template.js', 'TemplatedPathPlugin.js', 'runtime/GetChunkFilenameRuntimeModule.js', 'util/SetHelpers.js'],
	);
	assert.deepEqual(
		modules.get('AutoPublicPathRuntimeModule').units.map(relative).sort(),
		[
			'Compilation.js',
			'RuntimeGlobals.js',
			'RuntimeModule.js',
			'RuntimeTemplate.js',
			'Template.js',
			'TemplatedPathPlugin.js',
			'javascript/JavascriptModulesPlugin.js',
			'runtime/AutoPublicPathRuntimeModule.js',
			'util/identifier.js',
		],
	);
});

// The explicit public path is a different class, described the same way.
test('describes the explicit public path of a build that configures one', () => {
	const modules = runtimeModules(build('explicit-path').report);
	assert.equal(modules.get('PublicPathRuntimeModule').status, 'present', modules.get('PublicPathRuntimeModule').reason);
	assert.equal(modules.get('AutoPublicPathRuntimeModule'), undefined);
});

// A tap on any hook that shapes the chunk text, including the chunk format's
// own hook, leaves bytes no verified source accounts for.
test('reports no data for a lazy chunk another plugin shaped', () => {
	for (const [scenario, expected] of [
		['tapped-render', /fixture tapped render /],
		['tapped-chunk', /fixture tapped renderChunk /],
		['untapped', /0 plugins tapped renderChunk/],
	]) {
		const chunk = lazyChunk(build(scenario).report);
		assert.equal(chunk.status, 'no-data', `${scenario}: ${chunk.reason}`);
		assert.match(`${chunk.reason} `, expected);
		assert.deepEqual(chunk.units, []);
	}
});

// The two runtime modules that build their text through a hook of their own are
// described only while nothing taps it.
test('reports no data for a runtime module whose hook another plugin tapped', () => {
	for (const [scenario, name] of [
		['tapped-create-script', 'LoadScriptRuntimeModule'],
		['tapped-link-preload', 'JsonpChunkLoadingRuntimeModule'],
	]) {
		const modules = runtimeModules(build(scenario).report);
		const module = modules.get(name);
		assert.equal(module.status, 'no-data', `${scenario}: ${module.reason}`);
		assert.match(module.reason, /fixture tapped (createScript|linkPreload)/);
		assert.deepEqual(module.units, []);
		// Only that one module loses its description.
		assert.equal(modules.get('EnsureChunkRuntimeModule').status, 'present');
	}
});

// The whole collector on the shape Argo builds: a minified, content-hashed web
// build with one lazy import and no public path of its own. Both assets are
// described down to the files on disk.
test('writes a proof describing both assets of an argo-shaped build', () => {
	const result = build('plain', { collect: true });
	const proof = result.report.proof;
	assert.ok(proof, 'the child wrote no proof');
	assert.equal(proof.assets.length, 2, proof.assets.map((row) => row.path).join(', '));
	const lazy = proof.assets.find((row) => row.path.endsWith('.chunk.js'));
	const main = proof.assets.find((row) => row !== lazy);
	for (const row of [lazy, main]) {
		assert.equal(row.status, 'present', `${row.path}: ${row.reason}`);
		assert.equal(row.sha256, result.report.emitted[row.path]);
		assert.equal(row.sha256, sha256(path.join(result.setup.output, row.path)));
		assert.ok(row.inputs.length > 0);
		assert.ok(row.includedComponents.includes('node:webpack@5.94.0'), row.includedComponents.join(', '));
	}
	// The runtime chunk holds the hashed name of the chunk it loads, so the
	// content-hash substitution rewrote it after it was minified.
	assert.match(main.path, /^main\.[0-9a-f]+\.js$/);
});

// With the runtime moved to a chunk of its own, the entry chunk is rendered by
// the chunk renderer but wrapped in startup code built from files this adapter
// does not claim.
test('reports no data for a chunk that starts its own entry modules', () => {
	const result = build('runtime-chunk', { chunks: 3 });
	const entry = result.report.chunks.find((chunk) => !chunk.runtime && chunk.files.some((file) => file.startsWith('main.')));
	assert.ok(entry, result.report.chunks.map((chunk) => chunk.files.join('+')).join(', '));
	assert.equal(entry.status, 'no-data');
	assert.match(entry.reason, /starts its own entry modules/);
	assert.deepEqual(entry.units, []);
	// The lazy chunk of the same build carries none, and is still described.
	const lazy = result.report.chunks.find((chunk) => chunk.files.some((file) => file.endsWith('.chunk.js')));
	assert.equal(lazy.status, 'present', lazy.reason);
});

// The filenames the runtime builds are only described while the one stock
// substitution is what builds them.
test('reports no data for the filename runtime modules when another plugin taps the path hook', () => {
	const modules = runtimeModules(build('tapped-asset-path').report);
	for (const name of ['GetChunkFilenameRuntimeModule', 'AutoPublicPathRuntimeModule']) {
		const module = modules.get(name);
		assert.equal(module.status, 'no-data', `${name}: ${module.reason}`);
		assert.match(module.reason, /fixture, TemplatedPathPlugin tapped assetPath/);
		assert.deepEqual(module.units, []);
	}
	// A module that builds no filename is unaffected.
	assert.equal(modules.get('EnsureChunkRuntimeModule').status, 'present');
});

// An output filename with a directory of its own makes the public path module
// embed the way back out of it.
test('describes the public path of a build whose output filename has a directory', () => {
	const result = build('nested-output');
	const module = runtimeModules(result.report).get('AutoPublicPathRuntimeModule');
	assert.equal(module.status, 'present', module.reason);
	const main = Object.keys(result.report.emitted).find((name) => name.startsWith('js/'));
	assert.ok(main, Object.keys(result.report.emitted).join(', '));
	assert.match(fs.readFileSync(path.join(result.setup.output, main), 'utf8'), /scriptUrl \+ "\.\.\/"/);
});

// A second render of the same chunk, by a plugin with a context of its own, is
// not the render this adapter observed.
test('reports no data for a chunk a plugin rendered a second time', () => {
	const chunk = lazyChunk(build('second-render').report);
	assert.equal(chunk.status, 'no-data');
	assert.match(chunk.reason, /was rendered 2 times/);
	assert.deepEqual(chunk.units, []);
});

// What the filename was built from has to be a template of the output options,
// whatever function the module was built with returns.
test('reports no data for a filename built from a template of a plugin making', () => {
	const module = runtimeModules(build('forged-template').report).get('GetChunkFilenameRuntimeModule');
	assert.equal(module.status, 'no-data', module.reason);
	assert.match(module.reason, /template that is not one of the output options/);
	assert.deepEqual(module.units, []);
});

// The name of the global object is carried into both texts unquoted, so neither
// is described once it is not a plain identifier.
test('reports no data when the name of the global object is not an identifier', () => {
	const result = build('forged-global');
	const chunk = lazyChunk(result.report);
	assert.equal(chunk.status, 'no-data', chunk.reason);
	assert.match(chunk.reason, /name of its global object is not an identifier/);
	const module = runtimeModules(result.report).get('JsonpChunkLoadingRuntimeModule');
	assert.equal(module.status, 'no-data', module.reason);
	assert.match(module.reason, /name of its global object is not an identifier/);
});

// The recording of what a filename was built from is only worth something while
// it is the one in place: a compilation that already builds filenames its own
// way, one that shadows the loaded implementation, and a module that takes the
// recording away in the middle of its own generator are all refused.
test('reports no data when the filenames were not built by the loaded implementation', () => {
	for (const [scenario, expected] of [
		['own-path-builder', /already built filenames with a method of its own/],
		['shadowed-path-builder', /built its filenames with another implementation/],
		['swap-while-building', /was replaced while it generated/],
		['no-filename', /it built 0 filenames/],
	]) {
		const modules = runtimeModules(build(scenario).report);
		const module = modules.get('GetChunkFilenameRuntimeModule');
		assert.equal(module.status, 'no-data', `${scenario}: ${module.reason}`);
		assert.match(module.reason, expected);
		assert.deepEqual(module.units, []);
	}
});

// A library written in the amd style makes webpack add two runtime modules of
// its own, declared side by side in one file and exported as members of it.
test('describes the runtime modules a library in the amd style asks for', () => {
	const modules = runtimeModules(build('amd', { chunks: 2 }).report);
	for (const name of ['AMDDefineRuntimeModule', 'AMDOptionsRuntimeModule']) {
		const module = modules.get(name);
		assert.ok(module, [...modules.keys()].join(', '));
		assert.equal(module.status, 'present', `${name}: ${module.reason}`);
		assert.deepEqual(
			module.units.map(relative).sort(),
			['RuntimeGlobals.js', 'RuntimeModule.js', 'RuntimeTemplate.js', 'Template.js', 'dependencies/AMDRuntimeModules.js'],
		);
	}
});

// Those options are written out as json, so they have to be data this adapter
// can write out again.
test('reports no data for amd options that are not plain data', () => {
	const module = runtimeModules(build('forged-amd-options', { chunks: 2 }).report).get('AMDOptionsRuntimeModule');
	assert.equal(module.status, 'no-data', module.reason);
	assert.match(module.reason, /the amd options it writes out are not plain data/);
	assert.deepEqual(module.units, []);
});

// What the configuration says about amd is written into that text as json.
test('describes the amd options a build configured', () => {
	const result = build('amd-options', { chunks: 2 });
	const module = runtimeModules(result.report).get('AMDOptionsRuntimeModule');
	assert.equal(module.status, 'present', module.reason);
	const main = Object.keys(result.report.emitted).find((name) => name.startsWith('main.'));
	assert.match(fs.readFileSync(path.join(result.setup.output, main), 'utf8'), /amdO = \{"jQuery":true,"name":"argo"\}/);
});

// A commonjs module imported from an esm one makes webpack carry its
// compatibility helper, and asking that module for its own paths makes it carry
// the decorator that gives it them.
test('describes the runtime modules a commonjs interop build asks for', () => {
	const modules = runtimeModules(build('interop', { chunks: 2 }).report);
	const compat = modules.get('CompatGetDefaultExportRuntimeModule');
	assert.ok(compat, [...modules.keys()].join(', '));
	assert.equal(compat.status, 'present', compat.reason);
	assert.deepEqual(
		compat.units.map(relative).sort(),
		['RuntimeGlobals.js', 'RuntimeModule.js', 'RuntimeTemplate.js', 'Template.js', 'runtime/CompatGetDefaultExportRuntimeModule.js', 'runtime/HelperRuntimeModule.js'],
	);
	// The decorator is declared inside the plugin that installs it and exported
	// by nothing, so it is claimed with that plugin's own source.
	const decorator = modules.get('NodeModuleDecoratorRuntimeModule');
	assert.ok(decorator, [...modules.keys()].join(', '));
	assert.equal(decorator.status, 'present', decorator.reason);
	assert.deepEqual(
		decorator.units.map(relative).sort(),
		['RuntimeGlobals.js', 'RuntimeModule.js', 'RuntimeTemplate.js', 'Template.js', 'dependencies/CommonJsPlugin.js'],
	);
});

// Such a class is held to the text its own pinned source builds.
test('reports a hash mismatch for a declared runtime module whose code was forged', () => {
	const module = runtimeModules(build('forged-decorator', { chunks: 2 }).report).get('NodeModuleDecoratorRuntimeModule');
	assert.equal(module.status, 'hash-mismatch', module.reason);
	assert.match(module.reason, /is not what dependencies\/CommonJsPlugin\.js builds/);
	assert.deepEqual(module.units, []);
});

// Such a class is bound to the source that declares it, not to its name.
test('reports no data for a declared runtime module another class impersonates', () => {
	const module = runtimeModules(build('foreign-decorator', { chunks: 2 }).report).get('NodeModuleDecoratorRuntimeModule');
	assert.equal(module.status, 'no-data', module.reason);
	assert.match(module.reason, /is not the one dependencies\/CommonJsPlugin\.js declares|would not run the generator of the class it carries/);
	assert.deepEqual(module.units, []);
});
