'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { createFixture } = require('./fixture.cjs');
const { MARKER, packWebpack, child } = require('./runtime-fixture.cjs');

const PRELOAD = path.join(__dirname, 'runtime-preload.cjs');
const CLASSES = ['DefinePropertyGettersRuntimeModule', 'HasOwnPropertyRuntimeModule', 'MakeNamespaceObjectRuntimeModule'];
const SHARED = ['lib/RuntimeGlobals.js', 'lib/RuntimeModule.js', 'lib/RuntimeTemplate.js', 'lib/Template.js'];

// HasOwnPropertyRuntimeModule derives from RuntimeModule directly, the other two
// through HelperRuntimeModule.
function expectedSources(className) {
	const own = [`lib/runtime/${className}.js`];
	if (className !== 'HasOwnPropertyRuntimeModule') own.push('lib/runtime/HelperRuntimeModule.js');
	return [...SHARED, ...own].sort();
}

let scratch;
let fixture;
let distribution;
let scenarios = 0;

before(() => {
	scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-runtime-')));
	fixture = createFixture(path.join(scratch, 'fixture'));
	distribution = packWebpack(path.join(scratch, 'webpack-dist'), path.join(__dirname, 'node_modules', 'webpack'));
}, { timeout: 120000 });

after(() => fs.rmSync(scratch, { recursive: true, force: true }));

// One real webpack build per scenario, in its own process whose commonjs loader
// is recorded from the very first module on.
function build(scenario, options = {}) {
	const area = fixture.workspace(`${scenario}-${scenarios++}`, { isolateOriginals: Boolean(options.module) });
	if (options.module) {
		// An entry of its own inside a declared distribution: written to the
		// materialized package and to the original it is verified against, so the
		// collector binds it like any other module of that package.
		for (const target of [area.installed(options.module.path), area.originalOf(options.module.path)]) {
			fs.writeFileSync(target, options.module.content);
		}
	}
	let root = distribution.root;
	let originalRoot = distribution.original;
	if (options.isolate) {
		// A distribution of its own, extracted from the archive like the original it
		// is verified against, so the scenario may rewrite it; its own dependencies
		// are not part of any claim, so they are taken from the installed one.
		root = path.join(area.modules, 'webpack');
		fs.cpSync(distribution.original, root, { recursive: true });
		fs.cpSync(path.join(distribution.root, 'node_modules'), path.join(root, 'node_modules'), { recursive: true });
		const installed = path.join(__dirname, 'node_modules');
		for (const entry of fs.readdirSync(installed)) {
			if (entry.startsWith('.') || fs.existsSync(path.join(area.modules, entry))) continue;
			fs.symlinkSync(path.join(installed, entry), path.join(area.modules, entry));
		}
		originalRoot = path.join(area.root, 'webpack-original');
		fs.cpSync(distribution.original, originalRoot, { recursive: true });
	}
	if (options.fork) {
		// A distribution that is byte-for-byte its own original and still not the
		// pinned webpack: patched before anything loaded it.
		for (const target of [root, originalRoot]) fs.appendFileSync(path.join(target, 'lib', 'Template.js'), '\n// patched fork\n');
	}
	if (options.mutateOriginal) {
		if (originalRoot === distribution.original) {
			originalRoot = path.join(area.root, 'webpack-original');
			fs.cpSync(distribution.original, originalRoot, { recursive: true });
		}
		options.mutateOriginal(originalRoot);
	}
	const setup = {
		scenario,
		context: area.root,
		entry: area.installed(options.entry || 'app/lib.js'),
		library: options.library,
		output: area.output,
		modules: area.modules,
		root,
		originalRoot,
		component: distribution.component,
		proofPath: area.proofPath,
		originals: [...area.originals, { root, originalRoot, component: distribution.component }],
	};
	const output = execFileSync(process.execPath, [...(options.preload === false ? [] : ['--require', PRELOAD]), child], {
		cwd: area.root,
		encoding: 'utf8',
		timeout: 60000,
		env: { ...process.env, DK_RUNTIME_SETUP: JSON.stringify(setup) },
	});
	const line = output.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `no report in child output:\n${output}`);
	const report = JSON.parse(line.slice(MARKER.length));
	assert.equal(report.webpack, distribution.component.version);
	return { area, root, report };
}

function only(report, index = 0) {
	const chunks = report.builds[index];
	assert.ok(chunks, `no build ${index} in the report`);
	assert.equal(chunks.length, 1, 'the fixture library build emits one chunk');
	return chunks[0];
}

function classesOf(chunk) {
	return chunk.modules.map((module) => module.class).sort();
}

function statusOf(chunk, className) {
	const module = chunk.modules.find((candidate) => candidate.class === className);
	assert.ok(module, `no runtime module of class ${className} in ${classesOf(chunk).join(', ')}`);
	return module;
}

function sha256(file) {
	return `sha256:${crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')}`;
}

test('binds the standard runtime modules of a real build to the pinned webpack sources', () => {
	const chunk = only(build('standard').report);
	assert.deepEqual(classesOf(chunk), CLASSES);
	for (const module of chunk.modules) {
		assert.equal(module.status, 'present', `${module.class}: ${module.reason}`);
		assert.deepEqual(module.units.map((unit) => path.relative(distribution.root, unit.path)).sort(), expectedSources(module.class));
		for (const unit of module.units) {
			assert.equal(unit.sha256, sha256(unit.path), `${unit.path} must be reported with the bytes it has`);
			assert.deepEqual(unit.component, distribution.component);
		}
	}
});

test('reports no data for a runtime module class that is not a webpack one', () => {
	const chunk = only(build('unknown-class').report);
	const fixtureModule = chunk.modules.find((module) => module.identifier.includes('fixture marker'));
	assert.ok(fixtureModule, `no fixture runtime module in ${chunk.modules.map((module) => module.identifier).join(', ')}`);
	assert.equal(fixtureModule.status, 'no-data');
	assert.match(fixtureModule.reason, /is not a described webpack runtime module/);
	assert.deepEqual(fixtureModule.units, []);
	for (const module of chunk.modules) {
		if (module !== fixtureModule) assert.equal(module.status, 'present', `${module.class}: ${module.reason}`);
	}
});

test('reports no data when the generator is replaced on the instance', () => {
	const chunk = only(build('instance-generate').report);
	const replaced = statusOf(chunk, 'HasOwnPropertyRuntimeModule');
	assert.equal(replaced.status, 'no-data');
	assert.match(replaced.reason, /own generate implementation/);
	assert.deepEqual(replaced.units, []);
	assert.equal(statusOf(chunk, 'DefinePropertyGettersRuntimeModule').status, 'present');
});

test('reports no data when the generator is replaced on the class prototype', () => {
	const chunk = only(build('prototype-generate').report);
	const replaced = statusOf(chunk, 'HasOwnPropertyRuntimeModule');
	assert.equal(replaced.status, 'no-data');
	assert.match(replaced.reason, /no longer exports what it exported/);
	assert.deepEqual(replaced.units, []);
	assert.equal(statusOf(chunk, 'MakeNamespaceObjectRuntimeModule').status, 'present');
});

test('reports no data for every class once a shared helper export is replaced', () => {
	const chunk = only(build('helper-replaced').report);
	for (const module of chunk.modules) {
		assert.equal(module.status, 'no-data');
		assert.match(module.reason, /Template\.js no longer exports/);
		assert.deepEqual(module.units, []);
	}
});

test('reports a hash mismatch when a webpack source no longer matches its original', () => {
	const chunk = only(
		build('changed-original', {
			mutateOriginal: (original) => fs.appendFileSync(path.join(original, 'lib', 'Template.js'), '\n// injected into the original\n'),
		}).report,
	);
	for (const module of chunk.modules) {
		assert.equal(module.status, 'hash-mismatch');
		assert.match(module.reason, /Template\.js/);
		assert.deepEqual(module.units, []);
	}
});

test('reports a hash mismatch when a verified source is not the one this process loaded', () => {
	const { root, report } = build('changed-after-load', { isolate: true });
	const chunk = only(report);
	for (const module of chunk.modules) {
		assert.equal(module.status, 'hash-mismatch');
		assert.match(module.reason, /Template\.js differs from the bytes this process loaded/);
		assert.deepEqual(module.units, []);
	}
	assert.match(fs.readFileSync(path.join(root, 'lib', 'Template.js'), 'utf8'), /appended after loading/);
});

test('reports a hash mismatch when the used runtime source is not the generated one', () => {
	const { area, report } = build('replaced-source');
	const chunk = only(report);
	for (const module of chunk.modules) {
		assert.equal(module.status, 'hash-mismatch');
		assert.match(module.reason, /is not the code its generator produced/);
		assert.deepEqual(module.units, []);
	}
	assert.match(fs.readFileSync(path.join(area.output, 'lib.js'), 'utf8'), /replaced after hashing/, 'the replacement must be what the asset really carries');
});

test('describes a warm second build of the same compiler exactly like the first', () => {
	const { report } = build('warm');
	assert.equal(report.builds.length, 2);
	const [first, second] = report.builds;
	assert.deepEqual(classesOf(only(report, 0)), CLASSES);
	for (const module of only(report, 1).modules) assert.equal(module.status, 'present', `${module.class}: ${module.reason}`);
	assert.deepEqual(second, first);
});

// The production collector, wired to this adapter, over one real build: the
// runtime units have to reach the proof it writes.
test('writes a collector proof whose chunk asset includes the webpack runtime and bootstrap sources', () => {
	const { report } = build('collector', { library: false, entry: 'app/index.js' });
	const asset = report.proof.assets.find((row) => row.path === 'lib.js');
	assert.ok(asset, `no lib.js row in ${report.proof.assets.map((row) => row.path).join(', ')}`);
	assert.equal(asset.status, 'present', asset.reason);
	assert.deepEqual(asset.includedComponents, ['node:app@0.1.0', 'node:pkg-a@1.2.3', 'node:pkg-b@4.5.6', 'node:webpack@5.94.0']);
	const inputs = asset.inputs.filter((input) => input.path.startsWith(distribution.root + path.sep)).map((input) => path.relative(distribution.root, input.path)).sort();
	// This entry needs no runtime module, so the webpack sources in the proof are
	// exactly the ones its bootstrap was rendered from, including the stock
	// renderModuleContent tap and the class that wrote the line reaching the
	// external this build references.
	assert.deepEqual(inputs, ['lib/javascript/JavascriptModulesPlugin.js', 'lib/APIPlugin.js', 'lib/RuntimeGlobals.js', 'lib/RuntimeTemplate.js', 'lib/Template.js', 'lib/ExternalModule.js'].sort());
	for (const input of asset.inputs) {
		assert.equal(input.sha256, sha256(input.path));
		assert.equal(input.disposition, 'included');
	}
});

test('reports no data for the runtime modules of a build that was not recorded', () => {
	const { report } = build('collector', { preload: false, library: false, entry: 'app/index.js' });
	const asset = report.proof.assets.find((row) => row.path === 'lib.js');
	assert.equal(asset.status, 'no-data');
	assert.match(asset.reason, /registry is not installed/);
	assert.deepEqual(asset.includedComponents, []);
});

// A later reading cannot tell these three apart from an honest build: the
// evidence has to come from inside the generator call.
test('reports no data for a runtime module whose code was never generated', () => {
	const { area, report } = build('prefilled-cache');
	const chunk = only(report);
	const prefilled = statusOf(chunk, 'HasOwnPropertyRuntimeModule');
	assert.equal(prefilled.status, 'no-data');
	assert.match(prefilled.reason, /was not observed running/);
	assert.deepEqual(prefilled.units, []);
	assert.equal(statusOf(chunk, 'DefinePropertyGettersRuntimeModule').status, 'present');
	assert.match(fs.readFileSync(path.join(area.output, 'lib.js'), 'utf8'), /plugin source, never generated/);
});

test('reports no data when the generator is swapped only while it runs', () => {
	const { area, report } = build('swapped-generator');
	const swapped = statusOf(only(report), 'HasOwnPropertyRuntimeModule');
	assert.equal(swapped.status, 'no-data');
	assert.match(swapped.reason, /was not observed running/);
	assert.deepEqual(swapped.units, []);
	assert.match(fs.readFileSync(path.join(area.output, 'lib.js'), 'utf8'), /plugin source, never generated/);
});

test('reports no data when a helper is swapped only while the generator runs', () => {
	const { area, report } = build('swapped-helper');
	for (const module of only(report).modules) {
		assert.equal(module.status, 'no-data');
		assert.match(module.reason, /while the generator ran/);
		assert.deepEqual(module.units, []);
	}
	assert.match(fs.readFileSync(path.join(area.output, 'lib.js'), 'utf8'), /injected by a plugin/);
});

test('refuses a patched distribution that verifies against its own original', () => {
	const chunk = only(build('standard', { isolate: true, fork: true }).report);
	for (const module of chunk.modules) {
		assert.equal(module.status, 'unsupported');
		assert.match(module.reason, /Template\.js is not the source of the pinned webpack 5\.94\.0/);
		assert.deepEqual(module.units, []);
	}
});

test('reports no data for a helper that restores itself from inside the generator call', () => {
	const { area, report } = build('one-shot-helper');
	const chunk = only(report);
	const forged = chunk.modules.filter((module) => module.status !== 'present');
	assert.ok(forged.length > 0, 'the one-shot helper must leave at least one module undescribed');
	for (const module of forged) {
		assert.equal(module.status, 'no-data');
		assert.match(module.reason, /while the generator ran/);
		assert.deepEqual(module.units, []);
	}
	assert.match(fs.readFileSync(path.join(area.output, 'lib.js'), 'utf8'), /one-shot injection/, 'the forged text must be what the asset really carries');
});

test('reports no data for a chunk whose bootstrap another plugin shaped', () => {
	const { report } = build('collector', { entry: 'app/index.js' });
	const asset = report.proof.assets.find((row) => row.path === 'lib.js');
	assert.equal(asset.status, 'no-data');
	assert.match(asset.reason, /AssignLibraryPlugin tapped render while renderMain ran/);
	assert.deepEqual(asset.includedComponents, []);
});

test('reports no data for a chunk rewritten between its render and its emit', () => {
	const { area, report } = build('rewritten-asset', { library: false, entry: 'app/index.js' });
	const asset = report.proof.assets.find((row) => row.path === 'lib.js');
	assert.equal(asset.status, 'no-data');
	assert.match(asset.reason, /changed between its render and its emit/);
	assert.deepEqual(asset.includedComponents, []);
	assert.match(fs.readFileSync(path.join(area.output, 'lib.js'), 'utf8'), /rewritten after rendering/);
});

// One library-less build that needs runtime modules as well as a bootstrap: the
// proof has to carry both, and nothing else from webpack.
test('writes a collector proof carrying the runtime and the bootstrap sources of one chunk', () => {
	const entry = { path: 'app/namespace.js', content: 'import * as pkg from "pkg-a";\nconsole.log(Object.keys(pkg).length, pkg.a());\n' };
	const { report } = build('collector', { library: false, entry: entry.path, module: entry });
	const asset = report.proof.assets.find((row) => row.path === 'lib.js');
	assert.ok(asset, `no lib.js row in ${report.proof.assets.map((row) => row.path).join(', ')}`);
	assert.equal(asset.status, 'present', asset.reason);
	assert.deepEqual(asset.includedComponents, ['node:app@0.1.0', 'node:pkg-a@1.2.3', 'node:pkg-b@4.5.6', 'node:webpack@5.94.0']);
	const inputs = asset.inputs.filter((input) => input.path.startsWith(distribution.root + path.sep)).map((input) => path.relative(distribution.root, input.path)).sort();
	assert.deepEqual(
		inputs,
		[
			'lib/javascript/JavascriptModulesPlugin.js',
			'lib/APIPlugin.js',
			...SHARED,
			'lib/runtime/HelperRuntimeModule.js',
			...CLASSES.map((name) => `lib/runtime/${name}.js`),
		].sort(),
	);
	for (const input of asset.inputs) assert.equal(input.sha256, sha256(input.path));
});

test('reports a byte mismatch when the chunk file is rewritten after it was emitted', () => {
	const { area, report } = build('late-emit', { library: false, entry: 'app/index.js' });
	const asset = report.proof.assets.find((row) => row.path === 'lib.js');
	assert.equal(asset.status, 'hash-mismatch', asset.reason);
	assert.deepEqual(asset.includedComponents, []);
	assert.match(fs.readFileSync(path.join(area.output, 'lib.js'), 'utf8'), /appended after the emit/);
	assert.equal(asset.sha256, sha256(path.join(area.output, 'lib.js')), 'the proof must carry the bytes that stayed on disk');
});

test('reports no data when another plugin taps the module content hook', () => {
	const { area, report } = build('foreign-content', { library: false, entry: 'app/index.js' });
	const asset = report.proof.assets.find((row) => row.path === 'lib.js');
	assert.equal(asset.status, 'no-data');
	assert.match(asset.reason, /Fixture tapped renderModuleContent/);
	assert.deepEqual(asset.includedComponents, []);
	assert.match(fs.readFileSync(path.join(area.output, 'lib.js'), 'utf8'), /fixture module content/, 'the foreign content must be what the asset really carries');
});
