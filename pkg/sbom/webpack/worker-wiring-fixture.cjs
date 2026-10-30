'use strict';

// Test-only fixture for worker-wiring.test.cjs: the same worker builds as
// worker-fixture.cjs, collected whole rather than described module by module.
//
// What is under test here is the collector's dispatch - that a module pitched
// by workerize-loader reaches the worker adapter with the evidence of its own
// compilation, that the worker's modules are claimed through the wrapper, and
// that the child compilation a `fallback=false` worker is built in is not
// walked a second time.
//
// The loader is installed by worker-fixture.cjs, which this file borrows: it is
// a Git dependency of the project under study, packed from the verified clone
// DK_WORKERIZE_SOURCE names.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const { available, prepare, area, digest, loaderRoot, COMPONENT } = require('./worker-fixture.cjs');

const MARKER = '#dk-worker-wiring-report#';

// One collected compilation in its own process, with the recorders installed
// before the loader is first required.
function build(where, options = {}) {
	const runner = path.join(where.root, 'collect.cjs');
	fs.writeFileSync(runner, RUNNER);
	const out = execFileSync(process.execPath, ['--require', path.join(__dirname, 'runtime-preload.cjs'), '--require', path.join(__dirname, 'worker-preload.cjs'), runner], {
		cwd: where.root,
		encoding: 'utf8',
		timeout: 180000,
		env: {
			...process.env,
			// The esbuild adapter refuses to describe a process that could run an
			// executable other than the verified one.
			...(options.tail === 'esbuild' ? { ESBUILD_BINARY_PATH: path.join(process.env.DK_ESBUILD_SOURCE || '', 'esbuild') } : {}),
			DK_WORKER_ADAPTERS: __dirname,
			DK_WORKER_AREA: JSON.stringify({
				...where,
				loaderRoot: loaderRoot(),
				webpackRoot: path.join(__dirname, 'node_modules', 'webpack'),
				component: COMPONENT,
				query: options.query === undefined ? '?inline&fallback=false' : options.query,
				tail: options.tail || null,
				minimize: options.minimize === true,
				childDefine: options.childDefine === true,
				esbuild: options.tail === 'esbuild' ? esbuildTool() : null,
				tailRule: options.tail === 'esbuild',
				esbuildLoader: options.tail === 'esbuild' ? require.resolve('esbuild-loader') : null,
			}),
		},
	});
	const line = out.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `the build printed no report:\n${out}`);
	return { report: JSON.parse(line.slice(MARKER.length)), out };
}

function esbuildTool() {
	const source = process.env.DK_ESBUILD_SOURCE;
	assert.ok(source, 'DK_ESBUILD_SOURCE must name the instrumented esbuild for a tail build');
	const entry = path.join(source, 'npm', 'esbuild', 'lib', 'main.js');
	const binary = path.join(source, 'esbuild');
	return {
		versions: { esbuild: '0.25.0', esbuildLoader: '4.3.0' },
		entry,
		binary,
		loader: require.resolve('esbuild-loader'),
		entrySHA256: digest(fs.readFileSync(entry)),
		binarySHA256: digest(fs.readFileSync(binary)),
		runtimeSource: path.join(source, 'internal', 'runtime', 'runtime.go'),
	};
}

// Runs in the built process: one real build with the collector attached, and
// the proof it wrote.
const RUNNER = `'use strict';
const fs = require('node:fs');
const path = require('node:path');
const area = JSON.parse(process.env.DK_WORKER_AREA);
const adapters = process.env.DK_WORKER_ADAPTERS;
const webpack = require(path.join(adapters, 'node_modules', 'webpack'));
const Collector = require(path.join(adapters, 'collector.cjs'));

const crypto = require('node:crypto');

const proofPath = path.join(area.root, 'proof.json');
// Every file of this build is its own original: what is under test here is the
// dispatch, not the acquisition. Each file is answered with the component of
// the tree it stands in, the way a verified build context states one.
const modules = path.join(adapters, 'node_modules');
const COMPONENTS = [
	[area.loaderRoot, area.component],
	// The minifier and its library, which a minified build goes through.
	[path.join(modules, 'terser-webpack-plugin'), { id: 'npm:terser-webpack-plugin', name: 'terser-webpack-plugin', version: '5.3.10', source: { kind: 'pm', locator: 'https://registry.npmjs.org/terser-webpack-plugin', checksum: 'sha512-fixture' } }],
	[path.join(modules, 'terser'), { id: 'npm:terser', name: 'terser', version: '5.31.6', source: { kind: 'pm', locator: 'https://registry.npmjs.org/terser', checksum: 'sha512-fixture' } }],
	[area.webpackRoot, { id: 'npm:webpack@5.94.0', name: 'webpack', version: '5.94.0', source: { kind: 'pm', locator: 'https://registry.npmjs.org/webpack/-/webpack-5.94.0.tgz', checksum: 'sha512-fixture' } }],
	[area.src, { id: 'project', name: 'fixture', version: '0.0.0', source: { kind: 'declared', locator: 'fixture' } }],
];
if (area.esbuild) {
	COMPONENTS.unshift([path.dirname(path.dirname(area.esbuildLoader)), { id: 'npm:esbuild-loader', name: 'esbuild-loader', version: '4.3.0', source: { kind: 'pm', locator: 'https://registry.npmjs.org/esbuild-loader', checksum: 'sha512-fixture' } }]);
}

function resolveOriginal(resource) {
	const found = COMPONENTS.find(([root]) => resource === root || resource.startsWith(root + path.sep));
	if (!found) return undefined;
	const bytes = fs.readFileSync(resource);
	return { path: resource, sha256: 'sha256:' + crypto.createHash('sha256').update(bytes).digest('hex'), component: found[1] };
}

const compiler = webpack({
	mode: 'production',
	devtool: false,
	context: area.src,
	entry: './index.js',
	output: { path: area.out, filename: 'main.js' },
	optimization: { minimize: area.minimize, concatenateModules: false },
	module: area.tailRule ? { rules: [{ test: /\\.ts$/, loader: area.esbuildLoader, options: { target: 'es2015', loader: 'ts' } }] } : { rules: [] },
	resolveLoader: { modules: [path.dirname(area.loaderRoot), 'node_modules'] },
	plugins: [
		new Collector({ proofPath, originals: [], copied: [], resolveOriginal, esbuild: area.esbuild || undefined }),
		// A definer the worker's own compiler is given after it was made: what it
		// splices into the worker's modules is code, and the parent never saw it.
		...(area.childDefine ? [{
			apply(compiler) {
				compiler.hooks.compilation.tap('dk-worker-wiring', (compilation) => {
					compilation.hooks.childCompiler.tap('dk-worker-wiring', (child) => {
						new webpack.DefinePlugin({ __WORKER_CONSTANT__: 'globalThis.stolen = document.cookie' }).apply(child);
					});
				});
			},
		}] : []),
	],
});

// Which compilations the collector walked for the assets of this build, and
// which modules each of them holds: a worker built with no fallback is an
// asset of nobody, and its modules must be claimed through the wrapper alone.
const children = [];
compiler.hooks.compilation.tap('dk-worker-wiring', (compilation) => {
	if (!compilation.compiler.isChild()) return;
	compilation.hooks.afterProcessAssets.tap('dk-worker-wiring', () => {
		children.push({
			name: compilation.compiler.name || null,
			assets: [...compilation.getAssets()].map((asset) => asset.name).sort(),
			modules: [...compilation.modules].map((module) => path.basename(String(module.resource || module.identifier()))).sort(),
		});
	});
});

compiler.run((error, stats) => {
	const report = { children };
	if (error || stats.hasErrors()) {
		report.error = String(error || stats.toJson({ all: false, errors: true }).errors.map(e => e.message).join('; '));
	} else {
		report.assets = [...stats.compilation.getAssets()].map((asset) => asset.name).sort();
		report.proof = JSON.parse(fs.readFileSync(proofPath, 'utf8'));
		report.bundle = fs.readFileSync(path.join(area.out, 'main.js'), 'utf8');
	}
	process.stdout.write('${MARKER}' + JSON.stringify(report) + String.fromCharCode(10));
	compiler.close(() => {});
});
`;

module.exports = { available, prepare, area, build, MARKER };
