'use strict';

// Builds a real worker through the Git-pinned workerize-loader and describes
// what it built, in a process where the recorders were installed before the
// loader was first required.
//
// The loader is not a dependency of this package: it is a Git dependency of the
// project under study, pinned to one commit. A test packs it from the verified
// clone DK_WORKERIZE_SOURCE names and installs it into a directory the test
// owns, so nothing of it is kept here.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const tar = require('tar');

// Set by prepare(), which every test of this fixture runs first.
let installed = null;

const MARKER = '#dk-worker-report#';
// The pins of this package, kept apart from the collector's own dependencies:
// package.json and package-lock.json name the one runtime dependency of the
// loader, and the loader itself is packed from a verified clone.
const FIXTURE_ROOT = path.join(__dirname, 'worker-fixtures');
// The commit redoc's package-lock pins, and the files of it this adapter reads.
const COMMIT = '6897b3fa5784c8f4970c81e04dbc8025f3c60938';
const LOCATOR = `git+https://git@github.com/redocly/workerize-loader.git#${COMMIT}`;
const SOURCE = process.env.DK_WORKERIZE_SOURCE;
const PINNED = {
	'dist/index.js': 'sha256:3f7172d462ef8ec9704c0c586cd6e454a44093fa73ac94a0a3cf110b932e46f1',
	'dist/rpc-wrapper.js': 'sha256:a2e669e15b433058ae3233080418e7eaefbf268f5b6be26ba52edbd9f69edfe3',
	'dist/rpc-worker-loader.js': 'sha256:ba393a4cec8272c020121b3fd3be32836fa1bbf01e67ee0e02c540269b2d19dc',
};

const WORKER_SOURCE = 'export function add(a, b) {\n\treturn a + b;\n}\n\nexport function mul(a, b) {\n\treturn a * b;\n}\n';
// Redoc's worker is TypeScript behind an esbuild-loader, so the entry loader
// appends to a text no file holds.
const TS_WORKER_SOURCE = 'export function add(a: number, b: number): number {\n\treturn a + b;\n}\n\nexport function mul(a: number, b: number): number {\n\treturn a * b;\n}\n';
const entrySource = (query, worker) => `import makeWorker from 'workerize-loader${query}!./${worker}';\n\nconst worker = makeWorker();\nexport default worker;\n`;

// The component of the Git-pinned distribution, exactly as a verified build
// context manifest states one.
const COMPONENT = Object.freeze({
	id: 'node:workerize-loader',
	name: 'workerize-loader',
	version: '1.3.0',
	source: Object.freeze({ kind: 'node', locator: LOCATOR, checksum: `git-commit:sha1:${COMMIT}` }),
});

function available() {
	if (SOURCE === undefined || SOURCE === '') return 'DK_WORKERIZE_SOURCE is not set to a verified clone of workerize-loader';
	return false;
}

// Installs the loader a test needs, in a directory the test owns.
//
// The distribution is packed from the clone DK_WORKERIZE_SOURCE names, which
// must stand at the pinned commit, and is unpacked here rather than installed
// as a dependency: it is a Git dependency of the project under study, not of
// this package, and npm would hold a repacked archive against an integrity
// recorded for another one. Its single runtime dependency comes from this
// package's own lockfile, with the integrity that lockfile pins.
function prepare(scratch) {
	const head = execFileSync('git', ['-C', SOURCE, 'rev-parse', 'HEAD'], { encoding: 'utf8', timeout: 60000 }).trim();
	assert.equal(head, COMMIT, `${SOURCE} is at ${head}, not the pinned ${COMMIT}`);

	const root = path.join(scratch, 'installed');
	fs.mkdirSync(root, { recursive: true });
	for (const file of ['package.json', 'package-lock.json']) fs.copyFileSync(path.join(FIXTURE_ROOT, file), path.join(root, file));
	execFileSync('npm', ['ci', '--ignore-scripts', '--omit=peer', '--no-audit', '--no-fund'], { cwd: root, encoding: 'utf8', timeout: 600000 });

	const packed = execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', scratch, SOURCE], { encoding: 'utf8', timeout: 600000 }).trim().split('\n').pop();
	const loaderRoot = path.join(root, 'node_modules', 'workerize-loader');
	fs.mkdirSync(loaderRoot, { recursive: true });
	tar.x({ cwd: loaderRoot, strip: 1, sync: true, file: path.join(scratch, packed) });

	// The loader loads webpack's own plugins from where it sits, and it must be
	// the webpack that runs the build rather than one of its own.
	fs.symlinkSync(path.join(__dirname, 'node_modules', 'webpack'), path.join(root, 'node_modules', 'webpack'));

	assert.equal(JSON.parse(fs.readFileSync(path.join(loaderRoot, 'package.json'), 'utf8')).version, '1.3.0');
	for (const [file, sha256] of Object.entries(PINNED)) {
		assert.equal(digest(fs.readFileSync(path.join(loaderRoot, file))), sha256, `${file} of the packed workerize-loader is not the pinned ${COMMIT}`);
	}
	installed = { loaderRoot, modulesRoot: path.join(root, 'node_modules') };
	return installed;
}

function area(scratch, id, options = {}) {
	const root = path.join(scratch, id);
	const src = path.join(root, 'src');
	fs.mkdirSync(src, { recursive: true });
	const worker = options.tail === 'esbuild' ? 'worker.ts' : 'worker.js';
	fs.writeFileSync(path.join(src, worker), options.workerSource || (options.tail === 'esbuild' ? TS_WORKER_SOURCE : WORKER_SOURCE));
	fs.writeFileSync(path.join(src, 'index.js'), options.entrySource || entrySource(options.query === undefined ? '?inline&fallback=false' : options.query, worker));
	return { root, src, out: path.join(root, 'out'), reportPath: path.join(root, 'report.json') };
}

// One compilation in its own process, with the recorders installed first.
function build(where, options = {}) {
	const runner = path.join(where.root, 'run.cjs');
	fs.writeFileSync(runner, RUNNER);
	const out = execFileSync(
		process.execPath,
		[...(options.preload === false ? [] : ['--require', path.join(__dirname, 'worker-preload.cjs')]), runner],
		{
			cwd: where.root,
			encoding: 'utf8',
			timeout: 180000,
			env: {
				...process.env,
				// The esbuild adapter refuses to describe a process that could run an
				// executable other than the verified one.
				...(options.tail === 'esbuild' && options.withoutTail !== true ? { ESBUILD_BINARY_PATH: path.join(process.env.DK_ESBUILD_SOURCE || '', 'esbuild') } : {}),
				DK_WORKER_ADAPTERS: __dirname,
				DK_WORKER_AREA: JSON.stringify({
					...where,
					loaderRoot: options.loaderRoot || loaderRoot(),
					webpackRoot: path.join(__dirname, 'node_modules', 'webpack'),
					component: COMPONENT,
					query: options.query === undefined ? '?inline&fallback=false' : options.query,
					tamper: options.tamper || null,
					tail: options.tail || null,
					minimize: options.minimize === true,
					banner: options.banner || null,
					esbuild: options.tail === 'esbuild' && options.withoutTail !== true ? esbuildTool() : null,
					tailRule: options.tail === 'esbuild',
					esbuildLoader: options.tail === 'esbuild' ? require.resolve('esbuild-loader') : null,
				}),
			},
		},
	);
	const line = out.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `the build printed no report:\n${out}`);
	return { report: JSON.parse(line.slice(MARKER.length)), out };
}

// The instrumented esbuild the tail runs, declared exactly as the esbuild
// adapter requires. Without DK_ESBUILD_SOURCE a tail build is skipped.
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

function digest(bytes) {
	return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

// Runs in the built process: compiles, then describes the two modules the
// loader built with the adapter under test.
const RUNNER = `'use strict';
const fs = require('node:fs');
const path = require('node:path');
const area = JSON.parse(process.env.DK_WORKER_AREA);
const adapters = process.env.DK_WORKER_ADAPTERS;
const webpack = require(path.join(adapters, 'node_modules', 'webpack'));
const { observeAssets } = require(path.join(adapters, 'bootstrap-evidence.cjs'));
const { installWorkerEvidence, isWorkerLoader, isWorkerEntryLoader } = require(path.join(adapters, 'worker-evidence.cjs'));
const { installEsbuildEvidence } = require(path.join(adapters, 'esbuild-evidence.cjs'));
const { runtimeEvidence } = require(path.join(adapters, 'runtime-evidence.cjs'));
const crypto = require('node:crypto');

const webpackApi = require(path.join(adapters, 'node_modules', 'webpack'));
const compiler = webpack({
	mode: 'production',
	devtool: false,
	context: area.src,
	entry: './index.js',
	output: { path: area.out, filename: 'main.js' },
	optimization: { minimize: area.minimize },
	plugins: area.banner ? [new webpackApi.BannerPlugin({ banner: area.banner, raw: false })] : [],
	module: area.tailRule ? { rules: [{ test: /\.ts$/, loader: area.esbuildLoader, options: { target: 'es2015', loader: 'ts' } }] } : { rules: [] },
	resolveLoader: { modules: [path.dirname(area.loaderRoot), 'node_modules'] },
});
observeAssets(compiler);

// Every file of this build is its own original: what is under test here is the
// recomputation, not the acquisition.
async function verifyResource(resource) {
	const actual = path.resolve(resource);
	let bytes;
	try { bytes = fs.readFileSync(actual); } catch (error) { return { units: [], failure: { status: 'no-data', reason: String(error.message) } }; }
	const component = actual.startsWith(area.loaderRoot + path.sep)
		? area.component
		: actual.startsWith(area.webpackRoot + path.sep)
			? { id: 'npm:webpack@5.94.0', name: 'webpack', version: '5.94.0', source: { kind: 'pm', locator: 'https://registry.npmjs.org/webpack/-/webpack-5.94.0.tgz', checksum: 'sha512-fixture' } }
			: { id: 'project', name: 'fixture', version: '0.0.0', source: { kind: 'declared', locator: 'fixture' } };
	return { unit: { path: actual, sha256: 'sha256:' + crypto.createHash('sha256').update(bytes).digest('hex'), bytes, component } };
}

const esbuildEvidence = area.esbuild ? installEsbuildEvidence(compiler, area.esbuild, verifyResource) : null;

// What the collector does for every module of every compilation, in the small:
// a module of the worker's own chunk is described, or the worker that embeds it
// is refused.
async function describeModule(module, compilation, chunk) {
	// A runtime module wrote its own text, and the chunk it wrote it for is what
	// binds it to the class that did.
	if (module.type === 'runtime') return runtimeEvidence(compilation, chunk, module, verifyResource);
	const loaders = Array.isArray(module.loaders) ? module.loaders : [];
	if (loaders.length > 0 && isWorkerEntryLoader(loaders[0].loader)) return describe(module, compilation, {});
	if (loaders.length === 0 && typeof module.resource === 'string') {
		const resolved = await verifyResource(module.resource);
		if (resolved.failure) return resolved;
		return { units: [{ path: resolved.unit.path, sha256: resolved.unit.sha256, component: resolved.unit.component }] };
	}
	return { units: [], failure: { status: 'no-data', reason: 'loader-transformed module: ' + module.identifier() } };
}

const { observedBytes } = require(path.join(adapters, 'bootstrap-evidence.cjs'));

// Separates the two comparisons of the wrapper: the recompute embeds the bytes
// this reader answers, so answering different ones makes the recomputed text
// differ from the one the loader really wrote, while the source webpack kept
// stays exactly what the loader returned.
const readObservedBytes = area.tamper === 'observed-worker'
	? (compilation, name) => { const bytes = observedBytes(compilation, name); return bytes ? Buffer.concat([bytes, Buffer.from('/* observed differently */')]) : bytes; }
	: undefined;

const describe = installWorkerEvidence(compiler, verifyResource, {
	describeModule,
	tailTransform: esbuildEvidence ? (module) => esbuildEvidence.transformed(module) : undefined,
	readObservedBytes,
});
let parent = null;
compiler.hooks.thisCompilation.tap('dk-worker-fixture', (compilation) => { if (!compilation.compiler.isChild()) parent = compilation; });

compiler.run(async (error, stats) => {
	const report = { assets: [], modules: [] };
	if (area.tamper === 'worker-source') fs.writeFileSync(path.join(area.src, 'worker.js'), 'export function add() { return 0; }' + String.fromCharCode(10));
	if (area.tamper === 'wrapper-source') {
		for (const module of parent.modules) {
			const loaders = Array.isArray(module.loaders) ? module.loaders : [];
			if (loaders.length > 0 && isWorkerLoader(loaders[0].loader)) {
				const kept = module.originalSource();
				module.originalSource = () => ({ source: () => kept.source() + '/* changed after the loader ran */' });
			}
		}
	}
	if (error || stats.hasErrors()) {
		report.error = String(error || stats.toJson({ all: false, errors: true }).errors.map(e => e.message).join('; '));
		print(report);
		return;
	}
	report.assets = [...parent.getAssets()].map((asset) => asset.name).sort();
	for (const module of parent.modules) {
		const loaders = Array.isArray(module.loaders) ? module.loaders : [];
		if (loaders.length > 0 && isWorkerLoader(loaders[0].loader)) report.modules.push(await row('wrapper', module, describe));
	}
	for (const child of parent.children) {
		for (const module of child.modules) {
			const loaders = Array.isArray(module.loaders) ? module.loaders : [];
			if (loaders.length > 0 && isWorkerEntryLoader(loaders[0].loader)) report.modules.push(await row('entry', module, describe, child));
		}
	}
	print(report);
});

async function row(kind, module, describe, compilation) {
	const described = await describe(module, compilation || parent, {});
	return {
		kind,
		identifier: module.identifier(),
		status: described.failure ? described.failure.status : 'present',
		reason: described.failure ? described.failure.reason : undefined,
		units: (described.units || []).map((unit) => ({ path: unit.path, sha256: unit.sha256, component: unit.component.id })),
	};
}

function print(report) { process.stdout.write('${MARKER}' + JSON.stringify(report) + '\\n'); }
`;

function loaderRoot() {
	assert.ok(installed, 'prepare() must run before a worker fixture is built');
	return installed.loaderRoot;
}

function modulesRoot() {
	assert.ok(installed, 'prepare() must run before a worker fixture is built');
	return installed.modulesRoot;
}

module.exports = { available, prepare, area, build, digest, loaderRoot, modulesRoot, MARKER, FIXTURE_ROOT, COMPONENT, COMMIT, LOCATOR, PINNED };
