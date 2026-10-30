'use strict';

// Test-only fixture for esbuild-evidence.test.cjs.
//
// The parent builds a workspace with fixture.cjs, adds the TypeScript sources
// of this test to the installed application and to its own original root, and
// hands the child the paths and hashes it needs; this file is also the child
// entry point, run as `node --require runtime-preload.cjs esbuild-fixture.cjs`
// so that the load registry is in place before the esbuild client and the
// loader are required.

const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { installEsbuildEvidence } = require('./esbuild-evidence.cjs');

const MARKER = 'DK-ESBUILD-REPORT ';
const MODULE = 'github.com/evanw/esbuild';
// The module sum of each pinned version, as the Go toolchain reports it for a
// verified download; a locally computed sum of an unverifiable cache entry is
// not it.
const MODULE_SUMS = {
	'v0.25.0': 'h1:jRR9D1pfdb669VzdN4w0jwsDfrKE098nKMaDMKvMPyU=',
	'v0.17.19': 'h1:JdzNCvfFEoUCXKHhdP326Vn2mhCu8PybXeBDHaSRyWo=',
};
// Type annotations only: nothing here needs a helper from the esbuild runtime.
const PLAIN = "export type Flag = 'on' | 'off';\nexport function label(value: Flag): string {\n\treturn value === 'on' ? 'ON' : 'OFF';\n}\n";
// A lowered class field and a lowered async method: the transform has to select
// runtime parts to print them for es2015.
const RUNTIME = 'export class Counter {\n\tvalue = 0;\n\tasync bump(): Promise<number> {\n\t\tthis.value += 1;\n\t\treturn this.value;\n\t}\n}\n';
const INDEX = "import { label } from './plain';\nimport { Counter } from './runtime';\nconsole.log(label('on'), new Counter());\n";
const SOURCES = { 'plain.ts': PLAIN, 'runtime.ts': RUNTIME, 'index.ts': INDEX };
// Whole-bundle subjects for the collector cases: one module of its own, so the
// bundle is the transformed source and the webpack sources that render it.
const COLLECTOR_SOURCES = {
	'only-plain.ts': 'const n: number = 1;\nconsole.log(n);\n',
	'only-runtime.ts': 'class A {\n\tx = 1;\n}\nconsole.log(new A().x);\n',
};

// The sources of this test, written into the installed application and into the
// original root the workspace already declares for it: an explicit test
// construction, not a production path that could rewrite an original.
function addSources(area) {
	for (const [name, content] of Object.entries({ ...SOURCES, ...COLLECTOR_SOURCES })) {
		fs.writeFileSync(path.join(area.modules, 'app', name), content);
		fs.writeFileSync(path.join(area.originalOf('app'), name), content);
	}
}

// The original of the esbuild runtime source is the published Go module of the
// pinned version, verified by the Go toolchain: its checksum is the real h1 sum
// of that module, never a digest this fixture made up. The module is only used
// once its runtime source is byte-identical to the pinned commit of the
// checkout the instrumented tool was built from.
function resolveRuntimeModule(root, source, commit, version = 'v0.25.0') {
	const MODULE_VERSION = version;
	const MODULE_SUM = MODULE_SUMS[version];
	if (!MODULE_SUM) throw new Error(`no pinned module sum for ${MODULE}@${version}`);
	const head = execFileSync('git', ['-C', source, 'rev-parse', 'HEAD'], { encoding: 'utf8', timeout: 30000 }).trim();
	if (head !== commit) throw new Error(`${source} is at ${head}, not the pinned ${commit}`);
	const resolved = JSON.parse(execFileSync('go', ['mod', 'download', '-json', `${MODULE}@${MODULE_VERSION}`], { cwd: root, encoding: 'utf8', timeout: 60000, maxBuffer: 1 << 26 }));
	if (resolved.Sum !== MODULE_SUM) throw new Error(`${MODULE}@${MODULE_VERSION} resolved to ${resolved.Sum}, not the pinned ${MODULE_SUM}`);
	if (typeof resolved.Dir !== 'string' || resolved.Dir === '') throw new Error(`${MODULE}@${MODULE_VERSION} was not extracted`);
	// The Go toolchain reports the origin of a download, not of a cache hit; the
	// identity of the file this test selects is the byte comparison below.
	const origin = resolved.Origin && typeof resolved.Origin.Hash === 'string' ? resolved.Origin.Hash : null;
	if (origin !== null && origin !== commit) throw new Error(`${MODULE}@${MODULE_VERSION} was built from ${origin}, not ${commit}`);
	const originalRoot = path.join(resolved.Dir, 'internal', 'runtime');
	const originalBytes = fs.readFileSync(path.join(originalRoot, 'runtime.go'));
	const pinned = execFileSync('git', ['-C', source, 'show', `${commit}:internal/runtime/runtime.go`], { encoding: 'buffer', timeout: 30000, maxBuffer: 1 << 28 });
	if (!originalBytes.equals(pinned)) throw new Error(`the runtime source of ${MODULE}@${MODULE_VERSION} is not the one of ${commit}`);
	const file = path.join(source, 'internal', 'runtime', 'runtime.go');
	if (!fs.readFileSync(file).equals(originalBytes)) throw new Error(`${file} is not the runtime source of ${MODULE}@${MODULE_VERSION}`);
	const module = { path: resolved.Path, version: resolved.Version, sum: resolved.Sum, dir: resolved.Dir, origin, checked: { pinnedCommitBytes: true, toolCheckoutBytes: true, originHash: origin !== null } };
	fs.writeFileSync(path.join(root, `esbuild-go-module-${MODULE_VERSION}.json`), `${JSON.stringify(module, null, 2)}\n`);
	// Everything above prepares a source whose bytes are established; the
	// component those bytes are bound to is the real package the Go helper packs
	// and reads back through the ordinary original reader.
	const out = path.join(root, `runtime-packet-${MODULE_VERSION}`);
	fs.mkdirSync(out, { recursive: true });
	const packet = JSON.parse(
		execFileSync('go', ['run', './pkg/sbom/webpack/testdata/runtime_packet.go', '--', path.join(originalRoot, 'runtime.go'), out], {
			cwd: path.resolve(__dirname, '..', '..', '..'),
			encoding: 'utf8',
			timeout: 90000,
			maxBuffer: 1 << 26,
		}),
	);
	if (packet.relativePath !== 'internal/runtime/runtime.go') throw new Error(`the packet holds ${packet.relativePath}`);
	if (!fs.readFileSync(path.join(packet.originalRoot, 'internal', 'runtime', 'runtime.go')).equals(originalBytes)) {
		throw new Error('the packed original is not the verified runtime source');
	}
	return {
		file,
		module,
		packet,
		sha256: digest(originalBytes),
		binding: { root: source, originalRoot: packet.originalRoot, component: packet.component },
	};
}

// A client of its own that runs the verified one and corrupts what it reports:
// its own bytes verify against the hash the caller declared for them.
function writeCorruptingClient(file, entry) {
	fs.writeFileSync(
		file,
		`'use strict';\nconst real = require(${JSON.stringify(entry)});\nconst transform = async (source, options) => {\n\tconst result = await real.transform(source, options);\n\tif (result.sbom) result.sbom.outputSHA256 = 'sha256:${'0'.repeat(64)}';\n\treturn result;\n};\nmodule.exports = { ...real, transform };\n`,
	);
	return digest(fs.readFileSync(file));
}

// The same binding the collector performs: the materialized file is bound to
// the component only when its bytes are the bytes of the original counterpart.
function verifier(setup) {
	return async (resource) => {
		const actual = path.resolve(resource);
		const binding = setup.originals.find((candidate) => actual.startsWith(candidate.root.endsWith(path.sep) ? candidate.root : candidate.root + path.sep));
		if (!binding) return { failure: { status: 'no-data', reason: `outside the declared roots: ${actual}` } };
		const bytes = read(actual);
		if (bytes.failure) return bytes;
		const originalBytes = read(path.join(binding.originalRoot, path.relative(binding.root, actual)));
		if (originalBytes.failure) return originalBytes;
		const sha256 = digest(bytes.bytes);
		if (sha256 !== digest(originalBytes.bytes)) {
			return { failure: { status: 'hash-mismatch', reason: `materialized source differs from its original: ${actual}` } };
		}
		return { unit: { path: actual, sha256, bytes: bytes.bytes, component: binding.component } };
	};
}

function read(file) {
	try {
		return { bytes: fs.readFileSync(file) };
	} catch (error) {
		return { failure: { status: 'no-data', reason: `missing file ${file}: ${error.code || error.message}` } };
	}
}

function digest(bytes) {
	return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

// The loader options of the one rule of this compiler, kept here so the child
// can report whether the adapter left the user's own object alone.
function ruleOptions(setup) {
	const options = { loader: 'ts', target: 'es2015', tsconfigRaw: {} };
	// A client of the user's own, never the one the collector is configured for:
	// loading that one here would be the process loading it before the adapter.
	if (setup.scenario === 'foreign') options.implementation = { transform: require(require.resolve('esbuild', { paths: [setup.modules, __dirname] })).transform };
	return options;
}

function rules(setup, options) {
	const use = [{ loader: setup.tool.loader, options }];
	if (setup.scenario === 'chain') use.push({ loader: setup.passThroughLoader });
	return [{ test: /\.ts$/, use }];
}

function scenarioPlugin(setup) {
	return {
		apply(compiler) {
			if (setup.scenario === 'tamper') {
				// The same number of bytes in the file and in its original, written
				// after the loader read the file: the verification against the original
				// still passes and the bytes esbuild saw are no longer on disk.
				compiler.hooks.afterCompile.tap('fixture', () => {
					for (const root of setup.appRoots) {
						const file = path.join(root, 'plain.ts');
						const text = fs.readFileSync(file, 'utf8');
						if (text.includes("'ON'")) fs.writeFileSync(file, text.replace("'ON'", "'oN'"));
					}
				});
			}
			if (setup.scenario === 'late-source') {
				compiler.hooks.compilation.tap('fixture', (compilation) => {
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: compiler.webpack.Compilation.PROCESS_ASSETS_STAGE_REPORT }, () => {
						for (const module of compilation.modules) {
							if (typeof module.resource !== 'string' || !module.resource.endsWith('plain.ts')) continue;
							// What another plugin rewriting a built module leaves behind.
							module._source = new compiler.webpack.sources.RawSource(`${module.originalSource().source()}\nconsole.log('late');\n`);
						}
					});
				});
			}
		},
	};
}

function evidencePlugin(setup, reports) {
	return {
		apply(compiler) {
			const evidenceFor = installEsbuildEvidence(compiler, setup.tool, verifier(setup));
			compiler.hooks.afterEmit.tapPromise('fixture', async (compilation) => {
				const rows = [];
				for (const module of compilation.modules) {
					if (typeof module.resource !== 'string') continue;
					rows.push(describe(await evidenceFor(module), module));
				}
				rows.sort((a, b) => (a.name < b.name ? -1 : 1));
				reports.push(rows);
			});
		},
	};
}

function describe(result, module) {
	return {
		name: path.basename(module.resource),
		resource: module.resource,
		status: result.failure ? result.failure.status : 'present',
		reason: result.failure ? result.failure.reason : undefined,
		units: result.units.map((unit) => ({ path: unit.path, sha256: unit.sha256, component: unit.component.id })),
	};
}

function configuration(setup, options, plugins) {
	return {
		mode: 'production',
		context: setup.context,
		entry: setup.entry,
		output: { path: setup.output, filename: 'main.js', iife: false },
		target: 'node',
		resolve: { modules: [setup.modules], extensions: ['.ts', '.js'] },
		// Every described module stays a module of its own, with the source its
		// loader produced.
		optimization: { minimize: false, concatenateModules: false },
		module: { rules: rules(setup, options) },
		plugins,
	};
}

function run(compiler) {
	return new Promise((resolve, reject) => {
		compiler.run((error, stats) => {
			if (error) return reject(error);
			if (stats.hasErrors()) return reject(new Error(stats.toString({ all: false, errors: true })));
			resolve(stats);
		});
	});
}

async function main() {
	const setup = JSON.parse(process.env.DK_ESBUILD_SETUP);
	if (setup.scenario === 'preloaded-client') {
		// The client fixes the executable it will run when it is loaded, so one
		// loaded earlier - here for another executable - can carry no verified
		// claim however well its own bytes hash.
		const configured = process.env.ESBUILD_BINARY_PATH;
		process.env.ESBUILD_BINARY_PATH = setup.otherBinary;
		require(setup.tool.entry);
		process.env.ESBUILD_BINARY_PATH = configured;
	}
	const webpack = require(setup.webpackRoot);
	const options = ruleOptions(setup);
	const foreign = options.implementation;
	const reports = [];
	// The collector cases prove the production call site: the collector itself
	// installs the adapter from its own option and writes the proof.
	const collecting = typeof setup.proofPath === 'string';
	const plugins = collecting
		? [new (require('./collector.cjs'))({ proofPath: setup.proofPath, originals: setup.originals, esbuild: setup.tool })]
		: [scenarioPlugin(setup), evidencePlugin(setup, reports)];
	const compiler = webpack(configuration(setup, options, plugins));
	await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	for (const client of new Set([setup.tool.entry, require.resolve('esbuild', { paths: [setup.modules, __dirname] })])) {
		try {
			await require(client).stop();
		} catch {
			// Nothing was started by a client this scenario never loaded.
		}
	}
	process.stdout.write(
		`${MARKER}${JSON.stringify({
			loader: require(path.join(path.dirname(path.dirname(setup.tool.loader)), 'package.json')).version,
			userOptions: { keys: Object.keys(options).sort(), foreignIntact: foreign === undefined ? undefined : options.implementation === foreign },
			rows: reports[0] || [],
			proof: collecting ? JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')) : undefined,
		})}\n`,
	);
}

module.exports = { MARKER, SOURCES, COLLECTOR_SOURCES, addSources, resolveRuntimeModule, writeCorruptingClient, digest, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
