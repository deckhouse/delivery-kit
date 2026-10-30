'use strict';

// Test-only fixture for stylesheet-evidence.test.cjs.
//
// The parent builds a workspace with fixture.cjs, adds the stylesheets and
// entry points of this test to the installed application and to its own
// original root, and hands the child the paths it needs; this file is also the
// child entry point, run as `node --require stylesheet-preload.cjs
// stylesheet-fixture.cjs` so that both recorders are in place before webpack
// requires either loader.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { installStylesheetEvidence } = require('./stylesheet-evidence.cjs');

const MARKER = 'DK-STYLESHEET-REPORT ';
const SOURCES = {
	'a.css': '.app { color: red; }\n',
	'b.css': '.other { color: blue; }\n',
	'one.js': "import './a.css';\nconsole.log('one');\n",
	'two.js': "import './a.css';\nimport './b.css';\nconsole.log('two');\n",
	// The whole-bundle subjects of the collector cases, required the way the
	// application under test requires its own stylesheet.
	'required.js': "require('./a.css');\nconsole.log('required');\n",
};

function addSources(area) {
	for (const [name, content] of Object.entries(SOURCES)) {
		fs.writeFileSync(path.join(area.modules, 'app', name), content);
		fs.writeFileSync(path.join(area.originalOf('app'), name), content);
	}
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
		const original = read(path.join(binding.originalRoot, path.relative(binding.root, actual)));
		if (original.failure) return original;
		const sha256 = digest(bytes.bytes);
		if (sha256 !== digest(original.bytes)) {
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
	if (setup.scenario === 'insert') return { insert: () => document.head };
	if (setup.scenario === 'shared-options') return {};
	return undefined;
}

function rules(setup, options) {
	if (setup.scenario === 'raw-only') return [{ test: /\.css$/, use: [{ loader: setup.rawLoader }] }];
	const use = [options === undefined ? { loader: setup.styleLoader } : { loader: setup.styleLoader, options }];
	if (setup.scenario === 'chain') use.push({ loader: setup.passThroughLoader });
	use.push({ loader: setup.rawLoader });
	return [{ test: /\.css$/, use }];
}

function scenarioPlugin(setup) {
	return {
		apply(compiler) {
			if (setup.scenario === 'repitch') {
				// What a plugin that wraps the published pitch for itself leaves
				// behind: the recorded call is honest, the module is not its output.
				const api = require(setup.styleLoader);
				const previous = api.pitch;
				api.pitch = function (...args) {
					return `${previous.apply(this, args)}\n// added by another plugin\n`;
				};
			}
			if (setup.scenario === 'tamper') {
				// The same number of bytes in the file and in its original, written
				// after the loader read the file: the verification against the original
				// still passes and the bytes raw-loader saw are no longer on disk.
				compiler.hooks.afterCompile.tap('fixture', () => {
					for (const root of setup.appRoots) {
						const file = path.join(root, 'a.css');
						const text = fs.readFileSync(file, 'utf8');
						if (text.includes('red')) fs.writeFileSync(file, text.replace('red', 'r3d'));
					}
				});
			}
			if (setup.scenario === 'late-parent' || setup.scenario === 'late-child') {
				const loaderCount = setup.scenario === 'late-parent' ? 2 : 1;
				compiler.hooks.compilation.tap('fixture', (compilation) => {
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: compiler.webpack.Compilation.PROCESS_ASSETS_STAGE_REPORT }, () => {
						for (const module of compilation.modules) {
							if (typeof module.resource !== 'string' || !module.resource.endsWith('a.css') || module.loaders.length !== loaderCount) continue;
							// What another plugin rewriting a built module leaves behind.
							module._source = new compiler.webpack.sources.RawSource(`${module.originalSource().source()}\n// late\n`);
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
			const evidenceFor = installStylesheetEvidence(compiler, verifier(setup));
			compiler.hooks.afterEmit.tapPromise('fixture', async (compilation) => {
				const rows = [];
				for (const module of compilation.modules) {
					if (typeof module.resource !== 'string') continue;
					rows.push(describe(await evidenceFor(module), module));
				}
				rows.sort((a, b) => (a.name === b.name ? a.loaders.length - b.loaders.length : a.name < b.name ? -1 : 1));
				reports.push(rows);
			});
		},
	};
}

function describe(result, module) {
	const source = module.originalSource && module.originalSource();
	return {
		name: path.basename(module.resource),
		resource: module.resource,
		loaders: module.loaders.map((item) => item.loader),
		source: source ? source.source().toString() : undefined,
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
		output: { path: setup.output, filename: 'main.js' },
		target: 'web',
		resolve: { modules: [setup.modules] },
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
	const setup = JSON.parse(process.env.DK_STYLESHEET_SETUP);
	const webpack = require(setup.webpackRoot);
	const options = ruleOptions(setup);
	const reports = [];
	// The collector cases prove the production call site: the collector itself
	// dispatches to the adapter and writes the proof.
	const collecting = typeof setup.proofPath === 'string';
	const plugins = collecting
		? [new (require('./collector.cjs'))({ proofPath: setup.proofPath, originals: setup.originals })]
		: [scenarioPlugin(setup), evidencePlugin(setup, reports)];
	const configured = configuration(setup, options, plugins);
	const compiler = webpack(configured);
	await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	const configuredRule = configured.module.rules[0].use;
	process.stdout.write(
		`${MARKER}${JSON.stringify({
			styleLoader: require(path.join(path.dirname(path.dirname(setup.styleLoader)), 'package.json')).version,
			rawLoader: require(path.join(path.dirname(setup.rawLoader), 'package.json')).version,
			userOptions:
				options === undefined
					? undefined
					: { shared: configuredRule.every((item) => item.options === undefined || item.options === options), keys: Object.keys(options).sort() },
			rows: reports[0] || [],
			proof: collecting ? JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')) : undefined,
		})}\n`,
	);
}

module.exports = { MARKER, SOURCES, addSources, digest, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
