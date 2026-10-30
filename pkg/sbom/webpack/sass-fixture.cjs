'use strict';

// Test-only fixture for sass-evidence.test.cjs.
//
// The parent builds a workspace with fixture.cjs, adds the stylesheets and
// entry points of this test to the installed application and to its own
// original root, and hands the child the paths it needs; this file is also the
// child entry point, run as `node --require stylesheet-preload.cjs
// sass-fixture.cjs` so that both recorders are in place before webpack requires
// any loader.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { installStylesheetEvidence } = require('./stylesheet-evidence.cjs');
const { installSassEvidence } = require('./sass-evidence.cjs');

const MARKER = 'DK-SASS-REPORT ';
const BOM = '\ufeff';
const SOURCES = {
	'main.scss': "@import './colors';\n\n.app {\n  color: $app-color;\n}\n",
	'_colors.scss': '$app-color: #ff0000;\n',
	'other.scss': "@import './other-colors';\n\n.other {\n  color: $other-color;\n}\n",
	'_other-colors.scss': '$other-color: #0000ff;\n',
	// Never imported by any entry point of this fixture: nothing may claim it.
	'unused.scss': '.unused {\n  color: #00ff00;\n}\n',
	'bom.scss': `${BOM}.bom {\n  color: #000000;\n}\n`,
	'styled.js': "require('./main.scss');\nconsole.log('styled');\n",
	'two-sheets.js': "require('./main.scss');\nrequire('./other.scss');\nconsole.log('two');\n",
	'bom-entry.js': "require('./bom.scss');\nconsole.log('bom');\n",
};
// The one partial of main.scss, rewritten to the same length once it has been
// read: the file and its original still agree, and the bytes sass consumed are
// no longer on disk.
const MUTATION = ['#ff0000', '#ff0001'];

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

// The sass-loader options of the one rule of this compiler, kept here so the
// child can report whether the adapter left the user's own object alone.
function ruleOptions(setup) {
	if (setup.scenario === 'additional-data') return { additionalData: '$pad: 0;\n' };
	if (setup.scenario === 'custom-importer') return { sassOptions: { importer: () => null } };
	if (setup.scenario === 'custom-implementation') return { implementation: require(setup.sassEntry) };
	return undefined;
}

function rules(setup, options) {
	const sass = options === undefined ? { loader: setup.sassLoader } : { loader: setup.sassLoader, options };
	const use = setup.scenario === 'raw-only' ? [{ loader: setup.rawLoader }, sass] : [{ loader: setup.styleLoader }, { loader: setup.rawLoader }, sass];
	return [{ test: /\.scss$/, use }];
}

function scenarioPlugin(setup) {
	return {
		apply(compiler) {
			if (setup.scenario === 'mutate') {
				compiler.hooks.afterCompile.tap('fixture', () => {
					for (const root of setup.appRoots) {
						const file = path.join(root, '_colors.scss');
						const text = fs.readFileSync(file, 'utf8');
						if (text.includes(MUTATION[0])) fs.writeFileSync(file, text.replace(MUTATION[0], MUTATION[1]));
					}
				});
			}
			if (setup.scenario === 'replaced') {
				// Another plugin that puts its own reader in front of the one the
				// adapter installed, once that one is in place: every read of the
				// render runs through code this process never saw.
				let replaced = false;
				compiler.hooks.compilation.tap('fixture', (compilation) => {
					compiler.webpack.NormalModule.getCompilationHooks(compilation).beforeLoaders.tap('fixture', (chain) => {
						if (replaced || chain.length !== 2) return;
						replaced = true;
						const current = fs.readFileSync;
						fs.readFileSync = function (...args) {
							return current.apply(this, args);
						};
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

// The sass adapter driven directly, so that the binding between the css one
// render returned and the text the next loader was handed is exercised for
// what it is: the same module described twice, once with the css raw-loader
// really got and once with a single byte of it changed.
function directPlugin(setup, reports) {
	return {
		apply(compiler) {
			const evidenceFor = installSassEvidence(compiler, verifier(setup));
			compiler.hooks.afterEmit.tapPromise('fixture', async (compilation) => {
				const rows = [];
				for (const module of compilation.modules) {
					if (typeof module.resource !== 'string' || !Array.isArray(module.loaders) || module.loaders.length !== 2) continue;
					const css = rawInput(module);
					rows.push({ ...describe(await evidenceFor(module, css), module), label: 'returned' });
					rows.push({ ...describe(await evidenceFor(module, `${css} `), module), label: 'changed' });
				}
				reports.push(rows);
			});
		},
	};
}

// What raw-loader was given, read back off the module it produced.
function rawInput(module) {
	const source = module.originalSource().source().toString();
	const prefix = 'module.exports = ';
	return JSON.parse(source.slice(prefix.length));
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
	const setup = JSON.parse(process.env.DK_SASS_SETUP);
	const webpack = require(setup.webpackRoot);
	const options = ruleOptions(setup);
	const reports = [];
	// The collector cases prove the production call site: the collector itself
	// dispatches to the adapter and writes the proof.
	const collecting = typeof setup.proofPath === 'string';
	const plugins = collecting
		? [new (require('./collector.cjs'))({ proofPath: setup.proofPath, originals: setup.originals })]
		: [setup.scenario === 'direct' ? directPlugin(setup, reports) : evidencePlugin(setup, reports), scenarioPlugin(setup)];
	const configured = configuration(setup, options, plugins);
	const compiler = webpack(configured);
	await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	const configuredRule = configured.module.rules[0].use;
	process.stdout.write(
		`${MARKER}${JSON.stringify({
			sassLoader: require(path.join(path.dirname(path.dirname(setup.sassLoader)), 'package.json')).version,
			sass: require(setup.sassEntry).info.split('\t')[1],
			userOptions: options === undefined ? undefined : { shared: configuredRule[configuredRule.length - 1].options === options, keys: Object.keys(options).sort() },
			rows: reports[0] || [],
			proof: collecting ? JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')) : undefined,
		})}\n`,
	);
}

module.exports = { MARKER, SOURCES, MUTATION, addSources, digest, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
