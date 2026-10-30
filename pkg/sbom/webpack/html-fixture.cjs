'use strict';

// Test-only fixture for html-evidence.test.cjs.
//
// The parent builds a workspace with fixture.cjs and hands the child the paths
// and the scenario; this file is also the child entry point, run as
// `node --require runtime-preload.cjs html-fixture.cjs` so that the load
// recorder is in place before webpack and the html plugin are required.
//
// The adapter is driven directly: it describes one asset at a time, and this
// slice does not yet wire it into the collector.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { installHtmlEvidence } = require('./html-evidence.cjs');

const MARKER = 'DK-HTML-REPORT ';
const TEMPLATE = 'index.html';
// Argo's own template, fetched from the pinned delivery tag.
const ARGO_TEMPLATE = path.join(__dirname, 'testdata', 'argo-index.html');
// Whitespace, a comment and a redundant attribute, so that the minified html of
// a production build is visibly not the template text.
const SOURCES = {
	[TEMPLATE]: `<!DOCTYPE html>
<html>
  <head>
    <title><%= htmlWebpackPlugin.options.title %></title>
    <!-- the comment a production build removes -->
  </head>
  <body>
    <div id="app" class="app"></div>
  </body>
</html>
`,
};
const CHANGED_TEMPLATE = `<!DOCTYPE html>
<html>
  <head>
    <title>changed after it was read</title>
  </head>
  <body></body>
</html>
`;
// A loader of the project in front of the plugin's own, writing html nothing
// of this compilation ever read.
const FOREIGN_LOADER = 'module.exports = () => \'module.exports = function () { return "<html><body>from another loader</body></html>"; };\';\n';
// The three distributions the forked plugin copy has to reach from its own
// location; everything behind them is resolved from their real one.
const FORK_DEPENDENCIES = ['lodash', 'html-minifier-terser', 'tapable'];

function addSources(area, options = {}) {
	const template = options.argo ? fs.readFileSync(ARGO_TEMPLATE, 'utf8') : SOURCES[TEMPLATE];
	fs.writeFileSync(path.join(area.modules, 'app', TEMPLATE), template);
	fs.writeFileSync(path.join(area.originalOf('app'), TEMPLATE), template);
}

function templatePaths(setup) {
	return [path.join(setup.modules, 'app', TEMPLATE), path.join(setup.context, 'originals', 'app', TEMPLATE)];
}

// The same binding the collector performs: a materialized file is bound to its
// component only when its bytes are the bytes of its original counterpart.
function verifier(setup) {
	return async (resource) => {
		const actual = path.resolve(resource);
		// One instrument file, refused the way an unverifiable source is refused.
		if (setup.scenario === 'unverified' && actual.endsWith(path.join('lib', 'html-tags.js'))) {
			return { failure: { status: 'no-data', reason: `outside the declared roots: ${actual}` } };
		}
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

// A copy of the plugin with one changed instrument file, installed where its
// own dependencies are still the pinned ones, plus the verified original tree
// that copy would have: its bytes verify, and they are not the pinned source.
function forkPlugin(setup) {
	const roots = [path.join(setup.context, 'forked'), path.join(setup.context, 'forked-original')].map((root) => {
		const installed = path.join(root, 'node_modules', 'html-webpack-plugin');
		fs.cpSync(setup.pluginRoot, installed, { recursive: true });
		const tags = path.join(installed, 'lib', 'html-tags.js');
		fs.writeFileSync(tags, `${fs.readFileSync(tags, 'utf8')}\n// a fork keeping the version of the plugin it was made from\n`);
		for (const name of FORK_DEPENDENCIES) {
			fs.symlinkSync(setup.dependencyRoots[name], path.join(root, 'node_modules', name));
		}
		return installed;
	});
	setup.originals.push({
		root: roots[0],
		originalRoot: roots[1],
		component: { id: 'node:html-webpack-plugin@5.6.0', name: 'html-webpack-plugin', version: '5.6.0', source: { kind: 'node', locator: `file://${roots[0]}`, checksum: 'sha512-forked' } },
	});
	return roots[0];
}

// Another plugin reaching into the html: a tap on one of the public hooks, or
// the template bytes replaced after the loader read them.
function scenarioPlugin(setup, HtmlWebpackPlugin) {
	return {
		apply(compiler) {
			if (setup.scenario === 'child-render' || setup.scenario === 'child-assets') {
				// Webpack copies this tap into the child compiler of the template, so
				// this plugin reaches the compilation that renders the template bundle.
				compiler.hooks.compilation.tap('fixture', (compilation) => {
					if (!compilation.compiler.parentCompilation) return;
					if (setup.scenario === 'child-render') {
						compiler.webpack.javascript.JavascriptModulesPlugin.getCompilationHooks(compilation).render.tap('fixture', (source) => source);
						return;
					}
					const stage = compiler.webpack.Compilation.PROCESS_ASSETS_STAGE_ADDITIONS - 2;
					compilation.hooks.processAssets.tap({ name: 'fixture', stage }, (assets) => {
						for (const name of Object.keys(assets)) {
							compilation.updateAsset(name, new compiler.webpack.sources.RawSource(`${assets[name].source()}/* injected into the template bundle */`));
						}
					});
				});
			}
			if (setup.scenario === 'tap-before-emit' || setup.scenario === 'tap-alter-tags' || setup.scenario === 'intercepted') {
				compiler.hooks.compilation.tap('fixture', (compilation) => {
					if (compilation.compiler.parentCompilation) return;
					const hooks = HtmlWebpackPlugin.getHooks(compilation);
					if (setup.scenario === 'tap-before-emit') {
						hooks.beforeEmit.tap('fixture', (args) => ({ ...args, html: `${args.html}<!-- tapped -->` }));
					} else if (setup.scenario === 'intercepted') {
						// No tap of its own: every later tap is registered through this.
						hooks.beforeEmit.intercept({ register: (tap) => tap });
					} else {
						hooks.alterAssetTags.tap('fixture', (args) => args);
					}
				});
			}
			if (setup.scenario === 'rewritten') {
				// After the plugin emitted its html and before the evidence is taken.
				compiler.hooks.compilation.tap('fixture', (compilation) => {
					if (compilation.compiler.parentCompilation) return;
					const stage = compiler.webpack.Compilation.PROCESS_ASSETS_STAGE_OPTIMIZE_INLINE + 0.5;
					compilation.hooks.processAssets.tap({ name: 'fixture', stage }, (assets) => {
						compilation.updateAsset('index.html', new compiler.webpack.sources.RawSource(`${assets['index.html'].source()}<!-- rewritten -->`));
					});
				});
			}
			if (setup.scenario === 'retemplate') {
				// After the template was read and compiled, and before the evidence is
				// taken: both the installed file and its original are rewritten.
				compiler.hooks.emit.tap('fixture', () => {
					for (const file of templatePaths(setup)) fs.writeFileSync(file, CHANGED_TEMPLATE);
				});
			}
		},
	};
}

function evidencePlugin(setup, reports) {
	return {
		apply(compiler) {
			const evidenceFor = installHtmlEvidence(compiler, verifier(setup));
			compiler.hooks.afterEmit.tapPromise('fixture', async (compilation) => {
				const rows = [];
				for (const asset of compilation.getAssets()) {
					const result = await evidenceFor(compilation, asset.name);
					rows.push({
						name: asset.name,
						status: result.failure ? result.failure.status : result.status === 'none' ? 'none' : 'present',
						reason: result.failure ? result.failure.reason : undefined,
						units: result.units ? result.units.map((unit) => ({ path: unit.path, component: unit.component.id })) : undefined,
						requiredBytes: result.requiredBytes ? digest(result.requiredBytes) : undefined,
					});
				}
				rows.sort((a, b) => (a.name < b.name ? -1 : 1));
				reports.push(rows);
			});
		},
	};
}

function pluginOptions(setup) {
	const template = path.join(setup.modules, 'app', TEMPLATE);
	if (setup.scenario === 'custom-minify') return { template, minify: { collapseWhitespace: true } };
	if (setup.scenario === 'parameters') return { template, templateParameters: { extra: 'value' } };
	if (setup.scenario === 'no-inject') return { template, inject: false };
	return { template };
}

// The plugin object of the configuration: the instance itself, one carrying a
// tag generator of its own, or one that merely inherits from an instance.
function pluginInstance(setup, HtmlWebpackPlugin) {
	const plugin = new HtmlWebpackPlugin(pluginOptions(setup));
	if (setup.scenario === 'shadowed') {
		plugin.generatedScriptTags = (assets) => assets.map((src) => ({ tagName: 'script', voidTag: false, meta: {}, attributes: { src, defer: true, integrity: 'from an own tag generator' } }));
	}
	return setup.scenario === 'borrowed' ? Object.create(plugin) : plugin;
}

function foreignLoader(setup) {
	const file = path.join(setup.context, 'foreign-loader.cjs');
	fs.writeFileSync(file, FOREIGN_LOADER);
	return { module: { rules: [{ test: /\.html$/, use: [file] }] } };
}

// The shape Argo builds with: content-hashed chunk names the html refers to,
// the default minimizer, and the whole collector writing its proof.
function argoConfiguration(setup, HtmlWebpackPlugin, webpack) {
	const DkSbomWebpackCollector = require('./collector.cjs');
	return {
		mode: 'production',
		context: setup.context,
		entry: setup.entry,
		output: { path: setup.output, filename: '[name].[contenthash].js', chunkFilename: '[name].[contenthash].chunk.js', iife: false },
		externals: { 'some-ext': 'commonjs some-ext' },
		target: 'node',
		resolve: { modules: [setup.modules] },
		optimization: { minimize: true, concatenateModules: true, usedExports: true, realContentHash: true },
		cache: false,
		plugins: [
			// Argo defines its environment the same way; the plugin reaches the child
			// compilation of the template too, but taps nothing that writes it.
			new webpack.DefinePlugin({ 'process.env.NODE_ENV': JSON.stringify('production') }),
			new HtmlWebpackPlugin(pluginOptions(setup)),
			new DkSbomWebpackCollector({ proofPath: setup.proofPath, originals: setup.originals }),
		],
	};
}

function configuration(setup, HtmlWebpackPlugin, reports, webpack) {
	if (typeof setup.proofPath === 'string') return argoConfiguration(setup, HtmlWebpackPlugin, webpack);
	return {
		mode: setup.mode || 'production',
		context: setup.context,
		entry: setup.entry,
		output: { path: setup.output, filename: 'main.js', iife: false },
		externals: { 'some-ext': 'commonjs some-ext' },
		target: 'node',
		resolve: { modules: [setup.modules] },
		optimization: { minimize: false, concatenateModules: true, usedExports: true },
		cache: false,
		...(setup.scenario === 'extra-loader' ? foreignLoader(setup) : {}),
		plugins: [pluginInstance(setup, HtmlWebpackPlugin), scenarioPlugin(setup, HtmlWebpackPlugin), evidencePlugin(setup, reports)],
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
	const setup = JSON.parse(process.env.DK_HTML_SETUP);
	const webpack = require(setup.webpackRoot);
	const HtmlWebpackPlugin = require(setup.scenario === 'forked' ? forkPlugin(setup) : setup.pluginRoot);
	const reports = [];
	const compiler = webpack(configuration(setup, HtmlWebpackPlugin, reports, webpack));
	await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	const emitted = {};
	for (const name of fs.readdirSync(setup.output).sort()) emitted[name] = digest(fs.readFileSync(path.join(setup.output, name)));
	process.stdout.write(
		`${MARKER}${JSON.stringify({
			webpack: webpack.version,
			plugin: require(path.join(setup.pluginRoot, 'package.json')).version,
			emitted,
			html: fs.readFileSync(path.join(setup.output, 'index.html'), 'utf8'),
			rows: reports[0] || [],
			proof: typeof setup.proofPath === 'string' ? JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')) : undefined,
		})}\n`
	);
}

module.exports = { MARKER, TEMPLATE, SOURCES, CHANGED_TEMPLATE, FORK_DEPENDENCIES, addSources, digest, child: __filename };
if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
