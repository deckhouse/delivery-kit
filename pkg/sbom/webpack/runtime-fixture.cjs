'use strict';

// Test-only fixture for runtime.test.cjs.
//
// The parent packs the installed webpack once and hands each child the paths it
// needs; this file is also the child entry point, run as
// `node --require runtime-preload.cjs runtime-fixture.cjs` so that the load
// registry is in place before webpack is required here.

const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { runtimeEvidence } = require('./runtime-evidence.cjs');

const MARKER = 'DK-RUNTIME-REPORT ';
// The scenarios that run the production collector and leave a proof behind.
const COLLECTED = ['collector', 'rewritten-asset', 'late-emit', 'foreign-content'];

// The original root is extracted from the archive npm produced out of the
// installed distribution, never copied from it, and is bound to the integrity
// npm reported and this code recomputed from the archive bytes.
function packWebpack(root, installed) {
	const tarballs = path.join(root, 'tarballs');
	fs.mkdirSync(tarballs, { recursive: true });
	const report = JSON.parse(
		execFileSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', tarballs, installed], {
			encoding: 'utf8',
			env: { ...process.env, NPM_CONFIG_UPDATE_NOTIFIER: 'false', NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_FUND: 'false', GIT_TERMINAL_PROMPT: '0' },
		}),
	)[0];
	const tarball = path.join(tarballs, report.filename);
	const integrity = `sha512-${crypto.createHash('sha512').update(fs.readFileSync(tarball)).digest('base64')}`;
	if (integrity !== report.integrity) throw new Error('npm reported a different integrity for webpack');
	const original = path.join(root, 'original');
	fs.mkdirSync(original, { recursive: true });
	execFileSync('tar', ['-xzf', tarball, '-C', original, '--strip-components=1']);
	const version = JSON.parse(fs.readFileSync(path.join(original, 'package.json'), 'utf8')).version;
	return {
		root: fs.realpathSync(installed),
		original,
		tarball,
		integrity,
		component: {
			id: `node:webpack@${version}`,
			name: 'webpack',
			version,
			source: { kind: 'node', locator: `file://${tarball}`, checksum: integrity },
		},
	};
}

// The same binding the collector performs: the materialized file is bound to
// the component only when its bytes are the bytes of the original counterpart.
function verifier(setup) {
	return async (resource) => {
		const actual = path.resolve(resource);
		const prefix = setup.root.endsWith(path.sep) ? setup.root : setup.root + path.sep;
		if (!actual.startsWith(prefix)) return { failure: { status: 'no-data', reason: `outside the webpack root: ${actual}` } };
		const original = path.join(setup.originalRoot, path.relative(setup.root, actual));
		const bytes = read(actual);
		if (bytes.failure) return bytes;
		const originalBytes = read(original);
		if (originalBytes.failure) return originalBytes;
		const sha256 = digest(bytes.bytes);
		if (sha256 !== digest(originalBytes.bytes)) {
			return { failure: { status: 'hash-mismatch', reason: `materialized source differs from its original: ${actual}` } };
		}
		return { unit: { path: actual, sha256, bytes: bytes.bytes, component: setup.component } };
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

function configuration(setup) {
	return {
		mode: 'production',
		context: setup.context,
		entry: setup.entry,
		output: { path: setup.output, filename: 'lib.js', iife: false, ...(setup.library === false ? {} : { library: { type: 'commonjs2' } }) },
		externals: { 'some-ext': 'commonjs some-ext' },
		target: 'node',
		optimization: { minimize: false, concatenateModules: true, usedExports: true },
		resolve: { modules: [setup.modules] },
	};
}

// Each scenario is what some plugin of this compilation could do; the report
// then says what the adapter makes of the result.
function scenarioPlugin(webpack, setup, reports, verify) {
	const scenario = setup.scenario;
	return {
		apply(compiler) {
			if (scenario === 'unknown-class') {
				// A runtime module class of a plugin: a real commonjs module of its own,
				// recorded by the preload like any other, but not a webpack one.
				const file = path.join(setup.context, 'fixture-runtime-module.cjs');
				fs.writeFileSync(
					file,
					`'use strict';\nconst { RuntimeModule } = require(${JSON.stringify(setup.root)});\nmodule.exports = class FixtureRuntimeModule extends RuntimeModule {\n\tconstructor() { super('fixture marker'); }\n\tgenerate() { return '/* fixture runtime module */'; }\n};\n`,
				);
				const FixtureRuntimeModule = require(file);
				compiler.hooks.compilation.tap('fixture', (compilation) => {
					compilation.hooks.additionalTreeRuntimeRequirements.tap('fixture', (chunk) => {
						compilation.addRuntimeModule(chunk, new FixtureRuntimeModule());
					});
				});
			}
			if (scenario === 'instance-generate' || scenario === 'prototype-generate') {
				compiler.hooks.compilation.tap('fixture', (compilation) => {
					compilation.hooks.runtimeModule.tap('fixture', (module) => {
						if (module.constructor.name !== 'HasOwnPropertyRuntimeModule') return;
						const replacement = () => '/* replaced generator */\n';
						if (scenario === 'instance-generate') module.generate = replacement;
						else Object.getPrototypeOf(module).generate = replacement;
					});
				});
			}
			if (scenario === 'helper-replaced') {
				const original = webpack.Template.indent;
				webpack.Template.indent = (value) => original(value);
			}
			if (scenario === 'prefilled-cache' || scenario === 'swapped-generator' || scenario === 'swapped-helper') {
				compiler.hooks.compilation.tap('fixture', (compilation) => {
					const restore = [];
					compilation.hooks.runtimeModule.tap('fixture', (module) => {
						if (module.constructor.name !== 'HasOwnPropertyRuntimeModule') return;
						if (scenario === 'prefilled-cache') {
							module._cachedGeneratedCode = '/* plugin source, never generated */\n';
							return;
						}
						// Swapped for the duration of the generation and put back before
						// anything could read it again.
						const target = scenario === 'swapped-generator' ? Object.getPrototypeOf(module) : webpack.Template;
						const key = scenario === 'swapped-generator' ? 'generate' : 'indent';
						if (restore.some((entry) => entry.target === target)) return;
						const original = target[key];
						restore.push({ target, key, original });
						target[key] =
							scenario === 'swapped-generator'
								? function () {
										return '/* plugin source, never generated */\n';
								  }
								: (value) => `${original(value)}\n/* injected by a plugin */`;
					});
					compilation.hooks.beforeChunkAssets.tap('fixture', () => {
						for (const entry of restore) entry.target[entry.key] = entry.original;
					});
				});
			}
			if (scenario === 'one-shot-helper') {
				// Swaps itself in, forges the text and restores the original from inside
				// the very first call, so every later reading is honest.
				compiler.hooks.compilation.tap('fixture', () => {
					const original = webpack.Template.indent;
					if (webpack.Template.indent !== original) return;
					webpack.Template.indent = (value) => {
						webpack.Template.indent = original;
						return `${original(value)}\n/* one-shot injection */`;
					};
				});
			}
			if (scenario === 'foreign-content') {
				compiler.hooks.compilation.tap('Fixture', (compilation) => {
					const hooks = webpack.javascript.JavascriptModulesPlugin.getCompilationHooks(compilation);
					hooks.renderModuleContent.tap('Fixture', (source) => new webpack.sources.ConcatSource(source, '/* fixture module content */\n'));
				});
			}
			if (scenario === 'late-emit') {
				// Registered after the collector, and writing to disk after the bytes
				// were observed on their way out.
				compiler.hooks.assetEmitted.tap('fixture', (file, info) => {
					fs.appendFileSync(info.targetPath, '/* appended after the emit */\n');
				});
			}
			if (scenario === 'rewritten-asset') {
				compiler.hooks.compilation.tap('fixture', (compilation) => {
					compilation.hooks.processAssets.tap({ name: 'fixture', stage: compilation.constructor.PROCESS_ASSETS_STAGE_OPTIMIZE_SIZE }, (assets) => {
						for (const [name, source] of Object.entries(assets)) {
							compilation.updateAsset(name, new webpack.sources.RawSource(`${source.source()}/* rewritten after rendering */\n`));
						}
					});
				});
			}
			if (scenario === 'changed-after-load') {
				// Both copies change the same way, so the verifier still binds the file
				// to its original; only the bytes this process loaded are now stale.
				for (const root of [setup.root, setup.originalRoot]) {
					fs.appendFileSync(path.join(root, 'lib', 'Template.js'), '\n// appended after loading\n');
				}
			}
			if (scenario === 'replaced-source') {
				compiler.hooks.compilation.tap('fixture', (compilation) => {
					// Runtime modules are code generated after the hash is created, so this
					// is the first point where the result a chunk will be rendered from
					// exists and can still be swapped.
					compilation.hooks.beforeChunkAssets.tap('fixture', () => {
						for (const chunk of compilation.chunks) {
							for (const module of compilation.chunkGraph.getChunkRuntimeModulesIterable(chunk)) {
								const sources = compilation.codeGenerationResults.get(module, chunk.runtime).sources;
								const source = sources.get('runtime');
								const RawSource = Object.getPrototypeOf(source).constructor;
								sources.set('runtime', new RawSource(`${source.source()}/* replaced after hashing */\n`));
							}
						}
					});
				});
			}
			compiler.hooks.afterEmit.tapPromise('fixture', async (compilation) => {
				reports.push(await describe(compilation, verify));
			});
		},
	};
}

async function describe(compilation, verify) {
	const chunks = [];
	for (const chunk of compilation.chunks) {
		const modules = [];
		for (const module of compilation.chunkGraph.getChunkRuntimeModulesIterable(chunk)) {
			const result = await runtimeEvidence(compilation, chunk, module, verify);
			modules.push({
				identifier: module.identifier(),
				class: Object.getPrototypeOf(module).constructor.name,
				status: result.failure ? result.failure.status : 'present',
				reason: result.failure ? result.failure.reason : undefined,
				units: result.units.map((unit) => ({ path: unit.path, sha256: unit.sha256, component: unit.component })),
			});
		}
		modules.sort((a, b) => (a.identifier < b.identifier ? -1 : 1));
		chunks.push({ name: chunk.name, files: [...chunk.files].sort(), modules });
	}
	return chunks;
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
	const setup = JSON.parse(process.env.DK_RUNTIME_SETUP);
	const webpack = require(setup.root);
	const reports = [];
	const plugins = [scenarioPlugin(webpack, setup, reports, verifier(setup))];
	// The production collector itself, bound to the same originals the parent
	// verified, so the proof it writes is what the assertions read.
	if (COLLECTED.includes(setup.scenario)) {
		const DkSbomWebpackCollector = require('./collector.cjs');
		plugins.unshift(new DkSbomWebpackCollector({ proofPath: setup.proofPath, originals: setup.originals }));
	}
	const compiler = webpack({ ...configuration(setup), plugins });
	await run(compiler);
	if (setup.scenario === 'warm') await run(compiler);
	await new Promise((resolve, reject) => compiler.close((error) => (error ? reject(error) : resolve())));
	const proof = fs.existsSync(setup.proofPath) ? JSON.parse(fs.readFileSync(setup.proofPath, 'utf8')) : undefined;
	process.stdout.write(`${MARKER}${JSON.stringify({ webpack: webpack.version, builds: reports, proof })}\n`);
}

module.exports = { MARKER, packWebpack, child: __filename };

if (require.main === module) {
	main().catch((error) => {
		console.error(error && error.stack ? error.stack : String(error));
		process.exitCode = 1;
	});
}
