'use strict';

// Shared fixture for the collector tests and for the retained evidence build:
// synthetic node distributions are packed into real npm tarballs once, extracted
// into read-only original roots and installed into a per-build workspace.
//
// Run directly with DK_WEBPACK_EVIDENCE=<absolute directory> to perform one
// positive build and keep everything it consumed and produced in that directory.

// The bootstrap evidence describes the webpack sources this process loaded, so
// the load registry has to be in place before webpack is required below; a test
// file installs it itself, ahead of its own first webpack require.
if (require.main === module) require('./runtime-preload.cjs');

const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const DkSbomWebpackCollector = require('./collector.cjs');
const webpack = require('webpack');
const CopyPlugin = require('copy-webpack-plugin');

const PACKAGES = {
	'pkg-a': {
		version: '1.2.3',
		files: {
			'index.js': 'import { b } from "pkg-b";\nexport function a() { return "a:" + b(); }\n',
			'NOTICE.txt': 'Copyright holder of pkg-a.\n',
			LICENSE: 'Apache License 2.0 placeholder.\n',
		},
	},
	'pkg-b': { version: '4.5.6', files: { 'index.js': 'export function b() { return "b"; }\n' } },
	'pkg-c': {
		version: '7.8.9',
		files: {
			'index.js': 'export function c() { return "c"; }\n',
			'vendor.js': 'module.exports = { vendored: true };\n',
			LICENSE: 'Apache License 2.0 placeholder.\n',
		},
	},
	app: {
		version: '0.1.0',
		files: {
			'index.js': 'import { a } from "pkg-a";\nimport { x } from "some-ext";\nconsole.log(a(), x);\n',
			'lib.js': 'import { a } from "pkg-a";\nexport const value = a();\n',
			'styled.js': 'import "./style.css";\nimport { a } from "pkg-a";\nconsole.log(a());\n',
			'style.css': '.app { color: red; }\n',
		},
	},
};

function createFixture(root, options = {}) {
	fs.mkdirSync(root, { recursive: true });
	const resolved = fs.realpathSync(root);
	const distributions = packDistributions(path.join(resolved, 'distributions'));
	// The build tools this process is running are instruments, not packages of
	// this workspace: they are bound where they are installed and never land in
	// any node_modules of a fixture workspace.
	const tools = options.bootstrap
		? { bootstrap: bootstrapOriginal(path.join(resolved, 'webpack')), copy: bootstrapOriginal(path.join(resolved, 'copy-webpack-plugin'), 'copy-webpack-plugin') }
		: {};
	return {
		root: resolved,
		distributions,
		bootstrap: tools.bootstrap,
		copy: tools.copy,
		workspace: (name, workspaceOptions) => workspace(resolved, distributions, name, workspaceOptions, tools),
		buildPrimary: (name, overrides) => buildPrimary(resolved, distributions, name, overrides, tools),
	};
}

// The bootstrap of a rendered chunk belongs to the webpack this process is
// running, and an observed copy to the copy plugin it loaded, so the binding is
// the installed distribution itself: packed into a real npm archive, bound to
// the integrity npm reported and this code recomputed from the archive bytes,
// and verified against an original extracted from that archive rather than
// copied from the install.
function bootstrapOriginal(root, packageName = 'webpack') {
	const installed = fs.realpathSync(path.dirname(require.resolve(`${packageName}/package.json`)));
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
	if (integrity !== report.integrity) throw new Error(`npm reported a different integrity for ${packageName}`);
	const original = path.join(root, 'original');
	fs.mkdirSync(original, { recursive: true });
	execFileSync('tar', ['-xzf', tarball, '-C', original, '--strip-components=1']);
	const version = JSON.parse(fs.readFileSync(path.join(original, 'package.json'), 'utf8')).version;
	return {
		tarball,
		integrity,
		binding: {
			root: installed,
			originalRoot: original,
			component: {
				id: `node:${packageName}@${version}`,
				name: packageName,
				version,
				// The archive this fixture produced, not a registry one: nothing here
				// claims the identity of a published distribution.
				source: { kind: 'node', locator: `file://${tarball}`, checksum: integrity },
			},
		},
	};
}

// Each synthetic package becomes a real npm tarball whose integrity is the one
// npm reported and this code re-computed from the archive bytes; the read-only
// original root is extracted from that archive, never copied from the sources.
function packDistributions(root) {
	const tarballs = path.join(root, 'tarballs');
	const originals = path.join(root, 'originals');
	fs.mkdirSync(tarballs, { recursive: true });
	const packed = {};
	for (const [name, spec] of Object.entries(PACKAGES)) {
		const source = path.join(root, 'sources', name);
		fs.mkdirSync(source, { recursive: true });
		fs.writeFileSync(path.join(source, 'package.json'), `${JSON.stringify({ name, version: spec.version, main: 'index.js' }, null, 2)}\n`);
		for (const [file, content] of Object.entries(spec.files)) fs.writeFileSync(path.join(source, file), content);
		const report = JSON.parse(
			execFileSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', tarballs, source], {
				encoding: 'utf8',
				env: { ...process.env, NPM_CONFIG_UPDATE_NOTIFIER: 'false', NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_FUND: 'false', GIT_TERMINAL_PROMPT: '0' },
			}),
		)[0];
		const tarball = path.join(tarballs, report.filename);
		const integrity = `sha512-${crypto.createHash('sha512').update(fs.readFileSync(tarball)).digest('base64')}`;
		if (integrity !== report.integrity) throw new Error(`npm reported a different integrity for ${name}`);
		const original = path.join(originals, name);
		fs.mkdirSync(original, { recursive: true });
		execFileSync('tar', ['-xzf', tarball, '-C', original, '--strip-components=1']);
		packed[name] = {
			tarball,
			integrity,
			original,
			component: {
				id: `node:${name}@${spec.version}`,
				name,
				version: spec.version,
				source: { kind: 'node', locator: `file://${tarball}`, checksum: integrity },
			},
		};
	}
	return packed;
}

function workspace(scratch, distributions, name, options, tools = {}) {
	const root = path.join(scratch, name);
	const modules = path.join(root, 'node_modules');
	fs.mkdirSync(modules, { recursive: true });
	const originals = [];
	for (const [packageName, distribution] of Object.entries(distributions)) {
		const installed = path.join(modules, packageName);
		fs.cpSync(distribution.original, installed, { recursive: true });
		let original = distribution.original;
		// The shared original roots are read-only for every build; a test that has
		// to mutate one gets its own copy.
		if (options && options.isolateOriginals) {
			original = path.join(root, 'originals', packageName);
			fs.cpSync(distribution.original, original, { recursive: true });
		}
		originals.push({ root: installed, originalRoot: original, component: distribution.component });
	}
	// Never materialized into this workspace: a tool binding has to be the
	// distribution the compilation itself is running.
	for (const tool of [tools.bootstrap, tools.copy]) {
		if (tool) originals.push(tool.binding);
	}
	return {
		root,
		modules,
		originals,
		output: path.join(root, 'out'),
		proofPath: path.join(root, 'private', 'webpack-sources.json'),
		installed: (relative) => path.join(modules, relative),
		originalOf: (relative) => path.join(root, 'originals', relative),
	};
}

function configuration(area, overrides) {
	return {
		mode: 'production',
		context: area.root,
		entry: area.installed('app/index.js'),
		output: { path: area.output, filename: 'main.js', iife: false },
		externals: { 'some-ext': 'commonjs some-ext' },
		target: 'node',
		optimization: { minimize: false, concatenateModules: true, usedExports: true },
		resolve: { modules: [area.modules] },
		...overrides,
	};
}

function run(config) {
	return new Promise((resolve, reject) => {
		webpack(config).run((error, stats) => {
			if (error) return reject(error);
			if (stats.hasErrors()) return reject(new Error(stats.toString({ all: false, errors: true })));
			resolve(stats);
		});
	});
}

async function buildPrimary(scratch, distributions, name, overrides, tools) {
	const area = workspace(scratch, distributions, name, undefined, tools);
	const plugins = [
		new CopyPlugin({
			patterns: [
				{ from: area.installed('pkg-a/NOTICE.txt'), to: 'notice.txt' },
				{ from: area.installed('pkg-c/vendor.js'), to: 'vendor.js' },
				// Copied without being declared: the observed copy is the binding.
				{ from: area.installed('pkg-a/LICENSE'), to: 'undeclared.txt' },
			],
		}),
		new DkSbomWebpackCollector({
			proofPath: area.proofPath,
			originals: area.originals,
			copied: [
				{ from: area.installed('pkg-a/NOTICE.txt'), to: 'notice.txt' },
				{ from: area.installed('pkg-c/vendor.js'), to: 'vendor.js' },
			],
			...(overrides && overrides.prebuilt ? { prebuilt: overrides.prebuilt(area) } : {}),
		}),
	];
	if (overrides && overrides.plugins) plugins.push(...overrides.plugins);
	if (overrides && overrides.beforeRun) overrides.beforeRun(area);
	await run(configuration(area, { plugins }));
	return { area, proof: readProof(area) };
}

function toolManifest(tool) {
	return {
		name: tool.binding.component.name,
		version: tool.binding.component.version,
		tarball: tool.tarball,
		integrity: tool.integrity,
		tarballSHA256: sha256(tool.tarball),
		originalRoot: tool.binding.originalRoot,
		installedRoot: tool.binding.root,
	};
}

function readProof(area) {
	return JSON.parse(fs.readFileSync(area.proofPath, 'utf8'));
}

function sha256(file) {
	return `sha256:${crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')}`;
}

// One positive build whose inputs and outputs stay on disk for the Go embed
// consumer: the retained output root is the one the proof names, so the bytes
// can be staged and imported without rewriting any path.
async function exportEvidence(target) {
	if (!target || !path.isAbsolute(target)) throw new Error('DK_WEBPACK_EVIDENCE must be an absolute directory path');
	fs.mkdirSync(target, { recursive: true });
	const root = fs.realpathSync(target);
	if (fs.readdirSync(root).length > 0) throw new Error(`${root} is not empty`);
	const fixture = createFixture(path.join(root, 'fixture'), { bootstrap: true });
	const { area, proof } = await fixture.buildPrimary('workspace');

	const rows = Object.fromEntries(proof.assets.map((row) => [row.path, row]));
	for (const name of ['main.js', 'notice.txt']) {
		if (!rows[name] || rows[name].status !== 'present') {
			throw new Error(`${name} must be present, got ${rows[name] ? rows[name].status : 'no row'}`);
		}
	}
	if (proof.sourceRoot !== fs.realpathSync(area.output)) {
		throw new Error(`proof sourceRoot ${proof.sourceRoot} is not the retained output root`);
	}
	for (const row of proof.assets) {
		const emitted = path.join(proof.sourceRoot, row.path);
		if (sha256(emitted) !== row.sha256 || fs.statSync(emitted).size !== row.size) {
			throw new Error(`retained ${row.path} no longer matches the proof`);
		}
	}

	const manifest = {
		version: 1,
		webpack: require('webpack/package.json').version,
		copyWebpackPlugin: require('copy-webpack-plugin/package.json').version,
		sourceRoot: proof.sourceRoot,
		proofPath: area.proofPath,
		proofSHA256: sha256(area.proofPath),
		assets: proof.assets.map((row) => ({ path: row.path, sha256: row.sha256, size: row.size, status: row.status })),
		inputs: proof.assets.flatMap((row) => row.inputs.map((input) => ({ path: input.path, sha256: input.sha256 }))),
		distributions: Object.entries(fixture.distributions).map(([name, distribution]) => ({
			name,
			version: distribution.component.version,
			tarball: distribution.tarball,
			integrity: distribution.integrity,
			tarballSHA256: sha256(distribution.tarball),
			originalRoot: distribution.original,
			installedRoot: path.join(area.modules, name),
		})),
		bootstrapDistribution: toolManifest(fixture.bootstrap),
		copyDistribution: toolManifest(fixture.copy),
	};
	const manifestPath = path.join(root, 'manifest.json');
	fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

	const location = {
		version: 1,
		evidenceRoot: root,
		sourceRoot: proof.sourceRoot,
		proofPath: area.proofPath,
		proofSHA256: manifest.proofSHA256,
		manifestPath,
		manifestSHA256: sha256(manifestPath),
		assets: manifest.assets,
	};
	const checks = path.resolve(__dirname, '..', '..', '..', '..', 'ui-collector-checks');
	if (fs.existsSync(checks)) {
		fs.writeFileSync(path.join(checks, 'webpack-fixture-location.json'), `${JSON.stringify(location, null, 2)}\n`);
	}
	return location;
}

module.exports = { PACKAGES, createFixture, bootstrapOriginal, configuration, run, readProof, sha256, exportEvidence };

if (require.main === module) {
	exportEvidence(process.env.DK_WEBPACK_EVIDENCE).then(
		(location) => console.log(`${location.evidenceRoot}\n${location.sourceRoot}\n${location.proofPath}`),
		(error) => {
			console.error(error.message);
			process.exitCode = 1;
		},
	);
}
