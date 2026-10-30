'use strict';

// Fixture for the activation tests: one Yarn-installed workspace with a real
// lockfile and cache, a verified primary-source manifest beside a build context
// file, and a generated CommonJS configuration that records what the pinned
// Webpack CLI really loaded. Builds run the actual `webpack-cli` binary in a
// child process whose NODE_OPTIONS carries the activation preload, as the image
// recipe appends it.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const CLI = require.resolve('webpack-cli/bin/cli.js');
const ACTIVATE = path.join(__dirname, 'activate.cjs');
const HEAP_LIMIT_MB = 512;
const DEADLINE_MS = 60000;
const ENTRY = 'import {a} from "pkg-a";\nconsole.log(a());\n';
// A dependency a Yarn 1 lockfile pins to a Git commit: no integrity, and a cache
// that records the commit rather than bytes anybody checked.
const GIT_COMMIT = 'a1c32a45e83fdda4baafc7ca3105c3ead383f8ba';
const GIT_PACKAGE = 'git-dep';
const GIT_LOCATOR = `git+https://github.com/example/${GIT_PACKAGE}.git#${GIT_COMMIT}`;
const GIT_BODY = 'export const ui = 7;\n';
const GIT_COMPONENT = {
	id: 'node:git-dep',
	name: GIT_PACKAGE,
	version: '1.0.0',
	source: { kind: 'node', locator: GIT_LOCATOR, checksum: `git-commit:sha1:${GIT_COMMIT}` },
};
const PRIMARY = {
	id: 'pm:app-source@1.0.0',
	name: 'app-source',
	version: '1.0.0',
	source: { kind: 'pm', locator: 'app-source', checksum: 'sha256:0000000000000000000000000000000000000000000000000000000000000000' },
};

// `workspace` installs the synthetic distributions; everything the activation
// reads from the environment is laid out around that workspace.
function createArea(fixture, name, options = {}) {
	const workspace = fixture.workspace(name);
	const area = {
		...workspace,
		tmp: path.join(path.dirname(workspace.root), `${name}-tmp`),
		cacheDir: path.join(path.dirname(workspace.root), `${name}-cache`),
		lockPath: path.join(workspace.root, options.manager === 'npm' ? 'package-lock.json' : 'yarn.lock'),
		resolverModule: options.manager === 'npm' ? 'npm-originals.cjs' : 'yarn-originals.cjs',
		entry: path.join(workspace.root, 'src', 'main.js'),
		contextPath: path.join(workspace.root, 'context', 'build-context.json'),
		manifestPath: path.join(workspace.root, 'context', 'webpack-originals.json'),
		configPath: path.join(workspace.root, 'webpack.config.js'),
		unmatchedConfigPath: path.join(workspace.root, 'unmatched.config.js'),
		probePath: path.join(workspace.root, 'probe.json'),
	};
	fs.mkdirSync(area.tmp, { recursive: true });
	fs.mkdirSync(path.dirname(area.entry), { recursive: true });
	area.git = options.git ? installGitPackage(area) : undefined;
	area.esbuild = options.esbuild ? declaredEsbuild(area, options.esbuild) : undefined;
	let entry = area.git ? `${ENTRY}import {ui} from ${JSON.stringify(GIT_PACKAGE)};\nconsole.log(ui);\n` : ENTRY;
	if (area.esbuild) {
		fs.writeFileSync(area.esbuild.source, 'export const typed: number = 7;\n');
		entry = `${entry}import {typed} from "./typed.ts";\nconsole.log(typed);\n`;
	}
	fs.writeFileSync(area.entry, entry);
	if (options.manager === 'npm') writeNpm(fixture, area);
	else writeYarn(fixture, area);
	fs.mkdirSync(path.dirname(area.contextPath), { recursive: true });
	fs.writeFileSync(area.contextPath, `${JSON.stringify({ version: 1 }, null, 2)}\n`);
	writeManifest(area, options.git === 'listed');
	fs.writeFileSync(area.configPath, config(area, options.shape));
	fs.writeFileSync(area.unmatchedConfigPath, config(area, undefined));
	return area;
}

// The instrumented esbuild of one supported pair, as a stage would hold it: the
// patched client and executable of a real checkout, the published loader of the
// pair, and the runtime source that esbuild's own output is built from.
function declaredEsbuild(area, pair) {
	const source = process.env[pair === '0.17.19' ? 'DK_ESBUILD_0_17_SOURCE' : 'DK_ESBUILD_SOURCE'];
	assert.ok(source, 'an instrumented esbuild checkout must be named for a declared tool');
	const loader = require.resolve(pair === '0.17.19' ? 'esbuild-loader-3.0.1' : 'esbuild-loader');

	return {
		versions: { esbuild: pair, esbuildLoader: pair === '0.17.19' ? '3.0.1' : '4.3.0' },
		entry: path.join(source, 'npm', 'esbuild', 'lib', 'main.js'),
		binary: path.join(source, 'esbuild'),
		loader,
		runtimeSource: path.join(source, 'internal', 'runtime', 'runtime.go'),
		source: path.join(path.dirname(area.entry), 'typed.ts'),
	};
}

// The verified expected hashes DK writes beside the read-only build context
// after validating the scoped PM originals.
function writeManifest(area, withGit) {
	const manifest = {
		version: 1,
		components: [PRIMARY],
		files: [{ path: area.entry, sha256: `sha256:${crypto.createHash('sha256').update(fs.readFileSync(area.entry)).digest('hex')}`, component: PRIMARY.id }],
	};
	// What DK verified from the Git commit itself: the installed files whose
	// bytes are the commit's own, under the component that names that commit.
	if (withGit) {
		manifest.components.push(GIT_COMPONENT);
		manifest.files.push({ path: area.git.source, sha256: `sha256:${crypto.createHash('sha256').update(GIT_BODY).digest('hex')}`, component: GIT_COMPONENT.id });
		manifest.lifecycle = [{ component: GIT_COMPONENT.id, hooks: ['prepare'] }];
	}
	// The files of the instrumented esbuild this build made itself: the context
	// is where their digests come from, never the environment that names them.
	if (area.esbuild) {
		const digest = (file) => `sha256:${crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')}`;
		manifest.files.push({ path: area.esbuild.source, sha256: digest(area.esbuild.source), component: PRIMARY.id });
		for (const key of area.esbuildUnlisted === true ? [] : ['entry', 'binary']) {
			manifest.files.push({ path: area.esbuild[key], sha256: digest(area.esbuild[key]), component: PRIMARY.id });
		}
	}
	fs.writeFileSync(area.manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

// The install of the Git-locked package, as Yarn leaves it in the workspace.
function installGitPackage(area) {
	const root = path.join(area.modules, GIT_PACKAGE);
	fs.mkdirSync(root, { recursive: true });
	fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: GIT_PACKAGE, version: GIT_COMPONENT.version, main: 'index.js', type: 'module' }));
	fs.writeFileSync(path.join(root, 'index.js'), GIT_BODY);
	return { root, source: path.join(root, 'index.js') };
}

function writeYarn(fixture, area) {
	const entries = [];
	for (const [name, distribution] of Object.entries(fixture.distributions)) {
		const version = distribution.component.version;
		const resolved = `https://registry.example.test/${name}/download`;
		entries.push(`${JSON.stringify(`${name}@${version}`)}:\n  version ${JSON.stringify(version)}\n  resolved ${JSON.stringify(resolved)}\n  integrity ${distribution.integrity}\n`);
		const cached = path.join(area.cacheDir, name, 'node_modules', name);
		fs.mkdirSync(cached, { recursive: true });
		fs.writeFileSync(path.join(cached, '.yarn-metadata.json'), JSON.stringify({ manifest: { name, version }, remote: { type: 'tarball', resolved, integrity: distribution.integrity } }));
		fs.copyFileSync(distribution.tarball, path.join(cached, '.yarn-tarball.tgz'));
	}
	if (area.git) entries.push(`${JSON.stringify(`${GIT_PACKAGE}@${GIT_LOCATOR}`)}:\n  version ${JSON.stringify(GIT_COMPONENT.version)}\n  resolved ${JSON.stringify(GIT_LOCATOR)}\n`);
	fs.writeFileSync(area.lockPath, `# yarn lockfile v1\n\n${entries.join('\n')}`);
}

// The same installs as npm leaves them: a lockfile of its own, and the
// archives in its content store, put there by npm itself.
function writeNpm(fixture, area) {
	const packages = { '': { name: 'app', version: '1.0.0' } };
	area.cacheDir = path.join(area.cacheDir, '_cacache');
	fs.mkdirSync(area.cacheDir, { recursive: true });
	for (const [name, distribution] of Object.entries(fixture.distributions)) {
		const version = distribution.component.version;
		packages[`node_modules/${name}`] = { version, resolved: `https://registry.example.test/${name}/-/${name}-${version}.tgz`, integrity: distribution.integrity };
		const added = spawnSync('npm', ['cache', 'add', distribution.tarball, '--cache', path.dirname(area.cacheDir), '--offline'], { encoding: 'utf8', timeout: DEADLINE_MS });
		if (added.status !== 0) throw new Error(`npm cache add ${name}: ${added.stderr || added.stdout}`);
	}
	fs.writeFileSync(area.lockPath, `${JSON.stringify({ name: 'app', version: '1.0.0', lockfileVersion: 3, requires: true, packages }, null, 2)}\n`);
}

// A plain CommonJS configuration, as the actual project has one, carrying a
// plugin that records what the compiler really received: whether the exported
// object is still the one this file built, which plugins the CLI unshifted into
// the array literal it carries, which plugins the compiler ended up with, and
// every answer the originals resolver gave the activation.
function config(area, shape) {
	const body = `'use strict';
const fs = require('node:fs');
const path = require('node:path');
const v8 = require('node:v8');

// The very resolver module the activation loaded before this file was compiled,
// observed from the outside: these records are its own answers, never a stand-in
// for it.
const Originals = require(${JSON.stringify(path.join(__dirname, area.resolverModule))});
const originalsCalls = [];
const resolve = Originals.prototype.resolve;
Originals.prototype.resolve = async function (resource) {
	const where = path.relative(${JSON.stringify(area.root)}, resource);
	try {
		const binding = await resolve.call(this, resource);
		originalsCalls.push({resource: where, component: binding ? binding.component.name : null});
		return binding;
	} catch (error) {
		originalsCalls.push({resource: where, status: error.status || 'thrown'});
		throw error;
	}
};

const plugins = [];
const config = {
	mode: 'production',
	context: ${JSON.stringify(area.root)},
	entry: ${JSON.stringify(area.entry)},
	target: 'node',
	output: {path: ${JSON.stringify(area.output)}, filename: 'main.js', iife: false},
	optimization: {minimize: false, concatenateModules: true, usedExports: true},
	module: {rules: ${JSON.stringify(area.esbuild ? [{ test: '\\.ts$', loader: area.esbuild.loader, options: { loader: 'ts', target: 'es2015' } }] : [])}.map(rule => ({...rule, test: new RegExp(rule.test)}))},
	plugins,
};
let call = null;

class DkFixtureProbe {
	apply(compiler) {
		write(compiler);
		// The originals are resolved while the proof is built, long after this
		// plugin was applied.
		compiler.hooks.done.tap('DkFixtureProbe', () => write(compiler));
	}
}

function write(compiler) {
	fs.writeFileSync(${JSON.stringify(area.probePath)}, JSON.stringify({
		exportsIsConfig: module.exports === config,
		exportsType: typeof module.exports,
		esModule: Object.getOwnPropertyDescriptor(module.exports, '__esModule') || null,
		declaredPlugins: plugins.map(name),
		compilerPlugins: compiler.options.plugins.map(name),
		observer: Object.getOwnPropertySymbols(globalThis).map(symbol => symbol.description).includes('dk.sbom.webpack.cjs'),
		recorders: Object.getOwnPropertySymbols(globalThis).map(symbol => symbol.description).filter(name => name.startsWith('dk.sbom.webpack.')).sort(),
		heapLimit: v8.getHeapStatistics().heap_size_limit,
		nodeOptions: process.env.NODE_OPTIONS || '',
		argv: process.argv.slice(2),
		call,
		originalsCalls,
	}, null, 2));
}

function name(plugin) {
	return plugin && plugin.constructor ? plugin.constructor.name : typeof plugin;
}

plugins.push(new DkFixtureProbe());
`;
	// What a transpiled typescript or esm configuration looks like by the time
	// the CLI requires it: a namespace with a default the CLI unwraps.
	// Marked the way a transpiler marks it: not enumerable, so an activation that
	// spread the namespace would lose the flag the CLI reads.
	if (shape === 'transpiled') return `${body}Object.defineProperty(module.exports, "__esModule", {value: true});\nmodule.exports.default = config;\n`;
	return shape === 'function' ? `${body}module.exports = function (env, argv) { call = {env: env ?? null, argv: {mode: argv && argv.mode}}; return config; };\n` : `${body}module.exports = config;\n`;
}

// The actual CLI, started the way the image recipe starts it: the heap option
// the stage sets stays in NODE_OPTIONS beside the appended preload, and the
// activation's own variables are the only other thing this build is told.
function run(area, options = {}) {
	const env = {
		PATH: '/usr/bin:/bin',
		HOME: area.root,
		TMPDIR: area.tmp,
		NODE_OPTIONS: `--max_old_space_size=${HEAP_LIMIT_MB} --require ${ACTIVATE}`,
		npm_config_ignore_scripts: 'true',
	};
	if (options.active !== false) {
		env.DK_SBOM_WEBPACK_CONFIG = options.configPath || area.configPath;
		env.DK_SBOM_WEBPACK_PROOF = area.proofPath;
		env.DK_SBOM_YARN_CACHE = area.cacheDir;
		env.SBOM_BUILD_CONTEXT = area.contextPath;
		if (area.esbuild) {
			env.DK_SBOM_ESBUILD_VERSION = area.esbuild.versions.esbuild;
			env.DK_SBOM_ESBUILD_LOADER_VERSION = area.esbuild.versions.esbuildLoader;
			env.DK_SBOM_ESBUILD_ENTRY = area.esbuild.entry;
			env.DK_SBOM_ESBUILD_BINARY = area.esbuild.binary;
			env.DK_SBOM_ESBUILD_LOADER = area.esbuild.loader;
			env.DK_SBOM_ESBUILD_RUNTIME_SOURCE = area.esbuild.runtimeSource;
			// The adapter refuses a process that could run an executable other
			// than the one it verified.
			env.ESBUILD_BINARY_PATH = area.esbuild.binary;
		}
	}
	const result = spawnSync(process.execPath, [CLI, '--config', area.configPath, '--mode', 'production', ...(options.args || [])], {
		cwd: area.root,
		env: { ...env, ...(options.env || {}) },
		encoding: 'utf8',
		timeout: DEADLINE_MS,
	});
	if (result.error) throw result.error;
	return {
		status: result.status,
		stdout: result.stdout,
		stderr: result.stderr,
		probe: read(area.probePath),
		proof: read(area.proofPath),
		// Scratch trees the activation created for this build: the child has no
		// other temporary directory.
		scratch: fs.readdirSync(area.tmp),
	};
}

function read(file) {
	try {
		return JSON.parse(fs.readFileSync(file, 'utf8'));
	} catch (error) {
		if (error.code === 'ENOENT') return undefined;
		throw error;
	}
}

module.exports = { createArea, writeManifest, run, HEAP_LIMIT_MB, PRIMARY, GIT_COMPONENT, GIT_PACKAGE };
