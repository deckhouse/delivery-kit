'use strict';

// Fixture for the activation tests: one Yarn-installed workspace with a real
// lockfile and cache, a verified primary-source manifest beside a build context
// file, and a generated CommonJS configuration that records what the pinned
// Webpack CLI really loaded. Builds run the actual `webpack-cli` binary in a
// child process whose NODE_OPTIONS carries the activation preload, as the image
// recipe appends it.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const CLI = require.resolve('webpack-cli/bin/cli.js');
const ACTIVATE = path.join(__dirname, 'activate.cjs');
const HEAP_LIMIT_MB = 512;
const DEADLINE_MS = 60000;
const ENTRY = 'import {a} from "pkg-a";\nconsole.log(a());\n';
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
		lockPath: path.join(workspace.root, 'yarn.lock'),
		entry: path.join(workspace.root, 'src', 'main.js'),
		contextPath: path.join(workspace.root, 'context', 'build-context.json'),
		manifestPath: path.join(workspace.root, 'context', 'webpack-originals.json'),
		configPath: path.join(workspace.root, 'webpack.config.js'),
		unmatchedConfigPath: path.join(workspace.root, 'unmatched.config.js'),
		probePath: path.join(workspace.root, 'probe.json'),
	};
	fs.mkdirSync(area.tmp, { recursive: true });
	fs.mkdirSync(path.dirname(area.entry), { recursive: true });
	fs.writeFileSync(area.entry, ENTRY);
	writeYarn(fixture, area);
	fs.mkdirSync(path.dirname(area.contextPath), { recursive: true });
	fs.writeFileSync(area.contextPath, `${JSON.stringify({ version: 1 }, null, 2)}\n`);
	writeManifest(area);
	fs.writeFileSync(area.configPath, config(area, options.asFunction === true));
	fs.writeFileSync(area.unmatchedConfigPath, config(area, false));
	return area;
}

// The verified expected hashes DK writes beside the read-only build context
// after validating the scoped PM originals.
function writeManifest(area) {
	const manifest = {
		version: 1,
		components: [PRIMARY],
		files: [{ path: area.entry, sha256: `sha256:${crypto.createHash('sha256').update(fs.readFileSync(area.entry)).digest('hex')}`, component: PRIMARY.id }],
	};
	fs.writeFileSync(area.manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
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
	fs.writeFileSync(area.lockPath, `# yarn lockfile v1\n\n${entries.join('\n')}`);
}

// A plain CommonJS configuration, as the actual project has one, carrying a
// plugin that records what the compiler really received: whether the exported
// object is still the one this file built, which plugins the CLI unshifted into
// the array literal it carries, which plugins the compiler ended up with, and
// every answer the Yarn resolver gave the activation.
function config(area, asFunction) {
	const body = `'use strict';
const fs = require('node:fs');
const path = require('node:path');
const v8 = require('node:v8');

// The very resolver module the activation loaded before this file was compiled,
// observed from the outside: these records are its own answers, never a stand-in
// for it.
const YarnOriginals = require(${JSON.stringify(path.join(__dirname, 'yarn-originals.cjs'))});
const yarnCalls = [];
const resolve = YarnOriginals.prototype.resolve;
YarnOriginals.prototype.resolve = async function (resource) {
	const where = path.relative(${JSON.stringify(area.root)}, resource);
	try {
		const binding = await resolve.call(this, resource);
		yarnCalls.push({resource: where, component: binding ? binding.component.name : null});
		return binding;
	} catch (error) {
		yarnCalls.push({resource: where, status: error.status || 'thrown'});
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
		declaredPlugins: plugins.map(name),
		compilerPlugins: compiler.options.plugins.map(name),
		observer: Object.getOwnPropertySymbols(globalThis).map(symbol => symbol.description).includes('dk.sbom.webpack.cjs'),
		heapLimit: v8.getHeapStatistics().heap_size_limit,
		nodeOptions: process.env.NODE_OPTIONS || '',
		argv: process.argv.slice(2),
		call,
		yarnCalls,
	}, null, 2));
}

function name(plugin) {
	return plugin && plugin.constructor ? plugin.constructor.name : typeof plugin;
}

plugins.push(new DkFixtureProbe());
`;
	return asFunction ? `${body}module.exports = function (env, argv) { call = {env: env ?? null, argv: {mode: argv && argv.mode}}; return config; };\n` : `${body}module.exports = config;\n`;
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

module.exports = { createArea, writeManifest, run, HEAP_LIMIT_MB, PRIMARY };
