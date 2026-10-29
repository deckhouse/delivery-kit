'use strict';

// Private activation preload, used as `node --require activate.cjs` through the
// NODE_OPTIONS of one pinned Webpack CLI build. It attaches the collector to
// exactly one configuration file - the absolute path in DK_SBOM_WEBPACK_CONFIG -
// without touching that file, the project's package.json or any public command.
//
// With DK_SBOM_WEBPACK_CONFIG unset this module does nothing and requires
// nothing else, so an ordinary build of the same image is bit-for-bit the build
// it was before. Set, every process that inherits NODE_OPTIONS - the Yarn
// parent, a tool child - installs the load recorder and carries its
// process-local cost, and only the process that compiles the named file
// produces anything.
//
// Nothing here guesses a failure from the absence of a build: when the named
// file is never loaded - a path that no longer matches the project, or a process
// that compiles another config - no proof is written and no error is raised. The
// consuming Go embed obligation sees that absence as missing evidence; it is not
// reported here, where a false failure could not be told from a real one.
//
// Scope: one configuration load per process, one configuration object, no
// watching build. A second load or a multi-compiler array would need more than
// one proof path, and sharing one would let two compositions overwrite each
// other, so both are refused.

const NAME = 'DkSbomWebpackActivation';
const CONFIG = 'DK_SBOM_WEBPACK_CONFIG';
const PROOF = 'DK_SBOM_WEBPACK_PROOF';
const CACHE = 'DK_SBOM_YARN_CACHE';
const CONTEXT = 'SBOM_BUILD_CONTEXT';
const LOCKFILE = 'yarn.lock';

if (process.env[CONFIG]) activate();

function activate() {
	const fs = require('node:fs');
	const path = require('node:path');
	const settings = {
		configPath: requireRealFile(fs, path, CONFIG),
		proofPath: requireAbsolute(path, PROOF),
		cacheDir: requireRealDirectory(fs, path, CACHE),
		contextPath: requireAbsolute(path, CONTEXT),
	};
	// The load recorder has to be wrapping the module loader before the first
	// webpack file is compiled; everything else here is loaded after it.
	require('./runtime-preload.cjs');
	const Module = require('node:module');
	const Activation = activationPlugin();
	// Only the one compiled file this activation owns: every other request, of
	// the CLI and of the build itself, keeps the loader it already had. A `.cjs`
	// config reaches this handler too - Node registers no separate extension for
	// it and falls back to the `.js` one.
	const compile = Module._extensions['.js'];
	let loaded = false;
	Module._extensions['.js'] = function (module, filename) {
		compile.call(this, module, filename);
		if (filename !== settings.configPath) return;
		if (loaded) throw new Error(`${NAME}: ${settings.configPath} is loaded more than once in this process`);
		loaded = true;
		module.exports = attach(module.exports, settings, Activation);
	};
}

// The exported configuration, with this activation's plugin added. A function
// config is called by the CLI with the env and argv it parsed, so the wrapper
// passes both through untouched, along with its receiver, and attaches to what
// the call finally produces.
function attach(exported, settings, Activation) {
	if (exported !== null && (typeof exported === 'object' || typeof exported === 'function') && typeof exported.then === 'function') {
		return exported.then((resolved) => attach(resolved, settings, Activation));
	}
	if (typeof exported === 'function') {
		return function (...args) {
			return attach(exported.apply(this, args), settings, Activation);
		};
	}
	if (Array.isArray(exported)) throw new Error(`${NAME}: a multi-compiler configuration is not supported`);
	if (exported === null || typeof exported !== 'object') {
		throw new Error(`${NAME}: ${settings.configPath} exports no configuration object`);
	}
	// The CLI unwraps an exported `default`, which would leave the attachment on
	// an object no compiler ever sees.
	if (Object.hasOwn(exported, 'default')) {
		throw new Error(`${NAME}: ${settings.configPath} exports a transpiled default this activation does not support`);
	}
	const plugins = exported.plugins === undefined ? [] : exported.plugins;
	if (!Array.isArray(plugins)) throw new Error(`${NAME}: ${settings.configPath} exports a non-array plugins field`);
	// A copy, because the CLI unshifts its own plugin into whichever array the
	// configuration carries, and the project's own array is not ours to extend.
	return { ...exported, plugins: [...plugins, new Activation(settings)] };
}

// Built after the preload is in place: the collector and the original resolvers
// are the first modules loaded through the recorded loader.
function activationPlugin() {
	const fs = require('node:fs');
	const os = require('node:os');
	const path = require('node:path');
	const Collector = require('./collector.cjs');
	const ContextOriginals = require('./context-originals.cjs');
	const YarnOriginals = require('./yarn-originals.cjs');

	// One compilation, one scratch base: the extracted originals of that
	// compilation and nothing else.
	function open(compiler, cacheDir) {
		const base = fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-originals-'));
		try {
			return {
				base,
				yarn: new YarnOriginals({
					workdir: compiler.context,
					lockPath: path.join(compiler.context, LOCKFILE),
					cacheDir,
					outputRoot: base,
				}),
			};
		} catch (error) {
			fs.rmSync(base, { recursive: true, force: true });
			throw error;
		}
	}

	function close(scope) {
		try {
			scope.yarn.close();
		} finally {
			fs.rmSync(scope.base, { recursive: true, force: true });
		}
	}

	return class DkSbomWebpackActivation {
		constructor(settings) {
			this.settings = settings;
		}

		apply(compiler) {
			if (compiler.options.watch) throw new Error(`${NAME}: a watching build is not supported`);
			// The verified primary sources of this very build context, read where
			// the compiler runs rather than in the Yarn parent that spawned it.
			const primary = new ContextOriginals(this.settings.contextPath);
			const cacheDir = this.settings.cacheDir;
			let scope = null;
			compiler.hooks.thisCompilation.tap(NAME, () => {
				if (scope) throw new Error(`${NAME}: a second compilation of this compiler is not supported`);
				scope = open(compiler, cacheDir);
			});
			new Collector({
				proofPath: this.settings.proofPath,
				originals: [],
				copied: [],
				// A Yarn failure is a failure of the managed package it names, never
				// a reason to look for those bytes among the project's own sources.
				resolveOriginal: async (resource) => (await scope.yarn.resolve(resource)) ?? primary.resolve(resource),
			}).apply(compiler);
			for (const outcome of ['done', 'failed']) {
				compiler.hooks[outcome].tap(NAME, () => {
					if (!scope) return;
					const closing = scope;
					scope = null;
					close(closing);
				});
			}
		}
	};
}

function requireAbsolute(path, variable) {
	const value = process.env[variable];
	if (typeof value !== 'string' || value === '') throw new Error(`${NAME}: ${variable} must be a non-empty string`);
	if (!path.isAbsolute(value) || path.normalize(value) !== value) throw new Error(`${NAME}: ${variable} must be a normalized absolute path`);
	return value;
}

function requireRealFile(fs, path, variable) {
	const value = requireAbsolute(path, variable);
	const real = fs.realpathSync(value);
	if (!fs.statSync(real).isFile()) throw new Error(`${NAME}: ${variable} must be a file`);
	return real;
}

function requireRealDirectory(fs, path, variable) {
	const value = requireAbsolute(path, variable);
	const real = fs.realpathSync(value);
	if (!fs.statSync(real).isDirectory()) throw new Error(`${NAME}: ${variable} must be a directory`);
	return real;
}
