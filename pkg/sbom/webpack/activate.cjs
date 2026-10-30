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
// The package managers whose installs this collector can resolve back to
// published archives, told apart by the lockfile the project was built from.
// A shipped shrinkwrap is npm's own file with rules of its own, and nothing
// here reads it: it is named so that a project carrying one is refused rather
// than resolved by the lockfile beside it.
const LOCKFILES = new Map([
	['yarn.lock', './yarn-originals.cjs'],
	['package-lock.json', './npm-originals.cjs'],
	['npm-shrinkwrap.json', null],
]);

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
	require('./stylesheet-preload.cjs');
	require('./stylesheet3-preload.cjs');
	require('./include-preload.cjs');
	require('./worker-preload.cjs');
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
	// What a transpiled module looks like from here. The CLI unwraps such an
	// export, so the attachment belongs on what it unwraps to and not on the
	// namespace around it, which no compiler ever sees.
	if (Object.hasOwn(exported, 'default')) {
		if (exported.__esModule !== true) {
			throw new Error(`${NAME}: ${settings.configPath} exports a default this activation cannot tell from a configuration field`);
		}
		// Its own descriptors, so the namespace keeps the shape its transpiler
		// gave it (__esModule is non-enumerable) for whoever else reads it.
		return Object.defineProperties({}, {
			...Object.getOwnPropertyDescriptors(exported),
			default: { value: attach(exported.default, settings, Activation), writable: true, enumerable: true, configurable: true },
		});
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

	// Which package manager installed this project, said by the lockfile it was
	// built from. Two of them, or none, leave no single account of where the
	// installed bytes came from.
	function lockfileOf(workdir) {
		const found = [...LOCKFILES.keys()].filter((name) => isFile(path.join(workdir, name)));
		if (found.length !== 1) {
			throw new Error(`${NAME}: ${workdir} carries ${found.length === 0 ? 'no lockfile' : `${found.join(' and ')}`}, and one is needed to resolve installed packages`);
		}
		const resolver = LOCKFILES.get(found[0]);
		if (resolver === null) throw new Error(`${NAME}: ${workdir} carries ${found[0]}, whose installs this collector does not resolve`);
		return { name: found[0], Originals: require(resolver) };
	}

	function isFile(file) {
		try {
			return fs.statSync(file).isFile();
		} catch {
			return false;
		}
	}

	// One compilation, one scratch base: the extracted originals of that
	// compilation and nothing else. The build context is handed to the resolver
	// as well: a dependency the lockfile pins to a Git commit has no cached
	// archive, and the manifest beside the context is its only evidence.
	function open(compiler, cacheDir, contextPath) {
		const { name, Originals } = lockfileOf(compiler.context);
		const base = fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-originals-'));
		try {
			return {
				base,
				originals: new Originals({
					workdir: compiler.context,
					lockPath: path.join(compiler.context, name),
					cacheDir,
					outputRoot: base,
					contextPath,
				}),
			};
		} catch (error) {
			fs.rmSync(base, { recursive: true, force: true });
			throw error;
		}
	}

	// A resolver carries what it knows about an installed package - npm's, for
	// one, carries `hasInstallScript`, which nothing reads yet. An answer that
	// maps a tree to the distribution it came from is handed on as the three
	// fields the collector's contract defines, and that field is dropped here
	// rather than widening a contract for a field with no reader; an answer
	// about a single verified file is already in the other shape that contract
	// takes.
	function installed(resolved) {
		if (!resolved || typeof resolved.root !== 'string') return resolved;
		return { root: resolved.root, originalRoot: resolved.originalRoot, component: resolved.component };
	}

	function close(scope) {
		try {
			scope.originals.close();
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
			const { cacheDir, contextPath } = this.settings;
			let scope = null;
			compiler.hooks.thisCompilation.tap(NAME, () => {
				if (scope) throw new Error(`${NAME}: a second compilation of this compiler is not supported`);
				scope = open(compiler, cacheDir, contextPath);
			});
			new Collector({
				proofPath: this.settings.proofPath,
				originals: [],
				copied: [],
				// A failure of the package manager is a failure of the managed
				// package it names, never a reason to look for those bytes among
				// the project's own sources.
				resolveOriginal: async (resource) => installed(await scope.originals.resolve(resource)) ?? primary.resolve(resource),
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
