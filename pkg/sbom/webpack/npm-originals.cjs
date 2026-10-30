'use strict';

// npm original acquisition: binds an installed node_modules package to an
// independently extracted copy of the very distribution archive the
// package-lock pins, so the collector has something to compare the installed
// bytes against.
//
// Trust boundary: the lockfile entry (resolved locator + integrity) is the
// claim, and the archive the npm cache holds is the evidence. The cache is
// content-addressed, so the archive is looked up at the path its own locked
// integrity names and then checked against that integrity again: no index
// entry, no cache key and no cached manifest takes part, and neither does the
// installed tree. An original is produced only when those bytes satisfy the
// locked SRI and the archive's own manifest carries the locked identity.
// Anything else fails closed with a status instead of a guessed owner. The
// archive is hashed once and extracted from that same buffer, so the verified
// bytes are the extracted bytes.
//
// A lock entry pinning a Git commit has no archive and no integrity, so it is
// resolved against the build context manifest instead, which names what DK
// verified from the commit itself; see gitOriginal().
//
// Lifetime: one instance covers one compilation. The lockfile is read once, on
// the first resolve; a later edit is not observed. Construct a new resolver for
// every compilation and call close() once the compiler has consumed the
// originals.

const fs = require('fs');
const path = require('path');

const ssri = require('ssri');

const ContextOriginals = require('./context-originals.cjs');
const {
	archiveOriginals,
	NODE_MODULES,
	GIT_LOCATOR,
	findPackageRoot,
	isRegistryLocator,
	describeComponent,
	removeReadOnlyTree,
	readRegularFile,
	identityKey,
	contains,
	isPlainObject,
} = require('./archive-originals.cjs');

const NAME = 'DkSbomNpmOriginals';
const CONTENT_DIR = 'content-v2';
// npm writes `packages` from lockfileVersion 2 on; version 1 carries only the
// legacy tree, which does not state an installed path for an entry.
const SUPPORTED_LOCKFILE_VERSIONS = [2, 3];
const {
	fail,
	checkKeys,
	requireAbsolutePath,
	requireDirectory,
	prepareOutputRoot,
	readInstalledIdentity,
	lockedChecksum,
	extractArchive,
	gitBinding,
} = archiveOriginals(NAME);

class DkSbomNpmOriginals {
	constructor(options) {
		if (!isPlainObject(options)) throw new Error(`${NAME}: options object is required`);
		checkKeys(options, ['workdir', 'lockPath', 'cacheDir', 'outputRoot', 'contextPath'], 'options');
		this.workdir = requireDirectory(options.workdir, 'options.workdir');
		this.lockPath = requireAbsolutePath(options.lockPath, 'options.lockPath');
		// The content-addressed store of an npm cache, that is the `_cacache`
		// directory itself, not the cache folder that holds it.
		this.cacheDir = requireDirectory(options.cacheDir, 'options.cacheDir');
		this.outputRoot = prepareOutputRoot(options.outputRoot, [this.workdir, this.cacheDir]);
		// The build context file DK wrote; the private originals manifest beside it
		// is the only evidence a Git-locked dependency can be resolved against.
		this.contextPath = options.contextPath === undefined ? null : requireAbsolutePath(options.contextPath, 'options.contextPath');
		this.context = null;
		this.locked = null;
		this.originals = new Map();
	}

	async resolve(resourcePath) {
		const resource = requireAbsolutePath(resourcePath, 'resourcePath');
		const installed = findPackageRoot(resource);
		if (!installed) return undefined;
		if (!contains(this.workdir, installed.root)) {
			throw fail('no-data', `installed package ${installed.root} is outside the workdir ${this.workdir}`);
		}
		const identity = readInstalledIdentity(installed, resource);
		const entry = this.lockEntry(installed.root, identity);
		if (entry.commit) return this.gitOriginal(resource, identity, entry);
		const component = describeComponent(identity, entry);
		const originalRoot = await this.original(component, identity, entry);
		// Why installed bytes may differ from the distribution without anything
		// being wrong: npm ran an install script of this package, whose output is
		// nobody's original. The comparison itself is the collector's, and no
		// reader consumes this yet: it is carried so the reason exists where the
		// mismatch is seen.
		return { root: installed.root, originalRoot, component, hasInstallScript: entry.hasInstallScript === true };
	}

	// Removes the trees this resolver extracted. The caller's outputRoot and the
	// npm cache are left alone.
	close() {
		for (const original of this.originals.values()) removeReadOnlyTree(original.scratch);
		this.originals.clear();
	}

	// The lock entry of the very directory the package is installed in. npm keys
	// `packages` by installed path, so the owner of a physical directory is read
	// rather than searched for by name: a nested copy is its own entry.
	lockEntry(installedRoot, identity) {
		if (!this.locked) this.locked = readLock(this.lockPath);
		const location = installedLocation(this.workdir, installedRoot);
		const entry = this.locked.entries.get(location);
		if (!entry) throw fail('no-data', `no package-lock entry for ${location}`);
		if (entry.refusal) throw fail('no-data', entry.refusal);
		if (entry.link) throw fail('no-data', `package-lock entry for ${location} is a link, not an installed distribution`);
		// A bundled dependency ships inside its parent's tarball. Its own entry
		// names no distribution of its own — whatever locator and integrity it
		// carries describe a registry copy that was not what npm installed here.
		if (entry.inBundle) {
			throw fail('no-data', `package-lock entry for ${location} is bundled into its parent distribution`);
		}
		// An npm alias installs one package under another name, so the directory
		// does not name what it holds and the installed bytes are not this entry's
		// to own.
		if (isAliasEntry(entry, location)) {
			throw fail('no-data', `package-lock entry for ${location} is an npm alias of ${entry.name}`);
		}
		const declared = { name: packageNameOf(location), version: entry.version };
		if (declared.name !== identity.name || declared.version !== identity.version) {
			throw fail('invalid', `package-lock claims ${identityKey(declared)} for ${location}, which holds ${identityKey(identity)}`);
		}
		if (!isRegistryLocator(entry.resolved)) {
			const git = GIT_LOCATOR.exec(typeof entry.resolved === 'string' ? entry.resolved : '');
			if (git) return { ...entry, commit: git[1] };

			throw fail('no-data', `package-lock entry for ${location} is not an http registry archive: ${entry.resolved || 'without a locator'}`);
		}
		if (typeof entry.integrity !== 'string' || entry.integrity === '') {
			throw fail('no-data', `package-lock entry for ${location} carries no integrity`);
		}
		const checksum = lockedChecksum(entry.integrity, `package-lock entry for ${location}`, location);
		return { ...entry, location, checksum };
	}

	// The file binding DK verified for a Git-locked package: the commit of the
	// lock entry, read back from the build context manifest and held against that
	// very entry. The npm cache takes no part — it records what a fetch claimed,
	// not bytes anybody checked against the commit — and neither does any package
	// manager: a package the manifest does not list stays no-data.
	gitOriginal(resource, identity, entry) {
		if (!this.contextPath) throw fail('no-data', `no verified build context for the Git-locked ${identityKey(identity)}`);
		if (!this.context) this.context = new ContextOriginals(this.contextPath);
		return gitBinding(this.context.resolve(resource), resource, identity, entry);
	}

	async original(component, identity, entry) {
		const known = this.originals.get(component.id);
		if (known) return known.originalRoot;
		const archive = this.cacheArchive(identity, entry);
		const scratch = fs.mkdtempSync(path.join(this.outputRoot, 'original-'));
		let originalRoot;
		try {
			originalRoot = await extractArchive(archive, scratch, identity);
		} catch (error) {
			removeReadOnlyTree(scratch);
			if (error.status) throw error;
			throw fail('invalid', `archive of ${identityKey(identity)} could not be extracted: ${error.message}`);
		}
		this.originals.set(component.id, { scratch, originalRoot });
		return originalRoot;
	}

	// The cached archive is addressed by the locked integrity itself: npm stores
	// content at `content-v2/<algorithm>/<first>/<second>/<rest of the hex
	// digest>`, so the path is derived from the lock entry rather than looked up
	// through the cache index, and the bytes found there are checked against that
	// same integrity. A store that answers another content at that address is a
	// contradiction, not a reason to search for a better candidate.
	cacheArchive(identity, entry) {
		const file = contentPath(this.cacheDir, entry.checksum);
		const bytes = readRegularFile(file);
		if (!bytes) {
			throw fail('no-data', `no npm cache content for ${identityKey(identity)} at ${file}`);
		}
		if (!ssri.checkData(bytes, entry.checksum, { error: false })) {
			throw fail('hash-mismatch', `cached archive of ${identityKey(identity)} does not satisfy ${entry.checksum}`);
		}
		return { bytes, file, label: file };
	}
}

// The content address of one SRI token in an npm cache, as cacache lays it out.
function contentPath(cacheDir, checksum) {
	const parsed = ssri.parse(checksum, { single: true });
	const hex = parsed.hexDigest();
	return path.join(cacheDir, CONTENT_DIR, parsed.algorithm, hex.slice(0, 2), hex.slice(2, 4), hex.slice(4));
}

// The lockfile key of an installed directory: a path relative to the project
// root, in the posix spelling npm writes, below a node_modules of this project.
function installedLocation(workdir, installedRoot) {
	const relative = path.relative(workdir, installedRoot).split(path.sep).join('/');
	const segments = relative.split('/');
	if (segments.length < 2 || segments[0] !== NODE_MODULES || segments.includes('..')) {
		throw fail('no-data', `installed package ${installedRoot} is not in a node_modules tree of ${workdir}`);
	}
	return relative;
}

// The package a lockfile location belongs to: the part after its last
// node_modules segment, scope included.
function packageNameOf(location) {
	const segments = location.split('/');
	const at = segments.lastIndexOf(NODE_MODULES);
	return segments.slice(at + 1).join('/');
}

// Only the `packages` map is read, and only the entries of this project's own
// node_modules. A lockfile that states one member twice states two different
// things and is refused whole: the reading that keeps the last of them is a
// choice this gate does not get to make.
//
// From lockfileVersion 2 a file carries both the `packages` map and the legacy
// `dependencies` tree, and both state the same installs. Only what both agree
// on is read: a location the tree omits or contradicts is no distribution this
// file pins unambiguously. A version 3 file has no tree to agree with.
function readLock(lockPath) {
	const bytes = readRegularFile(lockPath);
	if (!bytes) throw fail('no-data', `no readable lockfile at ${lockPath}`);
	const text = bytes.toString('utf8');
	let parsed;
	try {
		parsed = JSON.parse(text);
	} catch (error) {
		throw fail('invalid', `lockfile ${lockPath} is malformed: ${error.message}`);
	}
	const duplicate = duplicateKeyIn(text);
	if (duplicate !== undefined) throw fail('no-data', `npm lockfile has a duplicate key: ${JSON.stringify(duplicate)}`);
	if (!isPlainObject(parsed)) throw fail('invalid', `lockfile ${lockPath} is not an object`);
	if (!SUPPORTED_LOCKFILE_VERSIONS.includes(parsed.lockfileVersion)) {
		throw fail('unsupported', `lockfile ${lockPath} has lockfileVersion ${String(parsed.lockfileVersion)}, only ${SUPPORTED_LOCKFILE_VERSIONS.join(' and ')} state installed paths`);
	}
	if (!isPlainObject(parsed.packages)) throw fail('invalid', `lockfile ${lockPath} carries no packages map`);
	const twoTrees = parsed.lockfileVersion === 2;
	const entries = new Map();
	for (const [location, value] of Object.entries(parsed.packages)) {
		if (!location.startsWith(`${NODE_MODULES}/`) || !isPlainObject(value)) continue;
		const entry = {
			resolved: value.resolved,
			integrity: value.integrity,
			version: value.version,
			name: value.name,
			link: value.link === true,
			inBundle: value.inBundle === true,
			hasInstallScript: value.hasInstallScript === true,
		};
		// An install this adapter refuses for what it is — a link, a bundled copy,
		// an alias — is left to say so itself; holding its two spellings against
		// each other first would answer a question nobody asked.
		if (twoTrees && !entry.link && !entry.inBundle && !isAliasEntry(entry, location)) {
			const legacy = legacyEntry(parsed.dependencies, location);
			if (!legacy) {
				entry.refusal = `package-lock version 2 states ${location} only in packages, not in its dependencies tree`;
			} else {
				const disagreement = legacyDisagreement(legacy, entry);
				if (disagreement) entry.refusal = `package-lock version 2 states ${location} ${disagreement}`;
			}
		}
		entries.set(location, entry);
	}
	return { entries };
}

// What the two trees of a lockfileVersion 2 have to say about one install, held
// against each other in the vocabulary npm writes each kind in.
//
// A registry install is stated the same way on both sides. A Git install is not:
// the legacy tree carries the locator in `version` and neither `resolved` nor
// `integrity` (npm builds it that way), so comparing the two as archives would
// refuse every Git-locked dependency of every version 2 lockfile.
function legacyDisagreement(legacy, entry) {
	if (typeof entry.resolved === 'string' && GIT_LOCATOR.test(entry.resolved)) {
		if (legacy.version !== entry.resolved) {
			return `as ${entry.resolved} in packages and ${legacy.version || 'nothing'} in its dependencies tree`;
		}
		if (legacy.resolved !== undefined || legacy.integrity !== undefined) {
			return `as a Git commit in packages and as the archive ${legacy.resolved || legacy.integrity} in its dependencies tree`;
		}
		return undefined;
	}
	if (distributionLabel(legacy) !== distributionLabel(entry)) {
		return `as ${distributionLabel(entry)} in packages and ${distributionLabel(legacy)} in its dependencies tree`;
	}
	return undefined;
}

function isAliasEntry(entry, location) {
	return typeof entry.name === 'string' && entry.name !== packageNameOf(location);
}

// The same installed path in the legacy tree a lockfileVersion 2 also carries:
// `node_modules/a/node_modules/b` is `dependencies.a.dependencies.b` there.
function legacyEntry(tree, location) {
	const names = location.split(`${NODE_MODULES}/`).slice(1).map((name) => name.replace(/\/$/, ''));
	let node = tree;
	for (const [index, name] of names.entries()) {
		if (!isPlainObject(node)) return undefined;
		const held = node[name];
		if (!isPlainObject(held)) return undefined;
		if (index === names.length - 1) return { resolved: held.resolved, integrity: held.integrity, version: held.version };
		node = held.dependencies;
	}
	return undefined;
}

// JSON.parse keeps the last of two members of one name, so duplicates are found
// in the text the lockfile actually holds. The document has already parsed, so
// this walks well-formed JSON: a string token followed by a colon is a member
// name, and every other string is a value. Names are compared within their own
// object, which is what a duplicate is.
function duplicateKeyIn(text) {
	const scopes = [];
	let pending;
	for (let at = 0; at < text.length; at++) {
		const character = text[at];
		if (character === '"') {
			const start = at + 1;
			for (at++; at < text.length && text[at] !== '"'; at++) if (text[at] === '\\') at++;
			// Only reachable if the text is not the JSON it parsed as; an unterminated
			// string names nothing, and guessing one is not this scanner's business.
			if (at >= text.length) throw fail('invalid', 'lockfile text ends inside a string');
			pending = text.slice(start, at);
			continue;
		}
		if (character === '{' || character === '[') {
			// An array holds no member names, so its scope simply stays empty.
			scopes.push(new Set());
			pending = undefined;
			continue;
		}
		if (character === '}' || character === ']') {
			scopes.pop();
			pending = undefined;
			continue;
		}
		if (character === ':' && pending !== undefined) {
			const names = scopes[scopes.length - 1];
			// A string escape is spelled many ways; the parsed member name is the one
			// that matters, so the raw token is read back through JSON.
			const name = JSON.parse(`"${pending}"`);
			pending = undefined;
			if (names.has(name)) return name;
			names.add(name);
		}
	}
	return undefined;
}

function distributionLabel(entry) {
	return `${entry.resolved || ''} ${entry.integrity || ''} ${entry.version || ''}`;
}

module.exports = DkSbomNpmOriginals;
