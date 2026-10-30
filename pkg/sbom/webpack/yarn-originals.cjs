'use strict';

// Yarn 1 original acquisition: binds an installed node_modules package to an
// independently extracted copy of the very distribution archive the lockfile
// pins, so the collector has something to compare the installed bytes against.
//
// Trust boundary: the lockfile entry (resolved locator + integrity) is the
// claim, and the Yarn cache archive is the evidence. Nothing here trusts the
// cache folder name, the cached package.json, or the installed tree: an
// original is produced only when a cached archive's own bytes satisfy the
// locked SRI and the archive's manifest carries the locked identity. Anything
// else fails closed with a status instead of a guessed owner. The archive is
// hashed once and extracted from that same buffer, so the verified bytes are
// the extracted bytes.
//
// A lock entry pinning a Git commit has no archive and no integrity, so it is
// resolved against the build context manifest instead, which names what DK
// verified from the commit itself; see gitOriginal().
//
// Lifetime: one instance covers one compilation. The lockfile and the cache
// index are read once, on the first resolve; a later lockfile edit is not
// observed. Construct a new resolver for every compilation and call close()
// once the compiler has consumed the originals.

const fs = require('fs');
const path = require('path');

const lockfile = require('@yarnpkg/lockfile');
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
	readDirectory,
	readRegularFile,
	identityKey,
	contains,
	isPlainObject,
} = require('./archive-originals.cjs');

const NAME = 'DkSbomYarnOriginals';
const METADATA_FILE = '.yarn-metadata.json';
const ARCHIVE_FILE = '.yarn-tarball.tgz';
const BERRY_MARKER = /^__metadata:/m;
const {
	fail,
	worst,
	checkKeys,
	requireAbsolutePath,
	requireDirectory,
	prepareOutputRoot,
	readInstalledIdentity,
	lockedChecksum,
	extractArchive,
	gitBinding,
} = archiveOriginals(NAME);

class DkSbomYarnOriginals {
	constructor(options) {
		if (!isPlainObject(options)) throw new Error(`${NAME}: options object is required`);
		checkKeys(options, ['workdir', 'lockPath', 'cacheDir', 'outputRoot', 'contextPath'], 'options');
		this.workdir = requireDirectory(options.workdir, 'options.workdir');
		this.lockPath = requireAbsolutePath(options.lockPath, 'options.lockPath');
		this.cacheDir = requireDirectory(options.cacheDir, 'options.cacheDir');
		this.outputRoot = prepareOutputRoot(options.outputRoot, [this.workdir, this.cacheDir]);
		// The build context file DK wrote; the private originals manifest beside it is
		// the only evidence a Git-locked dependency can be resolved against.
		this.contextPath = options.contextPath === undefined ? null : requireAbsolutePath(options.contextPath, 'options.contextPath');
		this.context = null;
		this.locked = null;
		this.cached = null;
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
		const entry = this.lockEntry(identity);
		if (entry.commit) return this.gitOriginal(resource, identity, entry);
		const component = describeComponent(identity, entry);
		const originalRoot = await this.original(component, identity, entry);
		return { root: installed.root, originalRoot, component };
	}

	// Removes the trees this resolver extracted. The caller's outputRoot and the
	// Yarn cache are left alone.
	close() {
		for (const original of this.originals.values()) removeReadOnlyTree(original.scratch);
		this.originals.clear();
	}

	lockEntry(identity) {
		if (!this.locked) this.locked = readLock(this.lockPath);
		const entry = this.locked.get(identityKey(identity));
		if (!entry) throw fail('no-data', `no lockfile entry for ${identityKey(identity)}`);
		if (entry.ambiguous) {
			throw fail('no-data', `lockfile pins ${identityKey(identity)} to more than one distribution: ${entry.ambiguous.join(', ')}`);
		}
		if (!isRegistryLocator(entry.resolved)) {
			const git = GIT_LOCATOR.exec(typeof entry.resolved === 'string' ? entry.resolved : '');
			if (git) return { ...entry, commit: git[1] };

			throw fail('no-data', `lockfile entry for ${identityKey(identity)} is not an http registry archive: ${entry.resolved || 'without a locator'}`);
		}
		if (typeof entry.integrity !== 'string' || entry.integrity === '') {
			throw fail('no-data', `lockfile entry for ${identityKey(identity)} carries no integrity`);
		}
		const checksum = lockedChecksum(entry.integrity, `lockfile entry for ${identityKey(identity)}`, identityKey(identity));
		return { ...entry, checksum };
	}

	// The file binding DK verified for a Git-locked package: the commit of the
	// lock entry, read back from the build context manifest and held against that
	// very entry. The Yarn cache takes no part — it records the commit a fetch
	// claimed, not bytes it checked — and neither does any package manager: a
	// package the manifest does not list stays no-data.
	gitOriginal(resource, identity, entry) {
		if (!this.contextPath) throw fail('no-data', `no verified build context for the Git-locked ${identityKey(identity)}`);
		if (!this.context) this.context = new ContextOriginals(this.contextPath);
		return gitBinding(this.context.resolve(resource), resource, identity, entry);
	}

	async original(component, identity, entry) {
		const known = this.originals.get(component.id);
		if (known) return known.originalRoot;
		if (!this.cached) this.cached = indexCache(this.cacheDir);
		const archive = this.cacheArchive(identity, entry);
		const scratch = fs.mkdtempSync(path.join(this.outputRoot, 'original-'));
		let originalRoot;
		try {
			originalRoot = await extractArchive(archive, scratch, identity);
		} catch (error) {
			removeReadOnlyTree(scratch);
			if (error.status) throw error;
			throw fail('invalid', `archive of ${archive.dir} could not be extracted: ${error.message}`);
		}
		this.originals.set(component.id, { scratch, originalRoot });
		return originalRoot;
	}

	// The cached archive whose own bytes satisfy the locked integrity. Cache
	// folder names and cached package.json copies are claims, not evidence.
	cacheArchive(identity, entry) {
		const candidates = this.cached.get(remoteKey(entry)) || [];
		if (candidates.length === 0) {
			throw fail('no-data', `no Yarn cache entry for ${identityKey(identity)} resolved to ${entry.resolved}`);
		}
		const conflicting = candidates.find((candidate) => candidate.name !== identity.name || candidate.version !== identity.version);
		if (conflicting) {
			throw fail('invalid', `cache metadata of ${conflicting.dir} claims ${conflicting.name}@${conflicting.version} for ${identityKey(identity)}`);
		}
		const failures = [];
		for (const candidate of candidates) {
			const file = path.join(candidate.dir, ARCHIVE_FILE);
			const bytes = readRegularFile(file);
			if (!bytes) {
				failures.push(fail('no-data', `cache entry ${candidate.dir} has no readable ${ARCHIVE_FILE}`));
				continue;
			}
			if (!ssri.checkData(bytes, entry.checksum, { error: false })) {
				failures.push(fail('hash-mismatch', `cached archive of ${identityKey(identity)} does not satisfy ${entry.checksum}`));
				continue;
			}
			return { bytes, dir: candidate.dir, label: candidate.dir };
		}
		throw worst(failures);
	}
}

function readLock(lockPath) {
	const bytes = readRegularFile(lockPath);
	if (!bytes) throw fail('no-data', `no readable lockfile at ${lockPath}`);
	const text = bytes.toString('utf8');
	if (BERRY_MARKER.test(text)) throw fail('unsupported', `${lockPath} is a Yarn Berry lockfile, only Yarn 1 is supported`);
	let parsed;
	try {
		parsed = lockfile.parse(text);
	} catch (error) {
		throw fail('invalid', `lockfile ${lockPath} is malformed: ${error.message}`);
	}
	if (parsed.type !== 'success') throw fail('invalid', `lockfile ${lockPath} is not a resolved lockfile: ${parsed.type}`);
	const entries = new Map();
	for (const [selector, value] of Object.entries(parsed.object)) {
		const name = selectorName(selector);
		if (!name || !isPlainObject(value) || typeof value.version !== 'string' || value.version === '') continue;
		const key = identityKey({ name, version: value.version });
		const entry = { resolved: value.resolved, integrity: value.integrity };
		const previous = entries.get(key);
		if (!previous) {
			entries.set(key, entry);
			continue;
		}
		if (previous.ambiguous) {
			if (!previous.ambiguous.includes(distributionLabel(entry))) previous.ambiguous.push(distributionLabel(entry));
			continue;
		}
		if (distributionLabel(previous) === distributionLabel(entry)) continue;
		entries.set(key, { ambiguous: [distributionLabel(previous), distributionLabel(entry)] });
	}
	return entries;
}

// A lockfile selector is `<name>@<range>`, split at the first separator as Yarn
// does: a `git+ssh://git@…` range carries its own `@`, and splitting at the last
// one would file that entry under a different name and hide the ambiguity.
function selectorName(selector) {
	const separator = selector.indexOf('@', selector.startsWith('@') ? 1 : 0);
	if (separator <= 0) return undefined;
	return selector.slice(0, separator);
}

function distributionLabel(entry) {
	return `${entry.resolved || ''} ${entry.integrity || ''}`;
}

// Yarn 1 stores one package per cache folder, as
// `<cacheDir>/<slug>/node_modules/<name>/`, scopes included. Only those fixed
// positions are read: the cache is not searched.
function indexCache(cacheDir) {
	const entries = new Map();
	for (const slug of readDirectory(cacheDir)) {
		if (slug.startsWith('.')) continue;
		const packages = path.join(cacheDir, slug, NODE_MODULES);
		for (const name of readDirectory(packages)) {
			if (name.startsWith('@')) {
				for (const scoped of readDirectory(path.join(packages, name))) addCacheEntry(entries, path.join(packages, name, scoped));
				continue;
			}
			addCacheEntry(entries, path.join(packages, name));
		}
	}
	return entries;
}

function addCacheEntry(entries, dir) {
	const bytes = readRegularFile(path.join(dir, METADATA_FILE));
	if (!bytes) return;
	let parsed;
	try {
		parsed = JSON.parse(bytes.toString('utf8'));
	} catch {
		return;
	}
	if (!isPlainObject(parsed) || !isPlainObject(parsed.remote) || !isPlainObject(parsed.manifest)) return;
	const candidate = {
		dir,
		name: parsed.manifest.name,
		version: parsed.manifest.version,
		resolved: parsed.remote.resolved,
		integrity: parsed.remote.integrity,
	};
	if (typeof candidate.name !== 'string' || typeof candidate.version !== 'string') return;
	if (typeof candidate.resolved !== 'string' || typeof candidate.integrity !== 'string') return;
	const key = remoteKey(candidate);
	const known = entries.get(key) || [];
	known.push(candidate);
	entries.set(key, known);
}

function remoteKey(remote) {
	return `${remote.resolved}\u0000${remote.integrity}`;
}

module.exports = DkSbomYarnOriginals;
