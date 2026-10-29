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
// Lifetime: one instance covers one compilation. The lockfile and the cache
// index are read once, on the first resolve; a later lockfile edit is not
// observed. Construct a new resolver for every compilation and call close()
// once the compiler has consumed the originals.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const lockfile = require('@yarnpkg/lockfile');
const ssri = require('ssri');
const tar = require('tar');

const NAME = 'DkSbomYarnOriginals';
const NODE_MODULES = 'node_modules';
const METADATA_FILE = '.yarn-metadata.json';
const ARCHIVE_FILE = '.yarn-tarball.tgz';
const ARCHIVE_PREFIX = 'package';
const BERRY_MARKER = /^__metadata:/m;
const EXTRACTABLE_ENTRY_TYPES = ['File', 'OldFile', 'Directory'];
const DIGEST_BYTES = new Map([
	['sha1', 20],
	['sha256', 32],
	['sha384', 48],
	['sha512', 64],
]);
const SUPPORTED_SPELLING = /^(sha1|sha256|sha384|sha512)(?![a-z0-9])/i;

class DkSbomYarnOriginals {
	constructor(options) {
		if (!isPlainObject(options)) throw new Error(`${NAME}: options object is required`);
		checkKeys(options, ['workdir', 'lockPath', 'cacheDir', 'outputRoot'], 'options');
		this.workdir = requireDirectory(options.workdir, 'options.workdir');
		this.lockPath = requireAbsolutePath(options.lockPath, 'options.lockPath');
		this.cacheDir = requireDirectory(options.cacheDir, 'options.cacheDir');
		this.outputRoot = prepareOutputRoot(options.outputRoot, [this.workdir, this.cacheDir]);
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
			throw fail('no-data', `lockfile entry for ${identityKey(identity)} is not an http registry archive: ${entry.resolved || 'without a locator'}`);
		}
		if (typeof entry.integrity !== 'string' || entry.integrity === '') {
			throw fail('no-data', `lockfile entry for ${identityKey(identity)} carries no integrity`);
		}
		// This adapter supports SHA-1/256/384/512 SRI, the spellings Yarn 1
		// lockfiles carry, and the archive is checked against the strongest one the
		// entry holds: a weaker token may not stand in for a strong one that does
		// not hold, and a token whose digest cannot be read is a refusal rather than
		// a reason to fall back. A checksum is never synthesized from a URL fragment
		// or a Git commit.
		//
		// SHA-1 is collision-prone, so a sha1-only entry proves no more than that
		// the archive is the one the package manager already trusted when it wrote
		// the lockfile. It is reported verbatim, never restated as a stronger pin.
		const checksum = ssri.parse(entry.integrity);
		const algorithms = checksum ? Object.keys(checksum).filter((algorithm) => DIGEST_BYTES.has(algorithm)) : [];
		const kept = new Set(algorithms.flatMap((algorithm) => checksum[algorithm].map((hash) => hash.source)));
		for (const token of entry.integrity.trim().split(/\s+/)) {
			// ssri drops a token it cannot read, which would leave the check to a
			// weaker one: a token naming an algorithm this adapter supports is either
			// kept or a refusal.
			if (SUPPORTED_SPELLING.test(token) && !kept.has(token)) {
				throw fail('invalid', `lockfile entry for ${identityKey(identity)} carries an unreadable checksum: ${token}`);
			}
		}
		if (algorithms.length === 0) {
			throw fail('unsupported', `unsupported checksum spelling for ${identityKey(identity)}: ${entry.integrity}`);
		}
		for (const algorithm of algorithms) {
			for (const hash of checksum[algorithm]) {
				if (!isCanonicalDigest(algorithm, hash.digest)) {
					throw fail('invalid', `lockfile entry for ${identityKey(identity)} carries a malformed ${algorithm} checksum: ${hash.toString()}`);
				}
			}
		}
		const algorithm = checksum.pickAlgorithm(undefined, algorithms);
		const strongest = checksum[algorithm];
		if (strongest.length !== 1) {
			throw fail('no-data', `lockfile entry for ${identityKey(identity)} carries ${strongest.length} ${algorithm} checksums`);
		}
		return { ...entry, checksum: strongest[0].toString() };
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
			return { bytes, dir: candidate.dir };
		}
		throw worst(failures);
	}
}

function findPackageRoot(resource) {
	let candidate = path.dirname(resource);
	for (;;) {
		const parent = path.dirname(candidate);
		if (parent === candidate) return undefined;
		if (path.basename(parent) === NODE_MODULES) return { root: candidate, directoryName: path.basename(candidate), scope: null };
		const grandparent = path.dirname(parent);
		if (path.basename(parent).startsWith('@') && path.basename(grandparent) === NODE_MODULES) {
			return { root: candidate, directoryName: path.basename(candidate), scope: path.basename(parent) };
		}
		candidate = parent;
	}
}

// The physical manifest of the nearest installed package, not the nearest
// package.json: a nested package.json may only carry a module type.
function readInstalledIdentity(installed, resource) {
	if (fs.realpathSync(installed.root) !== installed.root) {
		throw fail('no-data', `installed package ${installed.root} is a link, not an installed distribution`);
	}
	if (fs.realpathSync(resource) !== resource) {
		throw fail('invalid', `source ${resource} is reached through a link`);
	}
	const manifest = path.join(installed.root, 'package.json');
	const bytes = readRegularFile(manifest);
	if (!bytes) throw fail('no-data', `installed package ${installed.root} has no readable package.json`);
	let parsed;
	try {
		parsed = JSON.parse(bytes.toString('utf8'));
	} catch (error) {
		throw fail('invalid', `installed manifest ${manifest} is malformed: ${error.message}`);
	}
	if (!isPlainObject(parsed) || typeof parsed.name !== 'string' || parsed.name === '' || typeof parsed.version !== 'string' || parsed.version === '') {
		throw fail('invalid', `installed manifest ${manifest} has no exact name and version`);
	}
	const expected = installed.scope ? `${installed.scope}/${installed.directoryName}` : installed.directoryName;
	if (parsed.name !== expected) {
		throw fail('no-data', `installed directory ${installed.root} holds ${parsed.name}, an alias this version does not own`);
	}
	return { name: parsed.name, version: parsed.version };
}

// A Git or file locator is not a distribution archive this version can prove.
function isRegistryLocator(resolved) {
	if (typeof resolved !== 'string') return false;
	let url;
	try {
		url = new URL(resolved);
	} catch {
		return false;
	}
	return (url.protocol === 'https:' || url.protocol === 'http:') && url.username === '' && url.password === '';
}

function describeComponent(identity, entry) {
	const id = `node:${crypto
		.createHash('sha256')
		.update(JSON.stringify([identity.name, identity.version, entry.resolved, entry.integrity]))
		.digest('hex')}`;
	return {
		id,
		name: identity.name,
		version: identity.version,
		source: { kind: 'node', locator: entry.resolved, checksum: entry.integrity },
	};
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

// Extraction is driven by the hashed buffer only. Every member is checked
// before it is written: the archive's own `package/` prefix, clean relative
// paths, no duplicate members and plain files and directories only.
async function extractArchive(archive, scratch, identity) {
	const violations = [];
	const seen = new Set();
	const extractor = tar.x({
		cwd: scratch,
		strict: true,
		preservePaths: false,
		noChmod: true,
		filter: (entryPath, entry) => {
			const reason = memberViolation(entryPath, entry, seen);
			if (reason) violations.push(reason);
			return !reason;
		},
	});
	await new Promise((resolve, reject) => {
		let failure;
		extractor.on('error', (error) => {
			failure = failure || error;
			// A fatal error leaves the parser aborted, and an aborted parser never
			// closes; every other error is a strict-mode warning whose entry is
			// unpended, so the stream still closes with its writes finished. After an
			// abort a write may still be in flight when the scratch tree is removed.
			if (error.name === 'CwdError' || error.tarCode === 'TAR_ABORT') reject(error);
		});
		extractor.on('close', () => (failure ? reject(failure) : resolve()));
		extractor.end(archive.bytes);
	});
	if (violations.length > 0) throw worst(violations);
	const originalRoot = path.join(scratch, ARCHIVE_PREFIX);
	checkArchiveIdentity(originalRoot, archive, identity);
	makeReadOnly(originalRoot);
	return originalRoot;
}

function memberViolation(entryPath, entry, seen) {
	const type = entry.type;
	if (!EXTRACTABLE_ENTRY_TYPES.includes(type)) {
		return fail('unsupported', `archive member ${entryPath} is a ${type}, which this version does not extract`);
	}
	const normalized = entryPath.replace(/\/+$/, '');
	const segments = normalized.split('/');
	if (
		entryPath.includes('\\') ||
		segments.includes('..') ||
		segments.includes('.') ||
		segments.includes('')
	) {
		return fail('invalid', `archive member ${entryPath} is not a clean relative path`);
	}
	if (segments[0] !== ARCHIVE_PREFIX) {
		return fail('unsupported', `archive member ${entryPath} is outside the ${ARCHIVE_PREFIX}/ prefix this version extracts`);
	}
	if (seen.has(normalized)) return fail('invalid', `archive member ${entryPath} occurs more than once`);
	seen.add(normalized);
	return undefined;
}

function checkArchiveIdentity(originalRoot, archive, identity) {
	const bytes = readRegularFile(path.join(originalRoot, 'package.json'));
	if (!bytes) throw fail('invalid', `archive of ${archive.dir} has no package.json`);
	let parsed;
	try {
		parsed = JSON.parse(bytes.toString('utf8'));
	} catch (error) {
		throw fail('invalid', `archive manifest of ${archive.dir} is malformed: ${error.message}`);
	}
	if (!isPlainObject(parsed) || parsed.name !== identity.name || parsed.version !== identity.version) {
		throw fail('invalid', `archive of ${archive.dir} holds ${parsed && parsed.name}@${parsed && parsed.version}, not ${identityKey(identity)}`);
	}
}

function makeReadOnly(root) {
	walkOwnTree(root, (target, isDirectory) => fs.chmodSync(target, isDirectory ? 0o555 : 0o444));
}

function removeReadOnlyTree(root) {
	// A read-only directory cannot be unlinked from, so ownership is restored
	// before the tree is removed.
	walkOwnTree(root, (target, isDirectory) => {
		if (isDirectory) fs.chmodSync(target, 0o700);
	});
	fs.rmSync(root, { recursive: true, force: true });
}

// Depth-first over physical entries of this resolver's own tree; links are
// never followed, and directories are handled after their children.
function walkOwnTree(root, visit) {
	let stat;
	try {
		stat = fs.lstatSync(root);
	} catch {
		return;
	}
	if (stat.isDirectory()) {
		fs.chmodSync(root, 0o700);
		for (const child of readDirectory(root)) walkOwnTree(path.join(root, child), visit);
	}
	visit(root, stat.isDirectory());
}

function readDirectory(directory) {
	try {
		return fs.readdirSync(directory).sort();
	} catch {
		return [];
	}
}

function readRegularFile(file) {
	let stat;
	try {
		stat = fs.lstatSync(file);
	} catch {
		return undefined;
	}
	if (!stat.isFile()) return undefined;
	try {
		return fs.readFileSync(file);
	} catch {
		return undefined;
	}
}

function prepareOutputRoot(value, forbidden) {
	const outputRoot = requireAbsolutePath(value, 'options.outputRoot');
	const parent = path.dirname(outputRoot);
	if (!fs.existsSync(parent) || !fs.statSync(parent).isDirectory()) {
		throw new Error(`${NAME}: options.outputRoot parent ${parent} must be an existing directory`);
	}
	if (fs.existsSync(outputRoot)) {
		if (!fs.statSync(outputRoot).isDirectory()) throw new Error(`${NAME}: options.outputRoot must be a directory`);
		if (fs.readdirSync(outputRoot).length > 0) throw new Error(`${NAME}: options.outputRoot ${outputRoot} must be empty`);
	} else {
		fs.mkdirSync(outputRoot);
	}
	const resolved = fs.realpathSync(outputRoot);
	for (const other of forbidden) {
		if (contains(other, resolved) || contains(resolved, other)) {
			throw new Error(`${NAME}: options.outputRoot ${resolved} overlaps ${other}`);
		}
	}
	return resolved;
}

const FAILURE_STATUSES = ['invalid', 'hash-mismatch', 'unsupported', 'no-data'];

function fail(status, reason) {
	const error = new Error(`${NAME}: ${reason}`);
	error.status = status;
	return error;
}

function worst(failures) {
	const status = FAILURE_STATUSES.find((candidate) => failures.some((error) => error.status === candidate));
	return failures.find((error) => error.status === status);
}

// The base64 spelling of exactly one digest of that algorithm. Node decodes
// base64 leniently, so the digest is re-encoded: a truncated, repadded or
// otherwise rewritten digest is not the checksum the lockfile claims.
function isCanonicalDigest(algorithm, digest) {
	const decoded = Buffer.from(digest, 'base64');
	return decoded.length === DIGEST_BYTES.get(algorithm) && decoded.toString('base64') === digest;
}

function identityKey(identity) {
	return `${identity.name}@${identity.version}`;
}

// Cache entries are keyed by the distribution the lockfile pins, so an entry
// whose metadata claims another identity for those very bytes is seen as the
// contradiction it is instead of being silently skipped.
function remoteKey(remote) {
	return `${remote.resolved}\u0000${remote.integrity}`;
}

function contains(root, candidate) {
	return candidate === root || candidate.startsWith(root.endsWith(path.sep) ? root : root + path.sep);
}

function isPlainObject(value) {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function checkKeys(object, known, where) {
	for (const key of Object.keys(object)) {
		if (!known.includes(key)) throw new Error(`${NAME}: unknown ${where} field ${JSON.stringify(key)}`);
	}
}

function requireAbsolutePath(value, where) {
	if (typeof value !== 'string' || value === '') throw new Error(`${NAME}: ${where} must be a non-empty string`);
	if (!path.isAbsolute(value)) throw new Error(`${NAME}: ${where} must be an absolute path`);
	return path.resolve(value);
}

function requireDirectory(value, where) {
	const resolved = requireAbsolutePath(value, where);
	const real = fs.realpathSync(resolved);
	if (!fs.statSync(real).isDirectory()) throw new Error(`${NAME}: ${where} must be a directory`);
	return real;
}

module.exports = DkSbomYarnOriginals;
