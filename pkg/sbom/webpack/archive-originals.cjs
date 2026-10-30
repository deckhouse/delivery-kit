'use strict';

// What the npm and Yarn original resolvers do identically: hold a lockfile
// checksum to the SRI rules this gate accepts, turn a verified archive buffer
// into an owned read-only tree, and describe the component that tree belongs
// to. The package-manager-specific parts — how a lockfile states an entry, and
// where a cache keeps the archive — stay with each resolver.
//
// Nothing here reads a cache index, a cached manifest or the installed tree as
// evidence: the only inputs are the lockfile claim the caller passes in and the
// archive bytes the caller has already checked against it.
//
// The helpers that can refuse carry the caller's own name in the message, so
// they are built per resolver through archiveOriginals(name).

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ssri = require('ssri');
const tar = require('tar');

const NODE_MODULES = 'node_modules';
// npm and Yarn archives alike keep the distribution under `package/`.
const ARCHIVE_PREFIX = 'package';
const EXTRACTABLE_ENTRY_TYPES = ['File', 'OldFile', 'Directory'];
// A dependency pinned to a full commit, which no archive and no cache can
// stand in for; see the Git branch of each resolver.
const GIT_LOCATOR = /^git\+(?:https|ssh):\/\/[^\s#]+#([0-9a-f]{40})$/;
const FAILURE_STATUSES = ['invalid', 'hash-mismatch', 'unsupported', 'no-data'];
const DIGEST_BYTES = new Map([
	['sha1', 20],
	['sha256', 32],
	['sha384', 48],
	['sha512', 64],
]);
const SUPPORTED_SPELLING = /^(sha1|sha256|sha384|sha512)(?![a-z0-9])/i;

function archiveOriginals(name) {
	if (typeof name !== 'string' || name === '') throw new Error('archiveOriginals: a resolver name is required');

	function fail(status, reason) {
		const error = new Error(`${name}: ${reason}`);
		error.status = status;
		return error;
	}

	function worst(failures) {
		const status = FAILURE_STATUSES.find((candidate) => failures.some((error) => error.status === candidate));
		return failures.find((error) => error.status === status);
	}

	function checkKeys(object, known, where) {
		for (const key of Object.keys(object)) {
			if (!known.includes(key)) throw new Error(`${name}: unknown ${where} field ${JSON.stringify(key)}`);
		}
	}

	function requireAbsolutePath(value, where) {
		if (typeof value !== 'string' || value === '') throw new Error(`${name}: ${where} must be a non-empty string`);
		if (!path.isAbsolute(value)) throw new Error(`${name}: ${where} must be an absolute path`);
		return path.resolve(value);
	}

	function requireDirectory(value, where) {
		const resolved = requireAbsolutePath(value, where);
		const real = fs.realpathSync(resolved);
		if (!fs.statSync(real).isDirectory()) throw new Error(`${name}: ${where} must be a directory`);
		return real;
	}

	function prepareOutputRoot(value, forbidden) {
		const outputRoot = requireAbsolutePath(value, 'options.outputRoot');
		const parent = path.dirname(outputRoot);
		if (!fs.existsSync(parent) || !fs.statSync(parent).isDirectory()) {
			throw new Error(`${name}: options.outputRoot parent ${parent} must be an existing directory`);
		}
		if (fs.existsSync(outputRoot)) {
			if (!fs.statSync(outputRoot).isDirectory()) throw new Error(`${name}: options.outputRoot must be a directory`);
			if (fs.readdirSync(outputRoot).length > 0) throw new Error(`${name}: options.outputRoot ${outputRoot} must be empty`);
		} else {
			fs.mkdirSync(outputRoot);
		}
		const resolved = fs.realpathSync(outputRoot);
		for (const other of forbidden) {
			if (contains(other, resolved) || contains(resolved, other)) {
				throw new Error(`${name}: options.outputRoot ${resolved} overlaps ${other}`);
			}
		}
		return resolved;
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

	// The one checksum an archive is checked against: the strongest token the
	// lock entry holds. A weaker token may not stand in for a strong one that
	// does not hold, and a token whose digest cannot be read is a refusal rather
	// than a reason to fall back. A checksum is never synthesized from a URL
	// fragment or a Git commit.
	//
	// SHA-1 is collision-prone, so a sha1-only entry proves no more than that the
	// archive is the one the package manager already trusted when it wrote the
	// lockfile. It is reported verbatim, never restated as a stronger pin.
	//
	// `entryLabel` names the lock entry and `subject` the distribution, so each
	// resolver refuses in the vocabulary of its own lockfile.
	function lockedChecksum(integrity, entryLabel, subject) {
		const checksum = ssri.parse(integrity);
		const algorithms = checksum ? Object.keys(checksum).filter((algorithm) => DIGEST_BYTES.has(algorithm)) : [];
		const kept = new Set(algorithms.flatMap((algorithm) => checksum[algorithm].map((hash) => hash.source)));
		for (const token of integrity.trim().split(/\s+/)) {
			// ssri drops a token it cannot read, which would leave the check to a
			// weaker one: a token naming an algorithm this adapter supports is either
			// kept or a refusal.
			if (SUPPORTED_SPELLING.test(token) && !kept.has(token)) {
				throw fail('invalid', `${entryLabel} carries an unreadable checksum: ${token}`);
			}
		}
		if (algorithms.length === 0) {
			throw fail('unsupported', `unsupported checksum spelling for ${subject}: ${integrity}`);
		}
		for (const algorithm of algorithms) {
			for (const hash of checksum[algorithm]) {
				if (!isCanonicalDigest(algorithm, hash.digest)) {
					throw fail('invalid', `${entryLabel} carries a malformed ${algorithm} checksum: ${hash.toString()}`);
				}
			}
		}
		const algorithm = checksum.pickAlgorithm(undefined, algorithms);
		const strongest = checksum[algorithm];
		if (strongest.length !== 1) {
			throw fail('no-data', `${entryLabel} carries ${strongest.length} ${algorithm} checksums`);
		}
		return strongest[0].toString();
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
				// unpended, so the stream still closes with its writes finished. After
				// an abort a write may still be in flight when the scratch tree is
				// removed.
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
		if (!bytes) throw fail('invalid', `archive ${archive.label} has no package.json`);
		let parsed;
		try {
			parsed = JSON.parse(bytes.toString('utf8'));
		} catch (error) {
			throw fail('invalid', `archive manifest of ${archive.label} is malformed: ${error.message}`);
		}
		if (!isPlainObject(parsed) || parsed.name !== identity.name || parsed.version !== identity.version) {
			throw fail('invalid', `archive ${archive.label} holds ${parsed && parsed.name}@${parsed && parsed.version}, not ${identityKey(identity)}`);
		}
	}

	// The binding DK verified for a Git-locked package, held against the lock
	// entry it was asked about: a manifest naming another repository state, or
	// another package, proves nothing about this one.
	function gitBinding(binding, resource, identity, entry) {
		const component = binding.component;
		if (component.source.kind !== 'node' || component.source.locator !== entry.resolved || component.source.checksum !== `git-commit:sha1:${entry.commit}`) {
			throw fail('invalid', `the verified original of ${resource} does not pin ${entry.resolved}`);
		}
		if (component.name !== identity.name || component.version !== identity.version) {
			throw fail('invalid', `the verified original of ${resource} holds ${component.name}@${component.version}, not ${identityKey(identity)}`);
		}
		return { path: binding.path, sha256: binding.sha256, component };
	}

	return Object.freeze({
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
	});
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

// The pinned facts of one distribution, hashed: two lock entries that pin the
// same bytes of the same package are one component.
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

function contains(root, candidate) {
	return candidate === root || candidate.startsWith(root.endsWith(path.sep) ? root : root + path.sep);
}

function isPlainObject(value) {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

module.exports = {
	archiveOriginals,
	NODE_MODULES,
	ARCHIVE_PREFIX,
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
};
