'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const { execFileSync } = require('node:child_process');
const { test, before, after } = require('node:test');

const tar = require('tar');

const NpmOriginals = require('./npm-originals.cjs');

let scratch;
let packedRoot;
const packedCache = new Map();

before(() => {
	scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-npm-originals-')));
	packedRoot = path.join(scratch, 'packed');
	fs.mkdirSync(packedRoot);
});

after(() => {
	fs.rmSync(scratch, { recursive: true, force: true });
});

// A real npm distribution archive, with the SRI npm itself would publish.
function distribution(name, version, body) {
	const key = `${name}@${version}@${body || ''}`;
	if (packedCache.has(key)) return packedCache.get(key);
	const source = path.join(scratch, 'sources', key.replace(/[^a-zA-Z0-9.@]/g, '-'));
	fs.mkdirSync(source, { recursive: true });
	fs.writeFileSync(path.join(source, 'package.json'), `${JSON.stringify({ name, version, main: 'index.js' }, null, 2)}\n`);
	fs.writeFileSync(path.join(source, 'index.js'), body || `module.exports = ${JSON.stringify(`${name}@${version}`)};\n`);
	fs.writeFileSync(path.join(source, 'NOTICE.txt'), `notice for ${name}\n`);
	const packed = execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', packedRoot, source], { encoding: 'utf8' }).trim().split('\n').pop();
	// Two distributions of one name and version would otherwise overwrite each
	// other: npm packs by name and version alone.
	const file = path.join(packedRoot, `${key.replace(/[^a-zA-Z0-9.@]/g, '-')}.tgz`);
	fs.renameSync(path.join(packedRoot, packed), file);
	const bytes = fs.readFileSync(file);
	const entry = {
		name,
		version,
		bytes,
		file,
		integrity: `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`,
		resolved: `https://registry.npmjs.org/${name}/-/${packed}`,
	};
	packedCache.set(key, entry);
	return entry;
}

// A distribution that carries another package inside its own tarball, as npm
// packs a bundleDependencies entry.
function bundlingDistribution(name, version, bundled) {
	const key = `${name}@${version}+bundle`;
	if (packedCache.has(key)) return packedCache.get(key);
	const source = path.join(scratch, 'sources', key.replace(/[^a-zA-Z0-9.@]/g, '-'));
	const inner = path.join(source, 'node_modules', bundled.name);
	fs.mkdirSync(inner, { recursive: true });
	fs.writeFileSync(path.join(source, 'package.json'), `${JSON.stringify({ name, version, main: 'index.js', dependencies: { [bundled.name]: bundled.version }, bundleDependencies: [bundled.name] }, null, 2)}\n`);
	fs.writeFileSync(path.join(source, 'index.js'), `module.exports = require(${JSON.stringify(bundled.name)});\n`);
	tar.x({ cwd: inner, strip: 1, sync: true, file: bundled.file });
	const packed = execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', packedRoot, source], { encoding: 'utf8' }).trim().split('\n').pop();
	const file = path.join(packedRoot, `${key.replace(/[^a-zA-Z0-9.@]/g, '-')}.tgz`);
	fs.renameSync(path.join(packedRoot, packed), file);
	const bytes = fs.readFileSync(file);
	const entry = {
		name,
		version,
		bytes,
		file,
		integrity: `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`,
		resolved: `https://registry.npmjs.org/${name}/-/${packed}`,
	};
	packedCache.set(key, entry);
	return entry;
}

function area(id) {
	const root = path.join(scratch, 'areas', id);
	const workdir = path.join(root, 'work');
	// The cache folder npm is given; its content store is the `_cacache` below it.
	const cacheHome = path.join(root, 'cache');
	fs.mkdirSync(path.join(workdir, 'node_modules'), { recursive: true });
	fs.mkdirSync(path.join(root, 'out'), { recursive: true });
	const cacheDir = path.join(cacheHome, '_cacache');
	fs.mkdirSync(cacheDir, { recursive: true });
	return {
		root,
		workdir,
		cacheHome,
		cacheDir,
		outputRoot: path.join(root, 'out', 'originals'),
		lockPath: path.join(workdir, 'package-lock.json'),
		installedDir: (location) => path.join(workdir, ...location.split('/')),
		resolver: (overrides) =>
			new NpmOriginals({ workdir, lockPath: path.join(workdir, 'package-lock.json'), cacheDir, outputRoot: path.join(root, 'out', 'originals'), ...overrides }),
	};
}

// npm itself writes the content-addressed store this adapter reads.
function cache(where, dist) {
	const out = execFileSync('npm', ['cache', 'add', dist.file, '--cache', where.cacheHome, '--offline'], { encoding: 'utf8' });
	const hex = crypto.createHash('sha512').update(dist.bytes).digest('hex');
	const file = path.join(where.cacheDir, 'content-v2', 'sha512', hex.slice(0, 2), hex.slice(2, 4), hex.slice(4));
	if (!fs.existsSync(file)) throw new Error(`npm did not cache ${dist.name} at ${file}: ${out}`);
	return where.cacheDir;
}

// A content entry placed at the address a checksum names, for the spellings npm
// no longer writes itself.
function cacheAt(where, algorithm, bytes) {
	const hex = crypto.createHash(algorithm).update(bytes).digest('hex');
	const file = path.join(where.cacheDir, 'content-v2', algorithm, hex.slice(0, 2), hex.slice(2, 4), hex.slice(4));
	fs.mkdirSync(path.dirname(file), { recursive: true });
	fs.writeFileSync(file, bytes);
	return file;
}

function install(where, dist, location) {
	const target = where.installedDir(location || `node_modules/${dist.name}`);
	fs.mkdirSync(target, { recursive: true });
	tar.x({ cwd: target, strip: 1, sync: true, file: dist.file });
	return target;
}

function lock(where, packages, overrides = {}) {
	const document = {
		name: 'project',
		version: '1.0.0',
		lockfileVersion: 3,
		requires: true,
		packages: { '': { name: 'project', version: '1.0.0' }, ...packages },
		...overrides,
	};
	let body = JSON.stringify(document, null, 2);
	if (overrides.rawEdit) body = overrides.rawEdit(body);
	fs.writeFileSync(where.lockPath, body);
}

function lockEntry(dist, overrides) {
	return { version: dist.version, resolved: dist.resolved, integrity: dist.integrity, ...overrides };
}

async function rejection(promise) {
	try {
		await promise;
	} catch (error) {
		return error;
	}
	assert.fail('expected a rejection');
}

function relativeFiles(root) {
	const files = [];
	const walk = (dir) => {
		for (const child of fs.readdirSync(dir).sort()) {
			const target = path.join(dir, child);
			if (fs.lstatSync(target).isDirectory()) walk(target);
			else files.push(path.relative(root, target));
		}
	};
	walk(root);
	return files;
}

test('binds an installed package to an original extracted from the npm cache content', async () => {
	const where = area('registry');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	lock(where, { 'node_modules/pkg-a': lockEntry(dist) });

	const resolver = where.resolver();
	const binding = await resolver.resolve(path.join(installed, 'index.js'));
	assert.equal(binding.root, installed);
	assert.deepEqual(binding.component, {
		id: binding.component.id,
		name: 'pkg-a',
		version: '1.2.3',
		source: { kind: 'node', locator: dist.resolved, checksum: dist.integrity },
	});
	assert.match(binding.component.id, /^node:[0-9a-f]{64}$/);
	// The original is the archive, extracted beside the install and never from it.
	assert.deepEqual(relativeFiles(binding.originalRoot).sort(), ['NOTICE.txt', 'index.js', 'package.json']);
	assert.ok(binding.originalRoot.startsWith(where.outputRoot + path.sep));
	assert.deepEqual(fs.readFileSync(path.join(binding.originalRoot, 'index.js')), fs.readFileSync(path.join(installed, 'index.js')));
	assert.equal(fs.statSync(path.join(binding.originalRoot, 'index.js')).mode & 0o222, 0, 'the original must be read-only');

	resolver.close();
	assert.equal(fs.existsSync(binding.originalRoot), false);
	assert.deepEqual(fs.readdirSync(where.outputRoot), []);
});

test('extracts one distribution once, for every installed copy of it', async () => {
	const where = area('shared');
	const dist = distribution('pkg-a', '1.2.3');
	const first = install(where, dist);
	const second = install(where, dist, 'node_modules/host/node_modules/pkg-a');
	fs.writeFileSync(where.installedDir('node_modules/host/package.json'), JSON.stringify({ name: 'host', version: '2.0.0' }));
	cache(where, dist);
	lock(where, {
		'node_modules/pkg-a': lockEntry(dist),
		'node_modules/host/node_modules/pkg-a': lockEntry(dist),
	});

	const resolver = where.resolver();
	const one = await resolver.resolve(path.join(first, 'index.js'));
	const two = await resolver.resolve(path.join(second, 'index.js'));
	assert.notEqual(one.root, two.root, 'a nested install is its own installed root');
	assert.equal(one.originalRoot, two.originalRoot, 'one pinned distribution, one extracted original');
	resolver.close();
});

test('binds the nested installed copy against its own lock entry', async () => {
	const where = area('nested-identity');
	const outer = distribution('pkg-a', '1.2.3');
	const inner = distribution('pkg-a', '2.0.0');
	install(where, outer);
	const nested = install(where, inner, 'node_modules/host/node_modules/pkg-a');
	fs.writeFileSync(where.installedDir('node_modules/host/package.json'), JSON.stringify({ name: 'host', version: '2.0.0' }));
	cache(where, outer);
	cache(where, inner);
	lock(where, {
		'node_modules/pkg-a': lockEntry(outer),
		'node_modules/host/node_modules/pkg-a': lockEntry(inner),
	});

	const resolver = where.resolver();
	const binding = await resolver.resolve(path.join(nested, 'index.js'));
	assert.equal(binding.component.version, '2.0.0');
	assert.equal(binding.component.source.checksum, inner.integrity);
	resolver.close();
});

test('binds a scoped package through its scope directory', async () => {
	const where = area('scoped');
	const dist = distribution('@scope/pkg-s', '0.1.0');
	const installed = install(where, dist, 'node_modules/@scope/pkg-s');
	cache(where, dist);
	lock(where, { 'node_modules/@scope/pkg-s': lockEntry(dist) });

	const resolver = where.resolver();
	const binding = await resolver.resolve(path.join(installed, 'index.js'));
	assert.equal(binding.component.name, '@scope/pkg-s');
	resolver.close();
});

test('binds an aliased install through the name of its lock entry', async () => {
	const where = area('aliased');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist, 'node_modules/pkg-a');
	cache(where, dist);
	// npm states an alias with an explicit name; the directory is still the key.
	lock(where, { 'node_modules/pkg-a': lockEntry(dist, { name: 'pkg-a' }) });

	const resolver = where.resolver();
	assert.equal((await resolver.resolve(path.join(installed, 'index.js'))).component.name, 'pkg-a');
	resolver.close();

	// An entry naming another package than its directory is an npm alias: the
	// directory does not say what it holds, so these bytes are not its to own.
	const wrong = area('aliased-wrong');
	install(wrong, dist);
	cache(wrong, dist);
	lock(wrong, { 'node_modules/pkg-a': lockEntry(dist, { name: 'pkg-b' }) });
	const error = await rejection(wrong.resolver().resolve(path.join(wrong.installedDir('node_modules/pkg-a'), 'index.js')));
	assert.equal(error.status, 'no-data');
	assert.match(error.message, /is an npm alias of pkg-b/);
});

test('refuses a lock entry whose version is not the installed one', async () => {
	const where = area('version-mismatch');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	lock(where, { 'node_modules/pkg-a': lockEntry(dist, { version: '9.9.9' }) });

	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'invalid');
	assert.match(error.message, /claims pkg-a@9\.9\.9 for node_modules\/pkg-a, which holds pkg-a@1\.2\.3/);
});

test('reports no-data for an installed path the lockfile does not state', async () => {
	const where = area('unstated');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	lock(where, { 'node_modules/other': lockEntry(dist) });

	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'no-data');
	assert.match(error.message, /no package-lock entry for node_modules\/pkg-a/);
});

test('refuses a lockfile that states one member twice, wherever it is', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	for (const [id, edit, key] of [
		['the entry itself', (body) => body.replace('"node_modules/pkg-a": {', '"node_modules/pkg-a": {"version": "9.9.9"},\n    "node_modules/pkg-a": {'), 'node_modules/pkg-a'],
		['another object', (body) => body.replace('"name": "project",', '"name": "project",\n    "name": "other",'), 'name'],
		['an escaped name', (body) => body.replace('"packages": {', '"packages": {\n    "a\\u0062": 1,\n    "ab": 2,'), 'ab'],
	]) {
		const where = area(`duplicate-${id.replace(/\W/g, '-')}`);
		const installed = install(where, dist);
		cache(where, dist);
		lock(where, { 'node_modules/pkg-a': lockEntry(dist) }, { rawEdit: edit });
		const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
		assert.equal(error.status, 'no-data', id);
		assert.equal(error.message, `DkSbomNpmOriginals: npm lockfile has a duplicate key: ${JSON.stringify(key)}`, id);
	}
});

test('reads a lockfile whose values merely look like member names', async () => {
	const where = area('duplicate-lookalike');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	// A value that spells a member name, and one name per object repeated in
	// objects of its own: neither is a duplicate.
	lock(where, {
		'node_modules/pkg-a': lockEntry(dist),
		'node_modules/other': { version: '1.0.0', resolved: 'file:x', funding: '"node_modules/pkg-a": {' },
	});

	const resolver = where.resolver();
	assert.equal((await resolver.resolve(path.join(installed, 'index.js'))).component.version, '1.2.3');
	resolver.close();
});

test('reads only what both trees of a lockfileVersion 2 agree on', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	const twin = distribution('pkg-a', '1.2.3', 'module.exports = "twin";\n');
	for (const [id, dependencies, match] of [
		['no tree at all', undefined, /only in packages, not in its dependencies tree/],
		['a tree without this install', { other: { version: '1.0.0' } }, /only in packages, not in its dependencies tree/],
		['a tree naming other bytes', { 'pkg-a': { version: dist.version, resolved: twin.resolved, integrity: twin.integrity } }, /in packages and .* in its dependencies tree/],
		['a tree naming another version', { 'pkg-a': { version: '9.9.9', resolved: dist.resolved, integrity: dist.integrity } }, /in packages and .* in its dependencies tree/],
	]) {
		const where = area(`legacy-${id.replace(/\W/g, '-')}`);
		const installed = install(where, dist);
		cache(where, dist);
		lock(where, { 'node_modules/pkg-a': lockEntry(dist) }, { lockfileVersion: 2, dependencies });
		const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
		assert.equal(error.status, 'no-data', id);
		assert.match(error.message, match, id);
	}
});

test('accepts a lockfileVersion 2 whose legacy tree agrees, nested installs included', async () => {
	const where = area('legacy-agreeing');
	const dist = distribution('pkg-a', '1.2.3');
	const nested = distribution('pkg-a', '2.0.0');
	const installed = install(where, dist);
	const deep = install(where, nested, 'node_modules/host/node_modules/pkg-a');
	fs.writeFileSync(where.installedDir('node_modules/host/package.json'), JSON.stringify({ name: 'host', version: '2.0.0' }));
	cache(where, dist);
	cache(where, nested);
	lock(where, { 'node_modules/pkg-a': lockEntry(dist), 'node_modules/host/node_modules/pkg-a': lockEntry(nested) }, {
		lockfileVersion: 2,
		dependencies: {
			'pkg-a': { version: dist.version, resolved: dist.resolved, integrity: dist.integrity },
			host: { version: '2.0.0', dependencies: { 'pkg-a': { version: nested.version, resolved: nested.resolved, integrity: nested.integrity } } },
		},
	});

	const resolver = where.resolver();
	assert.equal((await resolver.resolve(path.join(installed, 'index.js'))).component.version, '1.2.3');
	assert.equal((await resolver.resolve(path.join(deep, 'index.js'))).component.version, '2.0.0');
	resolver.close();
});

// A bundled dependency travels inside its parent's tarball, so its installed
// bytes are the parent's, whatever its own entry says they are.
test('reports no-data for a dependency bundled into its parent distribution', async () => {
	const where = area('bundled');
	const bundled = distribution('pkg-b', '0.5.0');
	const host = bundlingDistribution('host', '3.0.0', bundled);
	const installed = install(where, host);
	cache(where, host);
	assert.ok(fs.existsSync(path.join(installed, 'node_modules', 'pkg-b', 'index.js')), 'npm pack must carry the bundled package');
	lock(where, {
		'node_modules/host': lockEntry(host),
		'node_modules/host/node_modules/pkg-b': { version: bundled.version, inBundle: true },
	});

	const resolver = where.resolver();
	const error = await rejection(resolver.resolve(path.join(installed, 'node_modules', 'pkg-b', 'index.js')));
	assert.equal(error.status, 'no-data');
	assert.match(error.message, /node_modules\/host\/node_modules\/pkg-b is bundled into its parent distribution/);
	// The parent itself is still an ordinary distribution.
	assert.equal((await resolver.resolve(path.join(installed, 'index.js'))).component.name, 'host');
	resolver.close();
});

test('reports no-data for a bundled entry even when it also names a registry archive', async () => {
	const where = area('bundled-with-locator');
	const bundled = distribution('pkg-b', '0.5.0');
	const host = bundlingDistribution('host', '3.0.0', bundled);
	const installed = install(where, host);
	cache(where, host);
	cache(where, bundled);
	// The registry copy is cached and satisfies the entry; the installed bytes
	// still came out of the parent tarball.
	lock(where, {
		'node_modules/host': lockEntry(host),
		'node_modules/host/node_modules/pkg-b': lockEntry(bundled, { inBundle: true }),
	});

	const error = await rejection(where.resolver().resolve(path.join(installed, 'node_modules', 'pkg-b', 'index.js')));
	assert.equal(error.status, 'no-data');
	assert.match(error.message, /is bundled into its parent distribution/);
});

// The lockfile says an install script ran; what it wrote is nobody's original,
// so a later byte mismatch has a reason the collector can name.
test('carries the install-script fact of the lock entry onto the binding', async () => {
	const where = area('install-script');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	lock(where, { 'node_modules/pkg-a': lockEntry(dist, { hasInstallScript: true }) });

	const resolver = where.resolver();
	assert.equal((await resolver.resolve(path.join(installed, 'index.js'))).hasInstallScript, true);
	resolver.close();

	const plain = area('no-install-script');
	const other = install(plain, dist);
	cache(plain, dist);
	lock(plain, { 'node_modules/pkg-a': lockEntry(dist) });
	const quiet = plain.resolver();
	assert.equal((await quiet.resolve(path.join(other, 'index.js'))).hasInstallScript, false);
	quiet.close();
});

test('refuses a lockfileVersion that states no installed paths', async () => {
	const where = area('legacy-only');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	fs.writeFileSync(where.lockPath, JSON.stringify({ name: 'project', lockfileVersion: 1, dependencies: { 'pkg-a': lockEntry(dist) } }));

	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'unsupported');
	assert.match(error.message, /lockfileVersion 1/);
});

test('reports no-data for a cache that holds no content at the locked address', async () => {
	const where = area('missing-content');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	fs.mkdirSync(where.cacheDir, { recursive: true });
	lock(where, { 'node_modules/pkg-a': lockEntry(dist) });

	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'no-data');
	assert.match(error.message, /no npm cache content for pkg-a@1\.2\.3/);
	assert.match(error.message, /content-v2[/\\]sha512/);
});

test('refuses cache content that does not satisfy the integrity its address names', async () => {
	const where = area('tampered-content');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	const hex = crypto.createHash('sha512').update(dist.bytes).digest('hex');
	const file = path.join(where.cacheDir, 'content-v2', 'sha512', hex.slice(0, 2), hex.slice(2, 4), hex.slice(4));
	fs.chmodSync(file, 0o644);
	fs.writeFileSync(file, distribution('pkg-a', '1.2.3', 'module.exports = "other";\n').bytes);
	lock(where, { 'node_modules/pkg-a': lockEntry(dist) });

	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'hash-mismatch');
	assert.match(error.message, /does not satisfy sha512-/);
});

test('checks a multi-token integrity against its strongest spelling', async () => {
	const where = area('multi-token');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	const sha1 = `sha1-${crypto.createHash('sha1').update(dist.bytes).digest('base64')}`;
	lock(where, { 'node_modules/pkg-a': lockEntry(dist, { integrity: `${sha1} ${dist.integrity}` }) });

	const resolver = where.resolver();
	const binding = await resolver.resolve(path.join(installed, 'index.js'));
	// The component carries the lock entry verbatim; the archive was checked
	// against the strongest token of it.
	assert.equal(binding.component.source.checksum, `${sha1} ${dist.integrity}`);
	resolver.close();

	const broken = area('multi-token-broken');
	install(broken, dist);
	cache(broken, dist);
	const wrongStrong = `sha512-${Buffer.alloc(64, 7).toString('base64')}`;
	lock(broken, { 'node_modules/pkg-a': lockEntry(dist, { integrity: `${sha1} ${wrongStrong}` }) });
	const error = await rejection(broken.resolver().resolve(path.join(broken.installedDir('node_modules/pkg-a'), 'index.js')));
	assert.equal(error.status, 'no-data', 'the strongest token addresses content this cache does not hold');
});

test('binds a distribution a lockfile pins with sha1 alone, verbatim', async () => {
	const where = area('sha1-only');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	// npm stores content under the algorithm it verified; an old entry is sha1.
	cacheAt(where, 'sha1', dist.bytes);
	const sha1 = `sha1-${crypto.createHash('sha1').update(dist.bytes).digest('base64')}`;
	lock(where, { 'node_modules/pkg-a': lockEntry(dist, { integrity: sha1 }) });

	const resolver = where.resolver();
	const binding = await resolver.resolve(path.join(installed, 'index.js'));
	assert.equal(binding.component.source.checksum, sha1, 'a sha1 pin is reported as the sha1 it is');
	resolver.close();
});

test('reports invalid for an unreadable or malformed checksum and unsupported for a legacy one', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	const sha1 = `sha1-${crypto.createHash('sha1').update(dist.bytes).digest('base64')}`;
	const sha512 = `sha512-${crypto.createHash('sha512').update(dist.bytes).digest('base64')}`;
	// A digest that cannot be read must not hand the check to a weaker token,
	// whether ssri keeps that token or drops it as unreadable.
	for (const [id, integrity, status] of [
		['empty-strong-token', `sha512- ${sha1}`, 'invalid'],
		['uppercase-strong-token', `${sha512.toUpperCase()} ${sha1}`, 'invalid'],
		['separator-strong-token', `${sha512.replace('-', ':')} ${sha1}`, 'invalid'],
		['unpadded', sha1.replace(/=+$/, ''), 'invalid'],
		['not-base64', 'sha1-DD0L6u2KAclm2Xh793goElKpea*=', 'invalid'],
		['truncated', `sha512-${crypto.createHash('sha512').update(dist.bytes).digest('base64').slice(0, 40)}`, 'invalid'],
		['legacy', `md5-${crypto.createHash('md5').update(dist.bytes).digest('base64')}`, 'unsupported'],
	]) {
		const where = area(`checksum-${id}`);
		const installed = install(where, dist);
		cache(where, dist);
		lock(where, { 'node_modules/pkg-a': lockEntry(dist, { integrity }) });
		const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
		assert.equal(error.status, status, `${id}: ${error.message}`);
		assert.deepEqual(fs.readdirSync(where.outputRoot), [], id);
	}
});

test('reports no-data for a lock entry without integrity, a link and a file locator', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	for (const [id, overrides, match] of [
		['no-integrity', { integrity: undefined }, /carries no integrity/],
		['link', { link: true, resolved: undefined, integrity: undefined }, /is a link/],
		['file-locator', { resolved: 'file:../pkg-a', integrity: undefined }, /not an http registry archive/],
		['no-locator', { resolved: undefined, integrity: undefined }, /without a locator/],
	]) {
		const where = area(`locator-${id}`);
		const installed = install(where, dist);
		cache(where, dist);
		lock(where, { 'node_modules/pkg-a': lockEntry(dist, overrides) });
		const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
		assert.equal(error.status, 'no-data', id);
		assert.match(error.message, match, id);
	}
});

test('reports invalid for an archive carrying a different identity than the lock entry', async () => {
	const where = area('archive-identity');
	const dist = distribution('pkg-a', '1.2.3');
	const twin = distribution('pkg-b', '1.2.3');
	const installed = install(where, dist);
	cache(where, twin);
	// The locked address names the twin's bytes, which hold another package.
	lock(where, { 'node_modules/pkg-a': lockEntry(dist, { integrity: twin.integrity }) });

	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'invalid');
	assert.match(error.message, /holds pkg-b@1\.2\.3, not pkg-a@1\.2\.3/);
});

test('still binds an installed tree whose bytes were modified: the comparison is the collector job', async () => {
	const where = area('modified-install');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	lock(where, { 'node_modules/pkg-a': lockEntry(dist) });
	fs.writeFileSync(path.join(installed, 'index.js'), 'module.exports = "patched";\n');

	const resolver = where.resolver();
	const binding = await resolver.resolve(path.join(installed, 'index.js'));
	assert.notDeepEqual(fs.readFileSync(path.join(binding.originalRoot, 'index.js')), fs.readFileSync(path.join(installed, 'index.js')));
	resolver.close();
});

test('returns undefined outside node_modules and never undefined for a package it cannot prove', async () => {
	const where = area('outside');
	const dist = distribution('pkg-a', '1.2.3');
	install(where, dist);
	cache(where, dist);
	lock(where, { 'node_modules/pkg-a': lockEntry(dist) });
	fs.writeFileSync(path.join(where.workdir, 'own.js'), 'export const own = 1;\n');

	const resolver = where.resolver();
	assert.equal(await resolver.resolve(path.join(where.workdir, 'own.js')), undefined);
	resolver.close();

	const foreign = area('foreign');
	const elsewhere = install(foreign, dist);
	cache(foreign, dist);
	lock(foreign, { 'node_modules/pkg-a': lockEntry(dist) });
	const other = area('foreign-workdir');
	const error = await rejection(other.resolver().resolve(path.join(elsewhere, 'index.js')));
	assert.equal(error.status, 'no-data');
	assert.match(error.message, /outside the workdir/);
});

test('reports no-data for an aliased install directory and for a linked package', async () => {
	const where = area('alias-directory');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist, 'node_modules/renamed');
	cache(where, dist);
	lock(where, { 'node_modules/renamed': lockEntry(dist) });
	const aliased = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(aliased.status, 'no-data');
	assert.match(aliased.message, /an alias this version does not own/);

	const linked = area('linked');
	const real = install(linked, dist, 'real/pkg-a');
	fs.symlinkSync(real, linked.installedDir('node_modules/pkg-a'));
	cache(linked, dist);
	lock(linked, { 'node_modules/pkg-a': lockEntry(dist) });
	const error = await rejection(linked.resolver().resolve(path.join(linked.installedDir('node_modules/pkg-a'), 'index.js')));
	assert.equal(error.status, 'no-data');
	assert.match(error.message, /is a link, not an installed distribution/);
});

test('reads the lockfile once per resolver: a later edit needs a new resolver', async () => {
	const where = area('lock-once');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	lock(where, { 'node_modules/pkg-a': lockEntry(dist) });

	const resolver = where.resolver();
	assert.ok(await resolver.resolve(path.join(installed, 'index.js')));
	fs.writeFileSync(where.lockPath, JSON.stringify({ lockfileVersion: 3, packages: {} }));
	assert.ok(await resolver.resolve(path.join(installed, 'index.js')), 'the lockfile read is the one this resolver started with');
	resolver.close();

	const after = where.resolver({ outputRoot: path.join(where.root, 'out', 'second') });
	const error = await rejection(after.resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'no-data');
});

test('refuses an output root that is not an owned empty directory', () => {
	const where = area('output-root');
	assert.throws(() => where.resolver({ outputRoot: where.workdir }), /must be empty|overlaps/);
	assert.throws(() => where.resolver({ outputRoot: path.join(where.workdir, 'node_modules', 'inside') }), /overlaps/);
	assert.throws(() => where.resolver({ outputRoot: path.join(where.cacheDir, 'inside') }), /overlaps|must be an existing directory/);
	assert.throws(() => where.resolver({ unknown: 1 }), /unknown options field "unknown"/);
});

// A lockfileVersion 2 states each kind of install in its own vocabulary, and
// npm's own spelling of a Git dependency is the one redoc's lockfile carries.
test('reads a lockfileVersion 2 Git dependency through the verified build context', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	const git = gitArea('legacy-git', dist, {
		lockOverrides: {
			lockfileVersion: 2,
			dependencies: { 'pkg-a': { version: GIT_LOCATOR, dev: true, from: 'pkg-a@github:example/pkg-a#main' } },
		},
	});

	const binding = await git.resolver.resolve(git.source);
	assert.deepEqual(binding.component, git.manifest.components[0]);
});

test('refuses a lockfileVersion 2 whose trees pin different Git states', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	for (const [id, legacy, match] of [
		['another commit', { version: GIT_LOCATOR.replace(GIT_COMMIT, 'a'.repeat(40)) }, /in packages and git\+ssh:.*aaaa.* in its dependencies tree/],
		['no locator at all', { version: '1.2.3' }, /in packages and 1\.2\.3 in its dependencies tree/],
		['an archive as well', { version: GIT_LOCATOR, resolved: dist.resolved, integrity: dist.integrity }, /as a Git commit in packages and as the archive /],
	]) {
		const git = gitArea(`legacy-git-${id.replace(/\W/g, '-')}`, dist, {
			lockOverrides: { lockfileVersion: 2, dependencies: { 'pkg-a': legacy } },
		});
		const error = await rejection(git.resolver.resolve(git.source));
		assert.equal(error.status, 'no-data', id);
		assert.match(error.message, match, id);
	}
});

test('leaves a lockfileVersion 2 link and alias to say what they are', async () => {
	const dist = distribution('pkg-a', '1.2.3');

	const linked = area('legacy-link');
	const installed = install(linked, dist);
	cache(linked, dist);
	lock(linked, { 'node_modules/pkg-a': { version: '1.2.3', link: true, resolved: 'pkg-a' } }, {
		lockfileVersion: 2,
		dependencies: { 'pkg-a': { version: 'file:../pkg-a' } },
	});
	const link = await rejection(linked.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(link.status, 'no-data');
	assert.match(link.message, /is a link, not an installed distribution/);

	const aliased = area('legacy-alias');
	const other = install(aliased, dist);
	cache(aliased, dist);
	lock(aliased, { 'node_modules/pkg-a': lockEntry(dist, { name: 'pkg-b' }) }, {
		lockfileVersion: 2,
		dependencies: { 'pkg-a': { version: 'npm:pkg-b@1.2.3' } },
	});
	const alias = await rejection(aliased.resolver().resolve(path.join(other, 'index.js')));
	assert.equal(alias.status, 'no-data');
	assert.match(alias.message, /is an npm alias of pkg-b/);
});

// A Git dependency of a package-lock: no integrity, and a cache that records
// what a fetch claimed rather than bytes anybody checked against the commit.
const GIT_COMMIT = '6897b3fa5784c8f4970c81e04dbc8025f3c60938';
const GIT_LOCATOR = `git+ssh://git@github.com/redocly/workerize-loader.git#${GIT_COMMIT}`;

function gitArea(id, dist, overrides = {}) {
	const where = area(id);
	const installed = install(where, dist);
	lock(where, { 'node_modules/pkg-a': { version: dist.version, resolved: overrides.resolved || GIT_LOCATOR } }, overrides.lockOverrides);
	const contextDir = path.join(where.root, 'context');
	fs.mkdirSync(contextDir, { recursive: true });
	const component = {
		id: 'node:pkg-a',
		name: dist.name,
		version: dist.version,
		source: { kind: 'node', locator: GIT_LOCATOR, checksum: `git-commit:sha1:${GIT_COMMIT}` },
		...overrides.component,
	};
	const source = path.join(installed, 'index.js');
	const manifest = {
		version: 1,
		components: [component],
		files: [{ path: source, sha256: `sha256:${crypto.createHash('sha256').update(fs.readFileSync(source)).digest('hex')}`, component: component.id }],
		...overrides.manifest,
	};
	fs.writeFileSync(path.join(contextDir, 'webpack-originals.json'), JSON.stringify(manifest));
	return { where, source, manifest, resolver: where.resolver({ contextPath: path.join(contextDir, 'context.json') }) };
}

test('binds a Git-locked package to the file digest DK verified from its commit', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	const git = gitArea('git-verified', dist);
	const binding = await git.resolver.resolve(git.source);
	assert.deepEqual(binding, { path: git.source, sha256: git.manifest.files[0].sha256, component: git.manifest.components[0] });
	assert.equal(fs.readdirSync(git.where.outputRoot).length, 0, 'a Git original extracts nothing');
});

test('reports no-data for a Git-locked package without a build context or a manifest entry', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	const unlisted = gitArea('git-unlisted', dist, { manifest: { files: [] } });
	const missing = await rejection(unlisted.resolver.resolve(unlisted.source));
	assert.equal(missing.status, 'no-data');
	assert.match(missing.message, /no verified primary-source mapping/);

	const where = area('git-no-context');
	const installed = install(where, dist);
	lock(where, { 'node_modules/pkg-a': { version: dist.version, resolved: GIT_LOCATOR } });
	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'no-data');
	assert.match(error.message, /no verified build context/);
});

test('refuses a verified original that does not pin the locked commit or identity', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	for (const [id, component] of [
		['other-commit', { source: { kind: 'node', locator: GIT_LOCATOR.replace(GIT_COMMIT, 'a'.repeat(40)), checksum: `git-commit:sha1:${'a'.repeat(40)}` } }],
		['other-version', { version: '9.9.9' }],
		['other-name', { name: 'pkg-b' }],
	]) {
		const git = gitArea(`git-${id}`, dist, { component });
		const error = await rejection(git.resolver.resolve(git.source));
		assert.equal(error.status, 'invalid', id);
	}
});

test('reports no-data for a Git locator that pins no full commit', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	for (const resolved of [`git+ssh://git@github.com/redocly/workerize-loader.git#${GIT_COMMIT.slice(0, 8)}`, 'git+ssh://git@github.com/redocly/workerize-loader.git', `git+file:///tmp/repo#${GIT_COMMIT}`]) {
		const git = gitArea(`git-unpinned-${resolved.length}-${resolved.slice(-6).replace(/\W/g, '')}`, dist, { resolved });
		const error = await rejection(git.resolver.resolve(git.source));
		assert.equal(error.status, 'no-data', resolved);
		assert.match(error.message, /not an http registry archive/, resolved);
	}
});

// A hand-built ustar archive, for members npm pack would never produce.
function rawArchive(members) {
	const blocks = [];
	for (const member of members) {
		const content = Buffer.from(member.content || '');
		const header = Buffer.alloc(512);
		header.write(member.name, 0, 100);
		header.write('000644 \0', 100);
		header.write('000000 \0', 108);
		header.write('000000 \0', 116);
		header.write(`${content.length.toString(8).padStart(11, '0')} `, 124);
		header.write(`${'0'.padStart(11, '0')} `, 136);
		header.write('        ', 148);
		header.write(member.type || '0', 156, 1);
		if (member.link) header.write(member.link, 157, 100);
		header.write('ustar\0' + '00', 257);
		let sum = 0;
		for (const byte of header) sum += byte;
		header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
		blocks.push(header, content, Buffer.alloc((512 - (content.length % 512)) % 512));
	}
	blocks.push(Buffer.alloc(1024));
	return zlib.gzipSync(Buffer.concat(blocks));
}

test('refuses archive members that escape, link or repeat, writing nothing outside the scratch tree', async () => {
	const manifest = JSON.stringify({ name: 'pkg-a', version: '1.2.3' });
	for (const [id, members, status] of [
		['escape', [{ name: '../escaped.js', content: 'x' }], 'invalid'],
		['outside-prefix', [{ name: 'elsewhere/index.js', content: 'x' }], 'unsupported'],
		['symlink', [{ name: 'package/link.js', type: '2', link: '/etc/passwd' }], 'unsupported'],
		['duplicate', [{ name: 'package/package.json', content: manifest }, { name: 'package/package.json', content: manifest }], 'invalid'],
	]) {
		const where = area(`members-${id}`);
		const dist = distribution('pkg-a', '1.2.3');
		const installed = install(where, dist);
		const bytes = rawArchive([{ name: 'package/package.json', content: manifest }, ...members]);
		const integrity = `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`;
		cacheAt(where, 'sha512', bytes);
		lock(where, { 'node_modules/pkg-a': lockEntry(dist, { integrity }) });

		const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
		assert.equal(error.status, status, id);
		assert.deepEqual(fs.readdirSync(where.outputRoot), [], `${id}: the refused extraction leaves nothing behind`);
		assert.equal(fs.existsSync(path.join(where.root, 'out', 'escaped.js')), false, id);
	}
});

test('refuses an archive without the package manifest the lock entry names', async () => {
	const where = area('members-no-manifest');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	const bytes = rawArchive([{ name: 'package/index.js', content: 'module.exports = 1;\n' }]);
	cacheAt(where, 'sha512', bytes);
	lock(where, { 'node_modules/pkg-a': lockEntry(dist, { integrity: `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}` }) });

	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'invalid');
	assert.match(error.message, /has no package\.json/);
});

test('reports no-data for an entry carrying two checksums of its strongest algorithm', async () => {
	const where = area('two-strong');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	const other = `sha512-${crypto.createHash('sha512').update(Buffer.from('other')).digest('base64')}`;
	lock(where, { 'node_modules/pkg-a': lockEntry(dist, { integrity: `${dist.integrity} ${other}` }) });

	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'no-data');
	assert.match(error.message, /carries 2 sha512 checksums/);
});

test('reports no-data for a workdir that is itself a node_modules directory', async () => {
	const where = area('workdir-is-modules');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	lock(where, { 'node_modules/pkg-a': lockEntry(dist) });

	const resolver = where.resolver({ workdir: path.join(where.workdir, 'node_modules'), outputRoot: path.join(where.root, 'out', 'modules') });
	const error = await rejection(resolver.resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'no-data');
	assert.match(error.message, /is not in a node_modules tree of/);
});
