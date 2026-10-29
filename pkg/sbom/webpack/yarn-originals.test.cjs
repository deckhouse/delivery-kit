'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const { execFileSync, spawn } = require('node:child_process');
const { test, before, after } = require('node:test');

const lockfile = require('@yarnpkg/lockfile');
const tar = require('tar');

const YarnOriginals = require('./yarn-originals.cjs');

let scratch;
let packedRoot;
const packedCache = new Map();

before(() => {
	scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-yarn-originals-')));
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
	const file = path.join(packedRoot, packed);
	const bytes = fs.readFileSync(file);
	const entry = {
		name,
		version,
		bytes,
		integrity: `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`,
		resolved: `https://registry.example/${name}/-/${packed}#${crypto.createHash('sha1').update(bytes).digest('hex')}`,
	};
	packedCache.set(key, entry);
	return entry;
}

function area(id) {
	const root = path.join(scratch, 'areas', id);
	const workdir = path.join(root, 'work');
	const cacheDir = path.join(root, 'cache', 'v6');
	fs.mkdirSync(path.join(workdir, 'node_modules'), { recursive: true });
	fs.mkdirSync(cacheDir, { recursive: true });
	fs.mkdirSync(path.join(root, 'out'), { recursive: true });
	return {
		root,
		workdir,
		cacheDir,
		outputRoot: path.join(root, 'out', 'originals'),
		lockPath: path.join(workdir, 'yarn.lock'),
		installedDir: (name) => path.join(workdir, 'node_modules', name),
		resolver: (overrides) => new YarnOriginals({ workdir, lockPath: path.join(workdir, 'yarn.lock'), cacheDir, outputRoot: path.join(root, 'out', 'originals'), ...overrides }),
	};
}

function install(where, dist) {
	const target = where.installedDir(dist.name);
	fs.mkdirSync(target, { recursive: true });
	tar.x({ cwd: target, strip: 1, sync: true, file: writeTemp(`${dist.name.replace('/', '-')}-${dist.version}.tgz`, dist.bytes) });
	return target;
}

function writeTemp(name, bytes) {
	const file = path.join(scratch, 'temp', `${crypto.randomUUID()}-${name}`);
	fs.mkdirSync(path.dirname(file), { recursive: true });
	fs.writeFileSync(file, bytes);
	return file;
}

// The Yarn 1.22 cache shape observed from a real `yarn install`:
// <cacheDir>/<slug>/node_modules/<name>/{.yarn-metadata.json,.yarn-tarball.tgz,...}
function cache(where, dist, overrides) {
	const options = overrides || {};
	const slug = options.slug || `npm-${dist.name.replace('/', '-')}-${dist.version}-integrity`;
	const dir = path.join(where.cacheDir, slug, 'node_modules', dist.name);
	fs.mkdirSync(dir, { recursive: true });
	const metadata = {
		manifest: { name: options.manifestName || dist.name, version: options.manifestVersion || dist.version, main: 'index.js', _registry: 'npm' },
		artifacts: [],
		remote: {
			resolved: options.resolved || dist.resolved,
			type: 'tarball',
			reference: (options.resolved || dist.resolved).split('#')[0],
			integrity: options.integrity || dist.integrity,
			registry: 'npm',
			packageName: dist.name,
		},
		registry: 'npm',
		hash: crypto.createHash('sha512').update(dist.bytes).digest('hex'),
	};
	fs.writeFileSync(path.join(dir, '.yarn-metadata.json'), JSON.stringify(metadata, null, 2));
	if (options.archive !== null) fs.writeFileSync(path.join(dir, '.yarn-tarball.tgz'), options.archive || dist.bytes);
	fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: dist.name, version: dist.version }));
	return dir;
}

function lock(where, entries) {
	const body = entries
		.map((entry) => {
			const lines = [`"${entry.selector || `${entry.name}@^${entry.version}`}":`, `  version "${entry.version}"`];
			if (entry.resolved !== null) lines.push(`  resolved "${entry.resolved}"`);
			if (entry.integrity !== null) lines.push(`  integrity ${entry.integrity.includes(' ') ? `"${entry.integrity}"` : entry.integrity}`);
			return `${lines.join('\n')}\n`;
		})
		.join('\n');
	fs.writeFileSync(where.lockPath, `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n${body}`);
}

function lockEntry(dist, overrides) {
	return { name: dist.name, version: dist.version, resolved: dist.resolved, integrity: dist.integrity, ...overrides };
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

test('binds an installed package to an independently extracted original of the locked archive', async () => {
	const where = area('valid');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	lock(where, [lockEntry(dist)]);

	const resolver = where.resolver();
	const binding = await resolver.resolve(path.join(installed, 'index.js'));

	assert.equal(binding.root, installed);
	assert.ok(binding.originalRoot.startsWith(`${fs.realpathSync(where.outputRoot)}${path.sep}`), `${binding.originalRoot} must live under the output root`);
	assert.ok(!binding.originalRoot.startsWith(`${where.workdir}${path.sep}`));
	assert.ok(!binding.originalRoot.startsWith(`${where.cacheDir}${path.sep}`));
	assert.deepEqual(relativeFiles(binding.originalRoot).sort(), ['NOTICE.txt', 'index.js', 'package.json']);
	for (const file of relativeFiles(binding.originalRoot)) {
		assert.deepEqual(fs.readFileSync(path.join(binding.originalRoot, file)), fs.readFileSync(path.join(installed, file)), `${file} must be the archived bytes`);
	}
	assert.deepEqual(binding.component, {
		id: `node:${crypto.createHash('sha256').update(JSON.stringify(['pkg-a', '1.2.3', dist.resolved, dist.integrity])).digest('hex')}`,
		name: 'pkg-a',
		version: '1.2.3',
		source: { kind: 'node', locator: dist.resolved, checksum: dist.integrity },
	});
	assert.equal(fs.statSync(path.join(binding.originalRoot, 'index.js')).mode & 0o777, 0o444);
	assert.equal(fs.statSync(binding.originalRoot).mode & 0o777, 0o555);

	resolver.close();
	assert.deepEqual(fs.readdirSync(fs.realpathSync(where.outputRoot)), [], 'close must remove only the trees it extracted');
	assert.ok(fs.existsSync(where.outputRoot) && fs.existsSync(path.join(installed, 'index.js')));
});

test('resolves an actual Yarn 1.22 install against its actual cache', async (t) => {
	t.diagnostic('runs the vendored yarn 1.22.22 against a local HTTP registry');
	const where = area('real-yarn');
	const plain = distribution('plain-pkg', '3.1.0');
	const scoped = distribution('@probe/scoped-pkg', '2.0.1');
	const byName = new Map([plain, scoped].map((dist) => [dist.name, dist]));
	const cacheRoot = path.join(where.root, 'yarn-cache');

	const server = http.createServer((request, response) => {
		const url = decodeURIComponent(request.url);
		const tarball = url.match(/^\/(.+)\/-\/tarball-(.+)\.tgz$/);
		const dist = byName.get(tarball ? tarball[1] : url.slice(1));
		if (!dist) {
			response.writeHead(404).end('{}');
			return;
		}
		if (tarball) {
			response.writeHead(200, { 'content-type': 'application/octet-stream' }).end(dist.bytes);
			return;
		}
		const port = server.address().port;
		response.writeHead(200, { 'content-type': 'application/json' }).end(
			JSON.stringify({
				name: dist.name,
				'dist-tags': { latest: dist.version },
				versions: {
					[dist.version]: {
						name: dist.name,
						version: dist.version,
						main: 'index.js',
						dist: { tarball: `http://127.0.0.1:${port}/${dist.name}/-/tarball-${dist.version}.tgz`, integrity: dist.integrity },
					},
				},
			}),
		);
	});
	await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
	try {
		const registry = `http://127.0.0.1:${server.address().port}/`;
		fs.writeFileSync(
			path.join(where.workdir, 'package.json'),
			JSON.stringify({ name: 'probe-app', version: '0.0.0', dependencies: { [plain.name]: plain.version, [scoped.name]: scoped.version } }),
		);
		fs.writeFileSync(path.join(where.workdir, '.yarnrc'), `registry "${registry}"\n`);

		const code = await new Promise((resolve, reject) => {
			const child = spawn(process.execPath, [require.resolve('yarn/bin/yarn.js'), 'install', '--cache-folder', cacheRoot, '--ignore-scripts', '--non-interactive', '--no-default-rc'], {
				cwd: where.workdir,
				stdio: 'ignore',
				env: {
					...process.env,
					YARN_REGISTRY: registry,
					npm_config_registry: registry,
					// No credential prompt and no network beyond the local registry.
					GIT_TERMINAL_PROMPT: '0',
					GIT_ASKPASS: '/usr/bin/false',
					SSH_ASKPASS: '/usr/bin/false',
					GIT_SSH_COMMAND: 'ssh -o BatchMode=yes -o ConnectTimeout=8',
				},
			});
			const deadline = setTimeout(() => {
				child.kill('SIGKILL');
				reject(new Error('the yarn probe did not finish within 60s'));
			}, 60_000);
			child.on('error', (error) => {
				clearTimeout(deadline);
				reject(error);
			});
			child.on('exit', (status) => {
				clearTimeout(deadline);
				resolve(status);
			});
		});
		assert.equal(code, 0, 'the vendored yarn must install from the local registry');

		const cacheDir = path.join(cacheRoot, fs.readdirSync(cacheRoot).find((entry) => /^v\d+$/.test(entry)));
		const locked = lockfile.parse(fs.readFileSync(where.lockPath, 'utf8')).object;
		const resolver = where.resolver({ cacheDir });
		for (const dist of [plain, scoped]) {
			const installed = path.join(where.workdir, 'node_modules', dist.name);
			const entry = locked[`${dist.name}@${dist.version}`];
			const metadata = JSON.parse(fs.readFileSync(path.join(cacheDir, cacheEntryOf(cacheDir, dist.name), '.yarn-metadata.json'), 'utf8'));
			assert.equal(metadata.remote.resolved, entry.resolved, 'real Yarn writes the lockfile locator verbatim into the cache metadata');
			assert.equal(metadata.remote.integrity, entry.integrity, 'real Yarn writes the lockfile integrity verbatim into the cache metadata');

			const binding = await resolver.resolve(path.join(installed, 'index.js'));
			assert.equal(binding.root, installed);
			assert.equal(binding.component.name, dist.name);
			assert.equal(binding.component.version, dist.version);
			assert.equal(binding.component.source.locator, entry.resolved, 'the locator must be the lockfile one verbatim');
			assert.equal(binding.component.source.checksum, entry.integrity, 'the checksum must be the lockfile integrity verbatim');
			assert.equal(binding.component.source.checksum, dist.integrity, 'which is the SRI of the packed archive');
			assert.deepEqual(fs.readFileSync(path.join(binding.originalRoot, 'index.js')), fs.readFileSync(path.join(installed, 'index.js')));
		}
		resolver.close();
	} finally {
		server.close();
	}
});

// The cache folder real Yarn created for a package, found by its metadata.
function cacheEntryOf(cacheDir, name) {
	for (const slug of fs.readdirSync(cacheDir)) {
		const entry = path.join(slug, 'node_modules', name);
		if (fs.existsSync(path.join(cacheDir, entry, '.yarn-metadata.json'))) return entry;
	}
	assert.fail(`no cache entry for ${name} in ${cacheDir}`);
}

test('refuses a cached archive whose bytes do not satisfy the locked integrity', async () => {
	const where = area('corrupt');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	const corrupt = Buffer.from(dist.bytes);
	corrupt[corrupt.length - 10] ^= 0xff;
	cache(where, dist, { archive: corrupt });
	lock(where, [lockEntry(dist)]);

	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'hash-mismatch');
	assert.equal(corrupt.length, dist.bytes.length);
	assert.deepEqual(fs.readdirSync(fs.realpathSync(where.outputRoot)), [], 'a refused archive leaves no scratch tree behind');
});

test('does not touch the cache entry of a package nobody asked for', async () => {
	const where = area('unselected');
	const wanted = distribution('pkg-a', '1.2.3');
	const other = distribution('pkg-b', '4.5.6');
	const installed = install(where, wanted);
	install(where, other);
	cache(where, wanted);
	cache(where, other, { archive: Buffer.from('not a tarball at all') });
	lock(where, [lockEntry(wanted), lockEntry(other)]);

	const resolver = where.resolver();
	const binding = await resolver.resolve(path.join(installed, 'index.js'));
	assert.equal(binding.component.name, 'pkg-a');
	assert.equal(fs.readdirSync(fs.realpathSync(where.outputRoot)).length, 1, 'only the requested distribution is extracted');
	resolver.close();
});

test('binds the nearest installed package, not the nearest package.json', async () => {
	const where = area('nested-manifest');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	const nested = path.join(installed, 'esm');
	fs.mkdirSync(nested);
	fs.writeFileSync(path.join(nested, 'package.json'), JSON.stringify({ type: 'module' }));
	fs.writeFileSync(path.join(nested, 'index.mjs'), 'export default 1;\n');
	cache(where, dist);
	lock(where, [lockEntry(dist)]);

	const resolver = where.resolver();
	const binding = await resolver.resolve(path.join(nested, 'index.mjs'));
	assert.equal(binding.root, installed);
	assert.equal(binding.component.name, 'pkg-a');
	resolver.close();
});

test('binds the nested installed copy, not its host package', async () => {
	const where = area('nested-tree');
	const host = distribution('pkg-a', '1.2.3');
	const nestedDist = distribution('pkg-b', '4.5.6');
	const installed = install(where, host);
	const nested = path.join(installed, 'node_modules', nestedDist.name);
	fs.mkdirSync(path.dirname(nested), { recursive: true });
	fs.mkdirSync(nested);
	tar.x({ cwd: nested, strip: 1, sync: true, file: writeTemp('nested.tgz', nestedDist.bytes) });
	cache(where, host);
	cache(where, nestedDist);
	lock(where, [lockEntry(host), lockEntry(nestedDist)]);

	const resolver = where.resolver();
	const binding = await resolver.resolve(path.join(nested, 'index.js'));
	assert.equal(binding.root, nested);
	assert.equal(binding.component.name, 'pkg-b');
	resolver.close();
});

test('binds a scoped package through its scope directory', async () => {
	const where = area('scoped');
	const dist = distribution('@scope/pkg-c', '7.0.0');
	const installed = install(where, dist);
	cache(where, dist);
	lock(where, [lockEntry(dist, { selector: `${dist.name}@^7.0.0` })]);

	const resolver = where.resolver();
	const binding = await resolver.resolve(path.join(installed, 'index.js'));
	assert.equal(binding.root, installed);
	assert.equal(binding.component.name, '@scope/pkg-c');
	assert.deepEqual(fs.readFileSync(path.join(binding.originalRoot, 'index.js')), fs.readFileSync(path.join(installed, 'index.js')));
	resolver.close();
});

test('still binds an installed tree whose bytes were modified: the comparison is the collector job', async () => {
	const where = area('mutated');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	lock(where, [lockEntry(dist)]);
	fs.writeFileSync(path.join(installed, 'index.js'), 'module.exports = "trojan";\n');

	const resolver = where.resolver();
	const binding = await resolver.resolve(path.join(installed, 'index.js'));
	assert.notDeepEqual(fs.readFileSync(path.join(binding.originalRoot, 'index.js')), fs.readFileSync(path.join(installed, 'index.js')));
	assert.equal(fs.readFileSync(path.join(binding.originalRoot, 'index.js'), 'utf8'), `module.exports = ${JSON.stringify('pkg-a@1.2.3')};\n`, 'the original must be the archived bytes');
	resolver.close();
});

test('reports no-data for a missing cached archive and for a Git-backed lock entry', async () => {
	const missing = area('missing-archive');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(missing, dist);
	cache(missing, dist, { archive: null });
	lock(missing, [lockEntry(dist)]);
	const absent = await rejection(missing.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(absent.status, 'no-data');
	assert.match(absent.message, /\.yarn-tarball\.tgz/);

	const git = area('git-locator');
	const gitInstalled = install(git, dist);
	cache(git, dist);
	lock(git, [lockEntry(dist, { resolved: 'git+https://github.com/example/pkg-a.git#0f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6', integrity: null })]);
	const unproven = await rejection(git.resolver().resolve(path.join(gitInstalled, 'index.js')));
	assert.equal(unproven.status, 'no-data');
	assert.match(unproven.message, /not an http registry archive/);
});

test('accepts any http registry locator and checks the bytes, not the file name', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	for (const [id, resolved] of [
		['fragment-query', `https://registry.example/pkg-a/-/pkg%20a-1.2.3.tgz?download=1#${crypto.createHash('sha1').update(dist.bytes).digest('hex')}`],
		['no-extension', 'https://registry.example/api/v1/download?package=pkg-a&version=1.2.3'],
	]) {
		const where = area(`locator-${id}`);
		const installed = install(where, dist);
		cache(where, dist, { resolved });
		lock(where, [lockEntry(dist, { resolved })]);

		const resolver = where.resolver();
		const binding = await resolver.resolve(path.join(installed, 'index.js'));
		assert.equal(binding.component.source.locator, resolved, id);
		assert.deepEqual(fs.readFileSync(path.join(binding.originalRoot, 'index.js')), fs.readFileSync(path.join(installed, 'index.js')), id);
		resolver.close();
	}

	const credentials = area('locator-credentials');
	const credentialsInstalled = install(credentials, dist);
	const embedded = 'https://user:secret@registry.example/pkg-a/-/pkg-a-1.2.3.tgz';
	cache(credentials, dist, { resolved: embedded });
	lock(credentials, [lockEntry(dist, { resolved: embedded })]);
	const error = await rejection(credentials.resolver().resolve(path.join(credentialsInstalled, 'index.js')));
	assert.equal(error.status, 'no-data', 'a locator carrying credentials is not a distribution this version reports');
});

test('checks a multi-token integrity against its strongest spelling', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	const sha1 = `sha1-${crypto.createHash('sha1').update(dist.bytes).digest('base64')}`;
	const sha256 = `sha256-${crypto.createHash('sha256').update(dist.bytes).digest('base64')}`;
	const sha512 = `sha512-${crypto.createHash('sha512').update(dist.bytes).digest('base64')}`;
	const wrong512 = `sha512-${crypto.createHash('sha512').update('other bytes entirely').digest('base64')}`;

	for (const [id, integrity] of [
		['sha1-correct', `${sha1} ${wrong512}`],
		['sha256-correct', `${sha256} ${wrong512}`],
	]) {
		const weakFallback = area(`multi-token-${id}`);
		const weakInstalled = install(weakFallback, dist);
		cache(weakFallback, dist, { integrity });
		lock(weakFallback, [lockEntry(dist, { integrity })]);
		const error = await rejection(weakFallback.resolver().resolve(path.join(weakInstalled, 'index.js')));
		assert.equal(error.status, 'hash-mismatch', `${id}: a correct weaker token must not excuse a wrong sha512`);
	}

	const accepted = area('multi-token-strong');
	const acceptedInstalled = install(accepted, dist);
	cache(accepted, dist, { integrity: `${sha512} ${sha1}` });
	lock(accepted, [lockEntry(dist, { integrity: `${sha512} ${sha1}` })]);
	const resolver = accepted.resolver();
	const binding = await resolver.resolve(path.join(acceptedInstalled, 'index.js'));
	assert.equal(binding.component.source.checksum, `${sha512} ${sha1}`, 'the lockfile integrity is reported verbatim');
	resolver.close();
});

test('binds a distribution a Yarn 1 lockfile pins with sha1 alone', async () => {
	const where = area('sha1-only');
	const dist = distribution('pkg-a', '1.2.3');
	const sha1 = `sha1-${crypto.createHash('sha1').update(dist.bytes).digest('base64')}`;
	const installed = install(where, dist);
	cache(where, dist, { integrity: sha1 });
	lock(where, [lockEntry(dist, { integrity: sha1 })]);

	const resolver = where.resolver();
	const binding = await resolver.resolve(path.join(installed, 'index.js'));
	assert.equal(binding.component.source.checksum, sha1, 'the lockfile integrity is reported verbatim');
	assert.deepEqual(relativeFiles(binding.originalRoot).sort(), ['NOTICE.txt', 'index.js', 'package.json']);
	for (const file of relativeFiles(binding.originalRoot)) {
		assert.deepEqual(fs.readFileSync(path.join(binding.originalRoot, file)), fs.readFileSync(path.join(installed, file)), `${file} must be the archived bytes`);
	}
	resolver.close();

	const corrupted = area('sha1-only-corrupt');
	const corruptedInstalled = install(corrupted, dist);
	const corrupt = Buffer.from(dist.bytes);
	corrupt[corrupt.length - 10] ^= 0xff;
	cache(corrupted, dist, { integrity: sha1, archive: corrupt });
	lock(corrupted, [lockEntry(dist, { integrity: sha1 })]);
	const error = await rejection(corrupted.resolver().resolve(path.join(corruptedInstalled, 'index.js')));
	assert.equal(error.status, 'hash-mismatch', 'a sha1 entry still checks the archive bytes');
	assert.deepEqual(fs.readdirSync(fs.realpathSync(corrupted.outputRoot)), []);
});

test('rejects a synthetic archive against the real raw-loader 0.5.1 pin', async () => {
	// The integrity of raw-loader@0.5.1 as its yarn.lock entry spells it.
	const rawLoader = 'sha1-DD0L6u2KAclm2Xh793goElKpeao=';
	assert.equal(Buffer.from(rawLoader.slice('sha1-'.length), 'base64').toString('hex'), '0c3d0beaed8a01c966d9787bf778281252a979aa');

	const where = area('registry-sha1');
	const dist = distribution('raw-loader', '0.5.1');
	const installed = install(where, dist);
	cache(where, dist, { integrity: rawLoader });
	lock(where, [lockEntry(dist, { integrity: rawLoader })]);

	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'hash-mismatch', 'an archive that is not the published one fails, it is not accepted on the locator');
	assert.ok(error.message.includes(rawLoader), `${error.message} must name the locked checksum verbatim`);
});

test('reports invalid for a checksum that is not a canonical digest of its algorithm', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	const sha1 = `sha1-${crypto.createHash('sha1').update(dist.bytes).digest('base64')}`;
	const sha512 = `sha512-${crypto.createHash('sha512').update(dist.bytes).digest('base64')}`;
	for (const [id, integrity] of [
		['unpadded', sha1.replace(/=+$/, '')],
		['not-base64', 'sha1-DD0L6u2KAclm2Xh793goElKpea*='],
		['short-digest', `sha512-${crypto.createHash('sha256').update(dist.bytes).digest('base64')}`],
		// A digest that cannot be read must not hand the check to a weaker token,
		// whether ssri keeps that token or drops it as unreadable.
		['broken-strong-token', `${sha512.slice(0, -8)} ${sha1}`],
		['empty-strong-token', `sha512- ${sha1}`],
		['uppercase-strong-token', `${sha512.toUpperCase()} ${sha1}`],
		['separator-strong-token', `${sha512.replace('-', ':')} ${sha1}`],
		['empty-strong-token-alone', 'sha512-'],
	]) {
		const where = area(`malformed-${id}`);
		const installed = install(where, dist);
		cache(where, dist, { integrity });
		lock(where, [lockEntry(dist, { integrity })]);
		const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
		assert.equal(error.status, 'invalid', `${id}: ${error.message}`);
		assert.deepEqual(fs.readdirSync(fs.realpathSync(where.outputRoot)), [], id);
	}
});

test('checks a sha1 checksum that carries SRI options against the archive', async () => {
	const where = area('sha1-options');
	const dist = distribution('pkg-a', '1.2.3');
	const integrity = `sha1-${crypto.createHash('sha1').update(dist.bytes).digest('base64')}?foo=bar`;
	const installed = install(where, dist);
	cache(where, dist, { integrity });
	lock(where, [lockEntry(dist, { integrity })]);

	const resolver = where.resolver();
	const binding = await resolver.resolve(path.join(installed, 'index.js'));
	assert.equal(binding.component.source.checksum, integrity, 'the options are part of the checksum reported verbatim');
	assert.deepEqual(fs.readFileSync(path.join(binding.originalRoot, 'index.js')), fs.readFileSync(path.join(installed, 'index.js')));
	resolver.close();
});

test('indexes a lock selector by its own name, Git ranges and aliases included', async () => {
	const where = area('selector-names');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	// The very bytes the registry entry pins, also claimed by a Git entry of the
	// same name and version, plus an alias entry that owns nothing here.
	lock(where, [
		lockEntry(dist),
		lockEntry(dist, { selector: 'pkg-a@git+ssh://git@github.com/example/pkg-a.git#0f1e2d3c', resolved: 'git+ssh://git@github.com/example/pkg-a.git#0f1e2d3c', integrity: null }),
		lockEntry(dist, { selector: 'aliased@npm:pkg-a@1.2.3' }),
	]);

	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'no-data', 'a Git claim on the same identity makes the owner ambiguous');
	assert.match(error.message, /more than one distribution/);
	assert.match(error.message, /git\+ssh/);
});

test('reports no-data when the lockfile pins one identity to two distributions', async () => {
	const where = area('ambiguous');
	const dist = distribution('pkg-a', '1.2.3');
	const twin = distribution('pkg-a', '1.2.3', 'module.exports = "twin";\n');
	const installed = install(where, dist);
	cache(where, dist);
	lock(where, [lockEntry(dist), lockEntry(twin, { selector: 'pkg-a@~1.2.0' })]);

	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'no-data');
	assert.match(error.message, /more than one distribution/);
});

test('deduplicates identical lock selectors of one distribution', async () => {
	const where = area('dedup');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	lock(where, [lockEntry(dist), lockEntry(dist, { selector: 'pkg-a@~1.2.0' })]);

	const resolver = where.resolver();
	assert.equal((await resolver.resolve(path.join(installed, 'index.js'))).component.version, '1.2.3');
	resolver.close();
});

test('reports invalid for an archive carrying a different identity than the lock entry', async () => {
	const where = area('mislabeled');
	const dist = distribution('pkg-a', '1.2.3');
	const impostor = distribution('pkg-b', '4.5.6');
	const installed = install(where, dist);
	// The cache metadata claims the locked distribution, the archive is another package.
	cache(where, dist, { archive: impostor.bytes, integrity: dist.integrity });
	fs.writeFileSync(path.join(where.cacheDir, `npm-${dist.name}-${dist.version}-integrity`, 'node_modules', dist.name, '.yarn-tarball.tgz'), impostor.bytes);
	lock(where, [lockEntry(dist, { integrity: `sha512-${crypto.createHash('sha512').update(impostor.bytes).digest('base64')}` })]);
	// Rewrite the metadata integrity so the archive passes the SRI gate and only
	// its manifest contradicts the locked identity.
	const metadataPath = path.join(where.cacheDir, `npm-${dist.name}-${dist.version}-integrity`, 'node_modules', dist.name, '.yarn-metadata.json');
	const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
	metadata.remote.integrity = `sha512-${crypto.createHash('sha512').update(impostor.bytes).digest('base64')}`;
	fs.writeFileSync(metadataPath, JSON.stringify(metadata));

	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'invalid');
	assert.match(error.message, /holds pkg-b@4\.5\.6/);
	assert.deepEqual(fs.readdirSync(fs.realpathSync(where.outputRoot)), []);
});

test('refuses archive members that escape, link or repeat, writing nothing outside the scratch tree', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	const cases = [
		{ id: 'traversal', members: [{ name: 'package/../../escape.txt', content: 'escaped' }], status: 'invalid', message: /clean relative path/ },
		{ id: 'absolute', members: [{ name: '/escape.txt', content: 'escaped' }], status: 'invalid', message: /clean relative path/ },
		{ id: 'prefix', members: [{ name: 'other/index.js', content: 'x' }], status: 'unsupported', message: /outside the package\/ prefix/ },
		{
			id: 'collision',
			members: [
				{ name: 'package/a', content: 'file' },
				{ name: 'package/a/b', content: 'child of that file' },
			],
			status: 'invalid',
			message: /could not be extracted/,
		},
		{ id: 'empty-segment', members: [{ name: 'package//index.js', content: 'x' }], status: 'invalid', message: /clean relative path/ },
		{ id: 'dot-segment', members: [{ name: 'package/./index.js', content: 'x' }], status: 'invalid', message: /clean relative path/ },
		{ id: 'backslash', members: [{ name: 'package\\..\\escape.txt', content: 'x' }], status: 'invalid', message: /clean relative path/ },
		{
			id: 'duplicate',
			members: [
				{ name: 'package/index.js', content: 'first' },
				{ name: 'package/index.js', content: 'second' },
			],
			status: 'invalid',
			message: /more than once/,
		},
		{ id: 'symlink', members: [{ name: 'package/index.js', type: '2', link: '../../../../etc/passwd' }], status: 'unsupported', message: /SymbolicLink/ },
		{ id: 'hardlink', members: [{ name: 'package/index.js', type: '1', link: '../../escape.txt' }], status: 'unsupported', message: /Link/ },
		{ id: 'device', members: [{ name: 'package/node', type: '3' }], status: 'unsupported', message: /CharacterDevice/ },
	];

	for (const current of cases) {
		const where = area(`member-${current.id}`);
		const installed = install(where, dist);
		const archive = rawArchive(current.members);
		cache(where, dist, { archive, integrity: `sha512-${crypto.createHash('sha512').update(archive).digest('base64')}` });
		lock(where, [lockEntry(dist, { integrity: `sha512-${crypto.createHash('sha512').update(archive).digest('base64')}` })]);

		const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
		assert.equal(error.status, current.status, `${current.id}: ${error.message}`);
		assert.match(error.message, current.message, current.id);
		// Cleanup happens only once the extractor closed, so nothing is still being
		// written into a removed scratch tree.
		await new Promise((resolve) => setImmediate(resolve));
		assert.deepEqual(fs.readdirSync(fs.realpathSync(where.outputRoot)), [], `${current.id} must leave the output root empty`);
		assert.deepEqual(relativeFiles(path.join(where.root, 'out')), [], `${current.id} must write nothing outside its scratch tree`);
	}
});

test('fails a corrupt archive stream instead of waiting for a close that never comes', async () => {
	const where = area('aborted-stream');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	// A truncated gzip: the integrity gate passes, and tar aborts the parser
	// before any member is written, emitting TAR_ABORT without ever closing.
	const truncated = dist.bytes.subarray(0, 24);
	const integrity = `sha512-${crypto.createHash('sha512').update(truncated).digest('base64')}`;
	cache(where, dist, { archive: truncated, integrity });
	lock(where, [lockEntry(dist, { integrity })]);

	const resolved = where.resolver().resolve(path.join(installed, 'index.js'));
	const outcome = await Promise.race([resolved.then(() => 'resolved', (error) => error), new Promise((resolve) => setTimeout(() => resolve('timeout'), 1000))]);
	assert.notEqual(outcome, 'timeout', 'an aborted parser must not hang the resolve');
	assert.notEqual(outcome, 'resolved');
	assert.equal(outcome.status, 'invalid');
	assert.deepEqual(fs.readdirSync(fs.realpathSync(where.outputRoot)), []);
});

test('reports invalid when cache metadata claims another identity for the locked bytes', async () => {
	const where = area('cache-contradiction');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist, { manifestName: 'pkg-b', manifestVersion: '4.5.6' });
	lock(where, [lockEntry(dist)]);

	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'invalid');
	assert.match(error.message, /claims pkg-b@4\.5\.6 for pkg-a@1\.2\.3/);
	assert.deepEqual(fs.readdirSync(fs.realpathSync(where.outputRoot)), []);
});

test('ignores a cache entry whose metadata does not match the locked distribution', async () => {
	const wrongChecksum = area('cache-checksum');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(wrongChecksum, dist);
	cache(wrongChecksum, dist, { integrity: `sha512-${crypto.createHash('sha512').update('something else').digest('base64')}` });
	lock(wrongChecksum, [lockEntry(dist)]);
	const checksum = await rejection(wrongChecksum.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(checksum.status, 'no-data');
	assert.match(checksum.message, /no Yarn cache entry/);

	const wrongLocator = area('cache-locator');
	const locatorInstalled = install(wrongLocator, dist);
	cache(wrongLocator, dist, { resolved: `${dist.resolved.split('#')[0]}#0000000000000000000000000000000000000000` });
	lock(wrongLocator, [lockEntry(dist)]);
	const locator = await rejection(wrongLocator.resolver().resolve(path.join(locatorInstalled, 'index.js')));
	assert.equal(locator.status, 'no-data', 'the resolved locator must match verbatim, fragment included');
});

test('ignores a cache folder name claiming an identity its metadata does not carry', async () => {
	const where = area('fake-slug');
	const dist = distribution('pkg-a', '1.2.3');
	const impostor = distribution('pkg-b', '4.5.6');
	const installed = install(where, dist);
	// A folder named like the wanted package, holding another distribution.
	const liar = path.join(where.cacheDir, 'npm-pkg-a-1.2.3-integrity', 'node_modules', 'pkg-a');
	fs.mkdirSync(liar, { recursive: true });
	fs.writeFileSync(
		path.join(liar, '.yarn-metadata.json'),
		JSON.stringify({ manifest: { name: impostor.name, version: impostor.version }, remote: { resolved: impostor.resolved, integrity: impostor.integrity }, registry: 'npm' }),
	);
	fs.writeFileSync(path.join(liar, '.yarn-tarball.tgz'), impostor.bytes);
	cache(where, dist, { slug: 'npm-honest-entry' });
	lock(where, [lockEntry(dist)]);

	const resolver = where.resolver();
	const binding = await resolver.resolve(path.join(installed, 'index.js'));
	assert.equal(binding.component.checksum, undefined);
	assert.equal(binding.component.source.checksum, dist.integrity);
	assert.equal(fs.readFileSync(path.join(binding.originalRoot, 'index.js'), 'utf8'), `module.exports = ${JSON.stringify('pkg-a@1.2.3')};\n`);
	resolver.close();
});

test('extracts one distribution once, for every installed copy of it', async () => {
	const where = area('reuse');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	const host = distribution('pkg-b', '4.5.6');
	const hostRoot = install(where, host);
	const second = path.join(hostRoot, 'node_modules', dist.name);
	fs.mkdirSync(second, { recursive: true });
	tar.x({ cwd: second, strip: 1, sync: true, file: writeTemp('again.tgz', dist.bytes) });
	cache(where, dist);
	cache(where, host);
	lock(where, [lockEntry(dist), lockEntry(host)]);

	const resolver = where.resolver();
	const first = await resolver.resolve(path.join(installed, 'index.js'));
	const again = await resolver.resolve(path.join(installed, 'NOTICE.txt'));
	const nested = await resolver.resolve(path.join(second, 'index.js'));
	assert.equal(again.originalRoot, first.originalRoot);
	assert.equal(nested.originalRoot, first.originalRoot);
	assert.equal(nested.root, second);
	assert.equal(fs.readdirSync(fs.realpathSync(where.outputRoot)).length, 1);
	resolver.close();
});

test('reads the lockfile once per resolver: a later edit needs a new resolver', async () => {
	const where = area('lifetime');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	cache(where, dist);
	lock(where, [lockEntry(dist)]);

	const resolver = where.resolver();
	assert.equal((await resolver.resolve(path.join(installed, 'index.js'))).component.version, '1.2.3');
	lock(where, [lockEntry(dist, { version: '9.9.9' })]);
	assert.equal((await resolver.resolve(path.join(installed, 'NOTICE.txt'))).component.version, '1.2.3', 'the instance keeps the lockfile it read');
	resolver.close();

	const fresh = where.resolver();
	const error = await rejection(fresh.resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'no-data');
	assert.match(error.message, /no lockfile entry for pkg-a@1\.2\.3/);
});

test('returns undefined for a source outside any node_modules tree', async () => {
	const where = area('outside');
	const dist = distribution('pkg-a', '1.2.3');
	install(where, dist);
	cache(where, dist);
	lock(where, [lockEntry(dist)]);
	const own = path.join(where.workdir, 'src');
	fs.mkdirSync(own, { recursive: true });
	fs.writeFileSync(path.join(own, 'app.js'), 'module.exports = 1;\n');

	const resolver = where.resolver();
	assert.equal(await resolver.resolve(path.join(own, 'app.js')), undefined);
	assert.deepEqual(fs.readdirSync(fs.realpathSync(where.outputRoot)), []);
	resolver.close();
});

test('never returns undefined for an installed package it cannot prove', async () => {
	const where = area('unproven');
	const dist = distribution('pkg-a', '1.2.3');
	const installed = install(where, dist);
	lock(where, [lockEntry(dist)]);

	const error = await rejection(where.resolver().resolve(path.join(installed, 'index.js')));
	assert.equal(error.status, 'no-data');
	assert.match(error.message, /no Yarn cache entry/);
});

test('reports no-data for an aliased install directory and for a linked package', async () => {
	const alias = area('alias');
	const dist = distribution('pkg-a', '1.2.3');
	const aliasRoot = path.join(alias.workdir, 'node_modules', 'alias-name');
	fs.mkdirSync(aliasRoot, { recursive: true });
	tar.x({ cwd: aliasRoot, strip: 1, sync: true, file: writeTemp('alias.tgz', dist.bytes) });
	cache(alias, dist);
	lock(alias, [lockEntry(dist)]);
	const aliased = await rejection(alias.resolver().resolve(path.join(aliasRoot, 'index.js')));
	assert.equal(aliased.status, 'no-data');
	assert.match(aliased.message, /alias/);

	const linked = area('workspace-link');
	const workspace = path.join(linked.workdir, 'packages', 'pkg-a');
	fs.mkdirSync(workspace, { recursive: true });
	fs.writeFileSync(path.join(workspace, 'package.json'), JSON.stringify({ name: 'pkg-a', version: '1.2.3' }));
	fs.writeFileSync(path.join(workspace, 'index.js'), 'module.exports = "workspace";\n');
	fs.symlinkSync(workspace, linked.installedDir('pkg-a'));
	cache(linked, dist);
	lock(linked, [lockEntry(dist)]);
	const workspaceError = await rejection(linked.resolver().resolve(path.join(linked.installedDir('pkg-a'), 'index.js')));
	assert.equal(workspaceError.status, 'no-data');
	assert.match(workspaceError.message, /is a link/);
});

test('reports invalid for an installed manifest without an exact name and version', async () => {
	const where = area('manifest');
	const broken = path.join(where.workdir, 'node_modules', 'pkg-a');
	fs.mkdirSync(broken, { recursive: true });
	fs.writeFileSync(path.join(broken, 'package.json'), '{"name": "pkg-a"}');
	fs.writeFileSync(path.join(broken, 'index.js'), 'module.exports = 1;\n');
	lock(where, []);

	const error = await rejection(where.resolver().resolve(path.join(broken, 'index.js')));
	assert.equal(error.status, 'invalid');
	assert.match(error.message, /no exact name and version/);
});

test('reports no-data for a lock entry without integrity and unsupported for a legacy checksum', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	const bare = area('no-integrity');
	const bareInstalled = install(bare, dist);
	cache(bare, dist);
	lock(bare, [lockEntry(dist, { integrity: null })]);
	const missing = await rejection(bare.resolver().resolve(path.join(bareInstalled, 'index.js')));
	assert.equal(missing.status, 'no-data');
	assert.match(missing.message, /no integrity/);

	const legacy = area('md5-integrity');
	const legacyInstalled = install(legacy, dist);
	cache(legacy, dist);
	lock(legacy, [lockEntry(dist, { integrity: `md5-${crypto.createHash('md5').update(dist.bytes).digest('base64')}` })]);
	const unsupported = await rejection(legacy.resolver().resolve(path.join(legacyInstalled, 'index.js')));
	assert.equal(unsupported.status, 'unsupported');
	assert.match(unsupported.message, /unsupported checksum spelling/);
});

test('reports unsupported for a Berry lockfile and invalid for an unresolved merge', async () => {
	const dist = distribution('pkg-a', '1.2.3');
	const berry = area('berry');
	const berryInstalled = install(berry, dist);
	fs.writeFileSync(berry.lockPath, '__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"pkg-a@npm:1.2.3":\n  version: 1.2.3\n');
	const berryError = await rejection(berry.resolver().resolve(path.join(berryInstalled, 'index.js')));
	assert.equal(berryError.status, 'unsupported');
	assert.match(berryError.message, /Berry/);

	const merged = area('merge');
	const mergedInstalled = install(merged, dist);
	fs.writeFileSync(merged.lockPath, '# yarn lockfile v1\n\n<<<<<<< HEAD\npkg-a@^1.2.0:\n  version "1.2.3"\n=======\npkg-a@^1.2.0:\n  version "1.2.4"\n>>>>>>> other\n');
	const mergeError = await rejection(merged.resolver().resolve(path.join(mergedInstalled, 'index.js')));
	assert.equal(mergeError.status, 'invalid');
	assert.match(mergeError.message, /not a resolved lockfile/);
});

test('refuses an output root that is not an owned empty directory', () => {
	const where = area('output-root');
	fs.mkdirSync(where.outputRoot, { recursive: true });
	fs.writeFileSync(path.join(where.outputRoot, 'kept.txt'), 'kept');
	assert.throws(() => where.resolver(), /must be empty/);
	assert.throws(() => where.resolver({ outputRoot: path.join(where.workdir, 'originals') }), /overlaps/);
	assert.throws(() => where.resolver({ outputRoot: path.join(where.root, 'out', 'missing', 'deep') }), /must be an existing directory/);
	assert.equal(fs.readFileSync(path.join(where.outputRoot, 'kept.txt'), 'utf8'), 'kept');
});
