'use strict';
// Ahead of every webpack require of this file: the bootstrap evidence of the
// collector is a recording of the sources this process loads.
require('./runtime-preload.cjs');

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const PrebuiltOriginals = require('./prebuilt-originals.cjs');
const { createFixture } = require('./fixture.cjs');

const DIGEST = `sha256:${'a'.repeat(64)}`;
const OTHER = `sha256:${'b'.repeat(64)}`;
// A dependency of the rebuild as its lockfile states it: the archive it was
// installed from, and that entry's integrity.
const COMPONENT = {
	id: 'node:redoc@2.4.0',
	name: 'redoc',
	version: '2.4.0',
	source: { kind: 'node', locator: 'https://registry.yarnpkg.com/redoc/-/redoc-2.4.0.tgz', checksum: `sha512-${'c'.repeat(86)}==` },
};

let scratch;
let fixture;
let areas = 0;

before(
	() => {
		scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-prebuilt-')));
		fixture = createFixture(path.join(scratch, 'fixture'), { bootstrap: true, minifier: true });
	},
	{ timeout: 900000 },
);

after(() => scratch && fs.rmSync(scratch, { recursive: true, force: true }));

// A manifest written where the reader looks for it, beside the context.
function written(manifest) {
	const where = path.join(scratch, `context-${areas++}`);
	fs.mkdirSync(where, { recursive: true });
	if (manifest !== undefined) fs.writeFileSync(path.join(where, 'webpack-prebuilt.json'), typeof manifest === 'string' ? manifest : JSON.stringify(manifest));
	return new PrebuiltOriginals(path.join(where, 'context.json'));
}

function entry(overrides = {}) {
	return {
		sha256: DIGEST,
		components: [COMPONENT],
		inputs: [{ path: 'src/index.tsx', sha256: OTHER, components: [COMPONENT.id] }],
		...overrides,
	};
}

function refusal(manifest) {
	try {
		written(manifest);
	} catch (error) {
		return error;
	}
	return null;
}

// A build whose context delivers nothing is the ordinary case: the reader must
// answer that it knows nothing, not refuse the build.
test('answers nothing when the context delivers no composition', () => {
	const reader = written(undefined);
	assert.equal(reader.resolve(DIGEST), null);
});

test('answers the units of the build that emitted those very bytes', () => {
	const reader = written({ version: 1, entries: [entry()] });
	assert.deepEqual(reader.resolve(DIGEST), [{ path: 'src/index.tsx', sha256: OTHER, component: COMPONENT }]);
	// Keyed by the bytes and by nothing else.
	assert.equal(reader.resolve(OTHER), null);
});

// One unit per claiming component, which is the shape the collector builds an
// asset's own units in.
test('answers one unit for each component claiming an input', () => {
	const second = { ...COMPONENT, id: 'npm:other@1.0.0', name: 'other', version: '1.0.0' };
	const reader = written({
		version: 1,
		entries: [entry({ components: [COMPONENT, second], inputs: [{ path: 'shared.ts', sha256: OTHER, components: [COMPONENT.id, second.id] }] })],
	});
	assert.deepEqual(
		reader.resolve(DIGEST).map((unit) => unit.component.id),
		[COMPONENT.id, second.id],
	);
});

// A prepared source image of the rebuild, stated by the digest of that image.
test('accepts a prepared source stated by its image digest', () => {
	const pm = { ...COMPONENT, id: 'pm:source', source: { kind: 'pm', locator: 'example.test/source', checksum: `sha256:${'9'.repeat(64)}` } };
	const reader = written({ version: 1, entries: [entry({ components: [pm], inputs: [{ path: 'a.ts', sha256: OTHER, components: [pm.id] }] })] });
	assert.equal(reader.resolve(DIGEST)[0].component.id, 'pm:source');
});

// A Git-pinned dependency of the rebuild is stated the way the primary-source
// manifest states its own: the checksum must name the commit of its locator.
test('accepts a component pinned to the Git commit of its own locator', () => {
	const node = {
		id: 'node:thing',
		name: 'thing',
		version: '1.0.0',
		source: { kind: 'node', locator: `git+https://example.test/thing.git#${'1'.repeat(40)}`, checksum: `git-commit:sha1:${'1'.repeat(40)}` },
	};
	const reader = written({ version: 1, entries: [entry({ components: [node], inputs: [{ path: 'a.ts', sha256: OTHER, components: [node.id] }] })] });
	assert.equal(reader.resolve(DIGEST)[0].component.id, 'node:thing');
});

test('refuses a manifest it cannot read', () => {
	for (const [manifest, status, pattern] of [
		['{', 'invalid', /prebuilt manifest JSON/],
		[[], 'invalid', /must be an object/],
		[{ entries: [] }, 'no-data', /version is missing/],
		[{ version: '1', entries: [] }, 'invalid', /version is invalid/],
		[{ version: 2, entries: [] }, 'unsupported', /prebuilt manifest version 2/],
		[{ version: 1, entries: [], extra: true }, 'invalid', /unknown prebuilt manifest field/],
		[{ version: 1 }, 'invalid', /requires an entry array/],
	]) {
		const error = refusal(manifest);
		assert.ok(error, `${JSON.stringify(manifest)} was accepted`);
		assert.equal(error.status, status, error.message);
		assert.match(error.message, pattern);
	}
});

test('refuses an entry whose composition does not hold together', () => {
	for (const [overrides, pattern] of [
		[{ sha256: 'sha256:short' }, /invalid or duplicate prebuilt entry digest/],
		[{ extra: true }, /invalid prebuilt entry/],
		[{ components: [] }, /states no components and inputs/],
		// A composition of components alone describes nothing.
		[{ inputs: [] }, /states no components and inputs/],
		[
			{ components: [COMPONENT, { ...COMPONENT, id: 'npm:unclaimed@1.0.0' }] },
			/component npm:unclaimed@1\.0\.0 of prebuilt entry .* is claimed by no input/,
		],
		[{ components: [{ ...COMPONENT, id: '' }] }, /invalid or duplicate component/],
		[{ components: [{ ...COMPONENT, version: '' }] }, /carries no exact name and version/],
		[{ components: [{ ...COMPONENT, source: { kind: 'guess', locator: 'x', checksum: 'y' } }] }, /is of an unverifiable kind/],
		[{ components: [{ ...COMPONENT, source: null }] }, /is of an unverifiable kind/],
		[{ components: [{ ...COMPONENT, source: { kind: 'node', locator: '', checksum: 'y' } }] }, /pins no archive/],
		// A prepared source image is stated by its own digest.
		[{ components: [{ ...COMPONENT, source: { kind: 'pm', locator: 'example.test/source', checksum: 'sha512-x' } }] }, /pins no image digest/],
		[{ components: [{ ...COMPONENT, source: { kind: 'node', locator: 'git+https://e.test/a.git#main', checksum: 'sha512-x' } }] }, /pins no Git commit/],
		[
			{ components: [{ ...COMPONENT, source: { kind: 'node', locator: `git+https://e.test/a.git#${'1'.repeat(40)}`, checksum: `git-commit:sha1:${'2'.repeat(40)}` } }] },
			/pins no Git commit/,
		],
		[{ inputs: [{ path: '', sha256: OTHER, components: [COMPONENT.id] }] }, /invalid input path/],
		[{ inputs: [{ path: 'a.ts', sha256: 'nope', components: [COMPONENT.id] }] }, /invalid input digest/],
		[{ inputs: [{ path: 'a.ts', sha256: OTHER, components: [] }] }, /claimed by no component/],
		[{ inputs: [{ path: 'a.ts', sha256: OTHER, components: ['npm:ghost'] }] }, /claimed by the unknown component npm:ghost/],
		[{ inputs: [{ path: 'a.ts', sha256: OTHER, components: [COMPONENT.id], extra: 1 }] }, /invalid input of prebuilt entry/],
	]) {
		const error = refusal({ version: 1, entries: [entry(overrides)] });
		assert.ok(error, `${JSON.stringify(overrides)} was accepted`);
		assert.equal(error.status, 'invalid', error.message);
		assert.match(error.message, pattern);
	}
});

// One composition per bytes. Two of them are a contradiction, not a merge.
test('refuses two compositions for one digest', () => {
	const error = refusal({ version: 1, entries: [entry(), entry({ inputs: [{ path: 'other.ts', sha256: OTHER, components: [COMPONENT.id] }] })] });
	assert.ok(error);
	assert.match(error.message, /invalid or duplicate prebuilt entry digest/);
});

// The whole collector: a copied bundle this build did not build is described by
// the composition the rebuild that emitted those very bytes proved.
test('describes a copied prebundle by the composition delivered for its bytes', async () => {
	const { area, proof } = await fixture.buildPrimary('prebuilt-copy', { prebuilt: (where) => delivered(where) });
	const vendor = proof.assets.find((asset) => asset.path === 'vendor.js');
	assert.equal(vendor.status, 'present', vendor.reason);
	// The claim is what the prebundle is made of, not the identity of the
	// archive it was shipped in.
	assert.deepEqual(vendor.includedComponents, [COMPONENT.id]);
	assert.deepEqual(vendor.components, [COMPONENT]);
	assert.deepEqual(vendor.inputs, [{ kind: 'source', path: 'src/index.tsx', sha256: OTHER, components: [COMPONENT.id], disposition: 'included' }]);
	assert.equal(vendor.sha256, sha256(area.installed('pkg-c/vendor.js')));
	// The file it was copied from is not claimed by its own npm identity.
	assert.equal(JSON.stringify(vendor).includes('pkg-c'), false);
});

// Without a delivery for those bytes the old refusal stands, word for word.
test('refuses a copied prebundle no composition is delivered for', async () => {
	const { proof } = await fixture.buildPrimary('prebuilt-absent', { prebuilt: () => new PrebuiltOriginals(path.join(scratch, 'empty', 'context.json')) });
	const vendor = proof.assets.find((asset) => asset.path === 'vendor.js');
	assert.equal(vendor.status, 'no-data');
	assert.match(vendor.reason, /copied \.js carries an unsupplied nested composition/);
	assert.deepEqual(vendor.components, []);
});

// A copied file is an asset of this build like any other: the minifier of this
// compilation rewrites it, and the bytes to be found on disk are the ones it
// left. What the file is made of is unchanged by that rewrite.
test('describes a copied prebundle this build minified', async () => {
	const { area, proof } = await fixture.buildPrimary('prebuilt-minified', { prebuilt: (where) => delivered(where), configuration: { optimization: { minimize: true } } });
	const vendor = proof.assets.find((asset) => asset.path === 'vendor.js');
	assert.equal(vendor.status, 'present', vendor.reason);
	assert.deepEqual(vendor.includedComponents, [COMPONENT.id]);
	// The bytes on disk are the minified ones, and no longer what was copied.
	assert.equal(vendor.sha256, sha256(path.join(area.output, 'vendor.js')));
	assert.notEqual(vendor.sha256, sha256(area.installed('pkg-c/vendor.js')));
	// The comments that minification took out of the copied file are claimed by
	// what the file is made of, which is the delivered composition.
	const comments = proof.assets.find((asset) => asset.path === 'vendor.js.LICENSE.txt');
	assert.ok(comments, proof.assets.map((asset) => asset.path).join(', '));
	assert.equal(comments.status, 'present', comments.reason);
	assert.deepEqual(comments.includedComponents, [COMPONENT.id]);
	assert.equal(comments.sha256, sha256(path.join(area.output, 'vendor.js.LICENSE.txt')));
});

// Without a delivery the minified copy is still refused for what it is - an
// opaque bundle - and the comments taken out of it are refused with it.
test('refuses a minified copied prebundle no composition is delivered for', async () => {
	const { proof } = await fixture.buildPrimary('prebuilt-minified-absent', { configuration: { optimization: { minimize: true } } });
	const vendor = proof.assets.find((asset) => asset.path === 'vendor.js');
	assert.equal(vendor.status, 'no-data');
	assert.match(vendor.reason, /copied \.js carries an unsupplied nested composition/);
	const comments = proof.assets.find((asset) => asset.path === 'vendor.js.LICENSE.txt');
	assert.equal(comments.status, 'no-data');
	assert.match(comments.reason, /belongs to no chunk of this compilation and was not copied/);
	assert.deepEqual(comments.components, []);
});

// The delivery says what the bytes are made of; it never says what the bytes
// are. An asset rewritten after it was copied is refused by the byte checks that
// stand in front of the delivery, and a delivered composition cannot rescue it.
//
// The copy observer reaches it first - it compares the emitted bytes with the
// ones it saw copied - so this is `no-data` rather than the `hash-mismatch` the
// disk comparison would give. Either way the composition is not claimed.
test('refuses a copied prebundle rewritten after it was copied', async () => {
	const { proof } = await fixture.buildPrimary('prebuilt-rewritten', {
		prebuilt: (where) => delivered(where),
		plugins: [rewrite()],
	});
	const vendor = proof.assets.find((asset) => asset.path === 'vendor.js');
	assert.equal(vendor.status, 'no-data', vendor.reason);
	assert.match(vendor.reason, /does not carry the bytes of an observed copy/);
	assert.deepEqual(vendor.components, []);
	assert.deepEqual(vendor.inputs, []);
});

// The digest a composition is looked up by is the digest of bytes already bound
// to their own verified original. A file that is not what its distribution
// serves is refused before any delivery is consulted, even when the delivery
// names the very bytes that stand there.
test('refuses a prebundle that is not the file its distribution serves', async () => {
	const tampered = 'module.exports = { vendored: true, extra: 1 };\n';
	const { proof } = await fixture.buildPrimary('prebuilt-tampered', {
		beforeRun: (where) => fs.writeFileSync(where.installed('pkg-c/vendor.js'), tampered),
		prebuilt: () => deliveredFor(`sha256:${crypto.createHash('sha256').update(tampered).digest('hex')}`),
	});
	const vendor = proof.assets.find((asset) => asset.path === 'vendor.js');
	assert.equal(vendor.status, 'hash-mismatch', vendor.reason);
	assert.deepEqual(vendor.components, []);
	assert.deepEqual(vendor.inputs, []);
});

// A manifest naming the digest of the file the build really copies.
function delivered(where) {
	return deliveredFor(sha256(where.installed('pkg-c/vendor.js')));
}

function deliveredFor(digest) {
	const root = path.join(scratch, `delivery-${areas++}`);
	fs.mkdirSync(root, { recursive: true });
	fs.writeFileSync(
		path.join(root, 'webpack-prebuilt.json'),
		JSON.stringify({ version: 1, entries: [{ sha256: digest, components: [COMPONENT], inputs: [{ path: 'src/index.tsx', sha256: OTHER, components: [COMPONENT.id] }] }] }),
	);
	return new PrebuiltOriginals(path.join(root, 'context.json'));
}

// A plugin writing other bytes into the copied asset after it was copied.
function rewrite() {
	return {
		apply(compiler) {
			compiler.hooks.compilation.tap('fixture', (compilation) => {
				compilation.hooks.processAssets.tap({ name: 'fixture', stage: compiler.webpack.Compilation.PROCESS_ASSETS_STAGE_REPORT }, () => {
					compilation.updateAsset('vendor.js', new compiler.webpack.sources.RawSource(Buffer.from('module.exports = { vendored: false };\n')));
				});
			});
		},
	};
}

function sha256(file) {
	return `sha256:${crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')}`;
}
