'use strict';

// Ahead of every webpack require of this file: the bootstrap evidence of the
// collector is a recording of the sources this process loads.
require('./runtime-preload.cjs');

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');
const CopyPlugin = require('copy-webpack-plugin');
const Collector = require('./collector.cjs');
const { createFixture, configuration, run, readProof } = require('./fixture.cjs');

let root, fixture;
before(() => {
	root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-webpack-resolver-')));
	fixture = createFixture(root, {bootstrap: true});
});
after(() => fs.rmSync(root, {recursive: true, force: true}));

function row(area, name) { return readProof(area).assets.find(a => a.path === name); }

test('resolves selected managed modules before a containing static project root', async () => {
	const area = fixture.workspace('managed');
	const requested = new Set();
	const projectOriginal = path.join(root, 'empty-primary');
	fs.mkdirSync(projectOriginal);
	const primary = {root: area.root, originalRoot: projectOriginal, component: {...area.originals[0].component, id:'primary'}};
	await run(configuration(area, {plugins: [new CopyPlugin({patterns:[{from: area.installed('pkg-a/NOTICE.txt'), to:'notice.txt'}]}), new Collector({
		proofPath: area.proofPath, originals:[primary, fixture.bootstrap.binding], copied:[{from:area.installed('pkg-a/NOTICE.txt'),to:'notice.txt'}],
		resolveOriginal: async resource => {
			requested.add(resource);
			return area.originals.find(binding => resource.startsWith(binding.root + path.sep));
		}
	})]}));
	assert.equal(row(area, 'main.js').status, 'present');
	assert.deepEqual(row(area, 'main.js').includedComponents, ['node:app@0.1.0', 'node:pkg-a@1.2.3', 'node:pkg-b@4.5.6', 'node:webpack@5.94.0']);
	assert.equal(row(area, 'notice.txt').status, 'present');
	assert.ok([...requested].some(p => p.endsWith('/pkg-b/index.js')));
	assert.ok(![...requested].some(p => p.includes('/pkg-c/')));
	assert.deepEqual(row(area,'notice.txt').includedComponents,['node:pkg-a@1.2.3']);
});

test('does not fall back to static originals when a managed original is missing', async () => {
	const area = fixture.workspace('missing');
	await run(configuration(area, {plugins:[new Collector({proofPath:area.proofPath,originals:area.originals,copied:[],resolveOriginal:async resource=>{
		if(resource.includes('/pkg-b/'))throw Object.assign(new Error('locked archive is missing'),{status:'no-data'});
		return undefined;
	}})]}));
	assert.equal(row(area,'main.js').status,'no-data');
	assert.match(row(area,'main.js').reason,/locked archive is missing/);
});

test('rejects a dynamic binding whose root does not cover the resource', async () => {
	const area = fixture.workspace('wrong-root');
	await run(configuration(area, {plugins:[new Collector({proofPath:area.proofPath,originals:area.originals,copied:[],resolveOriginal:async ()=>area.originals.find(b=>b.component.name==='pkg-c')})]}));
	assert.equal(row(area,'main.js').status,'invalid');
	assert.match(row(area,'main.js').reason,/does not cover/);
});

test('refuses two dynamic identities that claim the same component id', async () => {
	const area = fixture.workspace('same-id');
	await run(configuration(area, {plugins:[new Collector({proofPath:area.proofPath,originals:area.originals,copied:[],resolveOriginal:async resource=>{
		const binding = area.originals.find(b=>resource.startsWith(b.root+path.sep));
		return binding && {...binding,component:{...binding.component,id:'same'}};
	}})]}));
	assert.equal(row(area,'main.js').status,'invalid');
	assert.match(row(area,'main.js').reason,/conflicting identities/);
});

test('fails the compilation for an untyped original acquisition error', async () => {
	const area = fixture.workspace('environment-error');
	await assert.rejects(run(configuration(area, {plugins:[new Collector({proofPath:area.proofPath, originals:area.originals,copied:[],resolveOriginal:async()=>{throw new Error('fixture original storage unavailable');}})]})), /fixture original storage unavailable/);
	assert.equal(fs.existsSync(area.proofPath),false);
});
