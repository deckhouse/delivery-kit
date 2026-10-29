'use strict';

// Ahead of every webpack require of this file: the bootstrap evidence of the
// collector is a recording of the sources this process loads.
require('./runtime-preload.cjs');

const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const {before,after,test} = require('node:test');
const CopyPlugin = require('copy-webpack-plugin');
const Collector = require('./collector.cjs');
const YarnOriginals = require('./yarn-originals.cjs');
const {createFixture,configuration,run,readProof} = require('./fixture.cjs');

let root,fixture;
before(()=>{root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'dk-yarn-collector-')));fixture=createFixture(root,{bootstrap:true});});
after(()=>fs.rmSync(root,{recursive:true,force:true}));

function originals(area, algorithm='sha512') {
	const cacheDir=path.join(area.root,'cache');
	fs.mkdirSync(cacheDir);
	const entries=[];
	for(const [name,dist] of Object.entries(fixture.distributions)) {
		const resolved=`https://registry.example.test/${name}/download`;
		const integrity=algorithm+'-'+crypto.createHash(algorithm).update(fs.readFileSync(dist.tarball)).digest('base64');
		entries.push(`${JSON.stringify(name+'@'+dist.component.version)}:\n  version ${JSON.stringify(dist.component.version)}\n  resolved ${JSON.stringify(resolved)}\n  integrity ${integrity}\n`);
		const cached=path.join(cacheDir,name,'node_modules',name);
		fs.mkdirSync(cached,{recursive:true});
		fs.writeFileSync(path.join(cached,'.yarn-metadata.json'),JSON.stringify({manifest:{name,version:dist.component.version},remote:{type:'tarball',resolved,integrity}}));
		fs.copyFileSync(dist.tarball,path.join(cached,'.yarn-tarball.tgz'));
	}
	const lockPath=path.join(area.root,'yarn.lock');
	fs.writeFileSync(lockPath,'# yarn lockfile v1\n\n'+entries.join('\n'));
	const outputRoot=path.join(root,path.basename(area.root)+'-verified');
	return {cacheDir,outputRoot, resolver:new YarnOriginals({workdir:area.root,lockPath,cacheDir,outputRoot})};
}

async function compile(area,resolver) {
	// The Yarn resolver owns the packages installed into this workspace; the
	// webpack that is running is not one of them and keeps its static binding.
	const resolveOriginal=resource=>resource.startsWith(area.root+path.sep)?resolver.resolve(resource):undefined;
	await run(configuration(area,{plugins:[new CopyPlugin({patterns:[{from:area.installed('pkg-a/NOTICE.txt'),to:'notice.txt'}]}),new Collector({proofPath:area.proofPath, originals:area.originals, copied:[{from:area.installed('pkg-a/NOTICE.txt'),to:'notice.txt'}],resolveOriginal})]}));
	return readProof(area);
}

test('joins selected webpack units with SRI-verified Yarn archives only',async()=>{
	const area=fixture.workspace('selected-yarn');
	const {cacheDir,outputRoot,resolver}=originals(area);
	fs.writeFileSync(path.join(cacheDir,'pkg-c','node_modules','pkg-c','.yarn-tarball.tgz'),'corrupt unselected archive');
	try {
		const proof=await compile(area,resolver);
		const main=proof.assets.find(a=>a.path==='main.js');
		const copy=proof.assets.find(a=>a.path==='notice.txt');
		assert.equal(main.status,'present');
		assert.equal(copy.status,'present');
		assert.deepEqual(main.components.map(c=>c.name).sort(),['app','pkg-a','pkg-b','webpack']);
		assert.deepEqual(copy.components.map(c=>c.name),['pkg-a']);
		for(const c of main.components) {
			if(c.name==='webpack') {
				// Verified independently of the lockfile, as the static binding it is.
				assert.deepEqual(c,fixture.bootstrap.binding.component);
				continue;
			}
			assert.equal(c.source.checksum,fixture.distributions[c.name].integrity);
			assert.equal(c.source.locator,`https://registry.example.test/${c.name}/download`);
		}
		assert.equal(fs.readdirSync(outputRoot).length,3,'the unused package archive must not be extracted');
	} finally {resolver.close();}
	assert.deepEqual(fs.readdirSync(outputRoot),[]);
});

test('never uses the static original when the selected locked archive is corrupt',async()=>{
	const area=fixture.workspace('corrupt-yarn');
	const {cacheDir,resolver}=originals(area);
	fs.writeFileSync(path.join(cacheDir,'pkg-b','node_modules','pkg-b','.yarn-tarball.tgz'),'corrupt selected archive');
	try {
		const proof=await compile(area,resolver);
		const main=proof.assets.find(a=>a.path==='main.js');
		assert.equal(main.status,'hash-mismatch');
		assert.match(main.reason,/cached archive of pkg-b@4\.5\.6 does not satisfy sha512-/);
		assert.deepEqual(main.components,[]);
	} finally {resolver.close();}
});

test('preserves SHA1 manager integrity while checking selected source bytes',async()=>{
	const area=fixture.workspace('sha1-yarn');
	const {resolver}=originals(area,'sha1');
	try {
		const proof=await compile(area,resolver);
		const main=proof.assets.find(a=>a.path==='main.js');
		assert.equal(main.status,'present');
		for(const component of main.components.filter(c=>c.name!=='webpack')) {
			const archive=fs.readFileSync(fixture.distributions[component.name].tarball);
			assert.equal(component.source.checksum,'sha1-'+crypto.createHash('sha1').update(archive).digest('base64'));
		}
		for(const input of main.inputs) assert.equal(input.sha256,'sha256:'+crypto.createHash('sha256').update(fs.readFileSync(input.path)).digest('hex'));
	} finally {resolver.close();}
});

test('rejects changed selected members of a SHA1-verified distribution',async()=>{
	const area=fixture.workspace('sha1-member-mismatch');
	const {resolver}=originals(area,'sha1');
	const installed=area.installed('pkg-b/index.js');
	const bytes=fs.readFileSync(installed);
	const altered=bytes.toString().replace('return "b"','return "z"');
	assert.notEqual(altered,bytes.toString());
	assert.equal(Buffer.byteLength(altered),bytes.length);
	fs.writeFileSync(installed,altered);
	try {
		const proof=await compile(area,resolver);
		const main=proof.assets.find(a=>a.path==='main.js');
		assert.equal(main.status,'hash-mismatch');
		assert.match(main.reason,/materialized source differs from its original/);
		assert.deepEqual(main.includedComponents,[]);
	} finally {resolver.close();}
});
