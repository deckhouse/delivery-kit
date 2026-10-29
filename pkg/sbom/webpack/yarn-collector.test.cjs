'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {before,after,test} = require('node:test');
const CopyPlugin = require('copy-webpack-plugin');
const Collector = require('./collector.cjs');
const YarnOriginals = require('./yarn-originals.cjs');
const {createFixture,configuration,run,readProof} = require('./fixture.cjs');

let root,fixture;
before(()=>{root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'dk-yarn-collector-')));fixture=createFixture(root);});
after(()=>fs.rmSync(root,{recursive:true,force:true}));

function originals(area) {
	const cacheDir=path.join(area.root,'cache');
	fs.mkdirSync(cacheDir);
	const entries=[];
	for(const [name,dist] of Object.entries(fixture.distributions)) {
		const resolved=`https://registry.example.test/${name}/download`;
		entries.push(`${JSON.stringify(name+'@'+dist.component.version)}:\n  version ${JSON.stringify(dist.component.version)}\n  resolved ${JSON.stringify(resolved)}\n  integrity ${dist.integrity}\n`);
		const cached=path.join(cacheDir,name,'node_modules',name);
		fs.mkdirSync(cached,{recursive:true});
		fs.writeFileSync(path.join(cached,'.yarn-metadata.json'),JSON.stringify({manifest:{name,version:dist.component.version},remote:{type:'tarball',resolved,integrity:dist.integrity}}));
		fs.copyFileSync(dist.tarball,path.join(cached,'.yarn-tarball.tgz'));
	}
	const lockPath=path.join(area.root,'yarn.lock');
	fs.writeFileSync(lockPath,'# yarn lockfile v1\n\n'+entries.join('\n'));
	const outputRoot=path.join(root,path.basename(area.root)+'-verified');
	return {cacheDir,outputRoot, resolver:new YarnOriginals({workdir:area.root,lockPath,cacheDir,outputRoot})};
}

async function compile(area,resolver) {
	await run(configuration(area,{plugins:[new CopyPlugin({patterns:[{from:area.installed('pkg-a/NOTICE.txt'),to:'notice.txt'}]}),new Collector({proofPath:area.proofPath, originals:area.originals, copied:[{from:area.installed('pkg-a/NOTICE.txt'),to:'notice.txt'}],resolveOriginal:resource=>resolver.resolve(resource)})]}));
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
		assert.deepEqual(main.components.map(c=>c.name).sort(),['app','pkg-a','pkg-b']);
		assert.deepEqual(copy.components.map(c=>c.name),['pkg-a']);
		for(const c of main.components) {
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
