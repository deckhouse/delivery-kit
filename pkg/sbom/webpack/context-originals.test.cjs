'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const crypto=require('node:crypto');
const {test}=require('node:test');
const Collector=require('./collector.cjs');
const ContextOriginals=require('./context-originals.cjs');
const {configuration,run,readProof}=require('./fixture.cjs');

function fixture(t) {
	const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'dk-context-sources-')));
	t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
	const area={root,output:path.join(root,'out'),modules:path.join(root,'node_modules'),proofPath:path.join(root,'private','assets.json'),installed:name=>path.join(root,name)};
	fs.writeFileSync(path.join(root,'primary.js'),'import {value} from "./secondary.js"; console.log(value);\n');
	fs.writeFileSync(path.join(root,'secondary.js'),'export const value = 42;\n');
	const contextDir=path.join(root,'context');fs.mkdirSync(contextDir);
	const component={id:'pm-source',name:'primary-source',version:'1',source:{kind:'pm',locator:'example.test/source',checksum:'sha256:'+'1'.repeat(64)}};
	const manifest={version:1,components:[component],files:['primary.js','secondary.js'].map(name=>{
		const file=path.join(root,name);return {path:file,sha256:'sha256:'+crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'),component:component.id};
	})};
	const save=()=>fs.writeFileSync(path.join(contextDir,'webpack-originals.json'),JSON.stringify(manifest));save();
	return {area,manifest,save,contextPath:path.join(contextDir,'context.json')};
}
async function compile(f) {
	const source=new ContextOriginals(f.contextPath);
	await run(configuration(f.area,{entry:'./primary.js',plugins:[new Collector({proofPath:f.area.proofPath,originals:[],copied:[],resolveOriginal:resource=>source.resolve(resource)})]}));
	return readProof(f.area).assets.find(a=>a.path==='main.js');
}

test('accepts a primary source only against its trusted original expected hash',async t=>{
	const f=fixture(t);const row=await compile(f);
	assert.equal(row.status,'present');assert.deepEqual(row.includedComponents,['pm-source']);
	assert.deepEqual(row.inputs.map(i=>i.path).sort(),f.manifest.files.map(i=>i.path).sort());
	assert.equal(row.components[0].source.kind,'pm');
});
test('refuses source bytes changed after original verification',async t=>{
	const f=fixture(t);fs.writeFileSync(path.join(f.area.root,'secondary.js'),'export const value = 43;\n');
	const row=await compile(f);assert.equal(row.status,'hash-mismatch');assert.deepEqual(row.components,[]);
});
test('does not invent an owner for a missing primary mapping',async t=>{
	const f=fixture(t);f.manifest.files.pop();f.save();const row=await compile(f);
	assert.equal(row.status,'no-data');assert.match(row.reason,/no verified primary-source mapping/);
});
test('refuses duplicate physical bindings and future manifest versions',t=>{
	const f=fixture(t);f.manifest.files.push({...f.manifest.files[0]});f.save();
	assert.throws(()=>new ContextOriginals(f.contextPath),error=>error.status==='invalid');
	f.manifest.version=2;f.save();assert.throws(()=>new ContextOriginals(f.contextPath),error=>error.status==='unsupported');
});

test('refuses a malformed component returned with an expected original hash',async t=>{
	const f=fixture(t);
	await run(configuration(f.area,{entry:'./primary.js',plugins:[new Collector({proofPath:f.area.proofPath,originals:[],copied:[],resolveOriginal:resource=>({path:resource,sha256:'sha256:'+crypto.createHash('sha256').update(fs.readFileSync(resource)).digest('hex'),component:{id:'incomplete'}})})]}));
	const row=readProof(f.area).assets.find(a=>a.path==='main.js');assert.equal(row.status,'invalid');assert.deepEqual(row.components,[]);
});
