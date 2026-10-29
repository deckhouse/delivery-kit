'use strict';
// Ahead of every webpack require of this file: the bootstrap evidence of the
// collector is a recording of the sources this process loads.
require('./runtime-preload.cjs');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const crypto=require('node:crypto');
const {before,after,test}=require('node:test');
const Collector=require('./collector.cjs');
const ContextOriginals=require('./context-originals.cjs');
const {bootstrapOriginal,configuration,run,readProof}=require('./fixture.cjs');

let bootstrapRoot,bootstrap;
before(()=>{bootstrapRoot=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'dk-context-webpack-')));bootstrap=bootstrapOriginal(bootstrapRoot);});
after(()=>fs.rmSync(bootstrapRoot,{recursive:true,force:true}));
// The chunk renderer of the pinned webpack, the three helper modules it reads
// and the stock APIPlugin tap that shaped its module content.
const BOOTSTRAP_SOURCES=['lib/javascript/JavascriptModulesPlugin.js','lib/RuntimeGlobals.js','lib/RuntimeTemplate.js','lib/Template.js','lib/APIPlugin.js'];

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
	// Only the sources of the project this manifest describes are its own; the
	// webpack that is running keeps the static binding it was verified under.
	const resolveOriginal=resource=>resource.startsWith(f.area.root+path.sep)?source.resolve(resource):undefined;
	await run(configuration(f.area,{entry:'./primary.js',plugins:[new Collector({proofPath:f.area.proofPath,originals:[bootstrap.binding],copied:[],resolveOriginal})]}));
	return readProof(f.area).assets.find(a=>a.path==='main.js');
}

test('accepts a primary source only against its trusted original expected hash',async t=>{
	const f=fixture(t);const row=await compile(f);
	assert.equal(row.status,'present');assert.deepEqual(row.includedComponents,['node:webpack@5.94.0','pm-source']);
	assert.deepEqual(row.inputs.map(i=>i.path).sort(),[...f.manifest.files.map(i=>i.path),...BOOTSTRAP_SOURCES.map(name=>path.join(bootstrap.binding.root,name))].sort());
	assert.equal(row.components.find(c=>c.id==='pm-source').source.kind,'pm');
	assert.deepEqual(row.components.find(c=>c.name==='webpack'),bootstrap.binding.component);
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
