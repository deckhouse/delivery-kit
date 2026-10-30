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
const YarnOriginals=require('./yarn-originals.cjs');
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

// A Git-locked dependency: the lockfile pins a commit, the Yarn cache holds no
// bytes anybody checked, and the only evidence is what DK verified from the
// commit itself and wrote into the manifest beside the context.
const GIT_COMMIT='a1c32a45e83fdda4baafc7ca3105c3ead383f8ba';
const GIT_LOCATOR=`git+https://github.com/argoproj/argo-ui.git#${GIT_COMMIT}`;
const GIT_BODY='export default { ui: true };\n';

function gitFixture(t,overrides={}) {
	const f=fixture(t);
	const installed=path.join(f.area.modules,'argo-ui');
	fs.mkdirSync(installed,{recursive:true});
	fs.writeFileSync(path.join(installed,'package.json'),JSON.stringify({name:'argo-ui',version:'1.0.0',main:'index.js',type:'module'}));
	fs.writeFileSync(path.join(installed,'index.js'),GIT_BODY);
	fs.writeFileSync(path.join(f.area.root,'primary.js'),'import {value} from "./secondary.js"; import ui from "argo-ui"; console.log(value, ui);\n');
	f.manifest.files[0].sha256='sha256:'+crypto.createHash('sha256').update(fs.readFileSync(path.join(f.area.root,'primary.js'))).digest('hex');
	fs.writeFileSync(path.join(f.area.root,'yarn.lock'),`# yarn lockfile v1\n\n"argo-ui@${GIT_LOCATOR}":\n  version "1.0.0"\n  resolved "${GIT_LOCATOR}"\n`);
	const component={id:'node:argo-ui',name:'argo-ui',version:'1.0.0',source:{kind:'node',locator:GIT_LOCATOR,checksum:`git-commit:sha1:${GIT_COMMIT}`,...overrides.source}};
	if (overrides.listed!==false) {
		f.manifest.components.push(component);
		f.manifest.files.push({path:path.join(installed,'index.js'),sha256:'sha256:'+crypto.createHash('sha256').update(GIT_BODY).digest('hex'),component:component.id});
		f.manifest.lifecycle=[{component:component.id,hooks:['preinstall','install','postinstall','prepare','prepublish','prepack','postpack']}];
	}
	f.save();
	// Outside the compiler context, which is the whole workdir of the resolver.
	const outputRoot=path.join(fs.mkdtempSync(path.join(os.tmpdir(),'dk-git-originals-')),'extracted');
	t.after(()=>fs.rmSync(path.dirname(outputRoot),{recursive:true,force:true}));
	const cacheDir=path.join(path.dirname(outputRoot),'cache');fs.mkdirSync(cacheDir);
	const yarn=new YarnOriginals({workdir:f.area.root,lockPath:path.join(f.area.root,'yarn.lock'),cacheDir,outputRoot,
		...(overrides.contextPath===null?{}:{contextPath:f.contextPath})});
	return {...f,installed,yarn};
}

async function compileWithYarn(f) {
	const primary=new ContextOriginals(f.contextPath);
	// As the activation composes them, but scoped to this project's own tree: the
	// webpack that is running is bound statically, not through the fixture lock.
	const resolveOriginal=async resource=>resource.startsWith(f.area.root+path.sep)?(await f.yarn.resolve(resource))??primary.resolve(resource):undefined;
	await run(configuration(f.area,{entry:'./primary.js',plugins:[new Collector({proofPath:f.area.proofPath,originals:[bootstrap.binding],copied:[],resolveOriginal})]}));
	return readProof(f.area).assets.find(a=>a.path==='main.js');
}

test('attributes a Git-locked dependency to the commit the manifest verified',async t=>{
	const f=gitFixture(t);const row=await compileWithYarn(f);
	assert.equal(row.status,'present');
	assert.ok(row.inputs.some(input=>input.path===path.join(f.installed,'index.js')));
	assert.deepEqual(row.components.find(c=>c.id==='node:argo-ui').source,{kind:'node',locator:GIT_LOCATOR,checksum:`git-commit:sha1:${GIT_COMMIT}`});
});

test('does not attribute a Git-locked dependency the manifest does not list',async t=>{
	const f=gitFixture(t,{listed:false});const row=await compileWithYarn(f);
	assert.equal(row.status,'no-data');
	assert.match(row.reason,/no verified primary-source mapping/);
	assert.deepEqual(row.components,[]);
});

test('refuses a verified original pinning another commit than the lockfile',async t=>{
	const other=`git-commit:sha1:${'b'.repeat(40)}`;
	const f=gitFixture(t,{source:{locator:GIT_LOCATOR.replace(GIT_COMMIT,'b'.repeat(40)),checksum:other}});
	const row=await compileWithYarn(f);
	assert.equal(row.status,'invalid');
	assert.match(row.reason,/does not pin/);
});

test('reports no-data for a Git-locked dependency without a build context',async t=>{
	const f=gitFixture(t,{contextPath:null});const row=await compileWithYarn(f);
	assert.equal(row.status,'no-data');
	assert.match(row.reason,/no verified build context/);
});

test('refuses installed bytes that are not the ones the commit serves',async t=>{
	const f=gitFixture(t);fs.writeFileSync(path.join(f.installed,'index.js'),'export default { ui: false };\n');
	const row=await compileWithYarn(f);
	assert.equal(row.status,'hash-mismatch');
	assert.deepEqual(row.components,[]);
});

test('refuses a node component that pins no commit and a lifecycle record of nobody',t=>{
	const f=gitFixture(t);
	assert.ok(new ContextOriginals(f.contextPath));
	const component=f.manifest.components.find(c=>c.id==='node:argo-ui');
	const source={...component.source};
	for (const [label,mutate] of [
		['another commit than the locator',()=>component.source.checksum=`git-commit:sha1:${'b'.repeat(40)}`],
		['a registry locator',()=>component.source.locator='https://registry.example/argo-ui.tgz'],
		['a locator without a commit',()=>component.source.locator=GIT_LOCATOR.split('#')[0]],
		['an archive checksum',()=>component.source.checksum=`sha512-${'a'.repeat(86)}==`],
		['no version',()=>delete component.version],
		['an unknown source kind',()=>component.source.kind='declared'],
		['no source at all',()=>delete component.source],
		['hooks of an unknown component',()=>f.manifest.lifecycle=[{component:'node:absent',hooks:['prepare']}]],
		['an unknown hook',()=>f.manifest.lifecycle=[{component:component.id,hooks:['prepare','rebuild']}]],
		['lifecycle that is not an array',()=>f.manifest.lifecycle={component:component.id,hooks:[]}],
	]) {
		mutate();f.save();
		assert.throws(()=>new ContextOriginals(f.contextPath),error=>error.status==='invalid',label);
		component.source={...source};component.version='1.0.0';f.manifest.lifecycle=[{component:component.id,hooks:['prepare']}];f.save();
	}
	assert.ok(new ContextOriginals(f.contextPath));
});
