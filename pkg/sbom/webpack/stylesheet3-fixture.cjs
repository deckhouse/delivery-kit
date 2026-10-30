'use strict';

// Builds a real style-loader 3 chain and describes the two modules its loaders
// made, in a process where the recorders were installed before either loader
// was first required.
//
// The loaders are the exact aliased pins of this package, recognized by the
// bytes of their published files rather than by the directory they sit in.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const MARKER = '#dk-stylesheet3-report#';
// What a build asks for: the commonjs entry of each distribution, which is what
// exposes the loader webpack runs. The implementation behind it is the file the
// adapter recognizes.
const STYLE_LOADER = path.join(__dirname, 'node_modules', 'style-loader-3.3.1', 'dist', 'cjs.js');
const CSS_LOADER = path.join(__dirname, 'node_modules', 'css-loader-5.2.6', 'dist', 'cjs.js');
const STYLE_IMPLEMENTATION = path.join(path.dirname(STYLE_LOADER), 'index.js');
const CSS_IMPLEMENTATION = path.join(path.dirname(CSS_LOADER), 'index.js');
const PINNED = {
	style: 'sha256:96b6870d8119a984c56a74e32dc44e5fb919d13dfc892ffbd4f93b797f7381c7',
	css: 'sha256:7ab8378e32b9a131eae561322265b73682ed2b81130051611476fe1f23a002af',
};
// The stylesheet redoc imports, in the shape that matters here: no url(), no
// @import, nothing but rules.
const STYLESHEET = '.ps {\n\toverflow: hidden !important;\n\ttouch-action: auto;\n}\n\n.ps__rail-x {\n\theight: 15px;\n\tbottom: 0px;\n}\n';
const ENTRY = "import styles from './styles.css';\n\nexport default styles;\n";

function available() {
	for (const [kind, file] of [['style', STYLE_IMPLEMENTATION], ['css', CSS_IMPLEMENTATION]]) {
		if (!fs.existsSync(file)) return `${file} is not installed (npm install in pkg/sbom/webpack)`;
		if (digest(fs.readFileSync(file)) !== PINNED[kind]) return `${file} is not the published file this adapter pins`;
	}
	return false;
}

function area(scratch, id, options = {}) {
	const root = path.join(scratch, id);
	const src = path.join(root, 'src');
	fs.mkdirSync(src, { recursive: true });
	fs.writeFileSync(path.join(src, 'styles.css'), options.stylesheet === undefined ? STYLESHEET : options.stylesheet);
	fs.writeFileSync(path.join(src, 'index.js'), options.entry || ENTRY);
	return { root, src, out: path.join(root, 'out') };
}

// One compilation in its own process, with both stylesheet recorders installed
// before anything else runs.
function build(where, options = {}) {
	const runner = path.join(where.root, 'run.cjs');
	fs.writeFileSync(runner, RUNNER);
	const preloads = options.preload === false ? [] : ['--require', path.join(__dirname, 'stylesheet-preload.cjs'), '--require', path.join(__dirname, 'stylesheet3-preload.cjs')];
	const out = execFileSync(process.execPath, [...preloads, runner], {
		cwd: where.root,
		encoding: 'utf8',
		timeout: 180000,
		env: {
			...process.env,
			...(options.tail === 'esbuild' ? { ESBUILD_BINARY_PATH: path.join(process.env.DK_ESBUILD_SOURCE || '', 'esbuild') } : {}),
			DK_STYLESHEET3_ADAPTERS: __dirname,
			DK_STYLESHEET3_AREA: JSON.stringify({
				...where,
				styleLoader: options.styleLoader || STYLE_LOADER,
				cssLoader: options.cssLoader || CSS_LOADER,
				styleOptions: options.styleOptions || null,
				cssOptions: options.cssOptions || null,
				sourceMap: options.sourceMap === true,
				tail: options.tail || null,
				withoutTail: options.withoutTail === true,
				tamper: options.tamper || null,
				secondTail: options.secondTail === true,
				esbuild: options.tail === 'esbuild' && options.withoutTail !== true ? esbuildTool() : null,
				esbuildLoader: options.tail === 'esbuild' ? require.resolve('esbuild-loader') : null,
			}),
		},
	});
	const line = out.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `the build printed no report:\n${out}`);
	return { report: JSON.parse(line.slice(MARKER.length)), out };
}

// The instrumented esbuild the css tail runs, declared as its adapter requires.
function esbuildTool() {
	const source = process.env.DK_ESBUILD_SOURCE;
	assert.ok(source, 'DK_ESBUILD_SOURCE must name the instrumented esbuild for a tail build');
	const entry = path.join(source, 'npm', 'esbuild', 'lib', 'main.js');
	const binary = path.join(source, 'esbuild');
	return {
		versions: { esbuild: '0.25.0', esbuildLoader: '4.3.0' },
		entry,
		binary,
		loader: require.resolve('esbuild-loader'),
		entrySHA256: digest(fs.readFileSync(entry)),
		binarySHA256: digest(fs.readFileSync(binary)),
		runtimeSource: path.join(source, 'internal', 'runtime', 'runtime.go'),
	};
}

function digest(bytes) {
	return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

const RUNNER = `'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const area = JSON.parse(process.env.DK_STYLESHEET3_AREA);
const adapters = process.env.DK_STYLESHEET3_ADAPTERS;
const webpack = require(path.join(adapters, 'node_modules', 'webpack'));
const { installStylesheetEvidence } = require(path.join(adapters, 'stylesheet-evidence.cjs'));
const { installStylesheet3Evidence } = require(path.join(adapters, 'stylesheet3-evidence.cjs'));
const { installEsbuildEvidence } = require(path.join(adapters, 'esbuild-evidence.cjs'));

const use = [
	{ loader: area.styleLoader, ...(area.styleOptions ? { options: area.styleOptions } : {}) },
	{ loader: area.cssLoader, ...(area.cssOptions ? { options: area.cssOptions } : {}) },
];
if (area.tail === 'esbuild') use.push({ loader: area.esbuildLoader, options: { loader: 'css', minify: true } });
// A second tail nobody asked about: what stands behind css-loader is then more
// than the one loader the seam reads.
if (area.secondTail) use.push({ loader: area.esbuildLoader, options: { loader: 'css' } });

const compiler = webpack({
	mode: 'production',
	devtool: area.sourceMap ? 'source-map' : false,
	context: area.src,
	entry: './index.js',
	output: { path: area.out, filename: 'main.js' },
	optimization: { minimize: false },
	module: { rules: [{ test: /\\.css$/, use }] },
});

// Every file of this build is its own original: what is under test here is the
// recomputation, not the acquisition.
async function verifyResource(resource) {
	const actual = path.resolve(resource);
	let bytes;
	try { bytes = fs.readFileSync(actual); } catch (error) { return { units: [], failure: { status: 'no-data', reason: String(error.message) } }; }
	const component = /node_modules/.test(actual)
		? { id: 'npm:' + path.basename(path.dirname(path.dirname(actual))), name: 'loader', version: '0.0.0', source: { kind: 'pm', locator: 'https://registry.npmjs.org/x', checksum: 'sha512-fixture' } }
		: { id: 'project', name: 'fixture', version: '0.0.0', source: { kind: 'declared', locator: 'fixture' } };
	return { unit: { path: actual, sha256: 'sha256:' + crypto.createHash('sha256').update(bytes).digest('hex'), bytes, component } };
}

installStylesheetEvidence(compiler, verifyResource);
const esbuildEvidence = area.esbuild ? installEsbuildEvidence(compiler, area.esbuild, verifyResource) : null;

// The esbuild css tail, as the stylesheet seam asks for one: it describes the
// transform and owes that what it returned is the text the asking loader read.
const tails = esbuildEvidence
	? [{
		matches: (request) => request === area.esbuildLoader,
		sourcesOf: async (module, text) => {
			const described = await esbuildEvidence.transformed(module);
			if (described.failure) return described;
			if (described.code !== text) return { units: [], failure: { status: 'hash-mismatch', reason: 'the esbuild transform did not produce the text css-loader read' } };
			return { units: described.units };
		},
	}]
	: [];

const describe = installStylesheet3Evidence(compiler, verifyResource, { tails });
let parent = null;
compiler.hooks.thisCompilation.tap('dk-stylesheet3-fixture', (compilation) => { parent = compilation; });

// Described while the compilation is still the one that was observed: the
// adapters forget what they watched once the build is done.
let described = null;
compiler.hooks.afterEmit.tapPromise('dk-stylesheet3-fixture', async () => { described = await collect(); });

compiler.run(async (error, stats) => {
	const report = { modules: [] };
	if (error || stats.hasErrors()) {
		report.error = String(error || stats.toJson({ all: false, errors: true }).errors.map(e => e.message).join('; '));
		print(report);
		return;
	}
	report.modules = described || [];
	print(report);
});

async function collect() {
	const rows = [];
	if (area.tamper === 'kept-source') {
		for (const module of parent.modules) {
			if (!/style-loader/.test(module.identifier()) || !module.originalSource) continue;
			const kept = module.originalSource();
			if (kept) module.originalSource = () => ({ buffer: () => Buffer.concat([kept.buffer(), Buffer.from('/* changed */')]) });
		}
	}
	// The two modules of the chain, told apart by which loader stands at the head
	// of each identifier: style-loader pitched the one, css-loader built the other.
	for (const module of parent.modules) {
		const id = module.identifier();
		const kind = id.startsWith(area.styleLoader) ? 'style' : id.startsWith(area.cssLoader) ? 'css' : null;
		if (!kind) continue;
		rows.push(await row(kind, module));
	}
	return rows;
}

async function row(kind, module) {
	const described = await describe(module);
	return {
		kind,
		identifier: module.identifier(),
		status: described.failure ? described.failure.status : 'present',
		reason: described.failure ? described.failure.reason : undefined,
		units: (described.units || []).map((unit) => ({ path: unit.path, sha256: unit.sha256, component: unit.component.id })),
	};
}

function print(report) { process.stdout.write('${MARKER}' + JSON.stringify(report) + '\\n'); }
`;

module.exports = { available, area, build, digest, MARKER, STYLE_LOADER, CSS_LOADER, STYLE_IMPLEMENTATION, CSS_IMPLEMENTATION, PINNED, STYLESHEET };
