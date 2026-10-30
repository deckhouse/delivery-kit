'use strict';

// Test-only fixture for stylesheet3-wiring.test.cjs: the style-loader 3 chain
// redoc builds, collected whole rather than described module by module.
//
// What is under test here is the collector's dispatch - that both modules of
// the chain reach the style-loader 3 adapter rather than the older one, and
// that the esbuild tail the collector hands it is the one that minified the
// stylesheet.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const { available, area, digest, STYLE_LOADER, CSS_LOADER, STYLESHEET } = require('./stylesheet3-fixture.cjs');

const MARKER = '#dk-stylesheet3-wiring-report#';

// One collected compilation in its own process, with both stylesheet recorders
// installed before anything else runs.
function build(where, options = {}) {
	const runner = path.join(where.root, 'collect.cjs');
	fs.writeFileSync(runner, RUNNER);
	const out = execFileSync(
		process.execPath,
		['--require', path.join(__dirname, 'runtime-preload.cjs'), '--require', path.join(__dirname, 'stylesheet-preload.cjs'), '--require', path.join(__dirname, 'stylesheet3-preload.cjs'), runner],
		{
			cwd: where.root,
			encoding: 'utf8',
			timeout: 180000,
			env: {
				...process.env,
				...(options.tail === 'esbuild' ? { ESBUILD_BINARY_PATH: path.join(process.env.DK_ESBUILD_SOURCE || '', 'esbuild') } : {}),
				DK_STYLESHEET3_ADAPTERS: __dirname,
				DK_STYLESHEET3_AREA: JSON.stringify({
					...where,
					...named(where),
					webpackRoot: path.join(__dirname, 'node_modules', 'webpack'),
					tail: options.tail || null,
					esbuild: options.tail === 'esbuild' ? esbuildTool() : null,
					esbuildLoader: options.tail === 'esbuild' ? require.resolve('esbuild-loader') : null,
				}),
			},
		},
	);
	const line = out.split('\n').find((candidate) => candidate.startsWith(MARKER));
	assert.ok(line, `the build printed no report:\n${out}`);
	return { report: JSON.parse(line.slice(MARKER.length)), out };
}

// The loaders under the names the real project installs them by: this package
// pins them side by side, so their directories carry their versions, and a
// dispatch that read the directory instead of what the loaders did would be
// told apart by that alone.
function named(where) {
	const root = path.join(where.root, 'loaders');
	fs.mkdirSync(root, { recursive: true });
	const linked = {};
	for (const [key, entry] of [['styleLoader', STYLE_LOADER], ['cssLoader', CSS_LOADER]]) {
		const distribution = path.dirname(path.dirname(entry));
		const link = path.join(root, path.basename(distribution).replace(/-\d+\.\d+\.\d+$/, ''));
		if (!fs.existsSync(link)) fs.symlinkSync(distribution, link);
		linked[key] = path.join(link, path.relative(distribution, entry));
	}
	return linked;
}

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

const RUNNER = `'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const area = JSON.parse(process.env.DK_STYLESHEET3_AREA);
const adapters = process.env.DK_STYLESHEET3_ADAPTERS;
const webpack = require(path.join(adapters, 'node_modules', 'webpack'));
const Collector = require(path.join(adapters, 'collector.cjs'));

const proofPath = path.join(area.root, 'proof.json');
// Every file of this build is its own original: what is under test here is the
// dispatch, not the acquisition.
function resolveOriginal(resource) {
	let bytes;
	try { bytes = fs.readFileSync(resource); } catch { return undefined; }
	// The package a file belongs to is the directory under node_modules it
	// stands in, so every file of one distribution answers with one component.
	const at = resource.lastIndexOf(path.sep + 'node_modules' + path.sep);
	const name = at < 0 ? null : resource.slice(at + 14).split(path.sep)[0];
	// The webpack that is running says its own version, and the adapters of its
	// sources hold every unit of it against that.
	const version = name === 'webpack' ? require(path.join(adapters, 'node_modules', 'webpack', 'package.json')).version : '0.0.0';
	const component = name
		? { id: 'npm:' + name + '@' + version, name, version, source: { kind: 'pm', locator: 'https://registry.npmjs.org/' + name, checksum: 'sha512-fixture' } }
		: { id: 'project', name: 'fixture', version: '0.0.0', source: { kind: 'declared', locator: 'fixture' } };
	return { path: resource, sha256: 'sha256:' + crypto.createHash('sha256').update(bytes).digest('hex'), component };
}

const use = [{ loader: area.styleLoader }, { loader: area.cssLoader }];
if (area.tail === 'esbuild') use.push({ loader: area.esbuildLoader, options: { loader: 'css', minify: true } });

const compiler = webpack({
	mode: 'production',
	devtool: false,
	context: area.src,
	entry: './index.js',
	output: { path: area.out, filename: 'main.js' },
	optimization: { minimize: false, concatenateModules: false },
	module: { rules: [{ test: /\\.css$/, use }] },
	plugins: [new Collector({ proofPath, originals: [], copied: [], resolveOriginal, esbuild: area.esbuild || undefined })],
});

compiler.run((error, stats) => {
	const report = {};
	if (error || stats.hasErrors()) {
		report.error = String(error || stats.toJson({ all: false, errors: true }).errors.map(e => e.message).join('; '));
	} else {
		report.proof = JSON.parse(fs.readFileSync(proofPath, 'utf8'));
		report.bundle = fs.readFileSync(path.join(area.out, 'main.js'), 'utf8');
	}
	process.stdout.write('${MARKER}' + JSON.stringify(report) + String.fromCharCode(10));
	compiler.close(() => {});
});
`;

module.exports = { available, area, build, MARKER, STYLESHEET };
