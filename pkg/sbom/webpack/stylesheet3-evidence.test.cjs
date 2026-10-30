'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test, before, after } = require('node:test');

const fixture = require('./stylesheet3-fixture.cjs');
const { internals } = require('./stylesheet3-evidence.cjs');

const SKIP = fixture.available();
// The css tail of redoc's chain needs the instrumented esbuild of its adapter.
const TAIL_SKIP = SKIP || (process.env.DK_ESBUILD_SOURCE ? false : 'DK_ESBUILD_SOURCE is not set to a checkout of the instrumented esbuild');

let scratch;

before(() => {
	scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-stylesheet3-')));
});

after(() => {
	fs.rmSync(scratch, { recursive: true, force: true });
});

function build(id, options = {}) {
	return fixture.build(fixture.area(scratch, id, options), options);
}

function rowOf(report, kind) {
	const row = report.modules.find((candidate) => candidate.kind === kind);
	assert.ok(row, `the build described no ${kind} module:\n${JSON.stringify(report, null, 1)}`);
	return row;
}

function unitOf(row, file) {
	return row.units.find((unit) => unit.path.endsWith(file));
}

test('describes both modules of a style-loader 3 chain', { skip: SKIP }, () => {
	const result = build('plain');

	// style-loader never reads the stylesheet: its module is its own code, and
	// the only source of it is the loader file that wrote it.
	const style = rowOf(result.report, 'style');
	assert.equal(style.status, 'present', style.reason);
	assert.deepEqual(style.units.map((unit) => path.basename(unit.path)), ['index.js']);
	assert.equal(unitOf(style, path.join('style-loader-3.3.1', 'dist', 'index.js')).sha256, fixture.PINNED.style);

	// css-loader read the file: its module carries the stylesheet and the loader
	// that embedded it.
	const css = rowOf(result.report, 'css');
	assert.equal(css.status, 'present', css.reason);
	assert.ok(unitOf(css, path.join('src', 'styles.css')), 'the stylesheet must be a source of the module built from it');
	assert.equal(unitOf(css, path.join('css-loader-5.2.6', 'dist', 'index.js')).sha256, fixture.PINNED.css);
	assert.equal(css.units.length, 2);
});

// The map css-loader embeds when the build asks for source maps describes this
// very module and carries the text it was built from, so it is data about the
// module rather than a source of it: the units do not change.
test('describes a module that embeds a source map of the text it was handed', { skip: SKIP }, () => {
	const plain = rowOf(build('plain-again').report, 'css');
	const mapped = rowOf(build('mapped', { sourceMap: true }).report, 'css');
	assert.equal(mapped.status, 'present', mapped.reason);
	assert.deepEqual(mapped.units.map((unit) => path.basename(unit.path)).sort(), plain.units.map((unit) => path.basename(unit.path)).sort());
});

// Redoc minifies its stylesheet with esbuild before css-loader parses it, so
// the text css-loader embedded is no file: it is what that transform returned.
test('describes a chain whose stylesheet was produced by an esbuild tail', { skip: TAIL_SKIP }, () => {
	const result = build('tail', { tail: 'esbuild' });
	const css = rowOf(result.report, 'css');
	assert.equal(css.status, 'present', css.reason);
	assert.ok(unitOf(css, path.join('src', 'styles.css')), 'the stylesheet the transform read must be a source of the module');
	assert.ok(unitOf(css, path.join('css-loader-5.2.6', 'dist', 'index.js')), 'the loader that embedded it must be a source too');
	assert.equal(rowOf(result.report, 'style').status, 'present');
});

// A tail handed css-loader a map along with the text it minified, and the map
// css-loader embedded was composed on top of it. It is still data about this
// module: what it carries is the file the tail read, which the seam has just
// claimed as a source.
test('describes a module whose embedded map was composed on a map of its tail', { skip: TAIL_SKIP }, () => {
	const css = rowOf(build('tail-mapped', { tail: 'esbuild', sourceMap: true }).report, 'css');
	assert.equal(css.status, 'present', css.reason);
	assert.ok(unitOf(css, path.join('src', 'styles.css')), 'the file the map describes must be a source of the module');
	assert.ok(unitOf(css, path.join('css-loader-5.2.6', 'dist', 'index.js')));
});

// The file a composed map carries must be one the sources of this module name:
// a tail that claimed something else leaves the map describing a text nothing
// of this module was verified as.
// What the map carries must be the file as this process verified it, not what
// the tail vouched for: the two are compared rather than one taken on trust.
test('refuses a composed map whose file is not the one the sources were verified as', { skip: TAIL_SKIP }, () => {
	const css = rowOf(build('tail-mapped-changed', { tail: 'esbuild', sourceMap: true, tamper: 'tail-digest' }).report, 'css');
	assert.equal(css.status, 'hash-mismatch', css.reason);
	assert.match(css.reason, /is not the file the sources of .* were verified as/);
	assert.deepEqual(css.units, []);
});

test('refuses a composed map of a file no source of the module names', { skip: TAIL_SKIP }, () => {
	const css = rowOf(build('tail-mapped-unclaimed', { tail: 'esbuild', sourceMap: true, tamper: 'tail-units' }).report, 'css');
	assert.equal(css.status, 'no-data', css.reason);
	assert.match(css.reason, /embeds a source map of a file no source of this module names/);
	assert.deepEqual(css.units, []);
});

// The seam of the stylesheet adapter answers for what stands behind css-loader,
// and a tail nobody describes is a text this module cannot account for.
test('refuses a chain whose tail no adapter of this collector describes', { skip: TAIL_SKIP }, () => {
	const css = rowOf(build('tail-undescribed', { tail: 'esbuild', withoutTail: true }).report, 'css');
	assert.equal(css.status, 'no-data', css.reason);
	assert.match(css.reason, /was built behind .*esbuild-loader.*, which no adapter of this collector describes/);
	assert.deepEqual(css.units, []);
	// The module style-loader pitched is its own code either way: it never read
	// the stylesheet, so a tail it knows nothing about takes nothing from it.
	assert.equal(rowOf(build('tail-undescribed-style', { tail: 'esbuild', withoutTail: true }).report, 'style').status, 'present');
});

test('refuses a chain with more loaders behind css-loader than one', { skip: TAIL_SKIP }, () => {
	const css = rowOf(build('two-tails', { tail: 'esbuild', secondTail: true }).report, 'css');
	assert.equal(css.status, 'no-data', css.reason);
	assert.match(css.reason, /was built behind 2 loaders this adapter does not describe/);
	assert.deepEqual(css.units, []);
});

// Every option of either loader changes the code it writes, and none of what it
// would write is recomputed here.
test('refuses loaders configured with options this version does not describe', { skip: SKIP }, () => {
	for (const [id, options, kind] of [
		['a style-loader option', { styleOptions: { injectType: 'singletonStyleTag' } }, 'style'],
		['a css-loader option', { cssOptions: { esModule: false } }, 'css'],
	]) {
		const row = rowOf(build(`options-${id.replace(/\W/g, '-')}`, options).report, kind);
		assert.equal(row.status, 'no-data', `${id}: ${row.reason}`);
		assert.match(row.reason, /configured with options this adapter does not describe/, id);
		assert.deepEqual(row.units, [], id);
	}
});

test('refuses a loader whose file is not the published one', { skip: SKIP }, () => {
	const root = path.join(scratch, 'tampered');
	const styleLoader = copyLoader(root, 'style-loader-3.3.1');
	const target = path.join(path.dirname(styleLoader), 'index.js');
	fs.writeFileSync(target, `${fs.readFileSync(target, 'utf8')}\n// not the published file\n`);

	// The recorder recognizes a loader by the bytes of its file, so a changed one
	// is never watched and nothing it built is described.
	const style = rowOf(build('tampered-style', { styleLoader }).report, 'style');
	assert.equal(style.status, 'no-data', style.reason);
	assert.match(style.reason, /was not built by an observed stylesheet loader/);
	assert.deepEqual(style.units, []);
});

test('refuses a module the compilation did not keep as its loader wrote it', { skip: SKIP }, () => {
	const style = rowOf(build('kept-source', { tamper: 'kept-source' }).report, 'style');
	assert.equal(style.status, 'hash-mismatch', style.reason);
	assert.match(style.reason, /is not what style-loader pitched/);
	assert.deepEqual(style.units, []);
});

test('describes nothing without the recorder that watched the loaders run', { skip: SKIP }, () => {
	const result = build('no-preload', { preload: false });
	for (const kind of ['style', 'css']) {
		const row = rowOf(result.report, kind);
		assert.equal(row.status, 'no-data', row.reason);
		assert.match(row.reason, /recorder is not installed in this process/);
		assert.deepEqual(row.units, []);
	}
});

// What makes an embedded map data rather than a claim about files nobody
// verified. The maps below are ones no build of a pinned loader writes, so they
// are held against the reading directly.
test('reads only a source map that says no more than this module does', () => {
	const call = { input: '.a{color:red}\n' };
	const module = { identifier: () => 'the module' };
	// The shape css-loader 5.2.6 writes: a webpack url built from the path of the
	// stylesheet relative to the build root.
	const plain = { version: 3, sources: ['webpack://./styles.css'], sourcesContent: [call.input], mappings: 'AAAA', names: [], sourceRoot: '' };
	assert.deepEqual(internals.describedMap(JSON.stringify(plain), call, module), { units: [] });

	for (const [id, map, match] of [
		['another version', { ...plain, version: 2 }, /is version 2, not 3/],
		// The runtime writes each source name into a comment of the stylesheet it
		// injects, so a name that can end that comment is code, not a name.
		['a source that ends its comment', { ...plain, sources: ['webpack://./a*/x'] }, /could end the comment it is written into/],
		['a source smuggling a rule', { ...plain, sources: ['*/ body{display:none} /*'] }, /could end the comment it is written into/],
		['a source with control characters', { ...plain, sources: ['webpack://./a\u0000b'] }, /carrying control characters/],
		['a source walking up', { ...plain, sources: ['webpack://./../etc/passwd'] }, /is not a clean relative path/],
		['a source spelled otherwise', { ...plain, sources: ['https://example.test/a.css'] }, /spelled in a way this version does not take/],
		['an endless source', { ...plain, sources: [`webpack://./${'a'.repeat(600)}`] }, /of a length this version does not take/],
		['an empty source', { ...plain, sources: [''] }, /of a length this version does not take/],
		['a section list', { ...plain, sections: [] }, /carries sections, which this version does not read/],
		['a vendor extension', { ...plain, x_google_ignoreList: [] }, /carries x_google_ignoreList/],
		['a file of its own', { ...plain, file: 'styles.css' }, /names a file of its own/],
		['a source root', { ...plain, sourceRoot: '/src' }, /is rooted at \/src/],
		['a text that is not the input', { ...plain, sourcesContent: ['.a{color:blue}\n'] }, /carries a text that is not what this module was built from/],
		['a missing text', { ...plain, sourcesContent: [null] }, /carries no text for webpack:\/\/\.\/styles\.css/],
		['more sources than texts', { ...plain, sources: ['webpack://./a.css', 'webpack://./b.css'] }, /carries 1 contents for 2 sources/],
		['a name that is not in the text', { ...plain, names: ['nowhere'] }, /names "nowhere", which is not an identifier/],
		['a name that is only part of a word', { ...plain, names: ['colo'] }, /names "colo", which is not an identifier/],
		['an empty name', { ...plain, names: [''] }, /names "", which is not an identifier/],
		['mappings that are not vlq', { ...plain, mappings: 'AA$A' }, /does not carry readable mappings/],
		['mappings that end mid number', { ...plain, mappings: 'g' }, /does not carry readable mappings/],
		['a number too wide to read', { ...plain, mappings: `${'g'.repeat(7)}A` }, /carries a number too wide to read/],
		['mappings of the wrong width', { ...plain, mappings: 'AAA' }, /carries a mapping of 3 fields/],
		['mappings of a source it does not name', { ...plain, mappings: 'ACAA' }, /maps to source 1, which it does not name/],
		['mappings beyond the last line', { ...plain, mappings: 'AAEA' }, /maps to line 3 of a text that has 2/],
		['mappings beyond the end of a line', { ...plain, mappings: 'AAAoB' }, /maps to column 21 of a line that has 13/],
		['mappings naming a name it does not carry', { ...plain, mappings: 'AAAAA' }, /maps to name 0, which it does not carry/],
		['mappings before the start of the text', { ...plain, mappings: 'D' }, /maps to a position before the start of its own text/],
	]) {
		const described = internals.describedMap(JSON.stringify(map), call, module);
		assert.equal(described.failure && described.failure.status, 'no-data', id);
		assert.match(described.failure.reason, match, id);
	}

	// A member stated twice says two things; the reading takes neither.
	const twice = internals.describedMap(`{"version":3,"version":3,"sources":[],"sourcesContent":[],"mappings":"","names":[],"sourceRoot":""}`, call, module);
	assert.equal(twice.failure.status, 'no-data');
	assert.match(twice.failure.reason, /is not the plain json it parses as/);
	// A map composed on a tail's own describes the file that tail read, not the
	// text it produced: what it carries is held against the one, and what it
	// maps against the other.
	const minified = '.a{color:red}';
	const composed = { input: minified, origin: call.input };
	assert.deepEqual(internals.describedMap(JSON.stringify(plain), composed, module), { units: [] });
	// A position on the second line of the file, which the embedded text does
	// not have: what bounds an original position is the file it is a position in.
	assert.deepEqual(internals.describedMap(JSON.stringify({ ...plain, mappings: 'AACA' }), composed, module), { units: [] });
	for (const [id, map, texts, match] of [
		['a text that is the tail output', { ...plain, sourcesContent: [minified] }, composed, /carries a text that is not what this module was built from/],
		['original positions beyond the file', { ...plain, mappings: 'AAEA' }, composed, /maps to line 3 of a text that has 2/],
		['generated positions beyond the embedded text', { ...plain, mappings: 'AAAA;AAAA' }, composed, /maps 2 lines of a text that has 1/],
		// An identifier of the text that was embedded, but not of the file the map
		// is about.
		['a name that is only of the embedded text', { ...plain, sourcesContent: ['.b{background:blue}\n'], names: ['color'], mappings: 'AAAAA' }, { input: call.input, origin: '.b{background:blue}\n' }, /names "color", which is not an identifier/],
	]) {
		const described = internals.describedMap(JSON.stringify(map), texts, module);
		assert.equal(described.failure && described.failure.status, 'no-data', id);
		assert.match(described.failure.reason, match, id);
	}

	// An identifier of the text is read, and so are mappings of every width, the
	// postcss spelling of a source with no file, and a name index it carries.
	assert.deepEqual(internals.describedMap(JSON.stringify({ ...plain, names: ['color'], mappings: 'AAAA,AAAAA;' }), call, module), { units: [] });
	// A map of more text than this module holds describes something else.
	const longer = internals.describedMap(JSON.stringify({ ...plain, mappings: 'AAAA;AAAA;AAAA' }), call, module);
	assert.equal(longer.failure.status, 'no-data');
	assert.match(longer.failure.reason, /maps 3 lines of a text that has 2/);
	const wider = internals.describedMap(JSON.stringify({ ...plain, mappings: 'AAAA,yBAAA' }), call, module);
	assert.equal(wider.failure.status, 'no-data');
	assert.match(wider.failure.reason, /maps 25 columns of a line that has 13/);
	assert.deepEqual(internals.describedMap(JSON.stringify({ ...plain, sources: ['<input css 1>'] }), call, module), { units: [] });
});

// A module text is rebuilt from what was read out of it, so what is read has to
// be a request and nothing more.
test('reads an import of a css-loader module as a request alone', () => {
	const css = '.a{color:red}\n';
	const call = { input: css };
	const forged = `// Imports\nimport ___CSS_LOADER_API_IMPORT___ from "../api.js"; evil(); var y = "x";\nvar ___CSS_LOADER_EXPORT___ = ___CSS_LOADER_API_IMPORT___(function(i){return i[1]});\n// Module\n___CSS_LOADER_EXPORT___.push([module.id, ${JSON.stringify(css)}, ""]);\n// Exports\nexport default ___CSS_LOADER_EXPORT___;\n`;
	const read = internals.cssParts(forged, call);
	assert.equal(read.failure.status, 'no-data');
	assert.match(read.failure.reason, /wrote a request this version does not read/);

	// What is read is the request itself, and the text is rebuilt from it.
	const honest = internals.cssParts(forged.replace('"../api.js"; evil(); var y = "x"', '"../api.js"'), call);
	assert.equal(honest.apiRequest, '../api.js');
	assert.equal(internals.cssTemplate(honest), forged.replace('"../api.js"; evil(); var y = "x"', '"../api.js"'));

	for (const [id, text, match] of [
		['an import of something that is not a file', forged.replace('"../api.js"; evil(); var y = "x"', '""'), /imported something other than a file/],
		['an import of a number', forged.replace('"../api.js"; evil(); var y = "x"', '42'), /wrote imports this version does not read/],
	]) {
		const refused = internals.cssParts(text, call);
		assert.equal(refused.failure && refused.failure.status, 'no-data', id);
		assert.match(refused.failure.reason, match, id);
	}
});

function copyLoader(root, name) {
	const entry = path.join(root, 'node_modules', name, 'dist', 'cjs.js');
	fs.mkdirSync(path.dirname(path.dirname(entry)), { recursive: true });
	fs.cpSync(path.join(__dirname, 'node_modules', name), path.join(root, 'node_modules', name), { recursive: true });
	return entry;
}

// What the reading of a css-loader module takes apart, and what it then
// demands the whole of it is. The texts below are ones no build of the pinned
// loader writes, so the reading is held against them directly.
test('reads a css-loader module only as the template it writes', () => {
	const css = '.a{color:red}\n';
	const call = { input: css };
	const api = '"../../css-loader/dist/runtime/api.js"';
	const written = (body) => `// Imports\nimport ___CSS_LOADER_API_IMPORT___ from ${api};\n${body}`;
	const module = `var ___CSS_LOADER_EXPORT___ = ___CSS_LOADER_API_IMPORT___(function(i){return i[1]});\n// Module\n___CSS_LOADER_EXPORT___.push([module.id, ${JSON.stringify(css)}, ""]);\n// Exports\nexport default ___CSS_LOADER_EXPORT___;\n`;

	// The shape the pinned loader writes is read, and rebuilt as what it was.
	const parts = internals.cssParts(written(module), call);
	assert.equal(parts.failure, undefined, parts.failure && parts.failure.reason);
	assert.equal(internals.cssTemplate(parts), written(module));

	// An argument the loader never passes is taken apart and then rebuilt as the
	// one it does pass, so the whole no longer matches what was written.
	const foreign = written(module.replace('function(i){return i[1]}', 'function(i){return i[0]}'));
	const takenApart = internals.cssParts(foreign, call);
	assert.equal(takenApart.failure, undefined, 'a foreign argument is read, and refused by the comparison that follows');
	assert.notEqual(internals.cssTemplate(takenApart), foreign);

	// Text the loader did not embed is refused where it is read, not later.
	const other = internals.cssParts(written(module.replace(JSON.stringify(css), JSON.stringify('.a{color:blue}\n'))), call);
	assert.equal(other.failure.status, 'hash-mismatch');
	assert.match(other.failure.reason, /did not embed the stylesheet it was handed/);

	for (const [id, text, match] of [
		['imports of its own', written(module).replace('// Imports\n', '// Imports\nimport x from "y";\n'), /imports this version does not read/],
		['an export of its own', written(module.replace('export default ___CSS_LOADER_EXPORT___;\n', 'export default 1;\n')), /a module this version does not read/],
		['a locals export', written(module.replace('// Exports\n', '// Exports\n___CSS_LOADER_EXPORT___.locals = {};\n')), /a module this version does not read/],
		['a second push', written(`${module}___CSS_LOADER_EXPORT___.push([module.id, "", ""]);\n`), /a module this version does not read/],
	]) {
		const read = internals.cssParts(text, call);
		assert.equal(read.failure && read.failure.status, 'no-data', id);
		assert.match(read.failure.reason, match, id);
	}
});
