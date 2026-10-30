'use strict';

// Binds the two modules of a style-loader 3 chain to what the loaders really
// did: the module style-loader pitched to the template its own source carries,
// and the module css-loader built to the stylesheet text it was handed.
//
// Neither module is a file. style-loader never reads the stylesheet: it pitches
// a small program that imports six helpers of its own runtime and the content
// module behind the request it was given. css-loader turns the stylesheet into
// one `push` of the text it parsed, with the api of its own runtime around it.
// Both are recomputed here from what the loaders were given, and the requests
// they wrote are held against the modules the graph really holds for them.
//
// Behind css-loader the chain may end in a tail that produced the text out of
// no file - redoc minifies its stylesheet with esbuild first - and then what
// the module contributes is what that tail's own adapter observed it consume.
// The seam is the stylesheet adapter's; the tails are the caller's.
//
// A source map embedded in the css-loader module is data, not a component: it
// describes the very text of this module and names nothing that is not already
// a source of it. It is claimed only when it says no more than that - see
// `describedMap`.
//
// The recordings come from stylesheet3-preload.cjs, which must already be
// installed when the loaders are first required, and the identity of the files
// it recognized comes from runtime-preload.cjs underneath it.

const crypto = require('node:crypto');
const path = require('node:path');

const { tailEvidenceFor } = require('./stylesheet-evidence.cjs');

const NAME = 'DkSbomStylesheet3Evidence';
const REGISTRY = Symbol.for('dk.sbom.webpack.cjs');
const STYLESHEET3 = Symbol.for('dk.sbom.webpack.stylesheet3');
const SUPPORTED_WEBPACK = '5.94.0';
const CANONICAL_SHA256 = /^sha256:[0-9a-f]{64}$/;

// The runtime files of each distribution this version describes, by the place
// they occupy in it. The loaders name them from their own directory, so a file
// found anywhere else is not theirs. Their bytes are not pinned here: each one
// is an ordinary module of the graph, verified and bound to its component by
// whoever describes the modules of this build.
// In the order the loader's own source asks about them. The singleton dom api
// is asked about and then not used: the loader builds both requests before it
// picks one, so it is expected here and imported nowhere.
const STYLE_RUNTIME = [
	{ slot: 'api', file: path.join('runtime', 'injectStylesIntoStyleTag.js'), imported: true },
	{ slot: 'domAPI', file: path.join('runtime', 'styleDomAPI.js'), imported: true },
	{ slot: 'singletonDomAPI', file: path.join('runtime', 'singletonStyleDomAPI.js'), imported: false },
	{ slot: 'insertFn', file: path.join('runtime', 'insertBySelector.js'), imported: true },
	{ slot: 'setAttributes', file: path.join('runtime', 'setAttributesWithoutAttributes.js'), imported: true },
	{ slot: 'insertStyleElement', file: path.join('runtime', 'insertStyleElement.js'), imported: true },
	{ slot: 'styleTagTransform', file: path.join('runtime', 'styleTagTransform.js'), imported: true },
];
const STYLE_IMPORTED = STYLE_RUNTIME.filter((runtime) => runtime.imported);
const CSS_RUNTIME = {
	api: path.join('runtime', 'api.js'),
	sourceMap: path.join('runtime', 'cssWithMappingToString.js'),
};

function installStylesheet3Evidence(compiler, verifyResource, options = {}) {
	if (typeof verifyResource !== 'function') throw new TypeError(`${NAME}: verifyResource must be a function`);
	for (const key of Object.keys(options)) {
		if (key !== 'tails') throw new TypeError(`${NAME}: unknown option ${JSON.stringify(key)}`);
	}
	const tails = options.tails === undefined ? [] : options.tails;
	if (!Array.isArray(tails)) throw new TypeError(`${NAME}: options.tails must be an array`);
	const recorder = globalThis[STYLESHEET3];
	const registry = globalThis[REGISTRY];
	const problem = prepare(compiler, recorder, registry);
	const compilations = new Set();
	if (!problem) {
		compiler.hooks.compilation.tap(NAME, (compilation) => compilations.add(compilation));
		compiler.hooks.done.tap(NAME, () => compilations.clear());
	}
	return async function evidenceFor(module) {
		if (problem) return problem;
		try {
			const tailOf = tailEvidenceFor(compiler);
			return await describe({ recorder, registry, compilations, verifyResource, tailOf, tails }, module);
		} catch (error) {
			return noData(`${identify(module)} could not be described: ${error.message}`);
		}
	};
}

function prepare(compiler, recorder, registry) {
	if (!recorder || typeof recorder.pitchOf !== 'function') return noData('the stylesheet load recorder is not installed in this process');
	if (!registry || typeof registry.getByFile !== 'function') return noData('the commonjs load registry is not installed in this process');
	const api = compiler.webpack;
	if (!api || typeof api.version !== 'string') return noData('the compiler does not expose the webpack that builds its modules');
	if (api.version !== SUPPORTED_WEBPACK) return failed('unsupported', `modules of webpack ${api.version} are not described, only ${SUPPORTED_WEBPACK}`);
	return null;
}

async function describe(context, module) {
	const pitch = context.recorder.pitchOf(module);
	const call = context.recorder.callOf(module);
	if (pitch && call) return noData(`${identify(module)} was built by both stylesheet loaders at once`);
	if (pitch) return describeStyle(context, module, pitch);
	if (call) return describeCss(context, module, call);
	return noData(`${identify(module)} was not built by an observed stylesheet loader`);
}

// What style-loader pitched: it never read the stylesheet, so its module is the
// template of its own source filled in with the requests it wrote, and every
// one of those requests is a module the graph really holds.
async function describeStyle(context, module, pitch) {
	const info = context.recorder.loaderOf('style');
	const ready = usable(info, pitch, 'style-loader');
	if (ready) return ready;
	const member = info.members && info.members.get('pitch');
	if (!member || member.value !== info.original) return noData(`${info.file} did not export the pitch this adapter recorded`);
	const published = publishedLoader(context.registry, info, info.api);
	if (published) return published;
	if (info.api.pitch !== info.wrapper || pitch.method !== info.wrapper) return noData(`the pitch of ${info.file} was replaced after this adapter recorded it`);

	// A distribution is asked for by its commonjs entry and implemented in
	// another file, so what names the loader of a chain item is what it exports,
	// not where it sits.
	const chain = Array.isArray(module.loaders) ? module.loaders : [];
	if (chain.length < 1 || loadedExports(chain[0] && chain[0].loader) !== info.api) {
		return noData(`${identify(module)} was not pitched by style-loader at the head of its chain`);
	}
	const bound = boundTo(pitch.context, module, 0);
	if (bound) return bound;
	if (typeof pitch.request !== 'string' || pitch.request === '' || typeof pitch.output !== 'string') {
		return noData(`${identify(module)} was pitched without a request of its own`);
	}

	// The requests of the generated code, as the loader context answered them
	// while the loader ran. Nothing here is recomputed from a path: what is
	// checked is that the loader asked about its own runtime files and about the
	// request it was pitched for, in the order its source writes them.
	const wrote = writtenRequests(pitch, info);
	if (wrote.failure) return wrote;
	if (pitch.output !== styleTemplate(wrote.slots)) {
		return failed('invalid', `style-loader did not pitch its own template for ${identify(module)}`);
	}
	const kept = keptSource(module);
	if (kept.failure) return kept;
	if (!kept.buffer.equals(Buffer.from(pitch.output, 'utf8'))) {
		return failed('hash-mismatch', `the source webpack kept for ${identify(module)} is not what style-loader pitched`);
	}
	const required = await requiredModules(context, module, pitch, info, wrote);
	if (required.failure) return required;

	const loader = await loaderUnit(context, info.file, info.sha256);
	if (loader.failure) return loader;
	return { units: [loader.unit] };
}

// What css-loader made of the stylesheet: the api of its own runtime around one
// push of the text it was handed, and nothing else. The text itself is the
// claim another adapter or the file system answers for.
async function describeCss(context, module, call) {
	const info = context.recorder.loaderOf('css');
	const ready = usable(info, call, 'css-loader');
	if (ready) return ready;
	const member = info.members && info.members.get('default');
	if (!member || member.value !== info.original) return noData(`${info.file} did not export the loader this adapter recorded`);
	const published = publishedLoader(context.registry, info, info.original);
	if (published) return published;
	if (info.exports.default !== info.wrapper || call.method !== info.wrapper) return noData(`${info.file} was replaced after this adapter recorded it`);

	const chain = Array.isArray(module.loaders) ? module.loaders : [];
	const ran = (item) => loadedExports(item.loader) === info.wrapper;
	const at = chain.findIndex(ran);
	if (at < 0 || chain.filter(ran).length !== 1) {
		return noData(`${identify(module)} was not built by css-loader exactly once`);
	}
	const bound = boundTo(call.context, module, at);
	if (bound) return bound;
	// The loader runner hands on only what the loader before it returned, so a
	// chain head is called with the text alone and a tail hands over three
	// arguments. Anything beyond those three is a call this version cannot read.
	if (call.arity < 1 || call.arity > 3 || typeof call.input !== 'string') return noData(`${identify(module)} was not built from text alone`);
	const written = answerOf(call, module);
	if (written.failure) return written;

	// Everything that can be settled from what this process already holds is
	// settled before the seam is asked: whatever stands behind css-loader may
	// run an adapter of its own, and a module this one cannot describe is not
	// worth that work.
	const parts = cssParts(written.content, call);
	if (parts.failure) return parts;
	const required = await requiredCssModules(context, module, parts);
	if (required.failure) return required;
	if (written.content !== cssTemplate(parts)) {
		return failed('invalid', `css-loader did not write its own template for ${identify(module)}`);
	}
	const kept = keptSource(module);
	if (kept.failure) return kept;
	if (!kept.buffer.equals(Buffer.from(written.content, 'utf8'))) {
		return failed('hash-mismatch', `the source webpack kept for ${identify(module)} is not what css-loader returned`);
	}

	if (typeof context.tailOf !== 'function') return noData(`${identify(module)} was built in a process with no stylesheet tail seam`);
	const sources = await context.tailOf(module, call.input, { after: at, resource: call.context.resourcePath, tails: context.tails });
	if (sources.failure) return sources;

	// The map is read last because what it may say depends on what the seam
	// settled: when a tail handed css-loader a map of its own, the map embedded
	// here describes the file that tail read, and that file is a source the seam
	// has just claimed.
	if (parts.sourceMap !== null) {
		const mapped = await mappedText(context, module, call, sources);
		if (mapped.failure) return mapped;
		const map = describedMap(parts.sourceMap, { input: call.input, origin: mapped.text }, module);
		if (map.failure) return map;
	}

	const loader = await loaderUnit(context, info.file, info.sha256);
	if (loader.failure) return loader;
	return { units: [...sources.units, loader.unit] };
}

// The text the sources of an embedded map describe.
//
// With nothing behind css-loader, the text it was handed is the whole of what
// the map can be about. A tail that handed a map along with that text built it
// out of a file of its own, and the map css-loader composed on top of that one
// describes that file - so it is read against the file itself, which the seam
// has just claimed as a source of this module.
async function mappedText(context, module, call, sources) {
	if (call.map === undefined || call.map === null) return { text: call.input };
	const resource = call.context.resourcePath;
	const claimed = sources.units.find((unit) => unit.path === resource);
	if (!claimed) return noData(`${identify(module)} embeds a source map of a file no source of this module names`);
	const resolution = await verified(context, resource);
	if (resolution.failure) return resolution;
	if (resolution.unit.sha256 !== claimed.sha256) {
		return failed('hash-mismatch', `${resource} is not the file the sources of ${identify(module)} were verified as`);
	}
	return textOf(resolution.unit, resource);
}

// The text of a verified file, as a map may carry it: bytes that are not utf8
// are not a text this version compares.
function textOf(unit, file) {
	if (!Buffer.isBuffer(unit.bytes)) return noData(`${file} was verified without its bytes`);
	const text = unit.bytes.toString('utf8');
	if (!Buffer.from(text, 'utf8').equals(unit.bytes)) return noData(`${file} is not valid utf8`);
	return { text };
}

// The embedded source map, read as data about this very module.
//
// A map is claimed only when it says nothing a source of this module does not
// already say: it must be a plain version 3 map of exactly the text that was
// parsed, carrying that text and nothing else. `sources` are diagnostic strings
// and prove nothing, so they are not read as inputs - what makes the map
// harmless is that every `sourcesContent` entry is the input this module was
// built from, byte for byte.
function describedMap(mapText, texts, module) {
	// A map read with no tail behind the loader describes the text css-loader
	// was handed, which is then both what it maps and what it maps from.
	const input = texts.input;
	const origin = texts.origin === undefined ? texts.input : texts.origin;
	const parsed = strictJson(mapText);
	if (parsed.failure) return parsed;
	const map = parsed.value;
	if (!isPlainObject(map)) return noData(`the source map of ${identify(module)} is not a map`);
	const known = ['version', 'sources', 'sourcesContent', 'mappings', 'names', 'file', 'sourceRoot'];
	for (const key of Object.keys(map)) {
		if (!known.includes(key)) return noData(`the source map of ${identify(module)} carries ${key}, which this version does not read`);
	}
	if (map.version !== 3) return noData(`the source map of ${identify(module)} is version ${String(map.version)}, not 3`);
	if (map.sourceRoot !== undefined && map.sourceRoot !== '') return noData(`the source map of ${identify(module)} is rooted at ${String(map.sourceRoot)}`);
	if (map.file !== undefined) return noData(`the source map of ${identify(module)} names a file of its own`);
	if (!Array.isArray(map.sources) || map.sources.some((source) => typeof source !== 'string')) {
		return noData(`the source map of ${identify(module)} names its sources in a way this version does not read`);
	}
	// A source name is not read as a file, but it is not inert either: the
	// runtime of this css-loader interpolates it into a `/*# sourceURL= */`
	// comment of the stylesheet it injects, unescaped. Only the two spellings
	// this version writes are taken, and neither can close that comment.
	for (const source of map.sources) {
		const problem = sourceNameProblem(source);
		if (problem) return noData(`the source map of ${identify(module)} names a source ${problem}`);
	}
	if (!Array.isArray(map.sourcesContent) || map.sourcesContent.length !== map.sources.length) {
		return noData(`the source map of ${identify(module)} carries ${Array.isArray(map.sourcesContent) ? map.sourcesContent.length : 'no'} contents for ${map.sources.length} sources`);
	}
	// The one claim that makes the map data rather than a statement about files
	// nobody verified: every text it carries is a text this module was built
	// from, byte for byte.
	for (const [index, content] of map.sourcesContent.entries()) {
		if (typeof content !== 'string') return noData(`the source map of ${identify(module)} carries no text for ${map.sources[index]}`);
		if (content !== origin) return noData(`the source map of ${identify(module)} carries a text that is not what this module was built from`);
	}
	const names = map.names === undefined ? [] : map.names;
	if (!Array.isArray(names)) return noData(`the source map of ${identify(module)} names identifiers in a way this version does not read`);
	const tokens = identifiersIn(origin);
	for (const name of names) {
		if (typeof name !== 'string' || !tokens.has(name)) {
			return noData(`the source map of ${identify(module)} names ${JSON.stringify(name)}, which is not an identifier of the text it maps`);
		}
	}
	const decoded = decodeMappings(map.mappings, { sources: map.sources.length, names: names.length, origin });
	if (decoded.failure) return noData(`the source map of ${identify(module)} ${decoded.failure.reason}`);
	// What the map maps is the text css-loader embedded beside it: the runtime is
	// handed the two together.
	const mapped = input.split('\n');
	if (decoded.lines > mapped.length) {
		return noData(`the source map of ${identify(module)} maps ${decoded.lines} lines of a text that has ${mapped.length}`);
	}
	if (decoded.lines > 0 && decoded.columns > mapped[decoded.lines - 1].length) {
		return noData(`the source map of ${identify(module)} maps ${decoded.columns} columns of a line that has ${mapped[decoded.lines - 1].length}`);
	}
	return { units: [] };
}

// What css-loader 5.2.6 writes as a source name: a webpack url built from a
// path relative to the build root, or the non-standard spelling postcss uses
// for a text it was handed with no file of its own. Anything else is a name
// this version does not take, and a name is never long, nested or able to end
// the comment it is interpolated into.
const SOURCE_LIMIT = 512;
const WEBPACK_SOURCE = /^webpack:\/\/\.\/[A-Za-z0-9._\-/@ ]+$/;
const POSTCSS_SOURCE = /^<[A-Za-z0-9 ._\-#]+>$/;

function sourceNameProblem(source) {
	if (source.length === 0 || source.length > SOURCE_LIMIT) return 'of a length this version does not take';
	// eslint-disable-next-line no-control-regex
	if (/[\u0000-\u001f\u007f]/.test(source)) return 'carrying control characters';
	if (source.includes('*/') || source.includes('/*')) return 'that could end the comment it is written into';
	if (POSTCSS_SOURCE.test(source)) return null;
	if (!WEBPACK_SOURCE.test(source)) return 'spelled in a way this version does not take';
	const walked = source.slice('webpack://./'.length).split('/');
	if (walked.includes('..') || walked.includes('.') || walked.includes('')) return 'that is not a clean relative path';
	return null;
}

// The identifiers of a text, as a tokenizer would see them: a name that merely
// occurs inside another word is not one of them.
function identifiersIn(text) {
	const found = new Set();
	for (const match of text.matchAll(/[A-Za-z_$][A-Za-z0-9_$-]*/g)) found.add(match[0]);
	return found;
}

// Base64 VLQ, decoded rather than merely recognized: every segment is one,
// four or five numbers, and every index and position they carry has to be one
// this map could be about.
function decodeMappings(mappings, bounds) {
	if (typeof mappings !== 'string') return mappingProblem('does not carry readable mappings');
	const DIGITS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
	const lines = bounds.origin.split('\n');
	const state = { source: 0, line: 0, column: 0, name: 0 };
	let generatedLine = 0;
	let lastColumn = 0;
	for (const group of mappings.split(';')) {
		let generatedColumn = 0;
		if (group !== '') {
			for (const segment of group.split(',')) {
				if (segment === '') return mappingProblem('carries an empty mapping');
				const fields = [];
				let value = 0;
				let shift = 0;
				let open = false;
				for (const character of segment) {
					const digit = DIGITS.indexOf(character);
					if (digit < 0) return mappingProblem('does not carry readable mappings');
					value += (digit & 31) << shift;
					if ((digit & 32) !== 0) {
						shift += 5;
						// A number wider than the shifts a 32 bit value holds would
						// overflow into a different number than the one written.
						if (shift >= 32) return mappingProblem('carries a number too wide to read');
						open = true;
						continue;
					}
					const negative = (value & 1) === 1;
					fields.push(negative ? -(value >> 1) : value >> 1);
					value = 0;
					shift = 0;
					open = false;
				}
				if (open) return mappingProblem('does not carry readable mappings');
				if (fields.length !== 1 && fields.length !== 4 && fields.length !== 5) {
					return mappingProblem(`carries a mapping of ${fields.length} fields`);
				}
				generatedColumn += fields[0];
				if (generatedColumn < 0) return mappingProblem('maps to a position before the start of its own text');
				if (fields.length === 1) continue;
				state.source += fields[1];
				state.line += fields[2];
				state.column += fields[3];
				if (state.source < 0 || state.source >= bounds.sources) return mappingProblem(`maps to source ${state.source}, which it does not name`);
				if (state.line < 0 || state.line >= lines.length) return mappingProblem(`maps to line ${state.line + 1} of a text that has ${lines.length}`);
				if (state.column < 0 || state.column > lines[state.line].length) {
					return mappingProblem(`maps to column ${state.column + 1} of a line that has ${lines[state.line].length}`);
				}
				if (fields.length === 5) {
					state.name += fields[4];
					if (state.name < 0 || state.name >= bounds.names) return mappingProblem(`maps to name ${state.name}, which it does not carry`);
				}
			}
		}
		generatedLine++;
		lastColumn = generatedColumn;
	}
	return { lines: generatedLine, columns: lastColumn };
}

function mappingProblem(reason) {
	return { failure: { reason } };
}

// JSON that says one thing: no member stated twice, and the text it was read
// from is the text it serializes back to.
function strictJson(text) {
	let value;
	try {
		value = JSON.parse(text);
	} catch (error) {
		return noData(`a source map of this module is malformed: ${error.message}`);
	}
	if (JSON.stringify(value) !== text) return noData('a source map of this module is not the plain json it parses as');
	return { value };
}

// The three parts of the module css-loader writes, taken apart at the only
// places its template leaves open: the two requests and the text it embedded.
function cssParts(content, call) {
	const withMap = /^\/\/ Imports\nimport ___CSS_LOADER_API_SOURCEMAP_IMPORT___ from (".*");\nimport ___CSS_LOADER_API_IMPORT___ from (".*");\n/;
	const withoutMap = /^\/\/ Imports\nimport ___CSS_LOADER_API_IMPORT___ from (".*");\n/;
	const mapped = withMap.exec(content);
	const plain = mapped ? null : withoutMap.exec(content);
	if (!mapped && !plain) return noData('css-loader wrote imports this version does not read');
	const head = mapped || plain;
	// A request is a json string literal and nothing else: read greedily, the
	// capture would swallow whatever a forged module wrote after it, and the
	// text rebuilt from it would carry that along as if the loader had.
	const requests = {};
	for (const [slot, capture] of [['apiRequest', head[mapped ? 2 : 1]], ['sourceMapRequest', mapped ? head[1] : null]]) {
		if (capture === null) {
			requests[slot] = null;
			continue;
		}
		const read = strictJson(capture);
		if (read.failure) return noData(`css-loader wrote a request this version does not read: ${capture}`);
		if (typeof read.value !== 'string' || read.value === '') return noData('css-loader imported something other than a file');
		requests[slot] = read.value;
	}
	const rest = content.slice(head[0].length);
	const body = /^var ___CSS_LOADER_EXPORT___ = ___CSS_LOADER_API_IMPORT___\((.*)\);\n\/\/ Module\n___CSS_LOADER_EXPORT___\.push\(\[module\.id, (".*"), ""(,.*)?\]\);\n\/\/ Exports\nexport default ___CSS_LOADER_EXPORT___;\n$/.exec(rest);
	if (!body) return noData('css-loader wrote a module this version does not read');
	const embedded = strictJson(body[2]);
	if (embedded.failure) return embedded;
	if (typeof embedded.value !== 'string') return noData('css-loader embedded something other than a stylesheet');
	if (embedded.value !== call.input) return failed('hash-mismatch', 'css-loader did not embed the stylesheet it was handed');
	return {
		apiRequest: requests.apiRequest,
		sourceMapRequest: requests.sourceMapRequest,
		argument: body[1],
		css: embedded.value,
		sourceMap: body[3] === undefined ? null : body[3].slice(1),
	};
}

function cssTemplate(parts) {
	const api = JSON.stringify(parts.apiRequest);
	const imports = parts.sourceMapRequest === null
		? `// Imports\nimport ___CSS_LOADER_API_IMPORT___ from ${api};\n`
		: `// Imports\nimport ___CSS_LOADER_API_SOURCEMAP_IMPORT___ from ${JSON.stringify(parts.sourceMapRequest)};\nimport ___CSS_LOADER_API_IMPORT___ from ${api};\n`;
	const argument = parts.sourceMapRequest === null ? 'function(i){return i[1]}' : '___CSS_LOADER_API_SOURCEMAP_IMPORT___';
	const tail = parts.sourceMap === null ? '' : `,${parts.sourceMap}`;
	return `${imports}var ___CSS_LOADER_EXPORT___ = ___CSS_LOADER_API_IMPORT___(${argument});\n// Module\n___CSS_LOADER_EXPORT___.push([module.id, ${JSON.stringify(parts.css)}, ""${tail}]);\n// Exports\nexport default ___CSS_LOADER_EXPORT___;\n`;
}

// style-loader 3.3.1 with no options of its own: a style tag inserted into the
// head, es modules, no attributes, the default tag transform and no hot module
// replacement. Every other option changes this text, and `boundTo` refuses one.
function styleTemplate(slots) {
	return `
      import API from ${slots.api};
      import domAPI from ${slots.domAPI};
      import insertFn from ${slots.insertFn};
      import setAttributes from ${slots.setAttributes};
      import insertStyleElement from ${slots.insertStyleElement};
      import styleTagTransformFn from ${slots.styleTagTransform};
      import content, * as namedExport from ${slots.content};
      
      

var options = {};

options.styleTagTransform = styleTagTransformFn;
options.setAttributes = setAttributes;

      options.insert = insertFn.bind(null, "head");
    
options.domAPI = domAPI;
options.insertStyleElement = insertStyleElement;

var update = API(content, options);



export * from ${slots.content};
       export default content && content.locals ? content.locals : undefined;
`;
}

// Which requests the loader wrote, in the order its source writes them: six
// files of its own runtime, then the request it was pitched for, then that same
// request once more for the exports it re-exports.
function writtenRequests(pitch, info) {
	const requests = Array.isArray(pitch.requests) ? pitch.requests : [];
	if (pitch.requests.intact !== true) return noData('the request recording of this pitch is not intact');
	const directory = path.dirname(info.file);
	const expected = [
		...STYLE_RUNTIME.map((runtime) => ({ slot: runtime.slot, request: `!${path.join(directory, runtime.file)}`, file: runtime.imported ? path.join(directory, runtime.file) : null })),
		{ slot: 'content', request: `!!${pitch.request}`, file: null },
		{ slot: 'content', request: `!!${pitch.request}`, file: null },
	];
	if (requests.length !== expected.length) {
		return noData(`style-loader wrote ${requests.length} requests for this module, not the ${expected.length} its template carries`);
	}
	const slots = {};
	const files = {};
	for (const [index, want] of expected.entries()) {
		const made = requests[index];
		if (made.arity !== 2 || made.context !== pitch.context.context || made.request !== want.request) {
			return noData(`style-loader asked for ${made.request}, not for ${want.request}`);
		}
		if (typeof made.answer !== 'string' || made.answer === '') return noData(`style-loader was answered nothing for ${want.request}`);
		if (slots[want.slot] !== undefined && slots[want.slot] !== JSON.stringify(made.answer)) {
			return noData(`style-loader was answered two different requests for ${want.slot}`);
		}
		slots[want.slot] = JSON.stringify(made.answer);
		if (want.file) files[want.slot] = want.file;
	}
	return { slots, files };
}

// The modules the pitched code imports, as the graph holds them: the six
// runtime files of the recognized distribution and the stylesheet behind the
// very request this call was given.
async function requiredModules(context, module, pitch, info, wrote) {
	const graph = moduleGraphOf(context, module);
	if (graph.failure) return graph;
	const wanted = new Map(Object.entries(wrote.files).map(([slot, file]) => [file, slot]));
	const seen = new Set();
	let content;
	for (const connection of graph.graph.getOutgoingConnections(module)) {
		const required = connection.module;
		if (!required || required === module) continue;
		if (required.request === pitch.request && typeof required.rawRequest === 'string' && required.rawRequest.startsWith('!!')) {
			content = required;
			continue;
		}
		const slot = wanted.get(required.resource);
		if (slot === undefined || !Array.isArray(required.loaders) || required.loaders.length !== 0) {
			return noData(`${identify(module)} also requires ${identify(required)}`);
		}
		seen.add(slot);
	}
	if (!content) return noData(`${identify(module)} does not require the stylesheet of the request it was pitched for`);
	if (seen.size !== STYLE_IMPORTED.length) {
		return noData(`${identify(module)} requires ${seen.size} of the ${STYLE_IMPORTED.length} runtime files its code imports`);
	}
	return { content };
}

// The modules the css-loader code imports: its own api, and the mapping helper
// when a map is embedded. The requests are the text's own, so what binds them
// is the file the graph resolved each one to.
async function requiredCssModules(context, module, parts) {
	const graph = moduleGraphOf(context, module);
	if (graph.failure) return graph;
	const info = context.recorder.loaderOf('css');
	const directory = path.dirname(info.file);
	const wanted = new Map();
	wanted.set(path.join(directory, CSS_RUNTIME.api), 'api');
	if (parts.sourceMapRequest !== null) wanted.set(path.join(directory, CSS_RUNTIME.sourceMap), 'sourceMap');
	const seen = new Set();
	for (const connection of graph.graph.getOutgoingConnections(module)) {
		const required = connection.module;
		if (!required || required === module) continue;
		const slot = wanted.get(required.resource);
		if (slot === undefined || !Array.isArray(required.loaders) || required.loaders.length !== 0) {
			return noData(`${identify(module)} also requires ${identify(required)}`);
		}
		seen.add(slot);
	}
	if (seen.size !== wanted.size) {
		return noData(`${identify(module)} requires ${seen.size} of the ${wanted.size} runtime files its code imports`);
	}
	return { seen };
}

function moduleGraphOf(context, module) {
	const compilations = [...context.compilations].filter((compilation) => compilation.modules.has(module));
	if (compilations.length !== 1) return noData(`${identify(module)} is not a module of exactly one observed compilation`);
	return { graph: compilations[0].moduleGraph };
}

function answerOf(call, module) {
	const answers = Array.isArray(call.answers) ? call.answers : [];
	if (call.answers.intact !== true) return noData('the callback recording of this call is not intact');
	if (answers.length !== 1) return noData(`css-loader answered ${answers.length} times for ${identify(module)}`);
	const answer = answers[0];
	if (answer.error) return noData(`css-loader failed for ${identify(module)}: ${answer.error.message || answer.error}`);
	if (typeof answer.content !== 'string') return noData(`css-loader wrote no text for ${identify(module)}`);
	// The map a loader hands on is an input of whatever reads it next; this
	// chain has nobody to read it, and a module that produced one was not the
	// module this version describes.
	if (answer.sourceMap !== undefined && answer.sourceMap !== null) return noData(`css-loader returned a source map of its own for ${identify(module)}`);
	return { content: answer.content };
}

function usable(info, record, name) {
	if (!info || !info.usable) return noData(`${name} is not the published file this adapter recognizes${info && info.reason ? `: ${info.reason}` : ''}`);
	if (!record.usable) return failed('invalid', `${info.file} ${record.reason}`);
	if (!sameState(record.states[0], record.states[1])) return failed('invalid', `${info.file} changed while it ran`);
	return null;
}

// The file the recorder wrapped is the file node really compiled, and the
// default member it wrapped is the one that file exported before anything else
// saw it: the loader api for style-loader, the loader itself for css-loader.
function publishedLoader(registry, info, published) {
	const entry = registry.getByFile(info.file);
	if (!entry || !entry.usable) return noData(`${info.file} was not recorded as a loaded commonjs module`);
	if (entry.sha256 !== info.sha256) return failed('hash-mismatch', `${info.file} ran source other than the published bytes`);
	if (entry.exports !== info.exports || memberOf(entry, 'default') !== published) {
		return noData(`${info.file} did not export what this adapter recorded`);
	}
	return null;
}

function memberOf(entry, key) {
	const member = entry && entry.usable && entry.members && entry.members.get(key);
	return member && member.kind === 'data' ? member.value : undefined;
}

function boundTo(context, module, loaderIndex) {
	if (!context) return noData(`${identify(module)} was built without a loader context of its own`);
	if (context.resourcePath !== module.resource) return noData(`${identify(module)} was built from ${typeof context.resourcePath === 'string' ? context.resourcePath : 'no file of its own'}`);
	if (context.resourceQuery || context.resourceFragment) return noData(`${identify(module)} was built from a request this adapter does not describe`);
	if (context.loaderIndex !== loaderIndex) return noData(`${identify(module)} was built by a loader chain this adapter does not describe`);
	if (context.hot) return noData(`${identify(module)} was built for hot module replacement`);
	// What the loader was configured with when it ran, not what the item holds
	// now: a rule object is shared and may be written to afterwards.
	if (!plainKeys(context.optionKeys, context.options) || !plain(context.query)) {
		return noData(`${identify(module)} was built by a loader configured with options this adapter does not describe`);
	}
	return null;
}

// Only the defaults are described: every option of either loader changes what
// the generated code is, and none of it would be observed here.
function plainKeys(optionKeys, options) {
	if (options === undefined || options === null || options === '') return optionKeys === null;
	return Array.isArray(optionKeys) && optionKeys.length === 0 && plain(options);
}

function plain(options) {
	if (options === undefined || options === null || options === '') return true;
	if (typeof options !== 'object' || Array.isArray(options) || Object.getPrototypeOf(options) !== Object.prototype) return false;
	return Reflect.ownKeys(options).length === 0;
}

async function loaderUnit(context, file, sha256) {
	const resolution = await verified(context, file);
	if (resolution.failure) return resolution;
	const unit = resolution.unit;
	if (unit.sha256 !== sha256) return failed('hash-mismatch', `${file} is not the published file this process ran`);
	return { unit: { path: unit.path, sha256: unit.sha256, component: unit.component } };
}

async function verified(context, file) {
	let resolution;
	try {
		resolution = await context.verifyResource(file);
	} catch (error) {
		return noData(`${file} could not be verified: ${error.message}`);
	}
	if (!resolution || (!resolution.unit && !resolution.failure)) return noData(`${file} was not verified`);
	if (resolution.failure) return { units: [], failure: resolution.failure };
	const unit = resolution.unit;
	if (!unit || typeof unit.path !== 'string' || !CANONICAL_SHA256.test(String(unit.sha256)) || unit.component === null || typeof unit.component !== 'object') {
		return noData(`${file} was not verified as a described unit`);
	}
	return { unit };
}

function keptSource(module) {
	const source = module.originalSource && module.originalSource();
	if (!source || typeof source.buffer !== 'function') return noData(`${identify(module)} does not expose the source webpack kept for it`);
	let buffer;
	try {
		buffer = source.buffer();
	} catch (error) {
		return noData(`${identify(module)} does not expose the source webpack kept for it: ${error.message}`);
	}
	if (!Buffer.isBuffer(buffer)) return noData(`${identify(module)} does not expose the source webpack kept for it`);
	return { buffer };
}

function sameState(before, after) {
	if (!(before instanceof Map) || !(after instanceof Map) || before.size !== after.size) return false;
	for (const [file, state] of before) {
		const other = after.get(file);
		if (!other || other.exports !== state.exports || !sameMembers(state.members, other.members)) return false;
	}
	return true;
}

function sameMembers(before, after) {
	if (before === null || after === null) return before === after;
	if (before.size !== after.size) return false;
	for (const [key, member] of before) {
		const other = after.get(key);
		if (!other || other.kind !== member.kind) return false;
		if (member.kind === 'data' ? other.value !== member.value || other.writable !== member.writable : other.get !== member.get || other.set !== member.set) return false;
		if (other.enumerable !== member.enumerable || other.configurable !== member.configurable) return false;
	}
	return true;
}

function loadedExports(file) {
	const entry = require.cache[resolved(file)];
	return entry ? entry.exports : undefined;
}

function resolved(file) {
	if (typeof file !== 'string') return undefined;
	try {
		return require.resolve(file);
	} catch {
		return undefined;
	}
}

function isPlainObject(value) {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function identify(module) {
	try {
		const name = module.identifier();
		if (typeof name === 'string' && name !== '') return name;
	} catch {
		// An identifier of its own making is not worth failing over.
	}
	return 'the module';
}

function failed(status, reason) {
	return { units: [], failure: { status, reason } };
}

function noData(reason) {
	return failed('no-data', reason);
}

// Whether the recorder of this version watched the loaders that built a module,
// which is what makes it one this adapter describes. The collector asks before
// it decides who describes a module, and has no business reading the recorder
// itself.
function isStylesheet3Module(module) {
	const recorder = globalThis[STYLESHEET3];
	if (!recorder || typeof recorder.pitchOf !== 'function' || typeof recorder.callOf !== 'function') return false;
	return Boolean(recorder.pitchOf(module) || recorder.callOf(module));
}

module.exports = {
	installStylesheet3Evidence,
	isStylesheet3Module,
	// The map reading, for tests that hold it against maps no build of a pinned
	// loader would produce.
	internals: Object.freeze({ describedMap, decodeMappings, sourceNameProblem, strictJson, cssParts, cssTemplate }),
};
