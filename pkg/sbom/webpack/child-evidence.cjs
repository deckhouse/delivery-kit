'use strict';

// Binds an asset of this compilation that no chunk of it built to the chunk of
// a child compilation that did.
//
// A child compilation - the one a worker entry point is compiled in - hands its
// finished assets to the compilation that made it, which emits them under the
// same names (`Compiler.runAsChild`). Such an asset therefore has no chunk here
// and every adapter of this set refuses it, while the compilation next door
// holds the chunk that produced it and every recording that describes it: the
// renderers, the runtime modules, the minifier and the content hashes are all
// observed per compilation, and a child compiler inherits the taps that install
// them.
//
// Nothing here describes bytes of its own: it finds the one chunk of the one
// child that built this file, hands it to the ordinary asset evidence of that
// compilation, and requires the file the parent holds to be the very source the
// child handed over - not a copy, and not something rewritten since.
//
// The plugin that created the child compilation decides which entry is compiled
// and under which name, and contributes no text; it is therefore not pinned
// here. What the text is made of is what the child compilation was observed
// doing with sources this caller verified.

const { assetEvidence, observedBytes } = require('./bootstrap-evidence.cjs');

async function childEvidence(compilation, chunk, child, verifyResource, evidence = {}) {
	// Only a compilation this one really made: one that merely put itself on the
	// list produced nothing through it.
	const compiler = child.compiler;
	if (!compiler || typeof compiler.isChild !== 'function' || !compiler.isChild() || compiler.parentCompilation !== compilation) {
		return noData(`chunk ${chunk.name || chunk.id} belongs to a compilation that is not a child of this one`);
	}
	for (const file of chunk.files) {
		const claimants = claiming(compilation, file);
		if (claimants !== 1) return noData(`${file} is emitted by ${claimants} chunks of this compilation and the ones it made`);
		if (!child.getAsset(file) || !compilation.getAsset(file)) return noData(`${file} is not an asset of both compilations`);
		// What the child was done with has to be what this compilation emitted: a
		// rewrite in between is bytes this adapter cannot attribute. Both are read
		// where their compilation stopped changing them, because an asset carries
		// no content of its own any more by the time a proof is written.
		const handed = observedBytes(child, file);
		const held = observedBytes(compilation, file);
		if (!handed || !held) return noData(`the bytes of ${file} were not observed in both compilations`);
		if (!handed.equals(held)) return noData(`${file} is not the asset the child compilation handed over`);
	}
	return assetEvidence(child, chunk, verifyResource, evidence);
}

// How many chunks of this compilation and of the ones it made emit that file.
function claiming(compilation, file) {
	let count = 0;
	for (const source of [compilation, ...(Array.isArray(compilation.children) ? compilation.children : [])]) {
		for (const chunk of source.chunks) {
			if (chunk.files && chunk.files.has(file)) count += 1;
		}
	}
	return count;
}

function noData(reason) {
	return { units: [], failure: { status: 'no-data', reason } };
}

module.exports = { childEvidence };
