'use strict';

const fs = require('node:fs');
const path = require('node:path');

// The delivered compositions of files this build installs but did not build: a
// dependency shipped as a prebundle, rebuilt elsewhere with this collector
// attached, whose proof DK read out of that pinned rebuild and wrote here.
//
// The manifest is keyed by the digest of the file's bytes and by nothing else.
// A path can be moved and a version can be reused; bytes cannot. DK writes an
// entry only after it has found that digest to be the digest the verified
// original of the installed file serves, so a reader that has the bytes has the
// whole of the join.
//
// This reader infers nothing. It does not resolve by path, it does not merge two
// compositions for one digest, and it holds every component to the same rules
// the primary-source manifest holds its own to.
const GIT_LOCATOR = /^git\+(?:https|ssh):\/\/[^\s#]+#([0-9a-f]{40})$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

class PrebuiltOriginals {
	constructor(contextPath) {
		if (typeof contextPath !== 'string' || !path.isAbsolute(contextPath)) throw failure('invalid', 'a compiler context path is required');
		this.entries = new Map();
		const filename = path.join(path.dirname(contextPath), 'webpack-prebuilt.json');
		let body;
		try {
			body = fs.readFileSync(filename, 'utf8');
		} catch (error) {
			// A build that delivers nothing is the ordinary case, not a failure.
			if (error.code === 'ENOENT') return;
			throw error;
		}
		let manifest;
		try {
			manifest = JSON.parse(body);
		} catch (error) {
			throw failure('invalid', `prebuilt manifest JSON: ${error.message}`);
		}
		if (!object(manifest)) throw failure('invalid', 'prebuilt manifest must be an object');
		if (!Object.hasOwn(manifest, 'version')) throw failure('no-data', 'prebuilt manifest version is missing');
		if (!Number.isInteger(manifest.version) || manifest.version < 1) throw failure('invalid', 'prebuilt manifest version is invalid');
		if (manifest.version !== 1) throw failure('unsupported', `prebuilt manifest version ${manifest.version}`);
		if (Object.keys(manifest).some((key) => !['version', 'entries'].includes(key))) throw failure('invalid', 'unknown prebuilt manifest field');
		if (!Array.isArray(manifest.entries)) throw failure('invalid', 'prebuilt manifest requires an entry array');
		for (const entry of manifest.entries) {
			if (!object(entry) || Object.keys(entry).some((key) => !['sha256', 'components', 'inputs'].includes(key))) throw failure('invalid', 'invalid prebuilt entry');
			if (!DIGEST.test(entry.sha256) || this.entries.has(entry.sha256)) throw failure('invalid', 'invalid or duplicate prebuilt entry digest');
			// A composition of components alone states what the file is said to
			// contain without stating one byte it was built from.
			if (!Array.isArray(entry.components) || entry.components.length === 0 || !Array.isArray(entry.inputs) || entry.inputs.length === 0) {
				throw failure('invalid', `prebuilt entry ${entry.sha256} states no components and inputs`);
			}
			const components = new Map();
			for (const component of entry.components) {
				if (!object(component) || typeof component.id !== 'string' || !component.id || components.has(component.id)) throw failure('invalid', `invalid or duplicate component of prebuilt entry ${entry.sha256}`);
				if (typeof component.name !== 'string' || !component.name || typeof component.version !== 'string' || !component.version) throw failure('invalid', `component ${component.id} carries no exact name and version`);
				const source = component.source;
				if (source === null || typeof source !== 'object' || (source.kind !== 'pm' && source.kind !== 'node')) {
					throw failure('invalid', `component ${component.id} is of an unverifiable kind`);
				}
				// A dependency fetched as a repository is pinned to the commit its
				// own locator names; everything else is pinned to the archive it
				// was installed from, and a prepared source image to its digest.
				if (source.kind === 'node' && typeof source.locator === 'string' && source.locator.startsWith('git+')) {
					const commit = GIT_LOCATOR.exec(source.locator);
					if (!commit || source.checksum !== `git-commit:sha1:${commit[1]}`) throw failure('invalid', `component ${component.id} pins no Git commit`);
				} else if (typeof source.locator !== 'string' || !source.locator || typeof source.checksum !== 'string' || !source.checksum) {
					throw failure('invalid', `component ${component.id} pins no archive`);
				} else if (source.kind === 'pm' && !DIGEST.test(source.checksum)) {
					throw failure('invalid', `component ${component.id} pins no image digest`);
				}
				components.set(component.id, component);
			}
			const units = [];
			for (const input of entry.inputs) {
				if (!object(input) || Object.keys(input).some((key) => !['path', 'sha256', 'components'].includes(key))) throw failure('invalid', `invalid input of prebuilt entry ${entry.sha256}`);
				if (typeof input.path !== 'string' || !input.path || input.path.includes('\0')) throw failure('invalid', `invalid input path of prebuilt entry ${entry.sha256}`);
				if (!DIGEST.test(input.sha256)) throw failure('invalid', `invalid input digest of prebuilt entry ${entry.sha256}`);
				if (!Array.isArray(input.components) || input.components.length === 0) throw failure('invalid', `input ${input.path} is claimed by no component`);
				for (const id of input.components) {
					if (!components.has(id)) throw failure('invalid', `input ${input.path} is claimed by the unknown component ${id}`);
				}
				// One unit per claiming component, which is the shape the collector
				// builds an asset's own units in.
				for (const id of input.components) units.push({ path: input.path, sha256: input.sha256, component: components.get(id) });
			}
			// A component no input is claimed by contributes nothing that can be
			// pointed at.
			for (const id of components.keys()) {
				if (!units.some((unit) => unit.component.id === id)) throw failure('invalid', `component ${id} of prebuilt entry ${entry.sha256} is claimed by no input`);
			}
			this.entries.set(entry.sha256, units);
		}
	}

	// The source units of the build that emitted exactly these bytes, or null.
	resolve(sha256) {
		return this.entries.get(sha256) || null;
	}
}

function object(value) {
	return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function failure(status, message) {
	return Object.assign(new Error(`PrebuiltOriginals: ${message}`), { status });
}

module.exports = PrebuiltOriginals;
