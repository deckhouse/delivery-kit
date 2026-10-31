'use strict';

const fs = require('node:fs');
const path = require('node:path');

// The immutable manifest is written only after DK verifies scoped PM originals
// and the Git commits a lockfile pins a Node package to. This reader does not
// infer an owner or treat a component dictionary as presence.
//
// A `node` component is the verified content of one Git commit: its locator is
// the lockfile `resolved` verbatim and its checksum names that very commit, so
// a reader can hold both against the lock entry it started from. The commit is
// a SHA-1 name, which proves no more than that the object graph is the one the
// lockfile already named; it is never restated as a stronger pin.
const GIT_LOCATOR = /^git\+(?:https|ssh):\/\/[^\s#]+#([0-9a-f]{40})$/;
// Kept in lockstep with gitLifecycleHooks of the writer.
const LIFECYCLE_HOOKS = ['preinstall','install','postinstall','prepare','prepublish','prepack','postpack'];
// A recorded fetch origin: a remote with no user info in it, because credentials of the
// build are never evidence about a component. A query and a fragment are no part of one
// either - the writer drops them with the userinfo, a token being as often passed there.
const MIRROR_ORIGIN = /^(?:(?:https|http|ssh|git):\/\/[^\s/@?#]+(?:\/[^\s@?#]*)?|[^\s/@:?#]+:[^\s@?#]+)$/;

class ContextOriginals {
	constructor(contextPath) {
		if (typeof contextPath !== 'string' || !path.isAbsolute(contextPath)) throw failure('invalid', 'a compiler context path is required');
		const filename = path.join(path.dirname(contextPath), 'webpack-originals.json');
		let body;
		try { body = fs.readFileSync(filename, 'utf8'); }
		catch (error) { if (error.code === 'ENOENT') throw failure('no-data', 'verified primary-source inputs are missing'); throw error; }
		let manifest;
		try { manifest = JSON.parse(body); }
		catch (error) { throw failure('invalid', `primary-source manifest JSON: ${error.message}`); }
		if (!object(manifest)) throw failure('invalid', 'primary-source manifest must be an object');
		if (!Object.hasOwn(manifest, 'version')) throw failure('no-data', 'primary-source manifest version is missing');
		if (!Number.isInteger(manifest.version) || manifest.version < 1) throw failure('invalid', 'primary-source manifest version is invalid');
		if (manifest.version !== 1) throw failure('unsupported', `primary-source manifest version ${manifest.version}`);
		if (Object.keys(manifest).some(key => !['version','components','files','lifecycle','mirrors'].includes(key))) throw failure('invalid', 'unknown primary-source manifest field');
		if (!Array.isArray(manifest.components) || !Array.isArray(manifest.files)) throw failure('invalid', 'primary-source manifest requires component and file arrays');
		const components = new Map();
		for (const component of manifest.components) {
			if (!object(component) || typeof component.id !== 'string' || !component.id || components.has(component.id)) throw failure('invalid', 'invalid or duplicate primary-source component');
			if (component.source?.kind === 'node') {
				const commit = GIT_LOCATOR.exec(component.source.locator);
				if (!commit || component.source.checksum !== `git-commit:sha1:${commit[1]}`) throw failure('invalid', `component ${component.id} pins no Git commit`);
				if (typeof component.name !== 'string' || !component.name || typeof component.version !== 'string' || !component.version) throw failure('invalid', `component ${component.id} carries no exact name and version`);
			} else if (component.source?.kind !== 'pm') throw failure('invalid', 'invalid or duplicate primary-source component');
			components.set(component.id, component);
		}
		// Install hooks the verified manifest of a component defines. Whatever they
		// wrote is not that component's own bytes, and is simply not a file here.
		if (manifest.lifecycle !== undefined && !Array.isArray(manifest.lifecycle)) throw failure('invalid', 'primary-source lifecycle must be an array');
		for (const entry of manifest.lifecycle || []) {
			if (!object(entry) || Object.keys(entry).some(key=>!['component','hooks'].includes(key)) || !components.has(entry.component) ||
				!Array.isArray(entry.hooks) || entry.hooks.some(hook => !LIFECYCLE_HOOKS.includes(hook))) throw failure('invalid', 'invalid primary-source lifecycle record');
		}
		// The mirror a component's objects were really fetched from. A component is the
		// repository its locator names whatever the mirror is called, so nothing is
		// resolved by this; it is read only to be held to a shape that carries no
		// credentials.
		if (manifest.mirrors !== undefined && !Array.isArray(manifest.mirrors)) throw failure('invalid', 'primary-source mirrors must be an array');
		for (const entry of manifest.mirrors || []) {
			if (!object(entry) || Object.keys(entry).some(key=>!['component','fetchedFrom'].includes(key)) || !components.has(entry.component) ||
				!MIRROR_ORIGIN.test(entry.fetchedFrom)) throw failure('invalid', 'invalid primary-source mirror record');
		}
		this.files = new Map();
		for (const file of manifest.files) {
			if (!object(file) || Object.keys(file).some(key=>!['path','sha256','component'].includes(key)) || !cleanPath(file.path) || !/^sha256:[0-9a-f]{64}$/.test(file.sha256) || !components.has(file.component) || this.files.has(file.path)) throw failure('invalid', 'invalid or duplicate primary-source file binding');
			this.files.set(file.path, {path:file.path, sha256:file.sha256, component:components.get(file.component)});
		}
	}
	resolve(resource) {
		const binding = this.files.get(resource);
		if (!binding) throw failure('no-data', `no verified primary-source mapping for ${resource}`);
		return binding;
	}
}

function cleanPath(value) { return typeof value === 'string' && path.isAbsolute(value) && path.normalize(value) === value && !value.includes('\\') && !value.includes('\0'); }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function failure(status, message) { return Object.assign(new Error(`ContextOriginals: ${message}`), {status}); }
module.exports = ContextOriginals;
