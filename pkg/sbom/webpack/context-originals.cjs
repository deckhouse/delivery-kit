'use strict';

const fs = require('node:fs');
const path = require('node:path');

// The immutable manifest is written only after DK verifies scoped PM originals.
// This reader does not infer an owner or treat a component dictionary as presence.
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
		if (Object.keys(manifest).some(key => !['version','components','files'].includes(key))) throw failure('invalid', 'unknown primary-source manifest field');
		if (!Array.isArray(manifest.components) || !Array.isArray(manifest.files)) throw failure('invalid', 'primary-source manifest requires component and file arrays');
		const components = new Map();
		for (const component of manifest.components) {
			if (!object(component) || typeof component.id !== 'string' || !component.id || components.has(component.id) || component.source?.kind !== 'pm') throw failure('invalid', 'invalid or duplicate primary-source component');
			components.set(component.id, component);
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
