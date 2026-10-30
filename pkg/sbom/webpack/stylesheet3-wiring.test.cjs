'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { before, after, test } = require('node:test');

const { available, area, build, STYLESHEET } = require('./stylesheet3-wiring-fixture.cjs');

const SKIP = available();
const TAIL_SKIP = SKIP || (process.env.DK_ESBUILD_SOURCE ? false : 'DK_ESBUILD_SOURCE is not set to the instrumented esbuild');

let scratch;

before(() => {
	if (SKIP) return;
	scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dk-stylesheet3-wiring-')));
});

after(() => scratch && fs.rmSync(scratch, { recursive: true, force: true }));

function assetOf(report) {
	const row = report.proof.assets.find((asset) => asset.path === 'main.js');
	assert.ok(row, report.proof.assets.map((asset) => asset.path).join(', '));
	return row;
}

// A chain carrying css-loader is the style-loader 3 pair: both of its modules
// have to reach that adapter, and the one for the older chain must not claim
// them.
test('describes a build whose stylesheet goes through style-loader 3', { skip: SKIP }, () => {
	const result = build(area(scratch, 'plain'));
	assert.ok(!result.report.error, result.report.error);
	const row = assetOf(result.report);
	assert.equal(row.status, 'present', row.reason);
	const claimed = row.inputs.map((input) => path.basename(input.path));
	// The stylesheet itself, the two loaders that rewrote it, and the runtime
	// helpers they wrote requests for.
	for (const file of ['styles.css', 'index.js', 'injectStylesIntoStyleTag.js', 'styleDomAPI.js', 'api.js']) {
		assert.ok(claimed.includes(file), `${file} is not claimed: ${claimed.join(', ')}`);
	}
	// The stylesheet really is in the bundle, as css-loader wrote it.
	assert.ok(result.report.bundle.includes(STYLESHEET.split('\n')[1].trim()), 'the stylesheet is not in the bundle');
});

// Redoc's chain: esbuild minifies the stylesheet before css-loader reads it, so
// what the css module contributes is what the tail the collector handed the
// adapter observed that transform consume.
test('describes a stylesheet minified by an esbuild tail', { skip: TAIL_SKIP }, () => {
	const result = build(area(scratch, 'esbuild-tail'), { tail: 'esbuild' });
	assert.ok(!result.report.error, result.report.error);
	const row = assetOf(result.report);
	assert.equal(row.status, 'present', row.reason);
	const claimed = row.inputs.map((input) => path.basename(input.path));
	for (const file of ['styles.css', 'injectStylesIntoStyleTag.js', 'api.js']) {
		assert.ok(claimed.includes(file), `${file} is not claimed: ${claimed.join(', ')}`);
	}
	// The stylesheet in the bundle is the minified one, not the file on disk.
	assert.ok(result.report.bundle.includes('.ps{'), 'the stylesheet was not minified');
	assert.ok(!result.report.bundle.includes('overflow: hidden !important'), 'the unminified stylesheet stands in the bundle');
});
