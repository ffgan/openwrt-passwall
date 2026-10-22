import fs from 'fs';
import vm from 'vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const src = fs.readFileSync(
	new URL('../luci-app-passwall/htdocs/luci-static/resources/view/passwall/tools.js', import.meta.url),
	'utf8'
);
const match = src.match(/function parseRuntime\(text\) \{[\s\S]*?\n\}\n\/\* parseRuntime:end \*\//);
if (!match)
	throw new Error('parseRuntime was not found in tools.js');
const parseRuntime = vm.runInNewContext(`${match[0]}\nparseRuntime`);

test('reads the legacy shell cache', () => {
	const map = parseRuntime("ENABLED_DEFAULT_ACL='1'\nNODE='a'\\''b'\nEMPTY=\n");
	assert.equal(map.ENABLED_DEFAULT_ACL, '1');
	assert.equal(map.NODE, "a'b");
	assert.equal(map.EMPTY, '');
});

test('reads the JSON runtime cache', () => {
	const map = parseRuntime('{ "ENABLED_DEFAULT_ACL": "1", "NODE": "a\'b", "n": 2 }\n');
	assert.equal(map.ENABLED_DEFAULT_ACL, '1');
	assert.equal(map.NODE, "a'b");
	assert.equal(map.n, '2');
});

test('falls back when the JSON is truncated', () => {
	const map = parseRuntime("{not json\nMODE='direct'\n");
	assert.equal(map.MODE, 'direct');
});

test('returns an empty map for an empty file', () => {
	assert.equal(JSON.stringify(parseRuntime('')), '{}');
	assert.equal(JSON.stringify(parseRuntime('   \n')), '{}');
});
