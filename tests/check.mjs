import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const viewDir = path.join(root, 'luci-app-passwall/htdocs/luci-static/resources/view/passwall');
let failed = 0;

function fail(message) {
	failed += 1;
	console.error('FAIL ' + message);
}

function walk(dir, out) {
	for (const name of fs.readdirSync(dir)) {
		const full = path.join(dir, name);
		const stat = fs.statSync(full);
		if (stat.isDirectory())
			walk(full, out);
		else
			out.push(full);
	}
	return out;
}

const jsFiles = walk(viewDir, []).filter((file) => file.endsWith('.js'));
for (const file of jsFiles) {
	const src = fs.readFileSync(file, 'utf8');
	try {
		new Function(src);
	}
	catch (err) {
		fail(path.relative(root, file) + ': ' + err.message);
	}
}

for (const gone of ['Sortable.min.js', 'func.js', 'cbi.js', 'qrcode.min.js']) {
	if (fs.existsSync(path.join(viewDir, gone)))
		fail(gone + ' is still packaged');
}

const ucodeDir = path.join(root, 'luci-app-passwall/root/usr/share/ucode/passwall');
const readUc = (name) => fs.readFileSync(path.join(ucodeDir, name), 'utf8');
const invokes = (text, bin) => text.includes("['" + bin + "'") || text.includes('["' + bin + '"');
const utilsSrc = readUc('utils.uc');
const apiSrc = readUc('api.uc');
const nftSrc = readUc('nftables.uc');
if (invokes(utilsSrc, 'netstat') || invokes(apiSrc, 'netstat'))
	fail('port checks still call netstat');
if (invokes(utilsSrc, 'route') || invokes(apiSrc, 'route'))
	fail('host routes still call the route command');
if (invokes(nftSrc, 'ubus') || invokes(apiSrc, 'ubus'))
	fail('nftables or api still shells out to the ubus command');
if ((utilsSrc.match(/\[\s*'ubus'/g) || []).length !== 1)
	fail('ubus CLI fallback should stay in ubus_call');
if (invokes(utilsSrc, 'ss') || invokes(apiSrc, 'ss'))
	fail('port checks still call ss');
if (!apiSrc.includes('/proc/net/tcp') || !apiSrc.includes('uci_show'))
	fail('api should read /proc/net and export uci_show');
const showCallers = readUc('helper_dnsmasq.uc') + readUc('util_xray.uc') + readUc('util_singbox.uc');
if (showCallers.includes('uci show'))
	fail('domain lists still shell out to uci show');
if (apiSrc.includes('command -v') || apiSrc.includes('md5sum ') || apiSrc.includes('rm -rf'))
	fail('api still shells out for command lookup, md5, or rm');
for (const name of fs.readdirSync(ucodeDir)) {
	if (!name.endsWith('.uc'))
		continue;
	const text = fs.readFileSync(path.join(ucodeDir, name), 'utf8');
	if (text.includes('busybox pgrep') || text.includes('busybox top'))
		fail(name + ' still shells out to busybox process listing');
}

const toolsSrc = fs.readFileSync(path.join(viewDir, 'tools.js'), 'utf8');
const parseMatch = toolsSrc.match(/function parseRuntime\(text\) \{[\s\S]*?\n\}\n\/\* parseRuntime:end \*\//);
if (!parseMatch)
	fail('parseRuntime was not found in tools.js');
const parseRuntime = parseMatch ? new Function(`${parseMatch[0]}\nreturn parseRuntime;`)() : () => ({});

function same(actual, expected, label) {
	const a = JSON.stringify(actual);
	const b = JSON.stringify(expected);
	if (a !== b)
		fail(label + ' => ' + a + ' expected ' + b);
}

same(parseRuntime(''), {}, 'empty');
same(parseRuntime("FOO='bar'\nBAZ=0\n"), { FOO: 'bar', BAZ: '0' }, 'legacy');
same(parseRuntime("Q='a'\\''b'\n"), { Q: "a'b" }, 'legacy quote');
same(parseRuntime('{"FOO":"bar","N":"0","skip":""}\n'), { FOO: 'bar', N: '0', skip: '' }, 'json');
same(parseRuntime('{not json'), {}, 'broken json');
same(parseRuntime('{"bad-key":"x","OK":"y"}'), { OK: 'y' }, 'json key');
same(parseRuntime('{"FOO":"old"}\nFOO=\'new\'\nBAR=1\n'), { FOO: 'new', BAR: '1' }, 'mixed');
same(parseRuntime("{not json\nMODE='direct'\n"), { MODE: 'direct' }, 'truncated json');

class Node {
	constructor(selector, top) {
		this.nodeType = 1;
		this.parentNode = null;
		this.nextSibling = null;
		this.selector = selector;
		this.top = top;
		this.listeners = {};
		this.classes = new Set();
		this.classList = {
			add: (name) => this.classes.add(name),
			remove: (name) => this.classes.delete(name)
		};
	}
	get firstChild() {
		return this.first || null;
	}
	get firstElementChild() {
		return this.first || null;
	}
	get nextElementSibling() {
		return this.nextSibling;
	}
	matches(selector) {
		return this.selector === selector;
	}
	closest() {
		return null;
	}
	addEventListener(type, fn) {
		this.listeners[type] = fn;
	}
	removeEventListener() {}
	getBoundingClientRect() {
		return { top: this.top, height: 20 };
	}
	insertBefore(node, ref) {
		const kids = this.children();
		const next = kids.filter((child) => child !== node);
		const at = ref == null ? next.length : next.indexOf(ref);
		next.splice(at < 0 ? next.length : at, 0, node);
		this.link(next);
	}
	children() {
		const out = [];
		for (let child = this.first; child; child = child.nextSibling)
			out.push(child);
		return out;
	}
	link(kids) {
		this.first = kids[0] || null;
		kids.forEach((child, index) => {
			child.parentNode = this;
			child.nextSibling = kids[index + 1] || null;
		});
	}
}

const host = new Node(null, 0);
const rows = [0, 1, 2].map((index) => new Node('tr.cbi-section-table-row', index * 20));
host.link(rows);
const calls = [];
globalThis.document = {
	point: null,
	addEventListener(type, fn) { this[type] = fn; },
	removeEventListener() {},
	elementFromPoint() { return this.point; }
};
globalThis.window = globalThis;
new Function(fs.readFileSync(path.join(viewDir, 'sortable.js'), 'utf8'))();
const sortable = window.Sortable.create(host, {
	handle: '.drag-handle',
	draggable: 'tr.cbi-section-table-row',
	onEnd() { calls.push(host.children().map((row) => row.top)); }
});
const handle = { nodeType: 1, parentNode: rows[0], closest: () => handle };
host.listeners.pointerdown({ button: 0, target: handle, cancelable: true, preventDefault() {} });
document.point = rows[2];
document.pointermove({ clientY: 51 });
document.pointerup();
sortable.destroy();
same(calls, [[20, 40, 0]], 'drag first row after the last row');

const api = fs.readFileSync(path.join(root, 'luci-app-passwall/root/usr/share/ucode/passwall/api.uc'), 'utf8');
if (api.includes('echo -n $(cat /proc/sys/kernel/random/uuid)'))
	fail('uuid still shells out to cat');
if (!api.includes('/proc/sys/kernel/random/uuid'))
	fail('uuid reader missing');
if (api.includes('echo -n $(wg genkey)'))
	fail('wireguard key still uses echo substitution');
for (const file of walk(viewDir, [])) {
	if (!file.endsWith('.js'))
		continue;
	const text = fs.readFileSync(file, 'utf8');
	if (text.includes('<font') || text.includes('color: red') || text.includes('color:red'))
		fail(path.relative(root, file) + ' still has a hardcoded red font');
}

if (failed) {
	console.error(failed + ' check(s) failed');
	process.exit(1);
}
console.log('checked ' + jsFiles.length + ' scripts');
