import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkgDir = path.join(root, 'luci-app-passwall');
const pkgName = 'luci-app-passwall';
const pkgVer = '26.10.25-r4';
const outDir = path.join(root, 'dist');
const outFile = path.join(outDir, `${pkgName}_${pkgVer}_all.apk`);

const depends = [
	'chinadns-ng',
	'coreutils',
	'coreutils-base64',
	'coreutils-timeout',
	'curl',
	'dns2socks',
	'dnsmasq-full',
	'firewall4',
	'ip-full',
	'libc',
	'luci-base',
	'luci-lib-uqr',
	'microsocks',
	'resolveip',
	'tcping',
	'ucode',
	'ucode-mod-digest',
	'ucode-mod-fs',
	'ucode-mod-math',
	'ucode-mod-ubus',
	'ucode-mod-uci'
];

const INT = 0x10000000;
const INT32 = 0x20000000;
const BLOB8 = 0x80000000;
const BLOB16 = 0x90000000;
const OBJECT = 0xe0000000;

class Writer {
	constructor() {
		this.buf = Buffer.alloc(65536);
		this.len = 8;
	}
	ensure(extra) {
		while (this.len + extra > this.buf.length) {
			const next = Buffer.alloc(this.buf.length * 2);
			this.buf.copy(next);
			this.buf = next;
		}
	}
	align(n) {
		while (this.len % n !== 0) {
			this.ensure(1);
			this.buf[this.len++] = 0;
		}
	}
	blob(value) {
		const data = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
		if (data.length < 256) {
			const off = this.len;
			this.ensure(1 + data.length);
			this.buf[this.len++] = data.length;
			data.copy(this.buf, this.len);
			this.len += data.length;
			return (BLOB8 | off) >>> 0;
		}
		this.align(2);
		const off = this.len;
		this.ensure(2 + data.length);
		this.buf.writeUInt16LE(data.length, this.len);
		this.len += 2;
		data.copy(this.buf, this.len);
		this.len += data.length;
		return (BLOB16 | off) >>> 0;
	}
	int(value) {
		if (value < 0 || value > 0xffffffff)
			throw new Error(`int out of range: ${value}`);
		if (value <= 0x0fffffff)
			return (INT | value) >>> 0;
		this.align(4);
		const off = this.len;
		this.ensure(4);
		this.buf.writeUInt32LE(value, this.len);
		this.len += 4;
		return (INT32 | off) >>> 0;
	}
	obj(slots) {
		let n = slots.length;
		while (n > 0 && slots[n - 1] === 0)
			n--;
		this.align(4);
		const off = this.len;
		this.ensure(4 * (n + 1));
		this.buf.writeUInt32LE(n + 1, this.len);
		this.len += 4;
		for (let i = 0; i < n; i++) {
			this.buf.writeUInt32LE((slots[i] || 0) >>> 0, this.len);
			this.len += 4;
		}
		return (OBJECT | off) >>> 0;
	}
	payload() {
		return this.buf.subarray(0, this.len);
	}
}

function walk(dir, prefix, files) {
	for (const name of fs.readdirSync(dir).sort()) {
		const absolute = path.join(dir, name);
		const relative = prefix ? `${prefix}/${name}` : name;
		const stat = fs.lstatSync(absolute);
		if (stat.isDirectory())
			walk(absolute, relative, files);
		else if (stat.isFile())
			files.push({ name: relative.replace(/\\/g, '/'), data: fs.readFileSync(absolute) });
		else
			throw new Error(`unsupported file: ${absolute}`);
	}
}

function modeFor(name, data) {
	const head = data.subarray(0, 64).toString('utf8');
	if (head.startsWith('#!') || name.startsWith('etc/init.d/') || name.startsWith('etc/uci-defaults/') || name.startsWith('usr/libexec/'))
		return 0o755;
	return 0o644;
}

function script(body) {
	return Buffer.from(`#!/bin/sh\n${body.replace(/\n+$/, '')}\n`, 'utf8');
}

const postBody = `[ "\${IPKG_NO_SCRIPT}" = "1" ] && exit 0
[ -s \${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. \${IPKG_INSTROOT}/lib/functions.sh
export root="\${IPKG_INSTROOT}"
export pkgname="${pkgName}"
add_group_and_user
default_postinst
rm -f \${IPKG_INSTROOT}/usr/share/passwall/rules/*.nft
rm -rf \${IPKG_INSTROOT}/tmp/etc/passwall_tmp
[ -n "\${IPKG_INSTROOT}" ] || {
	rm -f /tmp/luci-indexcache /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	/etc/init.d/rpcd reload >/dev/null 2>&1 || true
}
exit 0
`;

const files = [];
walk(path.join(pkgDir, 'htdocs'), 'www', files);
walk(path.join(pkgDir, 'root'), '', files);
const listed = files.map((file) => `/${file.name}`).sort();
const listText = Buffer.from(`${listed.join('\n')}\n`, 'utf8');
const confLines = [
	'/etc/config/passwall',
	'/etc/config/passwall_server',
	'/etc/passwall/'
];
const staticLines = [];
for (const conf of confLines) {
	const name = conf.replace(/^\//, '').replace(/\/$/, '');
	const found = files.find((file) => file.name === name);
	if (!found)
		continue;
	staticLines.push(`${conf.replace(/\/$/, '')} ${crypto.createHash('sha256').update(found.data).digest('hex')}`);
}
files.push({ name: `lib/apk/packages/${pkgName}.list`, data: listText });
files.push({ name: `lib/apk/packages/${pkgName}.conffiles`, data: Buffer.from(`${confLines.join('\n')}\n`, 'utf8') });
if (staticLines.length)
	files.push({ name: `lib/apk/packages/${pkgName}.conffiles_static`, data: Buffer.from(`${staticLines.join('\n')}\n`, 'utf8') });

const dirs = new Map();
function dir(name) {
	if (!dirs.has(name))
		dirs.set(name, []);
	return dirs.get(name);
}
dir('');
for (const file of files) {
	const slash = file.name.lastIndexOf('/');
	const folder = slash < 0 ? '' : file.name.slice(0, slash);
	const base = slash < 0 ? file.name : file.name.slice(slash + 1);
	const parts = folder ? folder.split('/') : [];
	let current = '';
	dir(current);
	for (const part of parts) {
		current = current ? `${current}/${part}` : part;
		dir(current);
	}
	dir(folder).push({
		base,
		data: file.data,
		mode: modeFor(file.name, file.data),
		hash: crypto.createHash('sha256').update(file.data).digest()
	});
}
for (const list of dirs.values())
	list.sort((a, b) => (a.base < b.base ? -1 : a.base > b.base ? 1 : 0));
const dirNames = [...dirs.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

const w = new Writer();
const rootBlob = w.blob('root');
function acl(mode) {
	return w.obj([(INT | mode) >>> 0, rootBlob, rootBlob]);
}
const acl755 = acl(0o755);
const aclByMode = new Map([[0o755, acl755]]);
function aclFor(mode) {
	if (!aclByMode.has(mode))
		aclByMode.set(mode, acl(mode));
	return aclByMode.get(mode);
}

const dataPlan = [];
const pathSlots = dirNames.map((folder, index) => {
	const pathIdx = index + 1;
	const fileSlots = dirs.get(folder).map((file, fileIndex) => {
		const fileIdx = fileIndex + 1;
		if (file.data.length)
			dataPlan.push({ pathIdx, fileIdx, data: file.data });
		return w.obj([
			w.blob(file.base),
			aclFor(file.mode),
			w.int(file.data.length),
			w.int(0),
			w.blob(file.hash)
		]);
	});
	const filesObj = w.obj(fileSlots);
	return w.obj([
		w.blob(folder),
		acl755,
		filesObj
	]);
});

const depSlots = depends.map((name) => w.obj([w.blob(name)]));
const provideSlots = [w.obj([w.blob(`${pkgName}-any`)])];
const hashOff = (() => {
	const off = w.len;
	w.ensure(21);
	w.buf[w.len++] = 20;
	w.buf.fill(0, w.len, w.len + 20);
	w.len += 20;
	return off;
})();
const installed = files.reduce((sum, file) => sum + file.data.length, 0) || 1;
const info = w.obj([
	w.blob(pkgName),
	w.blob(pkgVer),
	(BLOB8 | hashOff) >>> 0,
	w.blob('LuCI support for PassWall'),
	w.blob('noarch'),
	w.blob('GPL-3.0-only'),
	w.blob(pkgName),
	w.blob('Openwrt-Passwall Organization'),
	w.blob('https://github.com/Openwrt-Passwall/openwrt-passwall'),
	0,
	w.int(Math.floor(Date.now() / 1000)),
	w.int(installed),
	0,
	0,
	w.obj(depSlots),
	w.obj(provideSlots)
]);
const scripts = w.obj([
	0,
	0,
	w.blob(script(postBody)),
	w.blob(script(`[ -s \${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. \${IPKG_INSTROOT}/lib/functions.sh
export root="\${IPKG_INSTROOT}"
export pkgname="${pkgName}"
default_prerm
exit 0
`)),
	w.blob(script(`rm -f \${IPKG_INSTROOT}/usr/share/passwall/rules/*.nft
rm -rf \${IPKG_INSTROOT}/tmp/etc/passwall_tmp
exit 0
`)),
	0,
	w.blob(script(`export PKG_UPGRADE=1\n${postBody}`))
]);
const packageObj = w.obj([
	info,
	w.obj(pathSlots),
	scripts
]);
w.buf.writeUInt32LE(packageObj, 4);
const payload = Buffer.from(w.payload());
const digest = crypto.createHash('sha256').update(payload).digest();
digest.copy(payload, (hashOff & 0x0fffffff) + 1, 0, 20);

function block(type, body) {
	const raw = 4 + body.length;
	const padded = (raw + 7) & ~7;
	const out = Buffer.alloc(padded);
	out.writeUInt32LE(((type * 0x40000000) + raw) >>> 0, 0);
	body.copy(out, 4);
	return out;
}

const dataBlocks = dataPlan.map((item) => {
	const hdr = Buffer.alloc(8);
	hdr.writeUInt32LE(item.pathIdx, 0);
	hdr.writeUInt32LE(item.fileIdx, 4);
	return block(2, Buffer.concat([hdr, item.data]));
});
const plain = Buffer.concat([
	Buffer.from('ADB.pckg'),
	block(0, payload),
	...dataBlocks
]);
const packed = Buffer.concat([
	Buffer.from('ADBd'),
	zlib.deflateRawSync(plain, { level: 9 })
]);
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(outFile, packed);
console.log(outFile);
console.log(`files ${files.length} dirs ${dirNames.length} data ${dataPlan.length}`);
console.log(`size ${packed.length}`);
console.log(`sha256 ${crypto.createHash('sha256').update(packed).digest('hex')}`);
