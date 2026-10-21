'use strict';

// ucode port of the passwall API. LuCI CBI helpers are not included.

import { readfile, writefile, stat, unlink, mkdir, lsdir, popen, error, open, access, chmod, dirname } from 'fs';
import { cursor } from 'uci';
import { md5 } from 'digest';
import * as com from 'passwall.com';
let isset, ifnil, translate, translatef, as_str, comp, read_all, rand_int, shellquote, trim, index_from, split, sys_call, sys_exec, nixio_type, fs_stat, perm_has, fs_access, mkdir_p, fs_dir, wrap_uci, log, is_old_uci, resolve_sid, uci_del, uci_get, uci_set, uci_del_c, uci_foreach_c, uci_get_c, uci_set_c, uci_save_c, uci_del_s, uci_foreach_s, uci_get_s, uci_set_s, uci_save_s, sh_uci_commit, uci_save, sh_uci_get, sh_uci_set, sh_uci_del, sh_uci_add_list, del_cache_var, set_cache_var, get_cache_var, get_new_port, exec_call, has_bin, ffi_can_setgid, exec_call_as_gid, strip_controls, strip_nul, base64Decode, base64Encode, UrlEncode, UrlDecode, md5_file, md5_string, ip4addr, ip6_side, ip6addr, ipaddr, dt_port, mac_groups, macaddr, hostname, ip4prefix, ip6prefix, ipmask4, ipmask6, ip4addrport, ip6addrport, ipaddrport, hostport, is_json, is_timehhmm, is_uuid, get_domain_port_from_url, parse_dns_server, resolve_domain, table_join, curl_base, curl_proxy, curl_direct, curl_logic, curl_auto, is_exist, repeat_exist, remove, is_install, get_args, get_function_args, strToTable, is_normal_node, is_special_node, is_ip, is_ipv6, is_local_ip, is_ipv6addrport, get_ipv6_only, get_ipv6_full, get_ip_type, is_mac, ip_or_mac, iprange, get_domain_from_url, core_protocol_name, is_special_protocol, node_base_type, get_valid_nodes, get_node_list, get_node_remarks, get_full_node_remarks, get_random_normal_node, gen_uuid, gen_random_char, chmod_755, get_customed_path, get_app_path, get_bin_version_cache, get_app_version, finded_com, finded, is_finded, clone, is_reg, is_dir, get_final_dir, get_free_space, get_file_space, _unpack, exec_argv, version_part, compare_versions, release_value, auto_get_arch, parseURL, parseDoH, re_escape_char, lua_pattern_regexp, get_api_json, check_path, unwrap_release, strip_v_run, to_check, to_download, to_download_progress, to_extract, to_move, get_version, to_check_self, to_install_self, get_std_domain, format_go_time, match_cond, split_nonempty, match_node_rule, match_tokens, get_batch_nodes, get_socks_backup_nodes, get_core, cleanEmptyTables, fetch_cert_sha256, sha256_xray_sb, sha256_sb_xray, vps_domain_exclude, parse_realm_uri, get_network_devices, table_remove_duplicates, gen_wireguard_key, get_socks_port_by_cache, set_socks_port_to_cache;

export let appname = "passwall";
export let c_config = "passwall";
export let s_config = "passwall_server";

export let curl_args = ["-skfL", "--connect-timeout 3", "--retry 3", "-H 'Accept: */*'"];
export let command_timeout = 300;
export let DIRECT_GID = 9911;
export let OPENWRT_ARCH = null;
export let DISTRIB_ARCH = null;
export let OPENWRT_BOARD = null;

export let LOCK_PREFIX = "/var/lock/" + c_config;
export let LOG_FILE = "/tmp/log/" + c_config + ".log";
export let TMP_PATH = "/tmp/etc/" + c_config;
export let CACHE_PATH = TMP_PATH + "_tmp";
export let S_TMP_PATH = "/tmp/etc/" + s_config;
export let TMP_IFACE_PATH = TMP_PATH + "/iface";

let normal_nodes = [];
let bin_cache = {};
let ffi_gid_ok = null;

isset = function(v) {
	// ucode == coerces, so "0", "" and NUL strings compare equal to false.
	return v !== null && v !== false;
};

// Lua `or`: only nil and false fall through. "" and 0 do not.
ifnil = function(v, d) {
	if (v === null || v === false)
		return d;
	return v;
};

translate = function(msg) {
	if (!isset(msg))
		return "";
	return "" + msg;
};

translatef = function(fmt, ...args) {
	fmt = translate(fmt);
	if (length(args) == 0)
		return fmt;
	return sprintf(fmt, ...args);
};

as_str = function(v) {
	if (type(v) == "string")
		return v;
	if (type(v) == "int" || type(v) == "double")
		return "" + v;
	return null;
};

comp = function(name) {
	if (com.index != null && com.index[name] != null)
		return com.index[name];
	if (com[name] != null)
		return com[name];
	return null;
};

read_all = function(p) {
	let out = "";
	if (p == null)
		return out;
	let chunk = p.read(4096);
	while (chunk != null && chunk != "") {
		out += chunk;
		chunk = p.read(4096);
	}
	return out;
};

rand_int = function(a, b) {
	if (b == null) {
		b = a;
		a = 0;
	}
	if (a > b) {
		let t = a;
		a = b;
		b = t;
	}
	let span = b - a + 1;
	if (span <= 1)
		return a;
	let fd = open("/dev/urandom", "r");
	let n = null;
	if (fd != null) {
		let buf = fd.read(4);
		fd.close();
		if (type(buf) == "string" && length(buf) >= 4) {
			n = 0;
			for (let i = 0; i < 4; i++)
				n = n * 256 + ord(buf, i);
			if (n < 0)
				n = -n;
		}
	}
	if (n == null)
		n = time();
	return a + (n % span);
};

shellquote = function(s) {
	if (s === null || s === false)
		s = "";
	else
		s = "" + s;
	return "'" + replace(s, "'", "'\\''") + "'";
};

trim = function(s) {
	if (type(s) != "string")
		return "";
	let i = 0;
	let j = length(s) - 1;
	while (i <= j && ord(s, i) <= 32)
		i++;
	while (j >= i && ord(s, j) <= 32)
		j--;
	if (i > j)
		return "";
	return substr(s, i, j - i + 1);
};

// ucode index() does not take a start offset. Search from `off` by slicing.
index_from = function(s, needle, off) {
	if (type(s) != "string") {
		if (s == null)
			return -1;
		s = "" + s;
	}
	if (off == null || off <= 0)
		return index(s, needle);
	if (off >= length(s))
		return -1;
	let n = index(substr(s, off), needle);
	if (n < 0)
		return -1;
	return n + off;
};

// Literal split. Drops a trailing empty field, keeps empty fields in the middle, strips NUL.
split = function(full, sep) {
	if (!isset(full))
		return [];
	if (type(full) != "string")
		full = "" + full;
	if (index(full, "\0") >= 0) {
		let cleaned = "";
		for (let i = 0; i < length(full); i++) {
			if (ord(full, i) != 0)
				cleaned += substr(full, i, 1);
		}
		full = cleaned;
	}
	if (sep == null)
		sep = "";
	sep = "" + sep;
	if (sep == "")
		return global.split(full, "");
	let result = [];
	let off = 0;
	let seplen = length(sep);
	while (true) {
		let nstart = index_from(full, sep, off);
		if (nstart < 0) {
			let res = substr(full, off);
			if (length(res) > 0)
				push(result, res);
			break;
		}
		push(result, substr(full, off, nstart - off));
		off = nstart + seplen;
	}
	return result;
};

sys_call = function(cmd) {
	let p = popen(cmd, "r");
	if (p == null)
		return 127;
	read_all(p);
	let rc = p.close();
	if (rc == null)
		return 127;
	return rc;
};

sys_exec = function(cmd) {
	let p = popen(cmd, "r");
	if (p == null)
		return "";
	let out = read_all(p);
	p.close();
	if (out == null)
		return "";
	return out;
};

export const sys = {
	call: sys_call,
	exec: sys_exec
};

nixio_type = function(t) {
	if (t == "file")
		return "reg";
	if (t == "directory")
		return "dir";
	if (t == "link" || t == "symlink")
		return "lnk";
	if (t == "socket")
		return "sock";
	if (t == "fifo")
		return "fifo";
	if (t == "char")
		return "chr";
	if (t == "block")
		return "blk";
	return t;
};

fs_stat = function(path, field) {
	if (type(path) != "string" || path == "")
		return null;
	let st = stat(path);
	if (st == null)
		return null;
	let kind = nixio_type(st.type);
	if (field == "type")
		return kind;
	if (field == "size")
		return st.size;
	if (field == "mtime")
		return st.mtime;
	if (field == "ctime")
		return st.ctime;
	if (field == "atime")
		return st.atime;
	if (field == "ino" || field == "inode")
		return st.inode;
	if (field == "mode")
		return st.mode;
	if (field == "uid")
		return st.uid;
	if (field == "gid")
		return st.gid;
	return {
		dev: st.dev,
		ino: st.inode,
		inode: st.inode,
		mode: st.mode,
		size: st.size,
		mtime: st.mtime,
		ctime: st.ctime,
		atime: st.atime,
		uid: st.uid,
		gid: st.gid,
		nlink: st.nlink,
		perm: st.perm,
		type: kind
	};
};

perm_has = function(st, owner, group, other) {
	if (st == null || st.perm == null)
		return false;
	let rows = [
		[owner, "user_read", "user_write", "user_exec"],
		[group, "group_read", "group_write", "group_exec"],
		[other, "other_read", "other_write", "other_exec"]
	];
	let letters = ["r", "w", "x"];
	for (let row in rows) {
		let want = row[0] ?? "";
		for (let i = 0; i < 3; i++) {
			if (index(want, letters[i]) >= 0 && !st.perm[row[i + 1]])
				return false;
		}
	}
	return true;
};

fs_access = function(path, ...modes) {
	if (type(path) != "string" || path == "")
		return false;
	if (length(modes) >= 3 && type(modes[0]) == "string") {
		let st = stat(path);
		return perm_has(st, modes[0], modes[1], modes[2]);
	}
	let mode = "f";
	if (length(modes) > 0 && type(modes[0]) == "string" && modes[0] != "")
		mode = modes[0];
	return access(path, mode) == true;
};

mkdir_p = function(path) {
	if (path == null || path == "" || path == "/")
		return true;
	if (stat(path) != null)
		return true;
	mkdir_p(dirname(path));
	if (mkdir(path) == true)
		return true;
	return stat(path) != null;
};

fs_dir = function(path) {
	let names = lsdir(path);
	if (names == null)
		return [];
	let out = [];
	for (let name in names) {
		if (name != "." && name != "..")
			push(out, name);
	}
	return out;
};

export const fs = {
	readfile: function(path) { return readfile(path); },
	writefile: function(path, data) { return writefile(path, data); },
	access: fs_access,
	stat: fs_stat,
	unlink: function(path) { return unlink(path); },
	remove: function(path) { return unlink(path); },
	mkdir: function(path) { return mkdir(path); },
	mkdirr: mkdir_p,
	lsdir: fs_dir,
	dir: fs_dir,
	chmod: function(path, mode) { return chmod(path, mode); },
	dirname: function(path) { return dirname(path); }
};

// ucode's uci cursor is a resource. Properties cannot be added to it, and a
// method copied off the resource loses its receiver, so calls go through cur[name].
wrap_uci = function(cur) {
	let call = function(name) {
		return function(...args) {
			return cur[name](...args);
		};
	};
	return {
		get: call("get"),
		get_all: call("get_all"),
		set: call("set"),
		add: call("add"),
		delete: call("delete"),
		foreach: call("foreach"),
		revert: call("revert"),
		commit: call("commit"),
		save: call("save"),
		add_list: call("add_list"),
		del_list: call("del_list"),
		rename: call("rename"),
		reorder: call("reorder"),
		changes: call("changes"),
		unload: call("unload"),
		section: function(config, stype, name) {
			if (isset(name) && ("" + name) != "") {
				cur.set(config, name, stype);
				return name;
			}
			return cur.add(config, stype);
		}
	};
};

export let uci = wrap_uci(cursor());

log = function(...args) {
	let t = localtime();
	let parts = [];
	for (let a in args) {
		if (a == null)
			push(parts, "");
		else
			push(parts, "" + a);
	}
	let line = sprintf("%04d-%02d-%02d %02d:%02d:%02d: ", t.year, t.mon, t.mday, t.hour, t.min, t.sec) + join(" ", parts);
	let fh = open(LOG_FILE, "a");
	if (fh != null) {
		fh.write(line + "\n");
		fh.close();
	}
};

// ucode's uci cursor matches current LuCI: commit goes through the uci CLI.
// The old Lua cursor's save()/commit() split is not used.
is_old_uci = function() {
	return false;
};

// libuci extended names such as @global[0]. Resolved here so every caller
// hits a real section id.
resolve_sid = function(config, section) {
	if (type(section) != "string")
		return section;
	let m = match(section, /^@([A-Za-z0-9_]+)\[(-?[0-9]+)\]$/);
	if (m == null)
		return section;
	let found = [];
	uci.foreach(config, m[1], function(s) {
		push(found, s[".name"]);
	});
	let idx = int(m[2]);
	if (idx < 0)
		idx = length(found) + idx;
	if (idx < 0 || idx >= length(found))
		return null;
	return found[idx];
};

uci_del = function(config, section, option) {
	section = resolve_sid(config, section);
	if (section == null)
		return null;
	if (isset(option))
		return uci.delete(config, section, option);
	return uci.delete(config, section);
};

uci_get = function(config, section, option) {
	if (!isset(section))
		return uci.get_all(config);
	section = resolve_sid(config, section);
	if (section == null)
		return null;
	if (isset(option))
		return uci.get(config, section, option);
	return uci.get_all(config, section);
};

uci_set = function(config, section, option, value) {
	section = resolve_sid(config, section);
	if (section == null)
		return null;
	if (type(value) == "int" || type(value) == "double")
		value = "" + value;
	if (type(value) == "array") {
		if (length(value) > 0) {
			if (isset(option))
				return uci.set(config, section, option, value);
			return uci.set(config, section, value);
		}
		return uci_del(config, section, option);
	}
	if (type(value) != "string") {
		if (!isset(value))
			return null;
		value = "" + value;
	}
	if (length(value) > 0) {
		if (isset(option))
			return uci.set(config, section, option, value);
		return uci.set(config, section, value);
	}
	return uci_del(config, section, option);
};

uci_del_c = function(section, option) {
	return uci_del(c_config, section, option);
};

uci_foreach_c = function(stype, func) {
	return uci.foreach(c_config, stype, func);
};

uci_get_c = function(section, option) {
	return uci_get(c_config, section, option);
};

uci_set_c = function(section, option, value) {
	return uci_set(c_config, section, option, value);
};

uci_save_c = function(commit_flag, apply) {
	return uci_save(uci, c_config, commit_flag, apply);
};

uci_del_s = function(section, option) {
	return uci_del(s_config, section, option);
};

uci_foreach_s = function(stype, func) {
	return uci.foreach(s_config, stype, func);
};

uci_get_s = function(section, option) {
	return uci_get(s_config, section, option);
};

uci_set_s = function(section, option, value) {
	return uci_set(s_config, section, option, value);
};

uci_save_s = function(commit_flag, apply) {
	return uci_save(uci, s_config, commit_flag, apply);
};

sh_uci_commit = function(config) {
	exec_call(sprintf("uci -q commit %s", config));
};

uci_save = function(cur, config, commit_flag, apply) {
	if (!isset(cur))
		cur = uci;
	if (is_old_uci()) {
		cur.save(config);
		if (commit_flag) {
			cur.commit(config);
			if (apply)
				sys_call("/etc/init.d/" + config + " reload > /dev/null 2>&1 &");
		}
	} else if (apply) {
		cur.commit(config);
	} else {
		/* 25.12 ucode uci keeps set() in the cursor until save(). A shell
		   `uci commit` only sees that delta, so write it first. */
		cur.save(config);
		sh_uci_commit(config);
	}
};

sh_uci_get = function(config, section, option) {
	let res = exec_call(sprintf("uci -q get %s.%s.%s", config, section, option));
	return res[1];
};

sh_uci_set = function(config, section, option, val, commit_flag) {
	exec_call(sprintf("uci -q set %s.%s.%s=\"%s\"", config, section, option, val));
	if (commit_flag)
		sh_uci_commit(config);
};

sh_uci_del = function(config, section, option, commit_flag) {
	exec_call(sprintf("uci -q delete %s.%s.%s", config, section, option));
	if (commit_flag)
		sh_uci_commit(config);
};

sh_uci_add_list = function(config, section, option, val, commit_flag) {
	exec_call(sprintf("uci -q del_list %s.%s.%s=\"%s\"", config, section, option, val));
	exec_call(sprintf("uci -q add_list %s.%s.%s=\"%s\"", config, section, option, val));
	if (commit_flag)
		sh_uci_commit(config);
};

// Lua sourced passwall2 here; the shell helpers live in passwall.
del_cache_var = function(key) {
	sys_call(". /usr/share/passwall/utils.sh ; del_cache_var " + shellquote("" + key));
};

set_cache_var = function(key, val) {
	sys_call(". /usr/share/passwall/utils.sh ; set_cache_var " + shellquote("" + key) + " " + shellquote("" + val));
};

get_cache_var = function(key) {
	let val = sys_exec(". /usr/share/passwall/utils.sh ; echo -n $(get_cache_var " + shellquote("" + key) + ")");
	if (val == null || val == "")
		return null;
	return val;
};

get_new_port = function(start_port, protocol) {
	if (!isset(start_port) || match(trim("" + start_port), /^-?[0-9]+$/) == null)
		start_port = "auto";
	else
		start_port = "" + int(start_port);
	if (protocol != "tcp" && protocol != "udp")
		protocol = "tcp,udp";
	let out = sys_exec(". /usr/share/passwall/utils.sh ; echo -n $(get_new_port " + shellquote("" + start_port) + " " + shellquote(protocol) + ")");
	let n = int(trim(out));
	if (n != n)
		return null;
	return n;
};

exec_call = function(cmd) {
	let tag = "\x01__RC__" + rand_int(100000, 999999) + "\x01";
	let wrapped = "(" + cmd + ") 2>&1; printf '\n" + tag + "%d' \"$?\"";
	let p = popen(wrapped, "r");
	if (p == null)
		return [255, ""];
	let out = read_all(p);
	p.close();
	let rc_re = regexp(tag + "([0-9]+)[[:space:]]*$");
	let m = match(out, rc_re);
	if (m == null)
		return [255, trim(out)];
	let rc = int(m[1]);
	let strip_re = regexp("\n?" + tag + "[0-9]+[[:space:]]*$");
	out = replace(out, strip_re, "");
	return [rc, trim(out)];
};

has_bin = function(name) {
	if (bin_cache[name] != null)
		return bin_cache[name];
	let p = popen("command -v " + shellquote(name) + " >/dev/null 2>&1", "r");
	if (p == null) {
		bin_cache[name] = false;
		return false;
	}
	read_all(p);
	let ok = p.close() == 0;
	bin_cache[name] = ok;
	return ok;
};

ffi_can_setgid = function() {
	if (ffi_gid_ok != null)
		return ffi_gid_ok;
	ffi_gid_ok = false;
	try {
		let ffi = require("ffi");
		let libc = null;
		try {
			libc = ffi.import("libc.so", "int setgid(int gid);");
		} catch (e) {}
		if (libc == null) {
			try {
				libc = ffi.import("libc.so.6", "int setgid(int gid);");
			} catch (e) {}
		}
		ffi_gid_ok = libc != null && type(libc.setgid) == "function";
	} catch (e) {
		ffi_gid_ok = false;
	}
	return ffi_gid_ok;
};

exec_call_as_gid = function(cmd, gid) {
	let g = int(gid);
	if (g != g)
		return [255, "invalid gid"];
	if (has_bin("setpriv"))
		return exec_call("setpriv --regid " + g + " --init-groups /bin/sh -c " + shellquote(cmd));
	if (has_bin("chpst"))
		return exec_call("chpst -u :" + g + " /bin/sh -c " + shellquote(cmd));
	if (has_bin("ucode") && ffi_can_setgid()) {
		let snippet = "'use strict';"
			+ "import { popen } from 'fs';"
			+ "let ffi = null; try { ffi = require('ffi'); } catch (e) { exit(1); }"
			+ "let libc = null;"
			+ "try { libc = ffi.import('libc.so', 'int setgid(int gid);'); } catch (e) {}"
			+ "if (libc == null) { try { libc = ffi.import('libc.so.6', 'int setgid(int gid);'); } catch (e) {} }"
			+ "let gid = int(getenv('PW_GID'));"
			+ "let command = getenv('PW_CMD');"
			+ "if (libc == null || libc.setgid(gid) != 0) exit(1);"
			+ "let ph = popen(command, 'r');"
			+ "if (ph == null) exit(127);"
			+ "let chunk = ph.read(4096);"
			+ "while (chunk != null && chunk != '') { print(chunk); chunk = ph.read(4096); }"
			+ "let rc = ph.close();"
			+ "if (rc == null) exit(255);"
			+ "exit(rc);";
		return exec_call("PW_GID=" + g + " PW_CMD=" + shellquote(cmd) + " ucode -e " + shellquote(snippet));
	}
	// No setgid helper on this system. The command still runs, without DIRECT_GID.
	return exec_call(cmd);
};

strip_controls = function(s) {
	let out = "";
	for (let i = 0; i < length(s); i++) {
		let c = ord(s, i);
		// Lua %c is 0-31 and DEL.
		if (c > 31 && c != 127)
			out += substr(s, i, 1);
	}
	return out;
};

strip_nul = function(s) {
	if (type(s) != "string" || index(s, "\0") < 0)
		return s ?? "";
	let out = "";
	for (let i = 0; i < length(s); i++) {
		if (ord(s, i) != 0)
			out += substr(s, i, 1);
	}
	return out;
};

base64Decode = function(text) {
	if (type(text) != "string")
		return "";
	let encoded = strip_controls(text);
	encoded = replace(encoded, "_", "/");
	encoded = replace(encoded, "-", "+");
	encoded = replace(encoded, /=+$/, "");
	if (encoded == "")
		return text;
	if (match(encoded, /^[A-Za-z0-9+/]*$/) == null)
		return text;
	let mod4 = length(encoded) % 4;
	if (mod4 == 1)
		return text;
	let pad = (4 - mod4) % 4;
	let padded = encoded;
	for (let i = 0; i < pad; i++)
		padded += "=";
	let result = b64dec(padded);
	if (type(result) != "string")
		return text;
	let reencoded = b64enc(result);
	if (type(reencoded) != "string")
		return text;
	reencoded = replace(reencoded, /=+$/, "");
	if (reencoded != encoded)
		return text;
	return strip_nul(result);
};

base64Encode = function(text) {
	if (text === null || text === false)
		return null;
	if (type(text) != "string")
		text = "" + text;
	return b64enc(text);
};

UrlEncode = function(szText) {
	if (type(szText) != "string")
		return "";
	return replace(szText, /[^A-Za-z0-9_.~-]/g, function(ch) {
		return sprintf("%%%02X", ord(ch));
	});
};

UrlDecode = function(szText) {
	if (type(szText) != "string")
		return "";
	let s = replace(szText, /\+/g, " ");
	return replace(s, /%([0-9A-Fa-f][0-9A-Fa-f])/g, function(all, h) {
		return chr(hex(h));
	});
};

md5_file = function(path) {
	if (type(path) != "string")
		return "";
	try {
		let d = require("digest");
		if (d != null && type(d.md5_file) == "function") {
			let h = d.md5_file(path);
			if (type(h) == "string" && length(h) >= 32)
				return substr(h, 0, 32);
		}
	} catch (e) {}
	let out = sys_exec("md5sum " + shellquote(path));
	if (out == null || out == "")
		return "";
	return substr(out, 0, 32);
};

md5_string = function(str) {
	if (type(str) != "string")
		return "";
	if (type(md5) == "function") {
		let h = md5(str);
		if (type(h) == "string" && length(h) >= 32)
			return substr(h, 0, 32);
	}
	let path = trim(sys_exec("mktemp /tmp/md5.XXXXXX"));
	if (path == "")
		return "";
	let n = writefile(path, str);
	let out = (n == length(str)) ? md5_file(path) : "";
	unlink(path);
	return out;
};

ip4addr = function(val) {
	let s = as_str(val);
	if (s == null)
		return false;
	let m = match(s, /^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$/);
	if (m == null)
		return false;
	for (let i = 1; i <= 4; i++) {
		if (length(m[i]) > 3)
			return false;
		let n = int(m[i]);
		if (n != n || n < 0 || n > 255)
			return false;
	}
	return true;
};

ip6_side = function(s, out) {
	if (s == "")
		return true;
	let i = 0;
	let n = length(s);
	while (i < n) {
		let j = i;
		while (j < n && substr(s, j, 1) != ":")
			j++;
		let tok = substr(s, i, j - i);
		if (tok == "")
			return false;
		if (index(tok, ".") >= 0) {
			if (j != n || !ip4addr(tok))
				return false;
			push(out, 1);
			push(out, 1);
		} else {
			if (length(tok) < 1 || length(tok) > 4)
				return false;
			if (match(tok, /^[0-9A-Fa-f]+$/) == null)
				return false;
			push(out, 1);
		}
		if (j >= n)
			break;
		i = j + 1;
		if (i >= n)
			return false;
	}
	return true;
};

ip6addr = function(val) {
	let s = as_str(val);
	if (s == null || s == "")
		return false;
	let pct = index(s, "%");
	if (pct >= 0)
		s = substr(s, 0, pct);
	if (s == "")
		return false;
	let dbl = index(s, "::");
	if (dbl >= 0 && index_from(s, "::", dbl + 2) >= 0)
		return false;
	let left = dbl < 0 ? s : substr(s, 0, dbl);
	let right = dbl < 0 ? "" : substr(s, dbl + 2);
	let L = [];
	let R = [];
	if (!ip6_side(left, L) || !ip6_side(right, R))
		return false;
	let count = length(L) + length(R);
	if (dbl < 0)
		return count == 8;
	return count < 8;
};

ipaddr = function(val) {
	return ip4addr(val) || ip6addr(val);
};

dt_port = function(val) {
	if (type(val) == "int")
		return val >= 0 && val <= 65535;
	if (type(val) == "double") {
		if (val != val)
			return false;
		let n = int(val);
		return (val - n) == 0 && n >= 0 && n <= 65535;
	}
	if (type(val) != "string")
		return false;
	let s = trim(val);
	if (match(s, /^[0-9]+$/) != null) {
		let n = int(s);
		return n == n && n >= 0 && n <= 65535;
	}
	if (match(s, /^[0-9]+\.[0-9]+$/) == null)
		return false;
	let n = s * 1.0;
	if (n != n)
		return false;
	let i = int(n);
	return (n - i) == 0 && i >= 0 && i <= 65535;
};

mac_groups = function(val, sep) {
	let parts = split(val, sep);
	if (length(parts) != 6)
		return false;
	for (let p in parts) {
		if (match(p, /^[0-9A-Fa-f]{1,2}$/) == null)
			return false;
	}
	return true;
};

// luci.ip.checkmac: six hex bytes, consistent ':' or '-'.
macaddr = function(val) {
	if (type(val) != "string" || val == "")
		return false;
	let colon = index(val, ":") >= 0;
	let dash = index(val, "-") >= 0;
	if (colon == dash)
		return false;
	return mac_groups(val, colon ? ":" : "-");
};

// luci.cbi.datatypes.hostname (strict flag not applied).
hostname = function(val) {
	if (type(val) != "string")
		return false;
	if (length(val) == 0 || length(val) >= 254)
		return false;
	if (match(val, /^[A-Za-z_]+$/) != null)
		return true;
	if (match(val, /^[A-Za-z0-9_][A-Za-z0-9_%.-]*[A-Za-z0-9]$/) != null && match(val, /[^0-9.]/) != null)
		return true;
	return false;
};

ip4prefix = function(val) {
	if (type(val) != "string")
		return false;
	let m = match(val, /^([^/]+)\/([0-9]+)$/);
	if (m == null)
		return false;
	let bits = int(m[2]);
	return ip4addr(m[1]) && bits == bits && bits >= 0 && bits <= 32 && length(m[2]) < 3;
};

ip6prefix = function(val) {
	if (type(val) != "string")
		return false;
	let m = match(val, /^([^/]+)\/([0-9]+)$/);
	if (m == null)
		return false;
	let bits = int(m[2]);
	return ip6addr(m[1]) && bits == bits && bits >= 0 && bits <= 128 && length(m[2]) < 4;
};

ipmask4 = function(val) {
	if (ip4addr(val) || ip4prefix(val))
		return true;
	if (type(val) != "string")
		return false;
	let m = match(val, /^([^/]+)\/([^/]+)$/);
	if (m == null)
		return false;
	return ip4addr(m[1]) && ip4addr(m[2]);
};

ipmask6 = function(val) {
	return ip6addr(val) || ip6prefix(val);
};

ip4addrport = function(val) {
	if (type(val) != "string")
		return false;
	let m = match(val, /^([^:]+):([^:]+)$/);
	if (m == null)
		return false;
	return ip4addr(m[1]) && dt_port(m[2]);
};

ip6addrport = function(val) {
	if (type(val) != "string")
		return false;
	let m = match(val, /^\[([^]]+)\]:([^:]+)$/);
	if (m == null)
		return false;
	return ip6addr(m[1]) && dt_port(m[2]);
};

ipaddrport = function(val) {
	if (ip4addrport(val) || ip6addrport(val))
		return true;
	if (type(val) != "string")
		return false;
	let m = match(val, /^([^:]+):([^:]+)$/);
	if (m == null)
		return false;
	return hostname(m[1]) && dt_port(m[2]);
};

hostport = function(val) {
	return ipaddrport(val);
};

is_json = function(str) {
	if (str === null || str === false || type(str) != "string")
		return false;
	let v = null;
	try {
		v = json(str);
	} catch (e) {
		return false;
	}
	// Lua treats only nil/false as failure. JSON 0 and "" are valid.
	return v !== null && v !== false;
};

is_timehhmm = function(str) {
	if (type(str) != "string")
		return false;
	let m = match(str, /^([0-9][0-9]?):([0-9][0-9])$/);
	if (m == null)
		return false;
	let hour = int(m[1]);
	let minute = int(m[2]);
	return hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59;
};

is_uuid = function(str) {
	if (type(str) != "string")
		return false;
	return match(str, /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/) != null;
};

export const datatypes = {
	ip4addr: ip4addr,
	ip6addr: ip6addr,
	ipaddr: ipaddr,
	port: dt_port,
	macaddr: macaddr,
	hostname: hostname,
	ipaddrport: ipaddrport,
	ip4addrport: ip4addrport,
	ip6addrport: ip6addrport,
	ipmask4: ipmask4,
	ipmask6: ipmask6,
	ip4prefix: ip4prefix,
	ip6prefix: ip6prefix,
	hostport: hostport,
	json: is_json,
	timehhmm: is_timehhmm,
	uuid: is_uuid
};

export const jsonc = {
	parse: function(str) {
		if (type(str) != "string")
			return null;
		try {
			return json(str);
		} catch (e) {
			return null;
		}
	},
	stringify: function(value, pretty) {
		let want = isset(pretty) && pretty != 0 && pretty != "";
		if (want) {
			try {
				let s = json(value, pretty);
				if (type(s) == "string")
					return s;
			} catch (e) {}
			return sprintf("%.J", value);
		}
		try {
			let s = json(value);
			if (type(s) == "string")
				return s;
		} catch (e) {}
		return sprintf("%J", value);
	}
};

get_domain_port_from_url = function(url) {
	if (type(url) != "string")
		return [null, null];
	let m = match(url, /^(https?):\/\/([A-Za-z0-9._-]+):?([0-9]*)/);
	if (m == null)
		m = match(url, /^(https?):\/\/(\[[^]]*\])([^:/]*)\/?/);
	if (m == null)
		return [null, null];
	let scheme = m[1];
	let domain = m[2];
	let port = m[3] ?? "";
	if (substr(domain, 0, 1) == "[")
		domain = substr(domain, 1, length(domain) - 2);
	let port_n = port != "" ? int(port) : (scheme == "https" ? 443 : 80);
	if (ipaddr(domain) || ip6addr(domain))
		return [null, null];
	return [domain, port_n];
};

parse_dns_server = function(dns) {
	let address = null;
	let port = null;
	let m = match(dns, /^(.*)#([0-9]+)$/);
	if (m != null) {
		address = m[1];
		port = m[2];
	}
	if (address == null) {
		m = match(dns, /^\[(.*)\]:([0-9]+)$/);
		if (m != null) {
			address = m[1];
			port = m[2];
		}
	}
	if (address == null) {
		m = match(dns, /^([^:]+):([0-9]+)$/);
		if (m != null) {
			address = m[1];
			port = m[2];
		}
	}
	if (address == null)
		address = dns;
	let wrapped = match(address, /^\[(.*)\]$/);
	if (wrapped != null)
		address = wrapped[1];
	if (port == null)
		port = "53";
	return [address, port];
};

resolve_domain = function(domain, dns) {
	if (!isset(dns) || dns == "")
		dns = get_cache_var("LOCAL_DNS");
	if (!isset(dns) || dns == "")
		dns = "223.5.5.5";
	let parsed = parse_dns_server(dns);
	let address = parsed[0];
	let port = parsed[1];
	let server = ip6addr(address) ? ("[" + address + "]") : address;
	let last_result = "";
	let last_rc = 255;
	let servers = [server + ":" + port, address + "#" + port, "223.5.5.5"];
	for (let dns_server in servers) {
		let res = exec_call_as_gid("LC_ALL=C nslookup " + shellquote(domain) + " " + shellquote(dns_server), DIRECT_GID);
		last_rc = res[0];
		last_result = res[1] ?? "";
		let ips = [];
		let seen = {};
		let answer = false;
		let lines = split(last_result, "\n");
		for (let line in lines) {
			if (match(line, /^[ \t]*Name:/) != null)
				answer = true;
			let ipm = null;
			if (answer)
				ipm = match(line, /^[ \t]*Address[ \t]*[0-9]*:[ \t]*([^ \t]+)/);
			if (ipm != null && (ip4addr(ipm[1]) || ip6addr(ipm[1])) && seen[ipm[1]] != true) {
				push(ips, ipm[1]);
				seen[ipm[1]] = true;
			}
		}
		if (length(ips) > 0)
			return [ips, null, 0];
	}
	return [null, last_result, last_rc];
};

table_join = function(t, s) {
	if (s == null)
		s = " ";
	if (type(t) != "array")
		return "";
	return join(s, t) ?? "";
};

curl_base = function(url, file, args, gid) {
	if (args == null)
		args = [];
	if (isset(file) && file != "")
		push(args, "-o " + file);
	let cmd = "curl " + table_join(args) + " \"" + url + "\"";
	if (isset(gid))
		return exec_call_as_gid(cmd, gid);
	return exec_call(cmd);
};

curl_proxy = function(url, file, args) {
	let socks_server = get_cache_var("GLOBAL_SOCKS_server");
	if (isset(socks_server) && socks_server != "") {
		if (args == null)
			args = [];
		let tmp_args = clone(args);
		push(tmp_args, "-x socks5h://" + socks_server);
		return curl_base(url, file, tmp_args);
	}
	return [null, null];
};

curl_direct = function(url, file, args) {
	if (get_cache_var("ENABLED_DEFAULT_ACL") != "1" && get_cache_var("ENABLED_ACLS") != "1")
		return curl_base(url, file, args);
	let tmp_args = clone(args ?? []);
	push(tmp_args, "--noproxy '*'");
	let hostport = get_domain_port_from_url(url);
	let domain = hostport[0];
	let port = hostport[1];
	if (domain != null) {
		let resolved = resolve_domain(domain);
		let ips = resolved[0];
		if (ips == null)
			return [6, resolved[1]];
		for (let i = 0; i < length(ips); i++) {
			if (ip6addr(ips[i]))
				ips[i] = "[" + ips[i] + "]";
		}
		push(tmp_args, "--resolve " + shellquote(domain + ":" + port + ":" + join(",", ips)));
	}
	return curl_base(url, file, tmp_args, DIRECT_GID);
};

curl_logic = function(url, file, args) {
	let res = curl_proxy(url, file, args);
	if (res[0] == null || res[0] != 0)
		res = curl_direct(url, file, args);
	return res;
};

curl_auto = function(url, file, args) {
	let local_proxy = uci_get_c("@global[0]", "localhost_proxy");
	if (!isset(local_proxy))
		local_proxy = "1";
	if (local_proxy == "1")
		return curl_base(url, file, args);
	return curl_logic(url, file, args);
};

is_exist = function(arr, value) {
	if (type(arr) != "array")
		return false;
	for (let item in arr) {
		if (item == value)
			return true;
	}
	return false;
};

repeat_exist = function(arr, value) {
	if (type(value) != "string" || index(value, "-") < 0)
		return false;
	if (type(arr) != "array")
		return false;
	let count = 0;
	for (let item in arr) {
		if (item == value)
			count++;
	}
	return count > 1;
};

remove = function(...values) {
	for (let value in values) {
		if (type(value) == "string" && length(value) > 0 && value != "/")
			sys_call("rm -rf -- " + value);
	}
};

is_install = function(package_name) {
	if (type(package_name) != "string" || length(package_name) == 0)
		return false;
	if (match(package_name, /[^A-Za-z0-9+_.-]/) != null)
		return false;
	// apk is the package manager from OpenWrt 25.12 onward. Prefer its
	// database whenever it is present so a leftover opkg directory cannot
	// hide an apk-installed dependency.
	let apk_size = fs_stat("/lib/apk/db/installed", "size");
	let path;
	if (apk_size != null && apk_size > 0)
		path = "/lib/apk/packages/" + package_name + ".list";
	else
		path = "/usr/lib/opkg/info/" + package_name + ".control";
	return sys_call("[ -s " + shellquote(path) + " ]") == 0;
};

get_args = function(arg) {
	let out = {};
	if (type(arg) != "array")
		return out;
	for (let i = 0; i < length(arg); i++) {
		let key = arg[i];
		let v = arg[i + 1];
		if (isset(v) && repeat_exist(arg, v) == false)
			out[key] = v;
	}
	return out;
};

get_function_args = function(arg) {
	if (type(arg) != "array" || length(arg) <= 1)
		return null;
	let param = [];
	for (let i = 1; i < length(arg); i++)
		push(param, arg[i]);
	return get_args(param);
};

strToTable = function(str) {
	if (str == null || type(str) != "string")
		return {};
	let body = trim(str);
	if (body == "")
		return {};
	try {
		let v = json(body);
		if (type(v) == "array" || type(v) == "object")
			return v;
	} catch (e) {}
	return {};
};

is_normal_node = function(e) {
	if (e != null && e.type != null && e.protocol != null && (e.protocol == "_balancing" || e.protocol == "_shunt" || e.protocol == "_iface" || e.protocol == "_urltest"))
		return false;
	return true;
};

is_special_node = function(e) {
	return is_normal_node(e) == false;
};

is_ip = function(val) {
	let s = lc(trim(as_str(val) ?? ""));
	let m = match(s, /\[([^]]*)\]/);
	let inner = m != null ? m[1] : s;
	return ipaddr(inner) ? true : false;
};

is_ipv6 = function(val) {
	let s = lc(trim(as_str(val) ?? ""));
	let m = match(s, /\[([^]]*)\]/);
	let inner = m != null ? m[1] : s;
	return ip6addr(inner) ? true : false;
};

is_local_ip = function(ip) {
	ip = lc(trim(as_str(ip) ?? ""));
	ip = replace(ip, /^[A-Za-z0-9]+:\/\//, "");
	ip = replace(ip, /\/.*$/, "");
	ip = replace(ip, /^\[/, "");
	ip = replace(ip, /\]$/, "");
	ip = replace(ip, /:[0-9]+$/, "");
	if (match(ip, /^127\./) != null)
		return true;
	if (match(ip, /^10\./) != null)
		return true;
	if (match(ip, /^172\.1[6-9]\./) != null)
		return true;
	if (match(ip, /^172\.2[0-9]\./) != null)
		return true;
	if (match(ip, /^172\.3[0-1]\./) != null)
		return true;
	if (match(ip, /^192\.168\./) != null)
		return true;
	if (ip == "::1")
		return true;
	if (match(ip, /^f[cd]/) != null)
		return true;
	if (match(ip, /^fe[89ab]/) != null)
		return true;
	return false;
};

is_ipv6addrport = function(val) {
	if (type(val) != "string")
		return false;
	let m = match(val, /^\[([^]]+)\]:([0-9]+)$/);
	if (m == null)
		return false;
	return ip6addr(m[1]) && dt_port(m[2]);
};

get_ipv6_only = function(val) {
	if (type(val) != "string")
		return "";
	let m = match(val, /\[([^]]*)\]/);
	let inner = m != null ? m[1] : val;
	if (ip6addr(inner))
		return inner;
	return "";
};

get_ipv6_full = function(val) {
	if (!is_ipv6(val))
		return "";
	if (type(val) != "string")
		val = as_str(val) ?? "";
	if (match(val, /\[.*\]/) == null)
		return "[" + val + "]";
	return val;
};

get_ip_type = function(val) {
	if (is_ipv6(val))
		return "6";
	if (ip4addr(val))
		return "4";
	return "";
};

is_mac = function(val) {
	return macaddr(val) ? true : false;
};

ip_or_mac = function(val) {
	if (isset(val)) {
		if (get_ip_type(val) == "4")
			return "ip";
		if (is_mac(val))
			return "mac";
	}
	return "";
};

iprange = function(val) {
	if (isset(val)) {
		let m = match("" + val, /^([^/]+)-([^/]+)$/);
		if (m != null && ip4addr(m[1]) && ip4addr(m[2]))
			return true;
	}
	return false;
};

get_domain_from_url = function(url) {
	if (type(url) != "string")
		return url;
	let m = match(url, /\/\/([^/]+)/);
	if (m != null)
		return m[1];
	return url;
};

core_protocol_name = function(protocol) {
	if (protocol == "vmess") return "VMess";
	if (protocol == "vless") return "VLESS";
	if (protocol == "shadowsocks") return "SS";
	if (protocol == "shadowsocksr") return "SSR";
	if (protocol == "wireguard") return "WG";
	if (protocol == "hysteria") return "HY";
	if (protocol == "hysteria2") return "HY2";
	if (protocol == "anytls") return "AnyTLS";
	if (protocol == "ssh") return "SSH";
	let m = match(protocol, /^([a-z])(.*)$/);
	if (m != null)
		return uc(m[1]) + m[2];
	return protocol;
};

is_special_protocol = function(protocol) {
	return protocol == "_balancing" || protocol == "_shunt" || protocol == "_iface" || protocol == "_urltest";
};

node_base_type = function(n) {
	if (n.type == "sing-box")
		return "Sing-Box";
	return n.type ?? "";
};

get_valid_nodes = function() {
	/* rpcd keeps one uci cursor. LuCI writes the same config through another
	   cursor, so drop the cached package before reading it back. */
	uci.unload(c_config);
	let show_node_info = uci_get_c("@global_other[0]", "show_node_info");
	if (!isset(show_node_info))
		show_node_info = "0";
	let nodes = [];
	let default_nodes = [];
	let other_nodes = [];
	uci_foreach_c("nodes", function(e) {
		e.id = e[".name"];
		if (e.type != null && e.remarks != null) {
			let type_name = node_base_type(e);
			if (is_special_protocol(e.protocol)) {
				e.remark = trim(sprintf("%s：[%s]", type_name + " " + translate(e.protocol), e.remarks));
				e.node_type = "special";
				if (!isset(e.group) || e.group == "")
					push(default_nodes, e);
				else
					push(other_nodes, e);
			}
			let port = ifnil(e.port, ifnil(e.hysteria_hop, e.hysteria2_hop));
			let is_realm = (e.type == "Hysteria2" || e.protocol == "hysteria2") && isset(e.hysteria2_realms) && e.hysteria2_realms != "";
			if ((isset(port) && isset(e.address)) || is_realm) {
				let address = e.address;
				if (is_ip(address) || hostname(address) || is_realm) {
					if ((e.type == "sing-box" || e.type == "Xray") && isset(e.protocol) && e.protocol != "")
						type_name = type_name + " " + core_protocol_name(e.protocol);
					if (is_ipv6(address))
						address = get_ipv6_full(address);
					if (is_realm)
						type_name = type_name + " Realm";
					e.remark = trim(sprintf("%s：[%s]", type_name, e.remarks));
					if (show_node_info == "1") {
						let port_s = replace("" + (port ?? ""), ":", "-");
						if (!is_realm)
							e.remark = trim(sprintf("%s：[%s] %s:%s", type_name, e.remarks, address, port_s));
					}
					e.node_type = "normal";
					if (!isset(e.group) || e.group == "")
						push(default_nodes, e);
					else
						push(other_nodes, e);
				}
			}
		}
	});
	for (let i = 0; i < length(default_nodes); i++)
		push(nodes, default_nodes[i]);
	for (let i = 0; i < length(other_nodes); i++)
		push(nodes, other_nodes[i]);
	return nodes;
};

get_node_list = function() {
	let node_list = {
		socks_list: [],
		normal_list: []
	};
	uci_foreach_c("socks", function(s) {
		if (s.enabled == "1" && isset(s.node)) {
			push(node_list.socks_list, {
				id: s[".name"],
				remark: translate("Socks Config") + " [" + s.port + translate("Port") + "]",
				group: "Socks"
			});
		}
	});
	let valid = get_valid_nodes();
	for (let e in valid) {
		if (e.node_type == "normal") {
			push(node_list.normal_list, {
				id: e[".name"],
				remark: e.remark,
				type: e.type,
				chain_proxy: e.chain_proxy,
				group: e.group
			});
		}
		if (isset(e.protocol) && match(e.protocol, /^_/) != null) {
			let proto = substr(e.protocol, 1);
			let key = proto + "_list";
			if (node_list[key] == null)
				node_list[key] = [];
			push(node_list[key], {
				id: e[".name"],
				remark: e.remark,
				group: e.group,
				o: e
			});
		}
	}
	return node_list;
};

get_node_remarks = function(n) {
	let remarks = "";
	if (n != null) {
		let type_name = node_base_type(n);
		if (is_special_protocol(n.protocol)) {
			remarks = trim(sprintf("%s：[%s]", type_name + " " + translate(n.protocol), n.remarks));
		} else {
			if ((n.type == "sing-box" || n.type == "Xray") && isset(n.protocol) && n.protocol != "")
				type_name = type_name + " " + core_protocol_name(n.protocol);
			if ((n.type == "Hysteria2" || n.protocol == "hysteria2") && isset(n.hysteria2_realms) && n.hysteria2_realms != "")
				type_name = type_name + " Realm";
			remarks = trim(sprintf("%s：[%s]", type_name, n.remarks));
		}
	}
	return remarks;
};

get_full_node_remarks = function(n) {
	let remarks = get_node_remarks(n);
	if (length(remarks) > 0 && n != null) {
		let port = ifnil(n.port, ifnil(n.hysteria_hop, n.hysteria2_hop));
		if (isset(n.address) && isset(port)) {
			port = replace("" + port, ":", "-");
			remarks = remarks + " " + n.address + ":" + port;
		}
	}
	return remarks;
};

get_random_normal_node = function(exclude_id) {
	let lookup = {};
	if (type(exclude_id) == "array") {
		for (let v in exclude_id)
			lookup[v] = true;
	} else if (type(exclude_id) == "string") {
		lookup[exclude_id] = true;
	}
	let normal = [];
	let valid = get_valid_nodes();
	for (let e in valid) {
		if (e.node_type == "normal" && lookup[e[".name"]] != true)
			push(normal, e);
	}
	if (length(normal) > 0)
		return normal[rand_int(0, length(normal) - 1)];
	return null;
};

gen_uuid = function() {
	return sys_exec("echo -n $(cat /proc/sys/kernel/random/uuid)");
};

gen_random_char = function(len) {
	if (!isset(len))
		len = 8;
	return sys_exec("echo -n $(head /dev/urandom | tr -dc A-Za-z0-9 | head -c " + len + ")");
};

chmod_755 = function(file) {
	if (isset(file) && file != "") {
		let st = stat(file);
		if (!perm_has(st, "rwx", "rx", "rx"))
			chmod(file, 0755);
	}
};

get_customed_path = function(e) {
	return uci_get_c("@global_app[0]", e + "_file");
};

get_app_path = function(app_name) {
	let c = comp(app_name);
	if (c == null)
		return null;
	let def_path = c.default_path;
	let key = replace(app_name, "-", "_") + "_file";
	let path = uci_get_c("@global_app[0]", key);
	if (type(path) == "string" && length(path) > 0)
		return path;
	return def_path ?? null;
};

get_bin_version_cache = function(file, cmd) {
	if (isset(file) && file != "" && fs_access(file)) {
		chmod_755(file);
		let st = stat(file);
		let cache_file = null;
		if (st != null && st.dev != null && st.inode != null && st.size != null && st.mtime != null && st.ctime != null) {
			let dev_s = "";
			if (type(st.dev) == "object")
				dev_s = "" + st.dev.major + "_" + st.dev.minor;
			else
				dev_s = "" + st.dev;
			cache_file = CACHE_PATH + "/binver_" + dev_s + "_" + st.inode + "_" + st.size + "_" + st.mtime + "_" + st.ctime;
			let cached = readfile(cache_file);
			if (type(cached) == "string" && trim(cached) != "")
				return trim(cached);
		}
		let version = sys_exec("echo -n $(" + shellquote(file) + " " + cmd + ")");
		if (isset(version) && version != "") {
			if (cache_file != null) {
				mkdir_p(CACHE_PATH);
				writefile(cache_file, version);
			}
			return version;
		}
	}
	return "";
};

get_app_version = function(app_name, file) {
	if (file == null)
		file = get_app_path(app_name);
	let c = comp(app_name);
	if (c == null || c.cmd_version == null)
		return "";
	return get_bin_version_cache(file, c.cmd_version);
};

finded_com = function(e) {
	let bin = get_app_path(e);
	if (!isset(bin) || bin == "")
		return null;
	let s = sys_exec("echo -n $(type -t -p " + shellquote(bin) + " | head -n1)");
	if (s == null || s == "")
		return null;
	return s;
};

finded = function(name) {
	let bin = "" + name;
	let s = sys_exec("echo -n $(type -t -p " + shellquote("/bin/" + bin) + " -p " + shellquote("/usr/bin/" + bin) + " " + shellquote(bin) + " | head -n1)");
	if (s == null)
		return "";
	return s;
};

is_finded = function(name) {
	return finded(name) != "";
};

clone = function(org) {
	let kind = type(org);
	if (kind == "array") {
		let res = [];
		for (let v in org)
			push(res, clone(v));
		return res;
	}
	if (kind == "object") {
		let res = {};
		for (let k, v in org)
			res[k] = clone(v);
		return res;
	}
	return org;
};

is_reg = function(path) {
	return fs_stat(path, "type") == "reg";
};

is_dir = function(path) {
	if (type(path) == "string" && length(path) > 1)
		return fs_stat(path, "type") == "dir";
	return false;
};

get_final_dir = function(path) {
	if (is_dir(path))
		return path;
	if (path == null || path == "" || path == "/" || path == ".")
		return "/";
	let parent = dirname(path);
	if (parent == path)
		return "/";
	return get_final_dir(parent);
};

get_free_space = function(dir) {
	if (dir == null)
		dir = "/";
	if (sys_call("df -k " + shellquote(dir) + " >/dev/null 2>&1") != 0)
		return 0;
	let out = sys_exec("df -k " + shellquote(dir) + " | awk 'NR>1 {print $4}'");
	let n = int(trim(out));
	if (n != n)
		return 0;
	return n;
};

get_file_space = function(file) {
	if (file == null)
		return 0;
	if (!fs_access(file))
		return 0;
	let out = sys_exec("du -k " + shellquote(file) + " | awk 'NR==1 {print $1}'");
	let n = int(trim(out));
	if (n != n)
		return 0;
	return n;
};

_unpack = function(t, i) {
	if (type(t) != "array")
		return null;
	if (!isset(i))
		i = 0;
	if (i < 0)
		i = 0;
	return slice(t, i);
};

exec_argv = function(cmd, args, writer, timeout_sec) {
	let argv = [cmd];
	if (type(args) == "array") {
		for (let a in args)
			push(argv, "" + a);
	}
	if (writer == null && isset(timeout_sec) && timeout_sec > 0 && type(global.system) == "function") {
		let rc = global.system(argv, timeout_sec * 1000);
		if (rc == null)
			return 255;
		if (rc < 0)
			return 1;
		return rc;
	}
	let p = popen(argv, "r");
	if (p == null)
		return 255;
	let chunk = p.read(2048);
	while (chunk != null && chunk != "") {
		if (writer != null)
			writer(chunk);
		chunk = p.read(2048);
	}
	let rc = p.close();
	if (rc == null)
		return 255;
	return rc;
};

version_part = function(value) {
	if (type(value) == "int")
		return value;
	if (type(value) == "double")
		return int(value);
	if (type(value) != "string" || value == "")
		return 0;
	if (match(value, /^-?[0-9]+$/) != null)
		return int(value);
	let rev = match(value, /^[rR]([0-9]+)$/);
	if (rev != null)
		return int(rev[1]);
	return 0;
};

compare_versions = function(ver1, comp_op, ver2) {
	if (!isset(ver1))
		ver1 = "";
	if (!isset(ver2))
		ver2 = "";
	ver1 = "" + ver1;
	ver2 = "" + ver2;
	let av1 = global.split(ver1, /[.\-]/);
	let av2 = global.split(ver2, /[.\-]/);
	if (av1 == null)
		av1 = [];
	if (av2 == null)
		av2 = [];
	let maxn = length(av1);
	if (length(av2) > maxn)
		maxn = length(av2);
	for (let i = 0; i < maxn; i++) {
		let s1 = version_part(av1[i] ?? 0);
		let s2 = version_part(av2[i] ?? 0);
		if (comp_op == "~=" && s1 != s2)
			return true;
		if ((comp_op == "<" || comp_op == "<=") && s1 < s2)
			return true;
		if ((comp_op == ">" || comp_op == ">=") && s1 > s2)
			return true;
		if (s1 != s2)
			return false;
	}
	return !(comp_op == "<" || comp_op == ">");
};

release_value = function(path, key) {
	if (!fs_access(path))
		return null;
	let text = readfile(path);
	if (type(text) != "string")
		return null;
	let lines = global.split(text, "\n");
	if (lines == null)
		return null;
	for (let line in lines) {
		if (substr(line, 0, length(key)) != key)
			continue;
		let m = match(line, /^[A-Za-z0-9_]+=["']([^"']*)["']/);
		if (m == null)
			m = match(line, /^[A-Za-z0-9_]+=([^ \t\r\n]+)/);
		if (m != null) {
			if (m[1] == "")
				return null;
			return m[1];
		}
	}
	return null;
};

auto_get_arch = function() {
	let arch = trim(sys_exec("uname -m"));
	if (OPENWRT_ARCH == null && fs_access("/usr/lib/os-release")) {
		OPENWRT_ARCH = release_value("/usr/lib/os-release", "OPENWRT_ARCH");
		OPENWRT_BOARD = release_value("/usr/lib/os-release", "OPENWRT_BOARD");
	}
	if (DISTRIB_ARCH == null && fs_access("/etc/openwrt_release"))
		DISTRIB_ARCH = release_value("/etc/openwrt_release", "DISTRIB_ARCH");
	if (match(arch, /^i[0-9]86$/) != null)
		arch = "x86";
	else if (match(arch, /armv5/) != null)
		arch = "armv5";
	else if (match(arch, /armv6/) != null)
		arch = "armv6";
	else if (match(arch, /armv7/) != null)
		arch = "armv7";
	if (OPENWRT_ARCH != null || DISTRIB_ARCH != null) {
		if (arch == "mips") {
			let first = OPENWRT_ARCH != null && match(OPENWRT_ARCH, /mipsel/) != null;
			let second = DISTRIB_ARCH != null && match(DISTRIB_ARCH, /mipsel/) != null;
			if (first || second)
				arch = "mipsel";
		} else if (arch == "armv7") {
			let first = OPENWRT_ARCH != null && match(OPENWRT_ARCH, /vfp/) == null && match(OPENWRT_ARCH, /neon/) == null;
			let second = DISTRIB_ARCH != null && match(DISTRIB_ARCH, /vfp/) == null && match(DISTRIB_ARCH, /neon/) == null;
			if (first || second)
				arch = "armv5";
		}
	}
	if (arch == "aarch64" && OPENWRT_BOARD != null && match(OPENWRT_BOARD, /rockchip/) != null)
		arch = "rockchip";
	return trim(arch);
};

parseURL = function(url_str) {
	let res = {};
	if (type(url_str) != "string")
		return res;
	let rest = url_str;
	let scheme_m = match(url_str, /^([A-Za-z0-9._+-]+):\/\/(.+)$/);
	if (scheme_m != null) {
		res.protocol = scheme_m[1];
		rest = scheme_m[2];
	}
	let auth_m = match(rest, /^([^/]+)(.*)$/);
	if (auth_m == null)
		return res;
	let authority = auth_m[1];
	let path = auth_m[2];
	if (isset(path) && path != "") {
		let path_m = match(path, /^([^?#]*)/);
		if (path_m != null)
			res.pathname = path_m[1];
	}
	let user_m = match(authority, /^([^@]+)@(.+)$/);
	let host_port = authority;
	if (user_m != null) {
		let up = match(user_m[1], /^([^:]+):?(.*)$/);
		res.username = up != null ? (up[1] ?? "") : "";
		res.password = up != null ? (up[2] ?? "") : "";
		host_port = user_m[2];
	}
	let v6 = match(host_port, /^\[(.+)\]:([0-9]+)$/);
	if (v6 != null) {
		res.hostname = v6[1];
		res.port = int(v6[2]);
	} else {
		let pure = match(host_port, /^\[(.+)\]$/);
		if (pure != null) {
			res.hostname = pure[1];
		} else {
			let hp = match(host_port, /^([^:]+):([0-9]+)$/);
			if (hp != null) {
				res.hostname = hp[1];
				res.port = int(hp[2]);
			} else {
				res.hostname = host_port;
			}
		}
	}
	res.host = host_port;
	return res;
};

parseDoH = function(doh_str) {
	doh_str = trim(as_str(doh_str) ?? "");
	if (doh_str == "")
		return null;
	let url_part = doh_str;
	let ip_part = null;
	if (index(doh_str, ",") >= 0) {
		let m = match(doh_str, /^([^,]+),(.+)$/);
		if (m != null) {
			url_part = m[1];
			ip_part = m[2];
		}
	}
	let res = parseURL(url_part);
	if (res == null)
		return null;
	res.url = url_part;
	if (isset(ip_part) && ip_part != "" && is_ip(ip_part))
		res.hostip = ip_part;
	return res;
};

let default_file_tree = {
	x86_64: "amd64",
	x86: "386",
	aarch64: "arm64",
	rockchip: "arm64",
	mips: "mips",
	mips64: "mips64",
	mipsel: "mipsel",
	mips64el: "mips64el",
	armv5: "arm.*5",
	armv6: "arm.*6[^4]*",
	armv7: "arm.*7",
	armv8: "arm64",
	riscv64: "riscv64"
};

re_escape_char = function(ch) {
	if (index(".^$*+?()[]{}|\\", ch) >= 0)
		return "\\" + ch;
	return ch;
};

// Asset names are matched with Lua patterns stored in com.uc (after sprintf).
lua_pattern_regexp = function(pat) {
	let out = "";
	let i = 0;
	let n = length(pat);
	while (i < n) {
		let c = substr(pat, i, 1);
		if (c == "%") {
			let nx = substr(pat, i + 1, 1);
			i += 2;
			if (nx == "d") out += "[0-9]";
			else if (nx == "w") out += "[A-Za-z0-9_]";
			else if (nx == "a") out += "[A-Za-z]";
			else if (nx == "s") out += "[[:space:]]";
			else if (nx == "x") out += "[0-9A-Fa-f]";
			else if (nx == "l") out += "[a-z]";
			else if (nx == "u") out += "[A-Z]";
			else if (nx == "") out += "%";
			else out += re_escape_char(nx);
		} else if (c == "\\") {
			out += "\\\\";
			i++;
		} else if (c == "[") {
			out += "[";
			i++;
			if (i < n && substr(pat, i, 1) == "^") {
				out += "^";
				i++;
			}
			if (i < n && substr(pat, i, 1) == "]") {
				out += "]";
				i++;
			}
			while (i < n && substr(pat, i, 1) != "]") {
				let cc = substr(pat, i, 1);
				if (cc == "%") {
					out += substr(pat, i + 1, 1);
					i += 2;
				} else {
					out += cc;
					i++;
				}
			}
			if (i < n) {
				out += "]";
				i++;
			}
		} else {
			out += c;
			i++;
		}
	}
	try {
		return regexp(out);
	} catch (e) {
		return null;
	}
};

get_api_json = function(url) {
	let gh_proxy = uci_get_c("@global_app[0]", "gh_proxy_url") ?? "";
	let res;
	if (gh_proxy != "") {
		url = gh_proxy + url;
		res = curl_direct(url, null, curl_args);
	} else {
		res = curl_auto(url, null, curl_args);
	}
	if (res[0] != 0 || res[1] == null || res[1] == "")
		return {};
	let parsed = jsonc.parse(res[1]);
	if (parsed == null)
		return {};
	return parsed;
};

check_path = function(app_name) {
	let path = get_app_path(app_name) ?? "";
	if (path == "") {
		return {
			code: 1,
			error: translatef("You did not fill in the %s path. Please save and apply then update manually.", app_name)
		};
	}
	return { code: 0, app_path: path };
};

unwrap_release = function(value) {
	if (type(value) == "array" && length(value) > 0)
		return value[0];
	return value;
};

strip_v_run = function(s) {
	let m = match(s ?? "", /[^v]+/);
	if (m == null)
		return "";
	return m[0];
};

to_check = function(arch, app_name) {
	let result = check_path(app_name);
	if (result.code != 0)
		return result;
	if (!isset(arch) || arch == "")
		arch = auto_get_arch();
	let c = comp(app_name);
	if (c == null)
		return { code: 1, error: translate("Can't determine ARCH, or ARCH not supported.") };
	let file_tree = "";
	if (c.file_tree != null && c.file_tree[arch] != null)
		file_tree = c.file_tree[arch];
	else if (default_file_tree[arch] != null)
		file_tree = default_file_tree[arch];
	if (file_tree == "") {
		return {
			code: 1,
			error: translate("Can't determine ARCH, or ARCH not supported.")
		};
	}
	let local_version = get_app_version(app_name);
	let match_file_name = sprintf(c.match_fmt_str, file_tree);
	let name_re = lua_pattern_regexp(match_file_name);
	let payload = unwrap_release(get_api_json(c.get_url(c)));
	if (payload == null || payload.tag_name == null) {
		return {
			code: 1,
			error: translate("Get remote version info failed.")
		};
	}
	let remote_version = payload.tag_name;
	if (isset(c.remote_version_str_replace) && c.remote_version_str_replace != "")
		remote_version = replace(remote_version, c.remote_version_str_replace, "");
	let has_update = compare_versions(strip_v_run(local_version), "<", strip_v_run(remote_version));
	let asset = {};
	let assets = type(payload.assets) == "array" ? payload.assets : [];
	for (let v in assets) {
		if (v.name != null && name_re != null && match(v.name, name_re) != null) {
			asset = v;
			break;
		}
	}
	if (asset.browser_download_url == null) {
		return {
			code: 1,
			local_version: local_version,
			remote_version: remote_version,
			html_url: payload.html_url,
			data: asset,
			error: translate("New version found, but failed to get new version download url.")
		};
	}
	return {
		code: 0,
		has_update: has_update,
		local_version: local_version,
		remote_version: remote_version,
		html_url: payload.html_url,
		data: asset
	};
};

to_download = function(app_name, url, size, task_id, keep_files) {
	let result = app_name == appname ? { code: 0 } : check_path(app_name);
	if (result.code != 0)
		return result;
	if (!isset(url) || url == "")
		return { code: 1, error: translate("Download url is required.") };
	if (!keep_files)
		remove("/tmp/" + app_name + "_download.*");
	let tmp_file;
	if (isset(task_id) && match(task_id, /^[A-Za-z0-9_-]+$/) != null) {
		tmp_file = "/tmp/" + app_name + "_download." + task_id;
		remove(tmp_file);
	} else {
		tmp_file = trim(sys_exec("mktemp -u -t " + app_name + "_download.XXXXXX"));
	}
	if (isset(size)) {
		let kb1 = get_free_space("/tmp");
		let size_n = int(size);
		if (size_n == size_n && size_n > kb1)
			return { code: 1, error: translatef("%s not enough space.", "/tmp") };
	}
	let _curl_args = clone(curl_args);
	push(_curl_args, "--speed-limit 51200 --speed-time 15 --max-time 300");
	let gh_proxy = uci_get_c("@global_app[0]", "gh_proxy_url") ?? "";
	let res;
	if (gh_proxy != "") {
		url = gh_proxy + url;
		res = curl_direct(url, tmp_file, _curl_args);
	} else {
		res = curl_auto(url, tmp_file, _curl_args);
	}
	if (res[0] != 0) {
		exec_argv("/bin/rm", ["-f", tmp_file], null, null);
		return {
			code: 1,
			error: translatef("File download failed or timed out: %s", url)
		};
	}
	let c = comp(app_name);
	return { code: 0, file: tmp_file, zip: c != null ? c.zipped : null };
};

to_download_progress = function(app_name, task_id, total_size) {
	if (comp(app_name) == null || type(task_id) != "string" || match(task_id, /^[A-Za-z0-9_-]+$/) == null)
		return { code: 1, error: translate("Invalid download task.") };
	total_size = int(total_size);
	if (total_size != total_size)
		total_size = 0;
	let tmp_file = "/tmp/" + app_name + "_download." + task_id;
	let downloaded = 0;
	if (app_name == appname) {
		let a = fs_stat(tmp_file + "1", "size");
		let b = fs_stat(tmp_file + "2", "size");
		downloaded = (a == null ? 0 : int(a)) + (b == null ? 0 : int(b));
	} else {
		let a = fs_stat(tmp_file, "size");
		downloaded = a == null ? 0 : int(a);
	}
	if (downloaded != downloaded)
		downloaded = 0;
	let ret = { code: 0, downloaded: downloaded, total: total_size };
	if (total_size > 0)
		ret.percent = min(99, int(downloaded * 100 / total_size));
	return ret;
};

to_extract = function(app_name, file, subfix) {
	let result = check_path(app_name);
	if (result.code != 0)
		return result;
	if (!isset(file) || file == "" || !fs_access(file))
		return { code: 1, error: translate("File path required.") };
	let c = comp(app_name);
	let tools_name = null;
	if (c != null && c.zipped) {
		if (!isset(c.zipped_suffix) || c.zipped_suffix == "zip")
			tools_name = "unzip";
		if (isset(c.zipped_suffix) && c.zipped_suffix == "tar.gz")
			tools_name = "tar";
		if (tools_name != null) {
			if (trim(sys_exec("echo -n $(command -v " + shellquote(tools_name) + ")")) == "") {
				exec_argv("/bin/rm", ["-f", file], null, null);
				return {
					code: 1,
					error: translatef("Not installed %s, Can't unzip!", tools_name)
				};
			}
		}
	}
	remove("/tmp/" + app_name + "_extract.*");
	let new_file_size = get_file_space(file);
	let tmp_free_size = get_free_space("/tmp");
	if (tmp_free_size <= 0 || tmp_free_size <= new_file_size)
		return { code: 1, error: translatef("%s not enough space.", "/tmp") };
	let tmp_dir = trim(sys_exec("mktemp -d -t " + app_name + "_extract.XXXXXX"));
	let output = [];
	if (tools_name != null) {
		if (tools_name == "unzip") {
			let bin = trim(sys_exec("echo -n $(command -v unzip)"));
			exec_argv(bin, ["-o", file, app_name, "-d", tmp_dir], function(chunk) {
				push(output, chunk);
			}, null);
		} else if (tools_name == "tar") {
			let bin = trim(sys_exec("echo -n $(command -v tar)"));
			if (c.zipped_suffix == "tar.gz") {
				exec_argv(bin, ["-zxf", file, "-C", tmp_dir], function(chunk) {
					push(output, chunk);
				}, null);
				sys_call("/bin/mv -f " + tmp_dir + "/*/" + lc(c.name) + " " + tmp_dir);
			}
		}
	}
	// output is collected for parity with the Lua extractor; the caller uses tmp_dir.
	if (length(output) < 0)
		return { code: 1 };
	exec_argv("/bin/rm", ["-f", file], null, null);
	return { code: 0, file: tmp_dir };
};

to_move = function(app_name, file) {
	let result = check_path(app_name);
	if (result.code != 0)
		return result;
	let c = comp(app_name);
	let app_path = result.app_path;
	let bin_path = file;
	let rm_tmp = "/tmp/" + app_name + "_download.*";
	if (fs_stat(file, "type") == "dir") {
		bin_path = file + "/" + lc(c.name);
		rm_tmp = "/tmp/" + app_name + "_extract.*";
	}
	if (!isset(file) || file == "") {
		remove(rm_tmp);
		return { code: 1, error: translate("Client file is required.") };
	}
	let new_version = get_app_version(app_name, bin_path);
	if (new_version == "") {
		remove(rm_tmp);
		return {
			code: 1,
			error: translate("The client file is not suitable for current device.") + app_name + "__" + bin_path
		};
	}
	let flag = sys_call("busybox pgrep -af \"passwall/.*" + app_name + "\" >/dev/null");
	if (flag == 0)
		sys_call("/etc/init.d/passwall stop");
	let old_app_size = 0;
	if (fs_access(app_path))
		old_app_size = get_file_space(app_path);
	let new_app_size = get_file_space(bin_path);
	let final_dir = get_final_dir(app_path);
	let final_dir_free_size = get_free_space(final_dir);
	if (final_dir_free_size > 0) {
		final_dir_free_size = final_dir_free_size + old_app_size;
		if (new_app_size > final_dir_free_size) {
			remove(rm_tmp);
			return { code: 1, error: translatef("%s not enough space.", final_dir) };
		}
	}
	let moved = exec_argv("/bin/mv", ["-f", bin_path, app_path], null, command_timeout) == 0;
	remove(rm_tmp);
	if (flag == 0)
		sys_call("/etc/init.d/passwall restart >/dev/null 2>&1 &");
	if (!moved || !fs_access(app_path)) {
		return {
			code: 1,
			error: translatef("Can't move new file to path: %s", app_path)
		};
	}
	return { code: 0 };
};

get_version = function() {
	let version_file = CACHE_PATH + "/passwall_version";
	sys_call("mkdir -p " + CACHE_PATH);
	let version = null;
	if (fs_access(version_file)) {
		version = readfile(version_file);
	} else {
		// opkg list-installed on 24.10 and older. OpenWrt 25.12 replaced it
		// with apk; `apk info` lists names only, so read the version from
		// `apk query` and fall back to the installed database.
		version = trim(sys_exec("opkg list-installed luci-app-passwall 2>/dev/null | awk '{print $3; exit}'"));
		if (version == "")
			version = trim(sys_exec("apk query --installed --format json --fields name,version luci-app-passwall 2>/dev/null | jsonfilter -e '$[0].version' 2>/dev/null"));
		if (version == "")
			version = trim(sys_exec("awk '$0==\"P:luci-app-passwall\"{f=1;next} f&&/^V:/{sub(/^V:/,\"\"); print; exit} f&&NF==0{exit}' /lib/apk/db/installed 2>/dev/null"));
		if (version != "")
			writefile(version_file, version);
	}
	version = trim(version ?? "");
	return replace(version, /-r([0-9]+)$/, "-$1");
};

to_check_self = function() {
	let c = comp(appname);
	if (c == null || c.get_url == null)
		return { code: 1, error: translate("Get remote version info failed.") };
	let release = unwrap_release(get_api_json(c.get_url(c)));
	if (type(release) != "object" || release == null || release.tag_name == null)
		return { code: 1, error: translate("Get remote version info failed.") };
	let local_version = get_version();
	let remote_version = replace(release.tag_name, /^v/, "");
	let has_update = compare_versions(local_version, "<", remote_version);
	let prefix;
	let extension;
	if (sys_call("command -v apk >/dev/null 2>&1") == 0) {
		prefix = "25.12+_";
		extension = ".apk";
	} else {
		if (sys_call("command -v uname >/dev/null 2>&1") != 0)
			return { code: 1 };
		let kernel_m = match(trim(sys_exec("uname -r 2>/dev/null")), /^([0-9]+\.[0-9]+)/);
		if (kernel_m == null)
			return { code: 1 };
		prefix = compare_versions(kernel_m[1], "<", "5.11") ? "22.03-_" : "23.05-24.10_";
		extension = ".ipk";
	}
	let main_pkg = null;
	let i18n_package = null;
	let main_re = regexp("^luci-app-" + appname + "[_-][0-9]");
	let i18n_re = regexp("^luci-i18n-" + appname + "-zh-cn[_-][0-9]");
	let prefixes = [prefix, ""];
	let assets = type(release.assets) == "array" ? release.assets : [];
	for (let search_prefix in prefixes) {
		for (let asset in assets) {
			let name = asset.name ?? "";
			let starts = search_prefix == "" || substr(name, 0, length(search_prefix)) == search_prefix;
			let ends = length(name) >= length(extension) && substr(name, -length(extension)) == extension;
			if (starts && ends) {
				name = substr(name, length(search_prefix));
				if (main_pkg == null && match(name, main_re) != null)
					main_pkg = asset;
				if (i18n_package == null && match(name, i18n_re) != null)
					i18n_package = asset;
			}
		}
		if (main_pkg != null && i18n_package != null)
			break;
	}
	if (main_pkg == null || i18n_package == null)
		return { code: 1, error: translate("Get remote version info failed.") };
	return {
		code: 0,
		has_update: has_update,
		local_version: local_version,
		remote_version: remote_version,
		html_url: release.html_url,
		data: main_pkg,
		i18n: i18n_package
	};
};

to_install_self = function(id, force) {
	if (!isset(id) || match(id, /^[A-Za-z0-9_-]+$/) == null)
		return { code: 1 };
	let dir = "/tmp/" + appname + "_luci_update." + id;
	let manager = sys_call("command -v apk >/dev/null 2>&1") == 0 ? "apk" : "opkg";
	let extension = manager == "apk" ? ".apk" : ".ipk";
	let status_dir = "/www/luci-static/resources/" + appname + "-update";
	let status = status_dir + "/" + id + ".json";
	mkdir_p(dir);
	mkdir_p(status_dir);
	exec_argv("/bin/mv", ["/tmp/" + appname + "_download." + id + "1", dir + "/luci-app-" + appname + extension], null, null);
	exec_argv("/bin/mv", ["/tmp/" + appname + "_download." + id + "2", dir + "/luci-i18n-" + appname + "-zh-cn" + extension], null, null);
	let script = dir + "/luci_update.uc";
	if (exec_argv("/bin/cp", ["/usr/libexec/" + appname + "/luci_update.uc", script], null, null) != 0) {
		remove(dir);
		return { code: 1 };
	}
	chmod_755(script);
	writefile(status, '{"installing":true}');
	sys_call("nohup " + script + " " + dir + " " + status + " " + manager + " " + (force == "1" ? "1" : "0") + " >/dev/null 2>&1 </dev/null &");
	return { code: 0 };
};

get_std_domain = function(domain) {
	domain = trim(as_str(domain) ?? "");
	if (domain == "")
		return "";
	let n = length(domain);
	for (let i = 0; i < n; i++) {
		if (ord(domain, i) == 35)
			return "";
	}
	let si = 0;
	let ei = n - 1;
	while (si < n && ord(domain, si) == 46)
		si++;
	while (ei >= si && ord(domain, ei) == 46)
		ei--;
	if (si > ei)
		return "";
	domain = substr(domain, si, ei - si + 1);
	n = length(domain);
	let star = false;
	for (let i = 0; i < n; i++) {
		if (ord(domain, i) == 42) {
			star = true;
			break;
		}
	}
	if (!star)
		return domain;
	let parts = [];
	let pstart = 0;
	for (let i = 0; i <= n; i++) {
		let b = (i < n) ? ord(domain, i) : 46;
		if (b == 46) {
			push(parts, substr(domain, pstart, i - pstart));
			pstart = i + 1;
		}
	}
	for (let i = length(parts) - 1; i >= 0; i--) {
		let s = parts[i];
		let has = false;
		for (let j = 0; j < length(s); j++) {
			if (ord(s, j) == 42) {
				has = true;
				break;
			}
		}
		if (has) {
			if (i == length(parts) - 1)
				return "";
			let out = parts[i + 1];
			for (let k = i + 2; k < length(parts); k++)
				out = out + "." + parts[k];
			return out;
		}
	}
	return domain;
};

format_go_time = function(input, default_value) {
	if (isset(input))
		input = trim(as_str(input) ?? "");
	let N = 0;
	if (isset(input) && match(input, /^[0-9]+$/) != null) {
		N = int(input);
	} else if (isset(input) && input != "") {
		let parts = match(input, /([0-9]+)[[:space:]]*([hms])/g);
		if (parts != null) {
			for (let p in parts) {
				let value = int(p[1]);
				let unit = p[2];
				if (unit == "h")
					N = N + value * 3600;
				else if (unit == "m")
					N = N + value * 60;
				else if (unit == "s")
					N = N + value;
			}
		}
	}
	if (N != N || N <= 0)
		return ifnil(default_value, "0s");
	let result = "";
	let h = int(N / 3600);
	let m = int((N % 3600) / 60);
	let s = N % 60;
	if (h > 0)
		result = result + h + "h";
	if (m > 0)
		result = result + m + "m";
	if (s > 0 || result == "")
		result = result + s + "s";
	return result;
};

match_cond = function(str, cond) {
	if (cond == "")
		return true;
	if (substr(cond, 0, 1) == "!") {
		let k = substr(cond, 1);
		if (k == "")
			return true;
		return index(str, k) < 0;
	}
	if (substr(cond, 0, 1) == "^") {
		let k = substr(cond, 1);
		return substr(str, 0, length(k)) == k;
	}
	if (substr(cond, -1) == "$") {
		let k = substr(cond, 0, length(cond) - 1);
		if (k == "")
			return true;
		return length(str) >= length(k) && substr(str, -length(k)) == k;
	}
	return index(str, cond) >= 0;
};

split_nonempty = function(expr, sep) {
	let t = [];
	let parts = global.split(expr, sep);
	if (parts == null)
		return t;
	for (let part in parts) {
		part = trim(part);
		if (part != "")
			push(t, part);
	}
	return t;
};

match_node_rule = function(name, rule) {
	if (!isset(name))
		return false;
	name = "" + name;
	if (!isset(rule) || rule == "")
		return true;
	let groups = split_nonempty("" + rule, "||");
	for (let group in groups) {
		let conds = split_nonempty(group, "&&");
		let ok = true;
		for (let cond in conds) {
			if (!match_cond(name, cond)) {
				ok = false;
				break;
			}
		}
		if (ok)
			return true;
	}
	return false;
};

match_tokens = function(str) {
	let found = match(str, /[^[:space:]]+/g);
	if (found == null)
		return [];
	let out = [];
	for (let item in found) {
		if (type(item) == "array")
			push(out, item[0]);
		else
			push(out, item);
	}
	return out;
};

get_batch_nodes = function(node) {
	if (length(normal_nodes) == 0) {
		let valid = get_valid_nodes();
		for (let e in valid) {
			if (e.node_type == "normal" && (!isset(e.chain_proxy) || e.chain_proxy == "")) {
				push(normal_nodes, {
					id: e[".name"],
					remarks: e.remarks,
					group: e.group
				});
			}
		}
	}
	if (node == null || !isset(node.node_group) || node.node_group == "")
		return [];
	let nodes = [];
	let groups = match_tokens("" + node.node_group);
	for (let g in groups) {
		g = UrlDecode(g);
		for (let v in normal_nodes) {
			let gn = (isset(v.group) && v.group != "") ? v.group : "default";
			if (lc(gn) == lc(g) && match_node_rule(v.remarks, node.node_match_rule))
				push(nodes, v.id);
		}
	}
	return nodes;
};

get_socks_backup_nodes = function(id) {
	id = trim(as_str(id) ?? "");
	if (id == "")
		return "";
	let socks = uci_get_c(id);
	if (type(socks) != "object" || socks == null)
		return "";
	let nodes;
	if (isset(socks.backup_node_add_mode) && socks.backup_node_add_mode == "batch") {
		nodes = get_batch_nodes({
			node_group: socks.backup_node_group,
			node_match_rule: socks.backup_node_match_rule
		});
	} else {
		nodes = socks.autoswitch_backup_node;
	}
	if (type(nodes) == "string")
		nodes = [nodes];
	let backup = [];
	let seen = {};
	if (type(nodes) == "array") {
		for (let v in nodes) {
			if (v != socks.node && seen[v] != true) {
				seen[v] = true;
				push(backup, v);
			}
		}
	}
	return join(" ", backup) ?? "";
};

get_core = function(field, candidates) {
	if (type(candidates) != "array")
		return null;
	let v = uci_get_c("@global_subscribe[0]", field);
	if (isset(v) && v != "") {
		for (let c in candidates) {
			if (type(c) == "array" && c[0] && c[1] == v)
				return v;
		}
	}
	for (let c in candidates) {
		if (type(c) == "array" && c[0])
			return c[1];
	}
	return null;
};

cleanEmptyTables = function(t) {
	let kind = type(t);
	if (kind != "array" && kind != "object")
		return null;
	if (kind == "array") {
		let kept = [];
		for (let v in t) {
			if (type(v) == "array" || type(v) == "object")
				v = cleanEmptyTables(v);
			if (v != null)
				push(kept, v);
		}
		if (length(kept) == 0)
			return null;
		splice(t, 0, length(t));
		for (let v in kept)
			push(t, v);
		return t;
	}
	let ks = keys(t);
	if (ks != null) {
		for (let k in ks) {
			let v = t[k];
			if (type(v) == "array" || type(v) == "object") {
				v = cleanEmptyTables(v);
				if (v == null)
					delete t[k];
				else
					t[k] = v;
			}
		}
	}
	let left = keys(t);
	if (left == null || length(left) == 0)
		return null;
	return t;
};

fetch_cert_sha256 = function(host, port, sni, timeout, http3) {
	if (host === null || host === false)
		return "";
	if (port === null || port === false || port === "")
		port = 443;
	else {
		port = int(port);
		if (port != port)
			port = 443;
	}
	if (sni === null || sni === false)
		sni = host;
	if (timeout === null || timeout === false || timeout === "")
		timeout = 5;
	else {
		timeout = int(timeout);
		if (timeout != timeout)
			timeout = 5;
	}
	let awk = "awk 'BEGIN{c=0}/BEGIN CERT/{c++} c==1{print} /END CERT/{if(c==1)exit}'";
	let cmd;
	if (http3) {
		cmd = "timeout " + timeout + " curl --http3 -k -w '%{certs}' -o /dev/null https://" + host + ":" + port + " 2>/dev/null | " + awk + " | openssl x509 -outform der 2>/dev/null | sha256sum 2>/dev/null";
	} else {
		cmd = "timeout " + timeout + " openssl s_client -connect " + host + ":" + port + " -servername " + sni + " -showcerts </dev/null 2>/dev/null | " + awk + " | openssl x509 -outform der 2>/dev/null | sha256sum 2>/dev/null";
	}
	let out = trim(sys_exec(cmd));
	let m = match(out, /^([0-9a-fA-F]+)/);
	if (m == null)
		return "";
	let fp = m[1];
	if (match(lc(fp), /^e3b0c44298fc1c149afbf4c8996fb924/) != null)
		return "";
	return uc(fp);
};

sha256_xray_sb = function(str) {
	if (type(str) != "string")
		return str;
	let decoded = base64Decode(str);
	if (decoded != str && length(decoded) == 32)
		return str;
	let hexbody = replace(str, ":", "");
	if (length(hexbody) != 64 || match(hexbody, /^[A-Fa-f0-9]+$/) == null)
		return str;
	let binary = null;
	if (type(hexdec) == "function")
		binary = hexdec(hexbody);
	if (type(binary) != "string" || length(binary) != 32) {
		binary = "";
		for (let i = 0; i < length(hexbody); i += 2)
			binary += chr(hex(substr(hexbody, i, 2)));
	}
	let enc = base64Encode(binary);
	if (enc == null)
		return str;
	return enc;
};

sha256_sb_xray = function(str) {
	if (type(str) != "string")
		return str;
	let binary = base64Decode(str);
	if (binary == str || length(binary) != 32)
		return str;
	if (type(hexenc) == "function") {
		let h = hexenc(binary);
		if (type(h) == "string")
			return uc(h);
	}
	let out = "";
	for (let i = 0; i < length(binary); i++)
		out += sprintf("%02X", ord(binary, i));
	return out;
};

vps_domain_exclude = function(domain) {
	domain = trim(as_str(domain) ?? "");
	if (domain == "")
		return true;
	let map = {
		"engage.cloudflareclient.com": 1,
		"google.com": 1,
		"youtube.com": 1,
		"github.com": 1,
		"telegram.org": 1,
		"cloudflare.com": 1,
		"bing.com": 1,
		"x.com": 1,
		"dns.google": 1,
		"opendns.com": 1,
		"cloudflare-dns.com": 1,
		"one.one.one.one": 1,
		"quad9.net": 1,
		"adguard-dns.com": 1,
		"nextdns.io": 1,
		"libredns.gr": 1
	};
	while (true) {
		if (map[domain] != null)
			return true;
		let p = index(domain, ".");
		if (p < 0)
			break;
		domain = substr(domain, p + 1);
	}
	return false;
};

parse_realm_uri = function(uri) {
	uri = trim(as_str(uri) ?? "");
	if (uri == "")
		return null;
	let scheme = null;
	if (match(uri, /^realm\+http:\/\//) != null)
		scheme = "realm+http";
	else if (match(uri, /^realm:\/\//) != null)
		scheme = "realm";
	if (scheme == null)
		return null;
	uri = replace(uri, /^realm\+http:\/\//, "");
	uri = replace(uri, /^realm:\/\//, "");
	let m = match(uri, /^([^@]+)@([^/]+)\/([^?]*)\??(.*)$/);
	if (m == null || m[1] == null || m[2] == null || m[3] == null)
		return null;
	let token = m[1];
	let server_url = m[2];
	let realm_id = replace(m[3], /\/+$/, "");
	let query = m[4] ?? "";
	let address = null;
	let port = null;
	let v6 = match(server_url, /^\[([^]]+)\]:([0-9]+)$/);
	if (v6 != null) {
		address = v6[1];
		port = v6[2];
	} else {
		let v4 = match(server_url, /^([^:]+):([0-9]+)$/);
		if (v4 != null) {
			address = v4[1];
			port = v4[2];
		}
	}
	if (address == null) {
		let bare = match(server_url, /^\[([^]]+)\]$/);
		address = bare != null ? bare[1] : server_url;
	}
	if (port === null || port === "")
		port = scheme == "realm+http" ? 80 : 443;
	else {
		port = int(port);
		if (port != port)
			port = scheme == "realm+http" ? 80 : 443;
	}
	let realm = {
		scheme: scheme,
		token: token,
		server_url: server_url,
		address: address,
		port: port,
		realm_id: realm_id
	};
	let stun_servers = null;
	let stuns = match(query, /[Ss][Tt][Uu][Nn]=([^&]+)/g);
	if (stuns != null) {
		for (let item in stuns) {
			let v = type(item) == "array" ? item[1] : item;
			if (stun_servers == null)
				stun_servers = [];
			push(stun_servers, v);
		}
	}
	realm.stun_servers = stun_servers;
	return realm;
};

get_network_devices = function() {
	let sysnet = "/sys/class/net/";
	let iface_to_dev = {};
	let dev_to_ifaces = {};
	let iface_proto = {};
	uci.foreach("network", "interface", function(sec) {
		let name = sec[".name"];
		if (name != "loopback") {
			iface_proto[name] = sec.proto;
			if (isset(sec.device) && sec.device != "") {
				iface_to_dev[name] = sec.device;
				if (dev_to_ifaces[sec.device] == null)
					dev_to_ifaces[sec.device] = [];
				push(dev_to_ifaces[sec.device], name);
			}
		}
	});
	function classify_sysfs(dev) {
		if (fs_stat(sysnet + dev + "/bridge", "type") == "dir")
			return translate("Bridge");
		if (fs_stat(sysnet + dev + "/wireless", "type") == "dir")
			return translate("Wireless Adapter");
		if (match(dev, /^tun/) != null || match(dev, /^tap/) != null || match(dev, /^wg/) != null || match(dev, /^ppp/) != null)
			return translate("Tunnel Interface");
		return translate("Ethernet Adapter");
	}
	function classify_uci(dev_name, proto) {
		if (isset(dev_name) && match(dev_name, /^br-/) != null)
			return translate("Bridge");
		if (proto == "wireguard" || proto == "pppoe" || proto == "pptp" || proto == "l2tp")
			return translate("Tunnel Interface");
		return translate("Interface");
	}
	let seen = {};
	let devices = [];
	let names = lsdir(sysnet);
	if (names != null) {
		for (let dev in names) {
			if (dev == "." || dev == ".." || dev == "lo")
				continue;
			if (match(dev, /^veth/) != null || match(dev, /^ifb/) != null || match(dev, /^gre/) != null || match(dev, /^sit/) != null || match(dev, /^ip6tnl/) != null || match(dev, /^erspan/) != null)
				continue;
			if (stat(sysnet + dev + "/master") != null || stat(sysnet + dev + "/dsa") != null)
				continue;
			let dtype = classify_sysfs(dev);
			let label = dtype + ': "' + dev + '"';
			if (dev_to_ifaces[dev] != null)
				label = label + " (" + join(", ", dev_to_ifaces[dev]) + ")";
			push(devices, { name: dev, label: label, sort: dtype + ":" + dev });
			seen[dev] = true;
		}
	}
	for (let iface, dev in iface_to_dev) {
		if (seen[dev] != true) {
			let dtype = classify_uci(dev, iface_proto[iface]);
			let label = dtype + ': "' + iface + '"';
			push(devices, { name: iface, label: label, sort: "zzz:" + iface });
			seen[dev] = true;
		}
	}
	sort(devices, function(a, b) {
		if (a.sort < b.sort)
			return -1;
		if (a.sort > b.sort)
			return 1;
		return 0;
	});
	return devices;
};

table_remove_duplicates = function(t) {
	if (t == null || type(t) != "array" || length(t) == 0)
		return null;
	let seen = {};
	let out = [];
	for (let x in t) {
		if (type(x) == "string" && length(x) > 0 && seen[x] == null) {
			seen[x] = x;
			push(out, x);
		}
	}
	return out;
};

gen_wireguard_key = function() {
	if (sys_call("command -v wg >/dev/null") == 0) {
		let private_key = sys_exec("echo -n $(wg genkey)");
		let public_key = sys_exec("echo -n $(echo \"" + private_key + "\" | wg pubkey)");
		return { private_key: private_key, public_key: public_key };
	}
	let xray = finded_com("xray");
	if (xray != null) {
		let result = sys_exec(xray + " wg | awk -F ': ' '{print $2}'");
		let s = split(result, "\n");
		return { private_key: s[0], public_key: s[1] };
	}
	let sb = finded_com("sing-box");
	if (sb != null) {
		let result = sys_exec(sb + " generate wg-keypair | awk '{print $2}'");
		let s = split(result, "\n");
		return { private_key: s[0], public_key: s[1] };
	}
	return null;
};

get_socks_port_by_cache = function(node_id) {
	return get_cache_var(sprintf("node_%s_socks_port", node_id));
};

set_socks_port_to_cache = function(node_id, v) {
	set_cache_var(sprintf("node_%s_socks_port", node_id), v);
};
export { shellquote, trim, split, log, is_old_uci, uci_del, uci_get, uci_set, uci_del_c, uci_foreach_c, uci_get_c, uci_set_c, uci_save_c, uci_del_s, uci_foreach_s, uci_get_s, uci_set_s, uci_save_s, sh_uci_commit, uci_save, sh_uci_get, sh_uci_set, sh_uci_del, sh_uci_add_list, del_cache_var, set_cache_var, get_cache_var, get_new_port, exec_call, exec_call_as_gid, base64Decode, base64Encode, UrlEncode, UrlDecode, md5_file, md5_string, get_domain_port_from_url, resolve_domain, table_join, curl_base, curl_proxy, curl_direct, curl_logic, curl_auto, is_exist, repeat_exist, remove, is_install, get_args, get_function_args, strToTable, is_normal_node, is_special_node, is_ip, is_ipv6, is_local_ip, is_ipv6addrport, get_ipv6_only, get_ipv6_full, get_ip_type, is_mac, ip_or_mac, iprange, get_domain_from_url, get_valid_nodes, get_node_list, get_node_remarks, get_full_node_remarks, get_random_normal_node, gen_uuid, gen_random_char, chmod_755, get_customed_path, get_app_path, get_bin_version_cache, get_app_version, finded_com, finded, is_finded, clone, _unpack, compare_versions, parseURL, parseDoH, to_check, to_download, to_download_progress, to_extract, to_move, get_version, to_check_self, to_install_self, get_std_domain, format_go_time, match_node_rule, get_batch_nodes, get_socks_backup_nodes, get_core, cleanEmptyTables, fetch_cert_sha256, sha256_xray_sb, sha256_sb_xray, vps_domain_exclude, parse_realm_uri, get_network_devices, table_remove_duplicates, gen_wireguard_key, get_socks_port_by_cache, set_socks_port_to_cache };
