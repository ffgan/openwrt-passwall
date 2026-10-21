'use strict';

import * as fs from 'fs';
import * as api from 'passwall.api';

export const CONFIG = 'passwall';
export const DIRECT_GID = 9911;
export const APP_PATH = '/usr/share/passwall';
export const UCODE_BIN = '/usr/libexec/passwall';
export const TMP_PATH = '/tmp/etc/passwall';
export const TMP_PATH2 = TMP_PATH + '_tmp';
export const LOCK_PATH = '/var/lock';
export const LOG_FILE = '/tmp/log/passwall.log';
export const TMP_ACL_PATH = TMP_PATH + '/acl';
export const TMP_BIN_PATH = TMP_PATH + '/bin';
export const TMP_IFACE_PATH = TMP_PATH + '/iface';
export const TMP_ROUTE_PATH = TMP_PATH + '/route';
export const TMP_SCRIPT_FUNC_PATH = TMP_PATH + '/script_func';
export const RULES_PATH = '/usr/share/passwall/rules';
export const USER_RULES_PATH = '/etc/passwall/rules';

function str(v, fallback) {
	return v == null ? (fallback ?? '') : '' + v;
}

export function run(argv, quiet) {
	let rc;
	if (type(global.system) == 'function')
		rc = global.system(argv);
	else {
		let ph = fs.popen(argv, 'r');
		rc = ph == null ? 255 : ph.close();
	}
	rc = rc == null ? 255 : rc;
	if (rc != 0 && !quiet)
		api.log('命令执行失败 (' + rc + '): ' + join(' ', argv));
	return rc;
}

export function output(argv) {
	let ph = fs.popen(argv, 'r');
	if (ph == null)
		return '';
	let data = ph.read('all') ?? '';
	ph.close();
	return data;
}

export function launch(argv, name, logfile, env) {
	let args = ['/usr/bin/ucode', UCODE_BIN + '/ln_run.uc', argv[0], name ?? argv[0], logfile ?? '/dev/null'];
	for (let i = 1; i < length(argv); i++)
		push(args, str(argv[i]));
	if (type(env) == 'object' && length(keys(env))) {
		let with_env = ['/usr/bin/env'];
		for (let key, value in env)
			push(with_env, key + '=' + str(value));
		for (let arg in args)
			push(with_env, arg);
		args = with_env;
	}
	return run(args, true);
}

export function clean_log() {
	let data = fs.readfile(LOG_FILE) ?? '';
	if (length(split(data, '\n')) > 1001) {
		fs.writefile(LOG_FILE, '');
		api.log('日志文件过长，清空处理！');
	}
}

export function pkg_installed(pkg) {
	if (pkg == null || pkg == '')
		return false;
	if ((fs.stat('/lib/apk/db/installed')?.size ?? 0) > 0)
		return (fs.stat('/lib/apk/packages/' + pkg + '.list')?.size ?? 0) > 0;
	return (fs.stat('/usr/lib/opkg/info/' + pkg + '.control')?.size ?? 0) > 0;
}

export function config_get_type(section, fallback) {
	let got = api.uci_get_c(section);
	return got?.['.type'] ?? fallback ?? '';
}

export function config_n_get(section, option, fallback) {
	return str(api.uci_get_c(section, option), fallback);
}

export function config_t_get(type_name, option, fallback, index) {
	return config_n_get('@' + type_name + '[' + (index ?? 0) + ']', option, fallback);
}

export function del_cache_var(key) {
	let data = fs.readfile(TMP_PATH + '/var') ?? '';
	let kept = [];
	for (let line in split(data, '\n'))
		if (match(line, regexp('^' + replace(str(key), /[][(){}.^$*+?|\\]/g, '\\$&') + '=')) == null && line != '')
			push(kept, line);
	if (length(kept))
		fs.writefile(TMP_PATH + '/var', join('\n', kept) + '\n');
	else
		fs.unlink(TMP_PATH + '/var');
}

function decode_cache(value) {
	if (length(value) >= 2 && substr(value, 0, 1) == "'" && substr(value, -1) == "'") {
		value = substr(value, 1, length(value) - 2);
		value = replace(value, /'\\''/g, "'");
	}
	return value;
}

export function cache_all() {
	let out = {};
	for (let line in split(fs.readfile(TMP_PATH + '/var') ?? '', '\n')) {
		let m = match(line, /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
		if (m != null)
			out[m[1]] = decode_cache(m[2]);
	}
	return out;
}

export function set_cache_var(key, value) {
	if (key == null || key == '')
		return;
	del_cache_var(key);
	value = str(value);
	if (value == '')
		return;
	api.fs.mkdirr(TMP_PATH);
	let fh = fs.open(TMP_PATH + '/var', 'a');
	if (fh != null) {
		fh.write(key + '=' + api.shellquote(value) + '\n');
		fh.close();
	}
}

export function get_cache_var(key) {
	return cache_all()[key];
}

export function first_type(primary, fallback) {
	let names = [primary, fallback];
	let dirs = [], seen = {};
	let path_env = type(global.getenv) == 'function' ? global.getenv('PATH') : null;
	for (let dir in split(path_env ?? '', ':')) {
		dir = replace(dir, /\/+$/, '');
		if (dir != '' && !seen[dir]) {
			seen[dir] = true;
			push(dirs, dir);
		}
	}
	for (let dir in ['/bin', '/sbin', '/usr/bin', '/usr/sbin', TMP_BIN_PATH])
		if (!seen[dir]) {
			seen[dir] = true;
			push(dirs, dir);
		}
	for (let name in names) {
		if (name == null || name == '')
			continue;
		if (index(name, '/') >= 0 && fs.access(name, 'x'))
			return name;
		for (let dir in dirs) {
			let path = dir + '/' + name;
			if (fs.access(path, 'x'))
				return path;
		}
	}
	return '';
}

export function get_enabled_anonymous_secs(section_type) {
	let out = [];
	api.uci_foreach_c(section_type, function(s) {
		if (s.enabled == '1')
			push(out, s['.name']);
	});
	return out;
}

export function get_geoip(code, family) {
	let dir = TMP_PATH2 + '/geo_output';
	let dest = dir + '/geoip-' + code + '-' + family;
	api.fs.mkdirr(dir);
	if ((fs.stat(dest)?.size ?? 0) == 0) {
		let asset = config_n_get('@global_rules[0]', 'v2ray_location_asset');
		let geoip = replace(asset, /\/+$/, '') + '/geoip.dat';
		let bin = first_type(config_n_get('@global_app[0]', 'geoview_file'), 'geoview');
		if (bin == '' || (fs.stat(geoip)?.size ?? 0) == 0)
			return '';
		let argv = [bin, '-input', geoip, '-list', code];
		if (family == 'ipv4')
			push(argv, '-ipv6=false');
		else if (family == 'ipv6')
			push(argv, '-ipv4=false');
		push(argv, '-lowmem=true', '-output', dest);
		run(argv, true);
	}
	return fs.readfile(dest) ?? '';
}

export function is_ipv4(host) {
	let p = split(str(host), '.');
	if (length(p) != 4)
		return false;
	for (let n in p)
		if (match(n, /^[0-9]+$/) == null || int(n) < 0 || int(n) > 255)
			return false;
	return true;
}

export function is_ipv6(host) {
	host = replace(replace(str(host), /^\[/, ''), /\]$/, '');
	return index(host, ':') >= 0 && match(host, /^[0-9A-Fa-f:.%]+$/) != null;
}

export function get_host_ip(family, host, count) {
	host = replace(replace(str(host), /^\[/, ''), /\]$/, '');
	if ((family == 'ipv6' && is_ipv6(host)) || (family != 'ipv6' && is_ipv4(host)))
		return host;
	let got = output(['resolveip', family == 'ipv6' ? '-6' : '-4', '-t', str(count, '3'), host]);
	for (let line in split(trim(got), /[[:space:]]+/))
		if (line != '')
			return line;
	return '';
}

export function get_node_host_ip(node) {
	let host = config_n_get(node, 'address');
	if (host == '')
		return '';
	return get_host_ip(config_n_get(node, 'use_ipv6') == '1' ? 'ipv6' : 'ipv4', host);
}

export function get_ip_port_from(value, uci_priority) {
	let host = str(value), port = '';
	let m;
	if ((m = match(host, /^(.*)#([^#]+)$/)) != null) {
		host = m[1]; port = m[2];
	} else if ((m = match(host, /^\[(.*)\]:([0-9]+)$/)) != null) {
		host = m[1]; port = m[2];
	} else if ((m = match(host, /^([^:]+):([0-9]+)$/)) != null) {
		host = m[1]; port = m[2];
	}
	if (uci_priority) {
		port = config_n_get(value, 'port', port);
		host = config_n_get(value, 'address', host);
	}
	return { host: replace(replace(host, /^\[/, ''), /\]$/, ''), port: port };
}

export function parse_doh(value) {
	value = replace(str(value), /[ \t\r\n]/g, '');
	let parts = split(value, ',');
	let url = parts[0] ?? '';
	let bootstrap = parts[1] ?? '';
	let hp = api.get_domain_from_url(url) ?? '';
	let parsed = get_ip_port_from(hp);
	if (parsed.port == '')
		parsed.port = '443';
	if (is_ipv4(parsed.host) || is_ipv6(parsed.host))
		bootstrap = parsed.host;
	return { url: url, host: parsed.host, port: parsed.port, bootstrap: replace(replace(bootstrap, /^\[/, ''), /\]$/, '') };
}

export function host_from_url(value) {
	let s = replace(str(value), /^[^:]+:\/\//, '');
	s = split(s, /[\/?#]/)[0] ?? '';
	let at = split(s, '@');
	s = at[length(at) - 1] ?? '';
	let m = match(s, /^\[([^\]]+)\]/);
	if (m != null)
		return m[1];
	return split(s, ':')[0] ?? '';
}

export function hosts_foreach(values, default_port, callback, extra) {
	let rc = 0;
	for (let value in split(str(values), /[ ,]+/)) {
		if (value == '') continue;
		let parsed = get_ip_port_from(value);
		rc = callback(value, parsed.host, parsed.port || str(default_port), ...(extra ?? [])) ?? 0;
		if (rc >= 1) return rc;
	}
	return rc;
}

export function check_host(host) {
	return index(str(host), '/') < 0 && match(str(host), /^[\x21-\x7e]+$/) != null;
}

export function normalize_dns(value, default_port) {
	let p = get_ip_port_from(value);
	if (p.port == '')
		p.port = str(default_port);
	return p.host + (p.port == '' ? '' : '#' + p.port);
}

export function format_dns(value, default_port) {
	let p = get_ip_port_from(normalize_dns(value, default_port ?? 53));
	return (is_ipv6(p.host) ? '[' + p.host + ']' : p.host) + ':' + (p.port || '53');
}

export function check_port_exists(port, protocol) {
	let argv = ['netstat'];
	if (protocol == 'tcp')
		push(argv, '-tln');
	else if (protocol == 'udp')
		push(argv, '-uln');
	else
		push(argv, '-tuln');
	let needle = ':' + port;
	for (let line in split(output(argv), '\n'))
		if (index(line, needle) >= 0 && match(line, regexp(':' + port + '[[:space:]]')) != null)
			return true;
	return false;
}

export function get_new_port(start_port, protocol) {
	const min_port = 1025, max_port = 49151, default_port = 2001;
	let automatic = start_port == null || start_port == 'auto';
	let port = automatic ? int(get_cache_var('last_get_new_port_auto') ?? (default_port - 1)) + 1 : int(start_port);
	if (port != port || port < min_port || port > max_port)
		port = default_port;
	let start = port;
	while (true) {
		if (!check_port_exists(port, protocol ?? 'tcp,udp') && (!automatic || get_cache_var('get_port_' + port) == null))
			break;
		port = port < max_port ? port + 1 : min_port;
		if (port == start)
			return null;
	}
	if (automatic) {
		set_cache_var('get_port_' + port, '1');
		set_cache_var('last_get_new_port_auto', port);
	}
	return port;
}

export function check_ver(a, b) {
	let av = split(str(a), '.'), bv = split(str(b), '.');
	for (let i = 0; i < 3; i++) {
		let x = int(av[i] ?? 0), y = int(bv[i] ?? 0);
		if (x > y) return 0;
		if (x < y) return 1;
	}
	return 255;
}

export function has_1_65535(value) {
	for (let item in split(replace(str(value), /:/g, '-'), ','))
		if (item == '1-65535')
			return true;
	return false;
}

function interface_status(iface) {
	let raw = output(['ubus', 'call', 'network.interface.' + iface, 'status']);
	return json(raw) ?? {};
}

export function add_ip2route(host, iface) {
	let ip = get_host_ip('ipv4', host);
	if (ip == '') {
		api.log('  - 无法解析[' + host + ']，路由表添加失败！');
		return 1;
	}
	let status = interface_status(iface);
	let gateway = '';
	for (let route in status.route ?? []) {
		let target = route.target ?? '';
		let mask = route.mask;
		if (route.nexthop && (
			target == 'default' ||
			target == '0.0.0.0/0' ||
			(target == '0.0.0.0' && (mask == null || int(mask) == 0))
		)) {
			gateway = route.nexthop;
			break;
		}
	}
	let device = status.l3_device ?? status.device ?? iface;
	let remarks = host == ip ? host : host + '(' + ip + ')';
	if (gateway != '' && run(['route', 'add', '-host', ip, 'gw', gateway, 'dev', device], true) == 0) {
		api.fs.mkdirr(TMP_ROUTE_PATH);
		let fh = fs.open(TMP_ROUTE_PATH + '/' + device, 'a');
		if (fh != null) { fh.write(ip + '\n'); fh.close(); }
		api.log('  - [' + remarks + ']添加到接口[' + device + ']路由表成功！');
		return 0;
	}
	api.log('  - [' + remarks + ']添加到接口[' + device + ']路由表失败！' + (gateway == '' ? '原因是找不到[' + device + ']网关。' : ''));
	return 1;
}

export function delete_ip2route() {
	for (let device in fs.lsdir(TMP_ROUTE_PATH) ?? [])
		for (let ip in split(fs.readfile(TMP_ROUTE_PATH + '/' + device) ?? '', '\n'))
			if (ip != '')
				run(['route', 'del', '-host', ip, 'dev', device], true);
}

export function get_process_start_time(pid) {
	let data = fs.readfile('/proc/' + pid + '/stat') ?? '';
	let end = rindex(data, ') ');
	let fields = end < 0 ? [] : split(substr(data, end + 2), ' ');
	return fields[19] ?? '';
}

export function shell_quote(value) {
	return api.shellquote(value);
}

export function ln_run(argv) {
	if (type(argv) != 'array' || length(argv) < 3)
		return 1;
	return run(['/usr/bin/ucode', UCODE_BIN + '/ln_run.uc', ...argv], true);
}

export function kill_all(names) {
	if (type(names) != 'array') names = [names];
	let rc = 0;
	for (let name in names) {
		let pids = split(trim(output(['pidof', name])), /[[:space:]]+/);
		for (let pid in pids)
			if (pid != '') rc = run(['kill', '-9', pid], true);
	}
	return rc;
}

export function gen_lanlist(family) {
	let path = USER_RULES_PATH + (family == 'ip6' ? '/lanlist_ipv6' : '/lanlist_ipv4');
	let out = [];
	for (let line in split(fs.readfile(path) ?? '', '\n'))
		if (line != '' && substr(line, 0, 1) != '#')
			push(out, line);
	return out;
}

export function get_wan_ips(family) {
	let dump = json(output(['ubus', 'call', 'network.interface', 'dump'])) ?? {};
	let out = [], seen = {};
	for (let iface in dump.interface ?? []) {
		if (index(iface.interface ?? '', 'lan') >= 0 || !length(iface.route ?? []))
			continue;
		let values = family == 'ip6' ? iface['ipv6-address'] : iface['ipv4-address'];
		for (let item in values ?? []) {
			let addr = item.address ?? '';
			if (addr != '' && addr != '0.0.0.0' && addr != '::' && substr(addr, 0, 5) != 'fe80:' && !seen[addr]) {
				seen[addr] = true;
				push(out, addr);
			}
		}
	}
	return out;
}

export function get_local_ips(family) {
	let args = ['ip', '-o', family == 'ip6' ? '-6' : '-4', 'addr', 'show', 'scope', 'global'];
	let wan = {};
	for (let ip in get_wan_ips(family))
		wan[ip] = true;
	let out = [], seen = {};
	for (let line in split(output(args), '\n')) {
		let m = match(line, /\sinet6?\s+([^\/ ]+)/);
		if (m != null && !wan[m[1]] && !seen[m[1]]) {
			seen[m[1]] = true;
			push(out, m[1]);
		}
	}
	let loop = family == 'ip6' ? '::1' : '127.0.0.1';
	if (!wan[loop] && !seen[loop])
		push(out, loop);
	return out;
}
