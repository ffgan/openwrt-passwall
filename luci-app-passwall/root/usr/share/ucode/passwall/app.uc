'use strict';

import * as fs from 'fs';
import * as api from 'passwall.api';
import * as utils from 'passwall.utils';

const TMP = utils.TMP_PATH;
const ACL = utils.TMP_ACL_PATH;
const GLOBAL_ACL = ACL + '/default';
const LIBEXEC = utils.UCODE_BIN;
const UTIL = {
	'sing-box': LIBEXEC + '/util_singbox.uc',
	xray: LIBEXEC + '/util_xray.uc',
	naiveproxy: LIBEXEC + '/util_naiveproxy.uc',
	ss: LIBEXEC + '/util_shadowsocks.uc',
	hysteria2: LIBEXEC + '/util_hysteria2.uc'
};

let state = {};

function cfg(section, option, fallback) {
	return utils.config_n_get(section, option, fallback);
}

function stype(section) {
	return utils.config_get_type(section);
}

function lower(value) {
	return lc(trim(value ?? ''));
}

function option_args(argv) {
	let out = {};
	for (let raw in argv ?? []) {
		for (let arg in split(raw, /[[:space:]]+/)) {
			let p = index(arg, '=');
			if (p > 0)
				out[substr(arg, 0, p)] = substr(arg, p + 1);
		}
	}
	return out;
}

function command_output(argv) {
	return utils.output(argv);
}

function command(argv, quiet) {
	return utils.run(argv, quiet);
}

function capture(argv, destination) {
	let ph = api.command_pipe(argv, 'r');
	if (ph == null) return 127;
	let data = ph.read('all') ?? '';
	let rc = ph.close();
	fs.writefile(destination, data);
	return rc ?? 255;
}

function generate(util, action, object, destination) {
	let got = command_output(['/usr/bin/ucode', util, action, sprintf('%J', object)]);
	if (destination != null)
		return fs.writefile(destination, got) ? 0 : 1;
	print(got);
	return 0;
}

function helper_output(script, args, destination) {
	let argv = ['/usr/bin/ucode', LIBEXEC + '/' + script];
	for (let arg in args)
		push(argv, '' + arg);
	let got = command_output(argv);
	if (destination != null)
		return fs.writefile(destination, got) ? 0 : 1;
	print(got);
	return 0;
}

function mkdirs() {
	for (let dir in ['/tmp/etc', '/tmp/log', TMP, utils.TMP_BIN_PATH, utils.TMP_SCRIPT_FUNC_PATH,
	                 utils.TMP_ROUTE_PATH, ACL, utils.TMP_PATH2])
		api.fs.mkdirr(dir);
}

function append(path, text) {
	let fh = fs.open(path, 'a');
	if (fh != null) {
		fh.write(text);
		fh.close();
	}
}

function unlink_tree(path) {
	command(['rm', '-rf', path], true);
}

function bin(name, fallback) {
	return utils.first_type(cfg('@global_app[0]', name + '_file'), fallback ?? name);
}

function launch_core(file, name, logfile, args, env) {
	let asset = cfg('@global_rules[0]', 'v2ray_location_asset', '/usr/share/v2ray/');
	let launch_env = {
		V2RAY_LOCATION_ASSET: asset, XRAY_LOCATION_ASSET: asset,
		ENABLE_DEPRECATED_GEOSITE: 'true', ENABLE_DEPRECATED_GEOIP: 'true',
		SS_SYSTEM_DNS_RESOLVER_FORCE_BUILTIN: '1'
	};
	if (state.NO_REC_PROCESS == '1' || (type(global.getenv) == 'function' && global.getenv('NO_REC_PROCESS') == '1'))
		launch_env.NO_REC_PROCESS = '1';
	for (let key, value in env ?? {}) launch_env[key] = value;
	return utils.launch([file, ...args], name, logfile, launch_env);
}

export function check_run_environment() {
	let info = command_output(['dnsmasq', '-v']);
	let ver = match(info, /[Vv]ersion\s+([0-9.]+)/)?.[1] ?? '';
	let dns_nftset = match(info, /(^|[[:space:]])nftset([[:space:]]|$)/) != null;
	let has_fw4 = utils.first_type('fw4') != '';
	state.nftflag = '1';
	if (!(dns_nftset && has_fw4)) {
		api.log('警告：透明代理需要 firewall4，以及带 nftset 的 Dnsmasq。(has_fw4:' + (+has_fw4) + '/dnsmasq_nftset:' + (+dns_nftset) + ')');
		state.USE_TABLES = '';
		return '';
	}
	for (let dep in ['kmod-nft-socket', 'kmod-nft-tproxy', 'kmod-nft-nat', 'kmod-nf-reject', 'kmod-nf-reject6'])
		if (!utils.pkg_installed(dep))
			api.log('警告：nftables 透明代理缺失基础依赖 ' + dep + '！');
	if (utils.check_ver(ver, '2.92') == 1)
		api.log('提示：Dnsmasq (' + ver + ') 低于 2.92，建议升级以增强稳定性。');
	state.USE_TABLES = 'nftables';
	return 'nftables';
};

export function run_ipt2socks(raw) {
	let o = type(raw) == 'object' && type(raw) != 'array' ? raw : option_args(raw);
	let host = utils.get_host_ip('ipv4', o.socks_address);
	let args = ['-l', o.local_port, '-b', '0.0.0.0', '-B', '::', '-s', host, '-p', o.socks_port, '-o', '60', '-n', '65535', '-v'];
	if (o.socks_username != null && o.socks_password != null)
		push(args, '-a', o.socks_username, '-k', o.socks_password);
	if (o.tcp_tproxy == null || o.tcp_tproxy == '')
		push(args, '-R');
	return launch_core(utils.first_type('ipt2socks'), 'ipt2socks_' + (o.flag ?? '') + '_TCP_UDP', o.log_file || '/dev/null', args);
};

function dns_fields(o, target) {
	let local = o.direct_dns_udp_server ?? o.direct_dns_tcp_server ?? state.LOCAL_DNS;
	let p = utils.get_ip_port_from(local);
	if (o.direct_dns_tcp_server != null)
		target.direct_dns_tcp_server = p.host;
	else
		target.direct_dns_udp_server = p.host;
	target.direct_dns_port = p.port || '53';
	target.direct_dns_query_strategy = o.direct_dns_query_strategy || 'UseIP';
	for (let key in ['remote_dns_query_strategy', 'remote_dns_client_ip', 'dns_cache'])
		if (o[key] != null && o[key] != '') target[key] = o[key];
	if (o.remote_fakedns == '1') target.remote_dns_fake = '1';
	if (o.remote_rewrite_ttl != null && o.remote_rewrite_ttl != '') target.remote_rewrite_ttl = o.remote_rewrite_ttl;
	let proto = o.remote_dns_protocol;
	let remote;
	if (proto == 'udp' || proto == 'quic') {
		remote = utils.get_ip_port_from(o.remote_dns_udp_server);
		target.remote_dns_udp_server = remote.host;
		target.remote_dns_udp_port = remote.port || (proto == 'quic' ? '853' : '53');
		if (proto == 'quic') target.remote_dns_quic = '1';
	} else if (proto == 'tcp' || proto == 'tls') {
		remote = utils.get_ip_port_from(o.remote_dns_tcp_server);
		target.remote_dns_tcp_server = remote.host;
		target.remote_dns_tcp_port = remote.port || (proto == 'tls' ? '853' : '53');
		if (proto == 'tls') target.remote_dns_tls = '1';
	} else if (proto == 'doh' || proto == 'http3') {
		target.remote_dns_doh = o.remote_dns_doh;
		if (proto == 'http3') target.remote_dns_http3 = '1';
	}
}

function core_config(o, kind) {
	let c = {};
	if (kind == 'sing-box') {
		c.log = o.log_file && o.log_file != '/dev/null' ? '1' : '0';
		if (c.log == '1') c.logfile = o.log_file;
	}
	c.loglevel = o.loglevel || (kind == 'xray' ? 'warning' : 'warn');
	let copy = {
		flag: 'flag', node: 'node', use_proxy_list: 'use_proxy_list', use_gfw_list: 'use_gfw_list',
		chn_list: 'chn_list', server_host: 'server_host', server_port: 'server_port',
		redir_port: 'redir_port', tcp_proxy_way: 'tcp_proxy_way', socks_address: 'local_socks_address',
		socks_port: 'local_socks_port', socks_username: 'local_socks_username',
		socks_password: 'local_socks_password', http_address: 'local_http_address',
		http_port: 'local_http_port', http_username: 'local_http_username',
		http_password: 'local_http_password', dns_socks_address: 'dns_socks_address',
		dns_socks_port: 'dns_socks_port', dns_listen_port: 'dns_listen_port'
	};
	for (let from, to in copy)
		if (o[from] != null && o[from] != '') c[to] = o[from];
	dns_fields(o, c);
	if (o.no_run) c.no_run = '1';
	if (o.run_in_global) c.run_in_global = '1';
	return c;
}

function run_core(kind, raw) {
	let o = type(raw) == 'object' && type(raw) != 'array' ? raw : option_args(raw);
	if (!o.type) {
		o.type = lower(cfg(o.node, 'type'));
		if (o.type != kind && bin(kind == 'sing-box' ? 'sing_box' : 'xray', kind) != '')
			o.type = kind;
	}
	if (!o.type || !o.config_file)
		return 1;
	o.log_file = o.log_file || '/dev/null';
	generate(UTIL[kind], 'gen_config', core_config(o, kind), o.config_file);
	if (o.no_run)
		return 0;
	let executable = kind == 'sing-box' ? bin('sing_box', 'sing-box') : bin('xray', 'xray');
	let testlog = o.log_file == '/dev/null' ? TMP + '/' + split(o.config_file, '/')[length(split(o.config_file, '/')) - 1] + '_test.log' : o.log_file;
	let rc = 0;
	if (o.run_in_global)
		rc = capture(kind == 'sing-box' ? [executable, 'check', '-c', o.config_file] : [executable, 'run', '-test', '-c', o.config_file], testlog);
	if (rc == 0)
		launch_core(executable, kind, o.log_file, ['run', '-c', o.config_file]);
	else {
		api.log((kind == 'sing-box' ? 'Sing-box' : 'Xray') + ' 配置文件 ' + o.config_file + ' 校验有误，进程启动失败，错误信息：');
		append(utils.LOG_FILE, fs.readfile(testlog) ?? '');
	}
	if (testlog != o.log_file)
		fs.unlink(testlog);
	return rc;
}

export function run_singbox(raw) {
	return run_core('sing-box', raw);
};

export function run_xray(raw) {
	return run_core('xray', raw);
};

export function run_dns2socks(raw) {
	let o = type(raw) == 'object' && type(raw) != 'array' ? raw : option_args(raw);
	let socks = o.socks ? replace(o.socks, /#/g, ':') : (o.socks_address + ':' + o.socks_port);
	let args = [];
	if (o.socks_username && o.socks_password)
		push(args, '/u', o.socks_username, '/p', o.socks_password);
	if (o.cache == '0')
		push(args, '/d');
	push(args, socks, utils.format_dns(o.dns, 53), o.listen_address + ':' + o.listen_port);
	return launch_core(utils.first_type('dns2socks'), 'dns2socks' + (o.flag ? '_' + o.flag : ''), o.log_file || '/dev/null', args);
};

export function run_chinadns_ng(raw) {
	let o = type(raw) == 'object' && type(raw) != 'array' ? raw : option_args(raw);
	let dir = ACL + '/' + o._flag;
	api.fs.mkdirr(dir);
	let conf = dir + '/chinadns_ng.conf';
	let logfile = o._log == '1' ? dir + '/chinadns_ng.log' : '/dev/null';
	let args = [];
	let map = {
		_FLAG: o._flag, _NODE: o._node, _LISTEN_PORT: o._listen_port, _DNS_LOCAL: o._dns_local,
		_DNS_TRUST: o._dns_trust, _USE_DIRECT_LIST: o._use_direct_list, _USE_PROXY_LIST: o._use_proxy_list,
		_USE_BLOCK_LIST: o._use_block_list, _GFWLIST: o._gfwlist, _CHNLIST: o._chnlist,
		_NO_IPV6_TRUST: o._no_ipv6_trust, _DEFAULT_MODE: o._default_mode, _DEFAULT_TAG: o._default_tag,
		_NFTFLAG: state.nftflag, _NO_LOGIC_LOG: o._no_logic_log, _FILTER_HTTPS: o._filter_https, _LOG_FILE: logfile
	};
	for (let key, val in map)
		push(args, '-' + substr(key, 1), val ?? '');
	helper_output('helper_chinadns_add.uc', args, conf);
	return launch_core(utils.first_type('chinadns-ng'), 'chinadns-ng', logfile, ['-C', conf]);
};

function normalize_file(path) {
	if (!path)
		return path;
	return substr(path, 0, length(TMP)) == TMP ? path : TMP + '/' + path;
}

export function run_socks(raw) {
	let o = type(raw) == 'object' && type(raw) != 'array' ? raw : option_args(raw);
	mkdirs();
	o.config_file = normalize_file(o.config_file);
	o.http_config_file = normalize_file(o.http_config_file);
	o.log_file = !o.log_file || o.log_file == '/dev/null' ? '/dev/null' : normalize_file(o.log_file);
	o.http_port = o.http_port || '0';
	o.loglevel = o.loglevel || 'warn';
	let type_name = lower(cfg(o.node, 'type'));
	let remarks = cfg(o.node, 'remarks');
	let host = cfg(o.node, 'address');
	let port = cfg(o.node, 'port');
	if (stype(o.node) == 'socks') {
		type_name = 'socks';
		host = '127.0.0.1';
		remarks = 'Socks 配置(' + port + ' 端口)';
	}
	if (o.relay_port) {
		host = '127.0.0.1';
		port = o.relay_port;
	}
	let protocol = cfg(o.node, 'protocol');
	let special = type_name == 'sing-box' || type_name == 'xray';
	if ((!host || !port) && !(special && (protocol == '_balancing' || protocol == '_shunt' || protocol == '_iface' || protocol == '_urltest')) &&
	    !cfg(o.node, 'hysteria_hop') && !cfg(o.node, 'hysteria2_hop') && cfg(o.node, 'hysteria2_realms') != '1') {
		if (o.bind != '127.0.0.1')
			api.log('  - Socks节点：[' + remarks + ']，启动中止，配置已失联！');
		return 1;
	}
	if (host && !utils.check_host(host)) {
		api.log('  - Socks节点：[' + remarks + ']' + host + ' 是非法的服务器地址，无法启动！');
		return 1;
	}
	if (o.bind != '127.0.0.1')
		api.log('  - Socks节点：[' + remarks + ']' + host + ':' + port + '，启动 ' + o.bind + ':' + o.socks_port);
	let common = { node: o.node, server_host: host, server_port: port };
	if (type_name == 'socks') {
		let c = {
			node: o.node, local_socks_address: o.bind, local_socks_port: o.socks_port,
			server_proto: 'socks', server_address: host, server_port: port,
			server_username: cfg(o.node, 'username'), server_password: cfg(o.node, 'password')
		};
		if (o.http_port != '0') {
			c.local_http_address = o.bind; c.local_http_port = o.http_port;
			o.config_file = replace(o.config_file, /(\.[^.]*)$/, '+http$1');
		}
		let engine = bin('sing_box', 'sing-box') != '' ? 'sing-box' : 'xray';
		let executable = engine == 'sing-box' ? bin('sing_box', 'sing-box') : bin('xray', 'xray');
		generate(UTIL[engine], 'gen_proto_config', c, o.config_file);
		if (!o.no_run) launch_core(executable, engine, o.log_file, ['run', '-c', o.config_file]);
		type_name = engine;
	} else if (type_name == 'sing-box' || type_name == 'xray') {
		let core = {
			flag: o.flag, node: o.node, socks_address: o.bind, socks_port: o.socks_port,
			config_file: o.config_file, log_file: o.log_file, loglevel: o.loglevel,
			no_run: o.no_run
		};
		if (o.http_port != '0') {
			core.http_address = o.bind; core.http_port = o.http_port;
			o.config_file = replace(o.config_file, /(\.[^.]*)$/, '+http$1');
			core.config_file = o.config_file;
		}
		if (o.relay_port) { core.server_host = host; core.server_port = port; }
		run_core(type_name, core);
	} else {
		let c = { ...common };
		if (type_name == 'naiveproxy') {
			c.run_type = 'socks'; c.local_addr = o.bind; c.local_port = o.socks_port;
			generate(UTIL.naiveproxy, 'gen_config', c, o.config_file);
			if (!o.no_run) launch_core(utils.first_type('naive'), 'naive', o.log_file, [o.config_file]);
		} else if (type_name == 'ssr') {
			c.local_addr = o.bind; c.local_port = o.socks_port;
			generate(UTIL.ss, 'gen_config', c, o.config_file);
			if (!o.no_run) launch_core(utils.first_type('ssr-local'), 'ssr-local', o.log_file, ['-c', o.config_file, '-v', '-u']);
		} else if (type_name == 'ss-rust') {
			c.local_socks_address = o.bind; c.local_socks_port = o.socks_port; c.loglevel = o.loglevel;
			if (o.http_port != '0') { c.local_http_address = o.bind; c.local_http_port = o.http_port; }
			if (!o.no_run) c.plugin_sh = replace(o.config_file, /\.json$/, '_plugin.sh');
			generate(UTIL.ss, 'gen_config', c, o.config_file);
			if (!o.no_run) launch_core(utils.first_type('sslocal'), 'sslocal', o.log_file, ['-c', o.config_file, '-v']);
		} else if (type_name == 'hysteria2') {
			c.local_socks_address = o.bind; c.local_socks_port = o.socks_port;
			if (o.http_port != '0') { c.local_http_address = o.bind; c.local_http_port = o.http_port; }
			generate(UTIL.hysteria2, 'gen_config', c, o.config_file);
			if (!o.no_run)
				launch_core(bin('hysteria'), 'hysteria', o.log_file, ['-c', o.config_file, 'client'], { HYSTERIA_LOG_LEVEL: o.loglevel });
		}
	}
	if (o.http_port != '0' && o.http_config_file && type_name != 'sing-box' && type_name != 'xray' &&
	    type_name != 'ss-rust' && type_name != 'hysteria2') {
		let engine = bin('sing_box', 'sing-box') != '' ? 'sing-box' : (bin('xray', 'xray') != '' ? 'xray' : '');
		if (engine) {
			let c = {
				local_http_address: o.bind, local_http_port: o.http_port,
				server_proto: 'socks', server_address: '127.0.0.1', server_port: o.socks_port,
				server_username: '', server_password: ''
			};
			generate(UTIL[engine], 'gen_proto_config', c, o.http_config_file);
			if (!o.no_run) {
				let executable = engine == 'sing-box' ? bin('sing_box', 'sing-box') : bin('xray', 'xray');
				launch_core(executable, engine, '/dev/null', ['run', '-c', o.http_config_file]);
			}
		}
	}
	if (!o.no_run && host != '127.0.0.1' && type_name != 'sing-box' && type_name != 'xray')
		append(TMP + '/direct_node_list', o.node + '\n');
	return 0;
};

function get_direct_dns_mode() {
	return state.ENABLED_DEFAULT_ACL == '1' && state.DNS_SHUNT == 'smartdns'
		? 'auto' : cfg('@global[0]', 'direct_dns_mode', 'auto');
}

export { get_direct_dns_mode };

export function get_local_dns() {
	let resolv = '/tmp/resolv.conf.d/resolv.conf.auto';
	if ((fs.stat(resolv)?.size ?? 0) == 0)
		resolv = '/tmp/resolv.conf.auto';
	let text = fs.readfile(resolv) ?? '';
	let v4 = [], v6 = [], seen = {};
	for (let token in split(text, /[[:space:]]+/)) {
		if (utils.is_ipv4(token) && token != '0.0.0.0' && token != '127.0.0.1' && !seen[token]) {
			seen[token] = true; push(v4, token);
		} else if (utils.is_ipv6(token)) {
			token = split(token, '%')[0];
			if (token != '::' && token != '::1' && !seen[token]) { seen[token] = true; push(v6, token); }
		}
	}
	let servers = api.uci_get('dhcp', '@dnsmasq[0]', 'server');
	let defaults = [];
	if (type(servers) != 'array') servers = servers == null ? [] : [servers];
	for (let server in servers)
		if (index(server, '/') < 0) push(defaults, server);
	state.ISP_DNS = join(' ', v4);
	state.ISP_DNS6 = join(' ', v6);
	state.DEFAULT_DNS = length(defaults) ? join(',', defaults) : join(',', v4);
	state.LOCAL_DNS = split(state.DEFAULT_DNS || '223.5.5.5', ',')[0];
};

export function get_config() {
	get_local_dns();
	state.ENABLED = cfg('@global[0]', 'enabled', '0');
	state.SOCKS_ENABLED = cfg('@global[0]', 'socks_enabled', '0');
	state.NODE = cfg('@global[0]', 'node');
	state.ENABLED_DEFAULT_ACL = state.ENABLED == '1' && (stype(state.NODE) == 'nodes' || stype(state.NODE) == 'socks') ? '1' : '0';
	state.ENABLED_ACLS = cfg('@global[0]', 'acl_enable', '0');
	utils.set_cache_var('ENABLED_DEFAULT_ACL', state.ENABLED_DEFAULT_ACL);
	utils.set_cache_var('ENABLED_ACLS', state.ENABLED_ACLS);
	let values = {
		TCP_PROXY_WAY: ['@global_forwarding[0]', 'tcp_proxy_way', 'redirect'],
		PROXY_IPV6: ['@global_forwarding[0]', 'ipv6_tproxy', '0'],
		TCP_REDIR_PORTS: ['@global_forwarding[0]', 'tcp_redir_ports', '80,443'],
		UDP_REDIR_PORTS: ['@global_forwarding[0]', 'udp_redir_ports', '1:65535'],
		TCP_NO_REDIR_PORTS: ['@global_forwarding[0]', 'tcp_no_redir_ports', 'disable'],
		UDP_NO_REDIR_PORTS: ['@global_forwarding[0]', 'udp_no_redir_ports', 'disable'],
		TCP_PROXY_DROP_PORTS: ['@global_forwarding[0]', 'tcp_proxy_drop_ports', 'disable'],
		UDP_PROXY_DROP_PORTS: ['@global_forwarding[0]', 'udp_proxy_drop_ports', '80,443'],
		USE_DIRECT_LIST: ['@global[0]', 'use_direct_list', '1'], USE_PROXY_LIST: ['@global[0]', 'use_proxy_list', '1'],
		USE_BLOCK_LIST: ['@global[0]', 'use_block_list', '1'], USE_GFW_LIST: ['@global[0]', 'use_gfw_list', '1'],
		CHN_LIST: ['@global[0]', 'chn_list', 'direct'], TCP_PROXY_MODE: ['@global[0]', 'tcp_proxy_mode', 'proxy'],
		UDP_PROXY_MODE: ['@global[0]', 'udp_proxy_mode', 'proxy'], LOCALHOST_PROXY: ['@global[0]', 'localhost_proxy', '1'],
		CLIENT_PROXY: ['@global[0]', 'client_proxy', '1'], DNS_SHUNT: ['@global[0]', 'dns_shunt', 'dnsmasq'],
		DNS_MODE: ['@global[0]', 'dns_mode', 'tcp'], USE_DEFAULT_DNS: ['@global[0]', 'use_default_dns', 'direct'],
		FILTER_PROXY_IPV6: ['@global[0]', 'filter_proxy_ipv6', '0'], DNS_REDIRECT: ['@global[0]', 'dns_redirect', '1']
	};
	for (let key, spec in values)
		state[key] = cfg(spec[0], spec[1], spec[2]);
	if (utils.first_type(state.DNS_SHUNT) == '') state.DNS_SHUNT = 'dnsmasq';
	if (state.DNS_SHUNT == 'smartdns') state.DNS_MODE = cfg('@global[0]', 'smartdns_dns_mode', 'socks');
	state.REMOTE_DNS = utils.normalize_dns(cfg('@global[0]', 'remote_dns', '1.1.1.1'));
	state.TCP_PROXY_MODE = state.TCP_PROXY_MODE == 'disable' ? 'disable' : 'proxy';
	state.UDP_PROXY_MODE = state.UDP_PROXY_MODE == 'disable' ? 'disable' : 'proxy';
	if (state.LOCALHOST_PROXY == '1') {
		state.LOCALHOST_TCP_PROXY_MODE = state.TCP_PROXY_MODE;
		state.LOCALHOST_UDP_PROXY_MODE = state.UDP_PROXY_MODE;
	}
	state.REDIR_PORT = '' + utils.get_new_port(1041, 'tcp,udp');
	state.NEXT_DNS_LISTEN_PORT = utils.get_new_port(15353, 'tcp,udp');
	state.TUN_DNS = '127.0.0.1#' + state.NEXT_DNS_LISTEN_PORT;
	state.DNS_CACHE = '0';
	state.DIRECT_DNS_QUERY_STRATEGY = 'UseIP';
	state.REMOTE_DNS_QUERY_STRATEGY = state.FILTER_PROXY_IPV6 == '1' ? 'UseIPv4' : 'UseIP';
	state.DNSMASQ_FILTER_PROXY_IPV6 = state.FILTER_PROXY_IPV6;
	state.IPT_APPEND_DNS = state.LOCAL_DNS;
	let dnsmasq_dir = '/tmp/dnsmasq.d';
	let id = api.uci_get('dhcp', '@dnsmasq[0]')?.['.name'] ?? '';
	let conf = fs.readfile('/var/etc/dnsmasq.conf.' + id) ?? '';
	let m = match(conf, /(^|\n)conf-dir=([^\n]+)/);
	if (m != null && trim(m[2]) != '') dnsmasq_dir = replace(trim(m[2]), /\/+$/, '');
	state.GLOBAL_DNSMASQ_CONF = dnsmasq_dir + '/dnsmasq-passwall.conf';
	state.GLOBAL_DNSMASQ_CONF_PATH = GLOBAL_ACL + '/dnsmasq.d';
	utils.set_cache_var('GLOBAL_DNSMASQ_CONF', state.GLOBAL_DNSMASQ_CONF);
	utils.set_cache_var('GLOBAL_DNSMASQ_CONF_PATH', state.GLOBAL_DNSMASQ_CONF_PATH);
	state.SMARTDNS_LOCAL_PORT = '0';
	state.SMARTDNS_DIRECT_DNS = '';
	if (state.ENABLED_DEFAULT_ACL == '1' && state.DNS_SHUNT == 'smartdns') {
		state.SMARTDNS_DIRECT_DNS = join('|', split(trim(cfg('@global[0]', 'smartdns_direct_dns')), /[[:space:]]+/));
		if (state.SMARTDNS_DIRECT_DNS == 'nil') state.SMARTDNS_DIRECT_DNS = '';
		if (!state.SMARTDNS_DIRECT_DNS)
			state.SMARTDNS_DIRECT_DNS = state.LOCAL_DNS;
		else {
			let single = split(state.SMARTDNS_DIRECT_DNS, ',')[0], protocol = 'udp';
			let pm = match(single, /^([^:]+):\/\/(.*)$/);
			if (pm != null) { protocol = lower(pm[1]); single = pm[2]; }
			if (index(state.SMARTDNS_DIRECT_DNS, '|') < 0 && protocol == 'udp') {
				state.LOCAL_DNS = utils.normalize_dns(single, 53);
				let comma = index(state.SMARTDNS_DIRECT_DNS, ',');
				if (comma >= 0 && substr(state.SMARTDNS_DIRECT_DNS, comma + 1) != '')
					state.LOCAL_DNS = utils.normalize_dns(substr(state.SMARTDNS_DIRECT_DNS, comma + 1), utils.get_ip_port_from(state.LOCAL_DNS).port);
			} else {
				state.SMARTDNS_LOCAL_PORT = '' + state.NEXT_DNS_LISTEN_PORT++;
				state.LOCAL_DNS = '127.0.0.1#' + state.SMARTDNS_LOCAL_PORT;
			}
		}
	}
	utils.set_cache_var('LOCAL_DNS', state.LOCAL_DNS);
	return state;
};

export function start_socks() {
	if (state.SOCKS_ENABLED != '1')
		return;
	api.log('分析 Socks 服务的节点配置...');
	api.uci_foreach_c('socks', function(s) {
		if (s.enabled != '1' || !s.node) return;
		let id = s['.name'];
		state.NO_REC_PROCESS = s.enable_autoswitch == '1' ? '1' : '';
		run_socks({
			flag: id, node: s.node, bind: s.bind_local == '1' ? '127.0.0.1' : '0.0.0.0',
			socks_port: s.port, config_file: id + '.json', http_port: s.http_port ?? '0',
			http_config_file: id + '_http.json', log_file: s.log == '0' ? '' : id + '.log'
		});
		state.NO_REC_PROCESS = '';
		utils.set_cache_var(id, s.node);
		if (s.enable_autoswitch == '1')
			launch_core('/usr/bin/ucode', 'socks_auto_switch_' + id, '/dev/null', [LIBEXEC + '/socks_auto_switch.uc', id],
			            { NO_REC_PROCESS: '1' });
	});
};

export function socks_node_switch(raw) {
	let o = type(raw) == 'object' && type(raw) != 'array' ? raw : option_args(raw);
	if (!o.flag || !o.new_node) return 1;
	for (let suffix in ['', '+http']) {
		let text = fs.readfile(TMP + '/' + o.flag + suffix + '_plugin.pid') ?? '';
		let pid = match(text, /^([0-9]+)/)?.[1];
		if (pid) command(['kill', '-9', pid], true);
	}
	let listed = api.proc_lines(utils.TMP_BIN_PATH);
	for (let line in split(listed, '\n')) {
		if (index(lower(line), lower(o.flag)) < 0 || match(line, /acl\/|acl_/) != null) continue;
		let pid = match(line, /^([0-9]+)/)?.[1];
		if (pid) command(['kill', '-9', pid], true);
	}
	for (let name in fs.lsdir(TMP) ?? [])
		if (substr(name, 0, length(o.flag)) == o.flag)
			unlink_tree(TMP + '/' + name);
	for (let name in fs.lsdir(utils.TMP_SCRIPT_FUNC_PATH) ?? []) {
		let path = utils.TMP_SCRIPT_FUNC_PATH + '/' + name;
		if (index(fs.readfile(path) ?? '', o.flag) >= 0) {
			fs.unlink(path);
			fs.unlink(TMP + '/script_rstats/' + name + '.count');
		}
	}
	let s = api.uci_get_c(o.flag) ?? {};
	run_socks({ flag: o.flag, node: o.new_node, bind: s.bind_local == '1' ? '127.0.0.1' : '0.0.0.0',
		socks_port: s.port, config_file: o.flag + '.json', http_port: s.http_port ?? '0',
		http_config_file: o.flag + '_http.json', log_file: s.log == '0' ? '' : o.flag + '.log' });
	command(['sleep', '2s'], true);
	if (!utils.check_port_exists(s.port, 'tcp')) return 1;
	utils.set_cache_var(o.flag, o.new_node);
	return 0;
};

function direct_dns_options() {
	let mode = get_direct_dns_mode();
	if (mode == 'udp') return { direct_dns_udp_server: utils.normalize_dns(cfg('@global[0]', 'direct_dns', '223.5.5.5:53')) };
	if (mode == 'tcp') return { direct_dns_tcp_server: utils.normalize_dns(cfg('@global[0]', 'direct_dns', '223.5.5.5:53')) };
	return {};
}

export function start_global() {
	let node = state.NODE;
	if (!node) return 1;
	let type_name = lower(cfg(node, 'type'));
	let host = cfg(node, 'address'), port = cfg(node, 'port');
	let remarks = cfg(node, 'remarks');
	if (type_name == 'socks' || stype(node) == 'socks') {
		type_name = state.DNS_MODE == 'xray' || state.DNS_MODE == 'sing-box' ? state.DNS_MODE :
			(bin('sing_box', 'sing-box') ? 'sing-box' : (bin('xray', 'xray') ? 'xray' : 'socks'));
		if (stype(node) == 'socks') { host = '127.0.0.1'; remarks = 'Socks 配置(' + port + ' 端口)'; }
	}
	if (host && !utils.check_host(host)) {
		api.log('全局节点：[' + remarks + ']' + host + ' 是非法的服务器地址，无法启动！');
		return 1;
	}
	api.log('全局节点：[' + remarks + ']，监听端口：' + state.REDIR_PORT);
	let socks_bind = cfg('@global[0]', 'node_socks_bind_local', '1') == '1' ? '127.0.0.1' : '0.0.0.0';
	let socks_port = cfg('@global[0]', 'node_socks_port', '1070');
	let http_port = cfg('@global[0]', 'node_http_port', '0');
	if (state.PROXY_IPV6 == '1')
		api.log('开启实验性IPv6透明代理(TProxy)，请确认您的节点及类型支持IPv6！');
	let can_native = index(state.TCP_PROXY_WAY == 'tproxy'
		? 'socks ss-rust ssr sing-box xray hysteria2'
		: 'socks ss-rust ssr sing-box xray naiveproxy hysteria2', type_name) >= 0;
	if (!can_native) type_name = 'socks';
	let logfile = cfg('@global[0]', 'log_node', '1') == '1' ? GLOBAL_ACL + '/global.log' : '/dev/null';
	let config = GLOBAL_ACL + '/global.json';
	let native_socks = false;
	if (type_name == 'sing-box' || type_name == 'xray') {
		let protocol = cfg(node, 'protocol');
		if (protocol == '_shunt') {
			let asset = replace(cfg('@global_rules[0]', 'v2ray_location_asset', '/usr/share/v2ray/'), /\/+$/, '');
			if ((fs.stat(asset + '/geoip.dat')?.size ?? 0) == 0 || (fs.stat(asset + '/geosite.dat')?.size ?? 0) == 0)
				api.log('* 缺少Geo规则文件，TCP ' + (type_name == 'xray' ? 'Xray' : 'Sing-Box') + '分流节点无法正常使用！');
			if (cfg(node, 'fakedns') == '1') {
				state.USE_FAKEDNS = '1';
				state.GLOBAL_SHUNT_NODE_FAKEDNS = '1';
			}
		}
		let o = {
			flag: 'global', node: node, redir_port: state.REDIR_PORT, tcp_proxy_way: state.TCP_PROXY_WAY,
			socks_address: socks_bind, socks_port: socks_port, config_file: config, log_file: logfile,
			run_in_global: '1', use_proxy_list: state.USE_PROXY_LIST, use_gfw_list: state.USE_GFW_LIST, chn_list: state.CHN_LIST
		};
		if (http_port != '0') o.http_port = http_port;
		if (state.DNS_MODE == type_name || protocol == '_shunt') {
			state.DNS_MODE = type_name;
			state.NO_PLUGIN_DNS = '1';
			state.DNSMASQ_FILTER_PROXY_IPV6 = '0';
			let dns_port = utils.get_new_port(state.NEXT_DNS_LISTEN_PORT, 'tcp,udp');
			if (dns_port == null) return 1;
			state.resolve_dns_port = '' + dns_port;
			o.dns_listen_port = '' + dns_port;
			o.remote_dns_query_strategy = state.REMOTE_DNS_QUERY_STRATEGY;
			o.remote_dns_protocol = cfg('@global[0]', 'v2ray_dns_mode', 'tcp');
			if (type_name == 'xray' && protocol == '_shunt' &&
			    (o.remote_dns_protocol == 'http3' || o.remote_dns_protocol == 'tls' || o.remote_dns_protocol == 'quic')) {
				o.remote_dns_protocol = 'tcp';
				state.REMOTE_DNS = '1.1.1.1#53';
			}
			if (o.remote_dns_protocol == 'udp' || o.remote_dns_protocol == 'quic') o.remote_dns_udp_server = state.REMOTE_DNS;
			else if (o.remote_dns_protocol == 'tcp' || o.remote_dns_protocol == 'tls') o.remote_dns_tcp_server = state.REMOTE_DNS;
			else o.remote_dns_doh = cfg('@global[0]', 'remote_dns_doh', 'https://1.1.1.1/dns-query');
			if (cfg('@global[0]', 'remote_fakedns', '0') == '1') {
				o.remote_fakedns = '1'; state.USE_FAKEDNS = '1'; state.REMOTE_FAKEDNS = '1';
			}
			o.remote_dns_client_ip = cfg('@global[0]', 'remote_dns_client_ip');
			o.dns_cache = state.DNS_CACHE;
			if (type_name == 'sing-box') o.remote_rewrite_ttl = cfg('@global[0]', 'remote_rewrite_ttl');
			for (let key, val in direct_dns_options()) o[key] = val;
			state.NEXT_DNS_LISTEN_PORT = dns_port + 1;
		}
		run_core(type_name, o);
		native_socks = true;
	} else if (type_name == 'socks') {
		let direct = host, dport = port;
		if (!can_native) {
			run_socks({ flag: 'global', node: node, bind: socks_bind, socks_port: socks_port,
				config_file: 'global_' + node + '_socks.json', http_port: http_port });
			direct = '127.0.0.1'; dport = socks_port; native_socks = true;
		}
		run_ipt2socks({ flag: 'default', tcp_tproxy: state.TCP_PROXY_WAY == 'tproxy' ? '1' : '',
			local_port: state.REDIR_PORT, socks_address: direct, socks_port: dport,
			socks_username: cfg(node, 'username'), socks_password: cfg(node, 'password'), log_file: logfile });
	} else {
		let c = { node: node, server_host: host, server_port: port };
		if (type_name == 'naiveproxy') {
			c.run_type = 'redir'; c.local_addr = '0.0.0.0'; c.local_port = state.REDIR_PORT;
			generate(UTIL.naiveproxy, 'gen_config', c, config);
			launch_core(utils.first_type('naive'), 'naive', logfile, [config]);
		} else if (type_name == 'ssr') {
			c.local_addr = '0.0.0.0'; c.local_port = state.REDIR_PORT;
			if (state.TCP_PROXY_WAY == 'tproxy') c.tcp_tproxy = 'true';
			generate(UTIL.ss, 'gen_config', c, config);
			launch_core(utils.first_type('ssr-redir'), 'ssr-redir', logfile, ['-c', config, '-v', '-u']);
		} else if (type_name == 'ss-rust') {
			c.local_redir_port = state.REDIR_PORT; c.local_socks_address = socks_bind; c.local_socks_port = socks_port;
			if (http_port != '0') c.local_http_port = http_port;
			if (state.TCP_PROXY_WAY == 'tproxy') c.tcp_tproxy = 'true';
			c.plugin_sh = replace(config, /\.json$/, '_plugin.sh');
			generate(UTIL.ss, 'gen_config', c, config);
			launch_core(utils.first_type('sslocal'), 'sslocal', logfile, ['-c', config, '-v']);
			native_socks = true;
		} else if (type_name == 'hysteria2') {
			c.local_redir_port = state.REDIR_PORT; c.local_socks_address = socks_bind; c.local_socks_port = socks_port;
			c.tcp_proxy_way = state.TCP_PROXY_WAY;
			if (http_port != '0') c.local_http_port = http_port;
			generate(UTIL.hysteria2, 'gen_config', c, config);
			launch_core(bin('hysteria'), 'hysteria', logfile, ['-c', config, 'client'], { HYSTERIA_LOG_LEVEL: cfg('@global[0]', 'loglevel', 'warn') });
			native_socks = true;
		}
	}
	if (!native_socks)
		run_socks({ flag: 'TCP', node: node, bind: socks_bind, socks_port: socks_port,
			config_file: GLOBAL_ACL + '/global_socks.json', http_port: http_port,
			http_config_file: GLOBAL_ACL + '/global_socks_http.json' });
	state.GLOBAL_SOCKS_port = socks_port;
	state.GLOBAL_SOCKS_server = '127.0.0.1:' + socks_port;
	utils.set_cache_var('GLOBAL_SOCKS_server', state.GLOBAL_SOCKS_server);
	utils.set_cache_var('ACL_GLOBAL_node', node);
	utils.set_cache_var('ACL_GLOBAL_redir_port', state.REDIR_PORT);
	if (type_name != 'sing-box' && type_name != 'xray') append(TMP + '/direct_node_list', node + '\n');
	return 0;
};

function helper_args(object) {
	let args = [];
	for (let key, value in object)
		push(args, '-' + key, value == null || value == '' ? '0' : '' + value);
	return args;
}

function add_dnsmasq_rule(flag, path, conf, port, tun_dns, china_dns, opts) {
	let object = {
		FLAG: flag, TMP_DNSMASQ_PATH: path, DNSMASQ_CONF_FILE: conf,
		LISTEN_PORT: port, DEFAULT_DNS: state.DEFAULT_DNS, LOCAL_DNS: state.LOCAL_DNS,
		TUN_DNS: utils.normalize_dns(tun_dns, 53), USE_DEFAULT_DNS: opts.use_default_dns ?? state.USE_DEFAULT_DNS ?? 'direct',
		CHINADNS_DNS: china_dns ?? '0', USE_DIRECT_LIST: opts.use_direct_list ?? state.USE_DIRECT_LIST,
		USE_PROXY_LIST: opts.use_proxy_list ?? state.USE_PROXY_LIST, USE_BLOCK_LIST: opts.use_block_list ?? state.USE_BLOCK_LIST,
		USE_GFW_LIST: opts.use_gfw_list ?? state.USE_GFW_LIST, CHN_LIST: opts.chn_list ?? state.CHN_LIST,
		NODE: opts.node ?? state.NODE, DEFAULT_PROXY_MODE: opts.proxy_mode ?? state.TCP_PROXY_MODE,
		NO_PROXY_IPV6: opts.no_ipv6 ?? state.DNSMASQ_FILTER_PROXY_IPV6 ?? '0',
		NFTFLAG: state.nftflag ?? '0', NO_LOGIC_LOG: opts.no_logic_log ?? '0'
	};
	return command(['/usr/bin/ucode', LIBEXEC + '/helper_dnsmasq.uc', 'add_rule', ...helper_args(object)], true);
}

export function start_dns() {
	api.log('DNS域名解析：');
	let direct_mode = get_direct_dns_mode();
	let china_local = state.LOCAL_DNS;
	let acl_dnsmasq = false;
	api.uci_foreach_c('acl_rule', function(s) {
		if (s.enabled == '1' && s.dns_shunt == 'dnsmasq') acl_dnsmasq = true;
	});
	let direct_dns = '';
	if (direct_mode == 'udp') {
		state.LOCAL_DNS = utils.normalize_dns(cfg('@global[0]', 'direct_dns', '223.5.5.5:53'));
		china_local = state.LOCAL_DNS;
	} else if (direct_mode == 'tcp') {
		direct_dns = utils.normalize_dns(cfg('@global[0]', 'direct_dns', '223.5.5.5:53'));
		china_local = 'tcp://' + direct_dns;
		if ((state.DNS_SHUNT != 'chinadns-ng' && state.DNS_SHUNT != 'smartdns') || acl_dnsmasq) {
			state.LOCAL_DNS = '127.0.0.1#' + state.NEXT_DNS_LISTEN_PORT;
			launch_core(utils.first_type('chinadns-ng'), 'chinadns-ng', '/dev/null',
			            ['-b', '::', '-l', '' + state.NEXT_DNS_LISTEN_PORT, '-c', china_local, '-d', 'chn']);
			state.NEXT_DNS_LISTEN_PORT++;
		}
	}
	state.LOCAL_DNS = utils.normalize_dns(state.LOCAL_DNS, 53);
	utils.set_cache_var('LOCAL_DNS', state.LOCAL_DNS);
	let append_dns = [], append_seen = {};
	for (let item in split(state.IPT_APPEND_DNS || state.LOCAL_DNS, ',')) {
		item = utils.normalize_dns(item, 53);
		if (substr(item, 0, 10) != '127.0.0.1' && !append_seen[item]) { append_seen[item] = true; push(append_dns, item); }
	}
	for (let item in [state.LOCAL_DNS, direct_dns]) {
		if (!item) continue;
		item = utils.normalize_dns(item, 53);
		if (substr(item, 0, 10) != '127.0.0.1' && !append_seen[item]) { append_seen[item] = true; push(append_dns, item); }
	}
	state.IPT_APPEND_DNS = join(',', append_dns);
	state.TUN_DNS = state.NO_PLUGIN_DNS ? '127.0.0.1#' + state.resolve_dns_port : '127.0.0.1#' + state.NEXT_DNS_LISTEN_PORT;
	if (state.DNS_MODE == 'dns2socks') {
		let server = replace(cfg('@global[0]', 'socks_server', '127.0.0.1:1080'), /#/g, ':');
		run_dns2socks({ socks: server, listen_address: '127.0.0.1', listen_port: state.NEXT_DNS_LISTEN_PORT,
			dns: state.REMOTE_DNS, cache: state.DNS_CACHE });
	} else if ((state.DNS_MODE == 'sing-box' || state.DNS_MODE == 'xray') && !state.NO_PLUGIN_DNS) {
		let o = {
			type: state.DNS_MODE, config_file: GLOBAL_ACL + '/DNS.json', log_file: '/dev/null',
			dns_cache: state.DNS_CACHE, direct_dns_query_strategy: state.DIRECT_DNS_QUERY_STRATEGY,
			remote_dns_query_strategy: state.REMOTE_DNS_QUERY_STRATEGY, dns_listen_port: '' + state.NEXT_DNS_LISTEN_PORT,
			remote_dns_protocol: cfg('@global[0]', 'v2ray_dns_mode', 'tcp'), dns_socks_address: '127.0.0.1',
			dns_socks_port: state.GLOBAL_SOCKS_port
		};
		if (o.remote_dns_protocol == 'udp' || o.remote_dns_protocol == 'quic') o.remote_dns_udp_server = state.REMOTE_DNS;
		else if (o.remote_dns_protocol == 'tcp' || o.remote_dns_protocol == 'tls') o.remote_dns_tcp_server = state.REMOTE_DNS;
		else o.remote_dns_doh = cfg('@global[0]', 'remote_dns_doh', 'https://1.1.1.1/dns-query');
		for (let key, val in direct_dns_options()) o[key] = val;
		if (cfg('@global[0]', 'remote_fakedns', '0') == '1') { o.remote_fakedns = '1'; state.USE_FAKEDNS = '1'; }
		run_core(state.DNS_MODE, o);
		state.TCP_PROXY_DNS = '1';
	} else if (state.DNS_MODE == 'udp' || state.DNS_MODE == 'tcp') {
		let proto = state.DNS_MODE;
		state[proto == 'udp' ? 'UDP_PROXY_DNS' : 'TCP_PROXY_DNS'] = '1';
		if (state.DNS_SHUNT != 'chinadns-ng' && (proto == 'tcp' || state.FILTER_PROXY_IPV6 == '1')) {
			let args = ['-b', '::', '-l', '' + state.NEXT_DNS_LISTEN_PORT, '-t', proto + '://' + state.REMOTE_DNS, '-d', 'gfw'];
			if (state.FILTER_PROXY_IPV6 == '1') push(args, '-N');
			launch_core(utils.first_type('chinadns-ng'), 'chinadns-ng', '/dev/null', args);
		} else {
			state.TUN_DNS = state.REMOTE_DNS;
		}
	}
	let china_listen = '0';
	if (state.DNS_SHUNT == 'smartdns' && utils.first_type('smartdns')) {
		for (let name in fs.lsdir(utils.TMP_PATH2) ?? [])
			if (substr(name, 0, 15) == 'dnsmasq_default') unlink_tree(utils.TMP_PATH2 + '/' + name);
		let port = utils.get_new_port(state.NEXT_DNS_LISTEN_PORT + 1);
		if (port == null) return 1;
		let remote = trim(cfg('@global[0]', 'smartdns_remote_dns'));
		if (!remote || remote == 'nil') remote = 'tcp://1.1.1.1';
		else remote = join('|', split(remote, /[[:space:]]+/));
		let object = {
			FLAG: 'default', LISTEN_PORT: port, DIRECT_DNS: state.SMARTDNS_DIRECT_DNS,
			LOCAL_PORT: state.SMARTDNS_LOCAL_PORT, DNS_REDIRECT: state.DNS_REDIRECT,
			REMOTE_PROXY_SERVER: state.GLOBAL_SOCKS_server, USE_DEFAULT_DNS: cfg('@global[0]', 'smartdns_default_dns', 'direct'),
			REMOTE_DNS: remote, DNS_MODE: state.DNS_MODE,
			TUN_DNS: state.TUN_DNS, USE_DIRECT_LIST: state.USE_DIRECT_LIST, USE_PROXY_LIST: state.USE_PROXY_LIST,
			USE_BLOCK_LIST: state.USE_BLOCK_LIST, USE_GFW_LIST: state.USE_GFW_LIST, CHN_LIST: state.CHN_LIST,
			NODE: state.NODE, DEFAULT_PROXY_MODE: state.TCP_PROXY_MODE, NO_PROXY_IPV6: state.FILTER_PROXY_IPV6,
			NFTFLAG: state.nftflag, SUBNET: cfg('@global[0]', 'remote_dns_client_ip', '0'),
			NO_LOGIC_LOG: state.NO_LOGIC_LOG ?? '0', LOG: cfg('@global[0]', 'log_smartdns', '0'),
			LOG_LEVEL: cfg('@global[0]', 'smartdns_log_level', 'error'),
			LOG_SIZE: cfg('@global[0]', 'smartdns_log_size', '1'),
			UI: cfg('@global[0]', 'smartdns_ui', '0'),
			UI_PORT: cfg('@global[0]', 'smartdns_ui_port', '9880'),
			UI_DATA_DIR: cfg('@global[0]', 'smartdns_ui_data_dir', utils.TMP_PATH2 + '/smartdns'),
			UI_LOG_MAX_AGE: cfg('@global[0]', 'smartdns_ui_log_max_age', '7')
		};
		if (command(['/usr/bin/ucode', LIBEXEC + '/helper_smartdns_add.uc', ...helper_args(object)], true) != 0) {
			api.log('  * SmartDNS 配置生成失败！');
			return 1;
		}
		launch_core(utils.first_type('smartdns'), 'smartdns', '/dev/null',
		            ['-f', '-c', GLOBAL_ACL + '/smartdns.conf', '-p', GLOBAL_ACL + '/smartdns.pid']);
		state.DNS_REDIRECT_PORT = '' + port;
		utils.set_cache_var('ACL_default_dns_port', port);
	} else if (state.DNS_SHUNT == 'smartdns') {
		state.DNS_SHUNT = 'dnsmasq';
		api.log('  * 未安装SmartDNS，默认使用Dnsmasq进行域名解析！');
	}
	if (state.DNS_SHUNT == 'chinadns-ng' && utils.first_type('chinadns-ng')) {
		let port = state.NEXT_DNS_LISTEN_PORT + 1;
		china_listen = '127.0.0.1#' + port + ',::1#' + port;
		run_chinadns_ng({ _flag: 'default', _listen_port: port, _dns_local: china_local,
			_dns_trust: state.TUN_DNS, _no_ipv6_trust: state.FILTER_PROXY_IPV6,
			_use_direct_list: state.USE_DIRECT_LIST, _use_proxy_list: state.USE_PROXY_LIST,
			_use_block_list: state.USE_BLOCK_LIST, _gfwlist: state.USE_GFW_LIST, _chnlist: state.CHN_LIST,
			_default_mode: state.TCP_PROXY_MODE, _default_tag: cfg('@global[0]', 'chinadns_ng_default_tag', 'smart'),
			_no_logic_log: '0', _node: state.NODE, _filter_https: cfg('@global[0]', 'force_https_soa', '0'),
			_log: cfg('@global[0]', 'log_chinadns_ng', '0') });
		state.USE_DEFAULT_DNS = 'chinadns_ng';
	}
	if (state.DNS_REDIRECT == '0') {
		command(['/usr/bin/ucode', LIBEXEC + '/helper_dnsmasq.uc', 'stretch'], true);
		add_dnsmasq_rule('default', state.GLOBAL_DNSMASQ_CONF_PATH, state.GLOBAL_DNSMASQ_CONF, '', state.TUN_DNS, china_listen, {});
		api.uci_del('dhcp', '@dnsmasq[0]', 'min_cache_ttl');
		api.uci.add_list('dhcp', api.uci_get('dhcp', '@dnsmasq[0]')['.name'], 'addnmount', state.GLOBAL_DNSMASQ_CONF_PATH);
		api.uci_save(null, 'dhcp', true);
		command(['/usr/bin/ucode', LIBEXEC + '/helper_dnsmasq.uc', 'logic_restart', '-LOG', '1'], true);
	} else if (state.DNS_SHUNT == 'smartdns') {
		/* SmartDNS reads leases directly and is itself the redirect target. */
	} else {
		let port = utils.get_new_port(11400);
		let conf = GLOBAL_ACL + '/dnsmasq.conf', path = GLOBAL_ACL + '/dnsmasq.d';
		add_dnsmasq_rule('default', path, conf, port, state.TUN_DNS, china_listen, {});
		launch_core(utils.first_type('dnsmasq'), 'dnsmasq_default', '/dev/null', ['-C', conf, '-x', GLOBAL_ACL + '/dnsmasq.pid']);
		state.GLOBAL_DNSMASQ_PORT = '' + port;
		state.DNS_REDIRECT_PORT = '' + port;
		utils.set_cache_var('ACL_default_dns_port', port);
		launch_core('/usr/bin/ucode', 'lease2hosts', '/dev/null', [LIBEXEC + '/lease2hosts.uc'], { NO_REC_PROCESS: '1' });
	}
	return 0;
};

export function start_haproxy() {
	if (cfg('@global_haproxy[0]', 'balancing_enable', '0') != '1') return;
	let executable = utils.first_type('haproxy');
	let ver = match(command_output([executable, '-v']), /^[^\n]*?([0-9]+\.[0-9.]+)/)?.[1] ?? '';
	if (utils.check_ver(ver, '3.0.0') == 1) {
		api.log('* 注意：haproxy(' + ver + ') 程序版本低，HAPROXY 负载均衡启动失败，请更新到 3.0 以上版本。');
		return;
	}
	let path = TMP + '/haproxy';
	command(['/usr/bin/ucode', LIBEXEC + '/haproxy.uc', '-path', path, '-conf', 'config.cfg'], true);
	launch_core(executable, 'haproxy', '/dev/null', ['-f', path + '/config.cfg']);
};

function source_lines(section) {
	let out = [];
	let sources = section.sources;
	if (type(sources) != 'array') sources = sources == null ? [] : [sources];
	for (let source in sources) {
		let label = api.iprange(source) ? 'iprange:' : (substr(source, 0, 6) == 'ipset:' ? '' : api.ip_or_mac(source) + ':');
		if (label != 'null:' && label != ':') push(out, label + source);
	}
	if (!length(out)) push(out, 'any');
	return out;
}

function legacy_acl_app_port() {
	let enabled = 0, socks_port = 11100, redir_port = 11200, dns_port = 11300, dnsmasq_port = int(state.GLOBAL_DNSMASQ_PORT || 11400);
	api.uci_foreach_c('acl_rule', function(s) {
		if (s.enabled != '1') return;
		enabled++;
		let sid = s['.name'], path = ACL + '/' + sid;
		api.fs.mkdirr(path);
		fs.writefile(path + '/source_list', join('\n', source_lines(s)) + '\n');
		let tcp_skip = s.tcp_no_redir_ports ?? state.TCP_NO_REDIR_PORTS;
		let udp_skip = s.udp_no_redir_ports ?? state.UDP_NO_REDIR_PORTS;
		if (utils.has_1_65535(tcp_skip) && utils.has_1_65535(udp_skip)) return;
		let node = s.use_global_config == '1' ? 'default' : s.node;
		if (!node) return;
		if (node == 'default' || node == utils.get_cache_var('ACL_GLOBAL_node')) {
			let global_node = utils.get_cache_var('ACL_GLOBAL_node');
			if (!global_node) { api.log('  - 全局节点未启用，跳过【' + (s.remarks ?? sid) + '】'); return; }
			utils.set_cache_var('ACL_' + sid + '_node', global_node);
			utils.set_cache_var('ACL_' + sid + '_redir_port', utils.get_cache_var('ACL_GLOBAL_redir_port'));
			utils.set_cache_var('ACL_' + sid + '_dns_port', state.DNS_REDIRECT_PORT || state.GLOBAL_DNSMASQ_PORT);
			utils.set_cache_var('ACL_' + sid + '_default', '1');
			return;
		}
		let type_name = lower(cfg(node, 'type'));
		let log = s.log ?? '0';
		socks_port = utils.get_new_port(socks_port + 1);
		redir_port = utils.get_new_port(redir_port + 1);
		let node_log = log == '1' ? path + '/node.log' : '/dev/null';
		if (type_name == 'sing-box' || type_name == 'xray') {
			let o = { flag: node, node: node, redir_port: redir_port, tcp_proxy_way: state.TCP_PROXY_WAY,
				socks_address: '127.0.0.1', socks_port: socks_port, config_file: TMP + '/acl/' + node + '_' + redir_port + '.json',
				log_file: node_log, loglevel: s.loglevel ?? 'warn', use_proxy_list: s.use_proxy_list ?? '1',
				use_gfw_list: s.use_gfw_list ?? '1', chn_list: s.chn_list ?? 'direct' };
			if ((s.dns_mode ?? 'dns2socks') == type_name) {
				dns_port = utils.get_new_port(dns_port + 1);
				o.dns_listen_port = dns_port; o.remote_dns_protocol = s.v2ray_dns_mode ?? 'tcp';
				o.remote_dns_udp_server = utils.normalize_dns(s.remote_dns ?? '1.1.1.1');
				o.remote_dns_tcp_server = o.remote_dns_udp_server;
				o.remote_dns_doh = s.remote_dns_doh ?? 'https://1.1.1.1/dns-query';
				o.remote_dns_query_strategy = s.filter_proxy_ipv6 == '1' ? 'UseIPv4' : 'UseIP';
			}
			run_core(type_name, o);
		} else {
			run_socks({ flag: node, node: node, bind: '127.0.0.1', socks_port: socks_port,
				config_file: 'acl/' + node + '_SOCKS_' + socks_port + '.json', log_file: node_log, loglevel: s.loglevel ?? 'warn' });
			run_ipt2socks({ flag: 'acl_' + node, tcp_tproxy: state.TCP_PROXY_WAY == 'tproxy' ? '1' : '',
				local_port: redir_port, socks_address: '127.0.0.1', socks_port: socks_port });
		}
		let fwd = dns_port;
		if ((s.dns_mode ?? 'dns2socks') == 'dns2socks') {
			fwd = utils.get_new_port(dns_port + 1); dns_port = fwd;
			run_dns2socks({ flag: 'acl_' + sid, socks_address: '127.0.0.1', socks_port: socks_port,
				listen_address: '0.0.0.0', listen_port: fwd, dns: utils.normalize_dns(s.remote_dns ?? '1.1.1.1'), cache: '1' });
		}
		dnsmasq_port = utils.get_new_port(dnsmasq_port + 1);
		add_dnsmasq_rule(sid, path + '/dnsmasq.d', path + '/dnsmasq.conf', dnsmasq_port, '127.0.0.1#' + fwd, '0', {
			use_direct_list: s.use_direct_list ?? '1', use_proxy_list: s.use_proxy_list ?? '1',
			use_block_list: s.use_block_list ?? '1', use_gfw_list: s.use_gfw_list ?? '1', chn_list: s.chn_list ?? 'direct',
			node: node, proxy_mode: s.tcp_proxy_mode ?? 'proxy', no_ipv6: s.filter_proxy_ipv6 ?? '0', no_logic_log: '1'
		});
		launch_core(utils.first_type('dnsmasq'), 'dnsmasq_' + sid, '/dev/null',
		            ['-C', path + '/dnsmasq.conf', '-x', path + '/dnsmasq.pid']);
		utils.set_cache_var('ACL_' + sid + '_node', node);
		utils.set_cache_var('ACL_' + sid + '_redir_port', redir_port);
		utils.set_cache_var('ACL_' + sid + '_dns_port', dnsmasq_port);
	});
	if (!enabled) {
		state.ENABLED_ACLS = '0';
		utils.set_cache_var('ENABLED_ACLS', '0');
	}
}

export function acl_app() {
	let enabled = 0, next_socks = 11100, next_redir = 11200, next_dns = 11300;
	let next_dnsmasq = int(state.GLOBAL_DNSMASQ_PORT || 11400), next_china = 11500;
	api.uci_foreach_c('acl_rule', function(s) {
		if (s.enabled != '1') return;
		enabled++;
		let sid = s['.name'], path = ACL + '/' + sid;
		api.fs.mkdirr(path);
		fs.writefile(path + '/source_list', join('\n', source_lines(s)) + '\n');
		if (utils.has_1_65535(s.tcp_no_redir_ports ?? state.TCP_NO_REDIR_PORTS) &&
		    utils.has_1_65535(s.udp_no_redir_ports ?? state.UDP_NO_REDIR_PORTS)) return;
		let node = s.use_global_config == '1' ? 'default' : s.node;
		if (!node) return;
		let global_node = utils.get_cache_var('ACL_GLOBAL_node');
		if (node == global_node) node = 'default';
		if (node == 'default') {
			if (!global_node) { api.log('  - 全局节点未启用，跳过【' + (s.remarks ?? sid) + '】'); return; }
			utils.set_cache_var('ACL_' + sid + '_node', global_node);
			utils.set_cache_var('ACL_' + sid + '_redir_port', utils.get_cache_var('ACL_GLOBAL_redir_port'));
			utils.set_cache_var('ACL_' + sid + '_dns_port', state.DNS_REDIRECT_PORT || state.GLOBAL_DNSMASQ_PORT);
			utils.set_cache_var('ACL_' + sid + '_default', '1');
			if (state.GLOBAL_SHUNT_NODE_FAKEDNS == '1') utils.set_cache_var('ACL_' + sid + '_fakedns', '1');
			return;
		}
		if (stype(node) != 'nodes' && stype(node) != 'socks') return;
		let direct = s.use_direct_list ?? '1', proxy = s.use_proxy_list ?? '1', block = s.use_block_list ?? '1';
		let gfw = s.use_gfw_list ?? '1', chn = s.chn_list ?? 'direct', proxy_mode = s.tcp_proxy_mode ?? 'proxy';
		let filter6 = s.filter_proxy_ipv6 ?? '0', dns_filter6 = filter6, shunt = s.dns_shunt ?? 'dnsmasq';
		let dmode = s.dns_mode ?? 'dns2socks', remote = utils.normalize_dns(s.remote_dns ?? '1.1.1.1');
		let vmode = s.v2ray_dns_mode ?? 'tcp', doh = s.remote_dns_doh ?? 'https://1.1.1.1/dns-query';
		let client_ip = s.remote_dns_client_ip ?? '', fake = s.remote_fakedns ?? '0';
		let ttl = s.remote_rewrite_ttl ?? '30', use_default = s.use_default_dns ?? 'direct';
		let type_name = stype(node) == 'socks'
			? (dmode == 'xray' || dmode == 'sing-box' ? dmode : (bin('sing_box', 'sing-box') ? 'sing-box' : 'xray'))
			: lower(cfg(node, 'type'));
		if (stype(node) == 'socks' && dmode != 'xray' && dmode != 'sing-box' &&
		    !bin('sing_box', 'sing-box') && !bin('xray', 'xray'))
			type_name = '';
		let protocol = stype(node) == 'socks' ? '' : cfg(node, 'protocol');
		if ((type_name == 'sing-box' || type_name == 'xray') && protocol == '_shunt' && type_name != dmode) {
			dmode = type_name;
			if (type_name == 'xray' && (vmode == 'http3' || vmode == 'tls' || vmode == 'quic')) {
				vmode = 'tcp'; remote = '1.1.1.1#53';
			}
		}
		let dns_key = api.md5_string(join('_', [dmode, vmode, remote, doh, client_ip, fake, ttl, filter6]));
		let fakedns = fake == '1' || (protocol == '_shunt' && cfg(node, 'fakedns') == '1');
		let socks_port, redir_port, integrated_dns;

		function dns_for_acl(existing) {
			let fwd = existing;
			if (!fwd) {
				fwd = utils.get_new_port(++next_dns);
				if (dmode == 'dns2socks')
					run_dns2socks({ flag: 'acl_' + sid, socks_address: '127.0.0.1', socks_port: socks_port,
						listen_address: '0.0.0.0', listen_port: fwd, dns: remote, cache: '1' });
				else if (dmode == 'sing-box' || dmode == 'xray') {
					dns_filter6 = '0';
					if (filter6 == '1') utils.set_cache_var('node_' + node + '_' + dns_key + '_ipv6', '0');
					run_core(dmode, { flag: 'acl_' + sid, type: dmode, dns_socks_address: '127.0.0.1',
						dns_socks_port: socks_port, dns_listen_port: fwd, remote_dns_protocol: vmode,
						remote_dns_udp_server: remote, remote_dns_tcp_server: remote, remote_dns_doh: doh,
						remote_dns_query_strategy: filter6 == '1' ? 'UseIPv4' : 'UseIP',
						remote_dns_client_ip: client_ip, remote_rewrite_ttl: ttl,
						config_file: ACL + '/' + node + '_SOCKS_' + socks_port + '_DNS.json' });
				}
				utils.set_cache_var('node_' + node + '_' + dns_key, fwd);
			}
			let china = '0';
			if (shunt == 'chinadns-ng' && utils.first_type('chinadns-ng')) {
				if (filter6 == '1') dns_filter6 = '0';
				let cp = ++next_china;
				china = '127.0.0.1#' + cp + ',::1#' + cp;
				let local = state.LOCAL_DNS, dm = get_direct_dns_mode();
				if (dm == 'udp') local = utils.normalize_dns(cfg('@global[0]', 'direct_dns', '223.5.5.5:53'));
				else if (dm == 'tcp') local = 'tcp://' + utils.normalize_dns(cfg('@global[0]', 'direct_dns', '223.5.5.5:53'));
				run_chinadns_ng({ _flag: sid, _listen_port: cp, _dns_local: local,
					_dns_trust: '127.0.0.1#' + fwd, _no_ipv6_trust: filter6,
					_use_direct_list: direct, _use_proxy_list: proxy, _use_block_list: block,
					_gfwlist: gfw, _chnlist: chn, _default_mode: proxy_mode,
					_default_tag: s.chinadns_ng_default_tag ?? 'smart', _no_logic_log: '1',
					_node: node, _filter_https: s.force_https_soa ?? '0', _log: s.log_chinadns_ng ?? '0' });
				use_default = 'chinadns_ng';
			}
			if (filter6 == '1' && dns_filter6 == '1')
				dns_filter6 = utils.get_cache_var('node_' + node + '_' + dns_key + '_ipv6') ?? '1';
			let dp = utils.get_new_port(++next_dnsmasq);
			add_dnsmasq_rule(sid, path + '/dnsmasq.d', path + '/dnsmasq.conf', dp, '127.0.0.1#' + fwd, china, {
				use_default_dns: use_default, use_direct_list: direct, use_proxy_list: proxy,
				use_block_list: block, use_gfw_list: gfw, chn_list: chn, node: node,
				proxy_mode: proxy_mode, no_ipv6: dns_filter6, no_logic_log: '1'
			});
			launch_core(utils.first_type('dnsmasq'), 'dnsmasq_' + sid, '/dev/null',
			            ['-C', path + '/dnsmasq.conf', '-x', path + '/dnsmasq.pid']);
			utils.set_cache_var('ACL_' + sid + '_dns_port', dp);
			launch_core('/usr/bin/ucode', 'lease2hosts', '/dev/null', [LIBEXEC + '/lease2hosts.uc'], { NO_REC_PROCESS: '1' });
		}

		let cached_socks = utils.get_cache_var('acl_node_' + node + '_socks_port');
		let cached_redir = utils.get_cache_var('acl_node_' + node + '_redir_port');
		let log_used = utils.get_cache_var('acl_node_' + node + '_enable_log');
		if (cached_socks && cached_redir && log_used != '1' && (s.log ?? '0') != '1') {
			socks_port = int(cached_socks); redir_port = cached_redir;
			dns_for_acl(utils.get_cache_var('node_' + node + '_' + dns_key));
		} else {
			socks_port = utils.get_new_port(++next_socks);
			redir_port = utils.get_new_port(++next_redir);
			utils.set_cache_var('acl_node_' + node + '_socks_port', socks_port);
			utils.set_cache_var('acl_node_' + node + '_redir_port', redir_port);
			let logfile = '/dev/null';
			if ((s.log ?? '0') == '1') { logfile = path + '/node.log'; utils.set_cache_var('acl_node_' + node + '_enable_log', '1'); }
			if (type_name == 'sing-box' || type_name == 'xray') {
				let o = { flag: node, node: node, redir_port: redir_port, tcp_proxy_way: state.TCP_PROXY_WAY,
					socks_address: '127.0.0.1', socks_port: socks_port,
					config_file: TMP + '/acl/' + node + '_' + redir_port + '.json',
					log_file: logfile, loglevel: s.loglevel ?? 'warn',
					use_proxy_list: proxy, use_gfw_list: gfw, chn_list: chn };
				if (type_name == dmode) {
					integrated_dns = utils.get_new_port(++next_dns); dns_filter6 = '0';
					if (filter6 == '1') utils.set_cache_var('node_' + node + '_' + dns_key + '_ipv6', '0');
					o.dns_listen_port = integrated_dns; o.remote_dns_protocol = vmode;
					o.remote_dns_udp_server = remote; o.remote_dns_tcp_server = remote; o.remote_dns_doh = doh;
					o.remote_dns_query_strategy = filter6 == '1' ? 'UseIPv4' : 'UseIP';
					o.remote_fakedns = fake; o.remote_dns_client_ip = client_ip; o.remote_rewrite_ttl = ttl;
				}
				run_core(type_name, o);
			} else {
				run_socks({ flag: node, node: node, bind: '127.0.0.1', socks_port: socks_port,
					config_file: 'acl/' + node + '_SOCKS_' + socks_port + '.json',
					log_file: logfile, loglevel: s.loglevel ?? 'warn' });
				run_ipt2socks({ flag: 'acl_' + node, tcp_tproxy: state.TCP_PROXY_WAY == 'tproxy' ? '1' : '',
					local_port: redir_port, socks_address: '127.0.0.1', socks_port: socks_port, log_file: '/dev/null' });
			}
			dns_for_acl(integrated_dns);
		}
		utils.set_cache_var('ACL_' + sid + '_node', node);
		utils.set_cache_var('ACL_' + sid + '_redir_port', redir_port);
		if (fakedns) utils.set_cache_var('ACL_' + sid + '_fakedns', '1');
	});
	if (!enabled) {
		state.ENABLED_ACLS = '0';
		utils.set_cache_var('ENABLED_ACLS', '0');
	}
};

function clean_cron_lines() {
	let path = '/etc/crontabs/root';
	let keep = [];
	for (let line in split(fs.readfile(path) ?? '', '\n')) {
		if (index(line, '/etc/init.d/passwall') >= 0 || index(line, '/passwall/rule_update.') >= 0 ||
		    index(line, '/passwall/subscribe.') >= 0)
			continue;
		if (line != '') push(keep, line);
	}
	fs.writefile(path, length(keep) ? join('\n', keep) + '\n' : '');
}

export function clean_crontab() {
	api.fs.mkdirr('/etc/crontabs');
	clean_cron_lines();
	let listed = api.proc_lines('passwall/');
	for (let line in split(listed, '\n')) {
		if (match(line, /tasks\.uc/) == null) continue;
		let pid = match(line, /^([0-9]+)/)?.[1];
		if (pid) command(['kill', '-9', pid], true);
	}
	fs.unlink('/var/lock/passwall_tasks.lock');
};

function cron_time(week, value) {
	let parts = split(value ?? '', ':');
	let hour = int(parts[0] ?? 0), minute = int(parts[1] ?? 0);
	return minute + ' ' + hour + ' * * ' + (week == '7' ? '*' : week);
}

export function start_crontab(mode) {
	let setsid = utils.first_type('setsid') ? 'setsid ' : '';
	if (state.ENABLED_DEFAULT_ACL == '1' || state.ENABLED_ACLS == '1') {
		if (cfg('@global_delay[0]', 'start_daemon', '0') == '1')
			launch_core('/usr/bin/ucode', 'monitor', '/dev/null', [LIBEXEC + '/monitor.uc'], { NO_REC_PROCESS: '1' });
	}
	if (mode == 'cron') {
		api.log('当前为计划任务自动运行，不重新配置定时任务。');
		return;
	}
	clean_crontab();
	if (state.ENABLED != '1') {
		if (fs.access('/etc/init.d/cron', 'x')) command(['/etc/init.d/cron', 'restart'], true);
		return;
	}
	let entries = [], loop = false;
	for (let item in [
		['stop', 'stop_week_mode', 'stop_time_mode', '配置定时任务：自动关闭服务。'],
		['start', 'start_week_mode', 'start_time_mode', '配置定时任务：自动开启服务。'],
		['restart', 'restart_week_mode', 'restart_time_mode', '配置定时任务：自动重启服务。']
	]) {
		let week = cfg('@global_delay[0]', item[1]), value = cfg('@global_delay[0]', item[2]);
		if (!week) continue;
		if (week == '8') loop = true;
		else push(entries, cron_time(week, value) + ' ' + setsid + '/etc/init.d/passwall ' + item[0] + ' cron > /dev/null 2>&1 &');
		api.log(item[3]);
	}
	let week = cfg('@global_rules[0]', 'update_week_mode'), value = cfg('@global_rules[0]', 'update_time_mode');
	if (week) {
		if (week == '8') loop = true;
		else push(entries, cron_time(week, value) + ' ' + setsid + 'ucode ' + LIBEXEC + '/rule_update.uc log all cron > /dev/null 2>&1 &');
		api.log('配置定时任务：自动更新规则。');
	}
	let groups = {};
	api.uci_foreach_c('subscribe_list', function(s) {
		if (!s.update_week_mode) return;
		let key = s.update_week_mode + '_' + (s.update_time_mode ?? '');
		if (groups[key] == null) groups[key] = [];
		push(groups[key], s['.name']);
		api.log('配置定时任务：自动更新【' + (s.remark ?? '') + '】订阅。');
	});
	for (let key, ids in groups) {
		let p = split(key, '_');
		if (p[0] == '8') loop = true;
		else push(entries, cron_time(p[0], p[1]) + ' ' + setsid + 'ucode ' + LIBEXEC + '/subscribe.uc start ' + join(',', ids) + ' cron > /dev/null 2>&1 &');
	}
	if (length(entries)) append('/etc/crontabs/root', join('\n', entries) + '\n');
	if (loop && (state.ENABLED_DEFAULT_ACL == '1' || state.ENABLED_ACLS == '1')) {
		launch_core('/usr/bin/ucode', 'tasks', '/dev/null', [LIBEXEC + '/tasks.uc'], { NO_REC_PROCESS: '1' });
		api.log('自动更新：启动循环更新进程。');
	} else if (state.ENABLED_DEFAULT_ACL != '1' && state.ENABLED_ACLS != '1')
		api.log('运行于非代理模式，仅允许服务启停的定时任务。');
	if (fs.access('/etc/init.d/cron', 'x')) command(['/etc/init.d/cron', 'restart'], true);
};

export function stop_crontab(mode) {
	if (mode == 'cron') return;
	clean_crontab();
	if (fs.access('/etc/init.d/cron', 'x')) command(['/etc/init.d/cron', 'restart'], true);
};

export function write_nft_env() {
	let names = ['NODE','ENABLED','ENABLED_DEFAULT_ACL','ENABLED_ACLS','CLIENT_PROXY','TCP_NO_REDIR_PORTS',
		'UDP_NO_REDIR_PORTS','TCP_PROXY_DROP_PORTS','UDP_PROXY_DROP_PORTS','TCP_REDIR_PORTS','UDP_REDIR_PORTS',
		'TCP_PROXY_MODE','UDP_PROXY_MODE','USE_DIRECT_LIST','USE_PROXY_LIST','USE_BLOCK_LIST','USE_GFW_LIST',
		'CHN_LIST','DNS_REDIRECT_PORT','DIRECT_DNSMASQ_PORT','USE_FAKEDNS','PROXY_IPV6','TCP_PROXY_WAY',
		'LOCALHOST_TCP_PROXY_MODE','LOCALHOST_UDP_PROXY_MODE','LOCALHOST_PROXY','REDIR_PORT','TCP_PROXY_DNS',
		'UDP_PROXY_DNS','REMOTE_DNS','IPT_APPEND_DNS','ISP_DNS','ISP_DNS6','DNS_REDIRECT','FILTER_PROXY_IPV6'];
	let lines = [];
	for (let name in names) push(lines, name + '=' + api.shellquote(state[name] ?? ''));
	fs.writefile(TMP + '/nft.env', join('\n', lines) + '\n');
};

export function start(mode) {
	let residues = api.proc_lines(TMP + '/bin');
	if (trim(residues) != '') {
		command(['logger', '-t', 'PSW-RESTART', 'Upgrade or overload residue is detected, and the subprocess is being called to perform complete cleaning...'], true);
		stop(mode, true);
		command(['sleep', '2'], true);
	}
	mkdirs();
	get_config();
	start_haproxy();
	start_socks();
	check_run_environment();
	if (state.ENABLED_DEFAULT_ACL == '1' || state.ENABLED_ACLS == '1') {
		if (api.uci_get('dhcp', '@dnsmasq[0]', 'dns_redirect') == '1') {
			api.uci_set_c('@global[0]', 'dnsmasq_dns_redirect', '1');
			api.uci_save_c(true);
			api.uci_set('dhcp', '@dnsmasq[0]', 'dns_redirect', '0');
			api.uci_save(null, 'dhcp', true);
			command(['/usr/bin/ucode', LIBEXEC + '/helper_dnsmasq.uc', 'restart', '-LOG', '0'], true);
		}
	}
	if (state.ENABLED_DEFAULT_ACL == '1') {
		api.fs.mkdirr(GLOBAL_ACL);
		if (start_global() != 0 || start_dns() != 0) {
			api.log('全局节点或 DNS 启动失败，停止服务。');
			stop('');
			return 1;
		}
	}
	if (state.USE_TABLES == 'nftables') {
		if (state.ENABLED_ACLS == '1') acl_app();
		write_nft_env();
		command([LIBEXEC + '/nftables.uc', 'start'], false);
	}
	utils.set_cache_var('USE_TABLES', state.USE_TABLES);
	if (state.ENABLED_DEFAULT_ACL == '1' || state.ENABLED_ACLS == '1') {
		let old = trim(command_output(['sysctl', '-e', '-n', 'net.bridge.bridge-nf-call-iptables']));
		utils.set_cache_var('bak_bridge_nf_ipt', old);
		command(['sysctl', '-w', 'net.bridge.bridge-nf-call-iptables=0'], true);
		if (state.PROXY_IPV6 == '1') {
			old = trim(command_output(['sysctl', '-e', '-n', 'net.bridge.bridge-nf-call-ip6tables']));
			utils.set_cache_var('bak_bridge_nf_ip6t', old);
			command(['sysctl', '-w', 'net.bridge.bridge-nf-call-ip6tables=0'], true);
		}
	}
	start_crontab(mode);
	api.log('运行完成！\n');
	if (state.ENABLED == '1' && mode == 'boot') {
		let ids = [];
		api.uci_foreach_c('subscribe_list', function(s) {
			if (s.boot_update == '1') push(ids, s['.name']);
		});
		if (length(ids)) {
			command(['sleep', '5'], true);
			launch_core('/usr/bin/ucode', 'subscribe_boot', '/dev/null',
			            [LIBEXEC + '/subscribe.uc', 'start', join(',', ids), 'cron'], { NO_REC_PROCESS: '1' });
		}
	}
	return 0;
};

function kill_matching(pattern, excludes) {
	let got = api.proc_lines(pattern);
	for (let line in split(got, '\n')) {
		let skip = false;
		for (let exclude in excludes ?? [])
			if (match(line, exclude) != null) skip = true;
		if (skip) continue;
		let pid = match(line, /^([0-9]+)/)?.[1];
		if (pid) command(['kill', '-9', pid], true);
	}
}

export function stop(mode, internal) {
	utils.clean_log();
	let cache = utils.cache_all();
	if ((cache.USE_TABLES ?? '') == 'nftables')
		command([LIBEXEC + '/nftables.uc', 'stop'], true);
	utils.delete_ip2route();
	for (let path in split(command_output(['find', TMP, '-type', 'f', '-name', '*_plugin.pid']), '\n')) {
		if (!path) continue;
		let pid = match(fs.readfile(path) ?? '', /^([0-9]+)/)?.[1];
		if (pid) command(['kill', '-9', pid], true);
	}
	kill_matching('passwall/monitor.', []);
	kill_matching('sleep.*(6s|9s|58s)', []);
	kill_matching('passwall/', [/app\.uc/, /service\.uc/, /subscribe\.uc/, /rule_update\.uc/, /tasks\.uc/, /server_app\.uc/, /ujail/]);
	stop_crontab(mode);
	unlink_tree(cache.GLOBAL_DNSMASQ_CONF ?? '');
	unlink_tree(cache.GLOBAL_DNSMASQ_CONF_PATH ?? '');
	let backup = cfg('@global[0]', 'dnsmasq_dns_redirect');
	if (backup) {
		api.uci_set('dhcp', '@dnsmasq[0]', 'dns_redirect', backup);
		api.uci_del_c('@global[0]', 'dnsmasq_dns_redirect');
		api.uci_save(null, 'dhcp', true);
		api.uci_save_c(true);
	}
	if (!cache.ACL_default_dns_port || backup) {
		api.uci.del_list('dhcp', api.uci_get('dhcp', '@dnsmasq[0]')?.['.name'], 'addnmount', cache.GLOBAL_DNSMASQ_CONF_PATH ?? '');
		api.uci_save(null, 'dhcp', true);
		command(['/usr/bin/ucode', LIBEXEC + '/helper_dnsmasq.uc', 'restart', '-LOG', '0'], true);
	}
	if (cache.bak_bridge_nf_ipt) command(['sysctl', '-w', 'net.bridge.bridge-nf-call-iptables=' + cache.bak_bridge_nf_ipt], true);
	if (cache.bak_bridge_nf_ip6t) command(['sysctl', '-w', 'net.bridge.bridge-nf-call-ip6tables=' + cache.bak_bridge_nf_ip6t], true);
	unlink_tree(TMP);
	api.log('清空并关闭相关程序和缓存完成。');
	return 0;
};

export function main(argv) {
	let action = argv[0] ?? '';
	let args = [];
	for (let i = 1; i < length(argv); i++) push(args, argv[i]);
	get_local_dns();
	if (action == 'run_socks') return run_socks(args);
	if (action == 'socks_node_switch') return socks_node_switch(args);
	if (action == 'start') return start(args[0]);
	if (action == 'stop') return stop(args[0]);
	return 1;
};
