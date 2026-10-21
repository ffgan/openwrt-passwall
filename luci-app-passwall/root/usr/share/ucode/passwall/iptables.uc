'use strict';

import * as fs from 'fs';
import * as api from 'passwall.api';
import * as utils from 'passwall.utils';

const TMP = utils.TMP_PATH;
const ACL = utils.TMP_ACL_PATH;
const IFACES = utils.TMP_IFACE_PATH;
const RULES = utils.RULES_PATH;
const USER_RULES = utils.USER_RULES_PATH;
const LIBEXEC = utils.UCODE_BIN;
const MARK = '0x50535731';
const FAKE4 = '198.18.0.0/16';
const FAKE6 = '2001:2::/48';
const SET = {
	local:'psw_local', wan:'psw_wan', lan:'psw_lan', vps:'psw_vps', shunt:'psw_shunt',
	gfw:'psw_gfw', chn:'psw_chn', black:'psw_black', white:'psw_white', block:'psw_block',
	local6:'psw_local6', wan6:'psw_wan6', lan6:'psw_lan6', vps6:'psw_vps6',
	shunt6:'psw_shunt6', gfw6:'psw_gfw6', chn6:'psw_chn6', black6:'psw_black6',
	white6:'psw_white6', block6:'psw_block6'
};

let env = {};
let ipt = '', ip6t = '', fwi = '';
let use_geoview = false, use_shunt = false, tproxy = false;

function getenv(name, fallback) {
	let value = type(global.getenv) == 'function' ? global.getenv(name) : null;
	return value == null || value == '' ? (fallback ?? '') : '' + value;
}

function run(argv, quiet) {
	if (!argv[0]) return 127;
	return utils.run(argv, quiet ?? true);
}

function output(argv) {
	if (!argv[0]) return '';
	return utils.output(argv);
}

function load_env() {
	let names = [
		'NODE','ENABLED','ENABLED_DEFAULT_ACL','ENABLED_ACLS','CLIENT_PROXY','TCP_NO_REDIR_PORTS',
		'UDP_NO_REDIR_PORTS','TCP_PROXY_DROP_PORTS','UDP_PROXY_DROP_PORTS','TCP_REDIR_PORTS',
		'UDP_REDIR_PORTS','TCP_PROXY_MODE','UDP_PROXY_MODE','USE_DIRECT_LIST','USE_PROXY_LIST',
		'USE_BLOCK_LIST','USE_GFW_LIST','CHN_LIST','DNS_REDIRECT_PORT','DIRECT_DNSMASQ_PORT',
		'USE_FAKEDNS','PROXY_IPV6','TCP_PROXY_WAY','LOCALHOST_TCP_PROXY_MODE',
		'LOCALHOST_UDP_PROXY_MODE','LOCALHOST_PROXY','REDIR_PORT','TCP_PROXY_DNS','UDP_PROXY_DNS',
		'REMOTE_DNS','IPT_APPEND_DNS','ISP_DNS','ISP_DNS6','DNS_REDIRECT','FILTER_PROXY_IPV6'
	];
	for (let name in names) env[name] = getenv(name);
	if (env.ENABLED_DEFAULT_ACL == '' && fs.stat(TMP + '/var') != null)
		for (let name in names) env[name] = utils.get_cache_var(name) ?? env[name];
	ipt = utils.first_type('iptables-legacy','iptables');
	ip6t = utils.first_type('ip6tables-legacy','ip6tables');
	fwi = trim(output(['uci','-q','get','firewall.passwall.path'])) || '/tmp/etc/passwall.include';
	tproxy = env.TCP_PROXY_WAY == 'tproxy';
}

function words(text) {
	let out = [];
	for (let word in split(trim(text ?? ''), /[[:space:]]+/))
		if (word != '') push(out, word);
	return out;
}

function parse_json(text) {
	try { return json(text) ?? {}; }
	catch (e) { return {}; }
}

function command_words(command) {
	return type(command) == 'array' ? command : words(command);
}

function xt(family, table, args, quiet) {
	let binary = family == 6 ? ip6t : ipt;
	if (!binary) return 127;
	return run([binary, '-t', table, '-w', ...args], quiet);
}

function xf(family, args, quiet) {
	let binary = family == 6 ? ip6t : ipt;
	if (!binary) return 127;
	return run([binary, '-w', ...args], quiet);
}

function ipset(args, quiet) {
	return run(['ipset', ...args], quiet);
}

function ipset_restore(lines) {
	if (!length(lines)) return 0;
	let ph = fs.popen(['ipset', '-!', '-R'], 'w');
	if (ph == null) return 127;
	ph.write(join('\n', lines) + '\n');
	return ph.close() ?? 255;
}

function cfg(section, option, fallback) {
	return utils.config_n_get(section, option, fallback);
}

function section(section) {
	return api.uci_get_c(section) ?? {};
}

function dst(name) {
	return ['-m', 'set', '--match-set', name, 'dst'];
}

function comment(name) {
	return ['-m', 'comment', '--comment', replace('' + name, / /g, '_')];
}

function redirect(port, transparent) {
	if (!port) return ['-j', 'REDIRECT'];
	if (transparent) return ['-m', 'mark', '--mark', MARK, '-j', 'TPROXY', '--on-port', '' + port];
	return ['-j', 'REDIRECT', '--to-ports', '' + port];
}

function jump(mode, target, transparent) {
	if (mode == 'direct') return ['-m', 'mark', '!', '--mark', MARK, '-j', 'RETURN'];
	if (mode != 'proxy') return [];
	if (type(target) == 'array') return target;
	return redirect(target, transparent);
}

function normalize_ports(value) {
	let out = [], seen = {};
	value = replace(replace(value ?? '', / /g, ''), /-/g, ':');
	for (let p in split(value, ',')) {
		p = trim(p);
		if (p != '' && match(p, /[0-9]/) != null && !seen[p]) { seen[p] = true; push(out, p); }
	}
	return out;
}

function add_port_rules(base, ports, target) {
	let list = normalize_ports(ports);
	if (!length(list)) return;
	base = command_words(base);
	target = command_words(target);
	let singles = [], ranges = [];
	for (let port in list) {
		if (port == '1:65535') {
			run([...base, ...target], true);
			return;
		}
		if (index(port, ':') >= 0) push(ranges, port);
		else {
			push(singles, port);
			if (length(singles) == 15) {
				run([...base, '-m', 'multiport', '--dport', join(',', singles), ...target], true);
				singles = [];
			}
		}
	}
	if (length(singles)) run([...base, '-m', 'multiport', '--dport', join(',', singles), ...target], true);
	for (let port in ranges) run([...base, '--dport', port, ...target], true);
}

function destroy_ipset(...names) {
	for (let name in names) {
		ipset(['-q', '-F', name], true);
		ipset(['-q', '-X', name], true);
	}
}

function listed(command, chain) {
	let argv = [...command_words(command), '-n', '-L', chain, '--line-numbers'];
	return output(argv);
}

function matching_indexes(command, chain, keyword) {
	let out = [], pattern = regexp(keyword);
	for (let line in split(listed(command, chain), '\n')) {
		if (match(line, pattern) == null) continue;
		let m = match(line, /^[[:space:]]*([0-9]+)/);
		if (m != null) push(out, int(m[1]));
	}
	return out;
}

function insert_rule_before(command, chain, keyword, rule, default_index) {
	if (!command || !chain || keyword == null) return 1;
	let cmd = command_words(command), indexes = matching_indexes(cmd, chain, keyword);
	let index_no = length(indexes) ? indexes[0] : int(default_index ?? 0);
	return run([...cmd, index_no ? '-I' : '-A', chain, ...(index_no ? ['' + index_no] : []), ...command_words(rule)], true);
}

function insert_rule_after(command, chain, keyword, rule, default_index) {
	if (!command || !chain || keyword == null) return 1;
	let cmd = command_words(command), indexes = matching_indexes(cmd, chain, keyword);
	let index_no = length(indexes) ? indexes[length(indexes) - 1] + 1 : int(default_index ?? 0);
	return run([...cmd, index_no ? '-I' : '-A', chain, ...(index_no ? ['' + index_no] : []), ...command_words(rule)], true);
}

function RULE_LAST_INDEX(command, chain, keyword, fallback) {
	if (!command || !chain || keyword == null) {
		api.log('索引列举方式不正确（iptables），终止执行！');
		return null;
	}
	let indexes = matching_indexes(command, chain, keyword);
	if (!length(indexes)) return int(fallback ?? 0);
	return indexes[0];
}

function create_set(name, family, timeout) {
	let args = ['-!', 'create', name, 'nethash'];
	if (family == 6) push(args, 'family', 'inet6');
	push(args, 'maxelem', '1048576');
	if (timeout) push(args, 'timeout', '172800');
	ipset(args, true);
}

function valid_ip_lines(text, family) {
	let out = [], seen = {};
	for (let raw in split(replace(text ?? '', /\r/g, ''), '\n')) {
		let value = trim(split(raw, '#')[0]);
		if (value == '' || seen[value]) continue;
		let host = split(value, '/')[0];
		if ((family == 4 && utils.is_ipv4(host)) || (family == 6 && utils.is_ipv6(host))) {
			seen[value] = true; push(out, value);
		}
	}
	return out;
}

function load_values(setname, values) {
	let lines = [];
	let timed = match(setname, /^psw_(local|wan|lan|vps)6?$/) == null;
	for (let value in values)
		push(lines, 'add ' + setname + ' ' + value + (timed ? ' timeout 0' : ''));
	ipset_restore(lines);
}

function clone_static_set(source, target) {
	let values = [];
	for (let line in split(output(['ipset', 'save', source]), '\n')) {
		let fields = words(line);
		if (length(fields) >= 5 && fields[0] == 'add' && fields[3] == 'timeout' && fields[4] == '0')
			push(values, fields[2]);
	}
	load_values(target, values);
}

function geo_codes(text) {
	let out = [];
	for (let line in split(replace(text ?? '', /\r/g, ''), '\n')) {
		let m = match(trim(line), /^geoip:(.+)$/);
		if (m != null && m[1] != 'private') push(out, m[1]);
	}
	return out;
}

function load_rule_file(path, set4, set6, geo) {
	let text = fs.readfile(path) ?? '';
	load_values(set4, valid_ip_lines(text, 4));
	load_values(set6, valid_ip_lines(text, 6));
	if (geo && use_geoview) {
		let codes = geo_codes(text);
		if (length(codes)) {
			load_values(set4, valid_ip_lines(utils.get_geoip(join(',', codes), 'ipv4'), 4));
			load_values(set6, valid_ip_lines(utils.get_geoip(join(',', codes), 'ipv6'), 6));
		}
	}
}

function update_wan_sets_unlocked(log_enabled) {
	for (let ip in utils.get_wan_ips('ip4')) {
		let rc = ipset(['-!', 'add', SET.wan, ip], true);
		if (log_enabled) api.log('  - [' + rc + ']加入WAN IPv4到ipset[' + SET.wan + ']：' + ip);
	}
	for (let ip in utils.get_wan_ips('ip6')) {
		let rc = ipset(['-!', 'add', SET.wan6, ip], true);
		if (log_enabled) api.log('  - [' + rc + ']加入WAN IPv6到ipset[' + SET.wan6 + ']：' + ip);
	}
}

function update_wan_sets(log_mode, original_mode) {
	/* flock executes this entry point again, avoiding shell locking/evaluation. */
	if (log_mode != '--locked')
		return run(['flock', '-x', '/var/lock/passwall_update_wan_sets.lock',
		            '/usr/bin/ucode', LIBEXEC + '/iptables.uc', 'update_wan_sets', '--locked',
		            log_mode ?? ''], true);
	update_wan_sets_unlocked(original_mode == 'log');
	return 0;
}

function node_addresses() {
	let out = [];
	for (let type_name in ['nodes', 'socks']) api.uci_foreach_c(type_name, function(s) {
		for (let key in ['address', 'download_address'])
			if (s[key]) push(out, s[key]);
	});
	return out;
}

function filter_vpsip() {
	let v4 = [], v6 = [];
	for (let address in node_addresses()) {
		if (match(address, /^(0\.0\.0\.0|127\.0\.0\.1|1\.1\.1\.[12]|8\.8\.[48]\.8|9\.9\.9\.9)$/) != null) continue;
		if (utils.is_ipv4(address)) push(v4, address);
		else if (utils.is_ipv6(address)) push(v6, address);
	}
	load_values(SET.vps, v4); load_values(SET.vps6, v6);
}

function filter_haproxy() {
	if (cfg('@global_haproxy[0]', 'balancing_enable', '0') != '1') return;
	api.uci_foreach_c('haproxy_config', function(s) {
		let hp = utils.get_ip_port_from(s.lbss ?? '', true);
		let ip = utils.get_host_ip('ipv4', hp.host, 1);
		if (ip && match(ip, /^(0\.0\.0\.0|127\.0\.0\.1|1\.1\.1\.[12]|8\.8\.[48]\.8|9\.9\.9\.9)$/) == null)
			ipset(['-q', 'add', SET.vps, ip], true);
	});
}

function server_rule(address, ports, stream, transparent) {
	stream = lc(stream ?? '');
	if (stream == 'udp') transparent = true;
	for (let family in [4, 6]) {
		let table = transparent ? 'mangle' : 'nat';
		let base = [family == 6 ? ip6t : ipt, '-t', family == 6 ? 'mangle' : table, '-w'];
		if (!base[0]) continue;
		let ranges = [], singles = [];
		for (let p in normalize_ports(ports))
			if (index(p, ':') >= 0) push(ranges, p); else push(singles, p);
		for (let p in ranges) {
			let key = address + ':' + p + ':' + stream;
			if (index(listed(base, 'PSW_OUTPUT'), key) < 0)
				run([...base, '-I', 'PSW_OUTPUT', ...comment(key), '-p', stream, '-d', address, '--dport', p, '-j', 'RETURN'], true);
		}
		if (length(singles)) {
			sort(singles, (a,b) => int(a)-int(b));
			let value = join(',', singles), key = address + ':' + value + ':' + stream;
			if (index(listed(base, 'PSW_OUTPUT'), key) < 0)
				run([...base, '-I', 'PSW_OUTPUT', ...comment(key), '-p', stream, '-d', address,
				     '-m', 'multiport', '--dports', value, '-j', 'RETURN'], true);
		}
	}
}

function filter_node(node, stream, transparent) {
	if (!node) return 1;
	let address = cfg(node, 'address'), port = cfg(node, 'port'), hop = cfg(node, 'hysteria2_hop');
	if (hop) port += (port ? ',' : '') + hop;
	if (!address || !port || match(address, /^(0\.0\.0\.0|127\.0\.0\.1|1\.1\.1\.[12]|8\.8\.[48]\.8|9\.9\.9\.9)$/) != null) return 1;
	server_rule(address, port, stream, transparent);
}

function filter_direct_node_list() {
	let seen = {};
	for (let node in split(fs.readfile(TMP + '/direct_node_list') ?? '', '\n')) {
		node = trim(node);
		if (!node || seen[node]) continue;
		seen[node] = true;
		filter_node(node, 'tcp', cfg('@global_forwarding[0]', 'tcp_proxy_way', 'redirect') == 'tproxy');
		filter_node(node, 'udp', true);
	}
}

function sysctl_tproxy() {
	run(['sysctl', '-w', 'net.ipv4.conf.all.rp_filter=0'], true);
	run(['sysctl', '-w', 'net.ipv4.conf.default.rp_filter=0'], true);
	for (let path in fs.lsdir('/proc/sys/net/ipv4/conf') ?? [])
		fs.writefile('/proc/sys/net/ipv4/conf/' + path + '/rp_filter', '0\n');
}

function source_args(line, iface) {
	let args = [], ipv4 = false, description = '';
	if (iface) { push(args, '-i', iface); description = '源接口【' + iface + '】，'; }
	if (substr(line, 0, 8) == 'iprange:') {
		push(args, '-m', 'iprange', '--src-range', substr(line, 8)); ipv4 = true;
	} else if (substr(line, 0, 6) == 'ipset:') {
		let name = substr(line, 6);
		if (ipset(['-q', 'list', name], true) != 0) return null;
		push(args, '-m', 'set', '--match-set', name, 'src');
	} else if (substr(line, 0, 3) == 'ip:') {
		push(args, '-s', substr(line, 3)); ipv4 = true;
	} else if (substr(line, 0, 4) == 'mac:') {
		push(args, '-m', 'mac', '--mac-source', substr(line, 4));
	} else if (line != 'any') return null;
	return { args, ipv4, description };
}

function interface_device(name) {
	if (!name) return '';
	let status = parse_json(output(['ubus', 'call', 'network.interface.' + name, 'status']));
	return status.l3_device ?? status.device ?? name;
}

function populate_shunt(node, set4, set6) {
	let group = cfg(node, 'shunt_group'), codes = [];
	api.uci_foreach_c('shunt_rules', function(s) {
		if ((s.group ?? '') != group) return;
		load_values(set4, valid_ip_lines(s.ip_list, 4));
		load_values(set6, valid_ip_lines(s.ip_list, 6));
		for (let code in geo_codes(s.ip_list)) push(codes, code);
	});
	if (use_geoview && length(codes)) {
		load_values(set4, valid_ip_lines(utils.get_geoip(join(',', codes), 'ipv4'), 4));
		load_values(set6, valid_ip_lines(utils.get_geoip(join(',', codes), 'ipv6'), 6));
	}
}

function list_targets(base, family, proto, ports, options, target, drop) {
	let suffix = family == 6 ? '6' : '';
	let fake = family == 6 ? FAKE6 : FAKE4;
	if (options.fake == '1') {
		if (drop) add_port_rules(base, ports, ['-d', fake, ...target]);
		else run([...base, '-d', fake, ...target], true);
	}
	if (options.proxy == '1') add_port_rules(base, ports, [...dst(options.black), ...target]);
	if (options.use_gfw == '1') add_port_rules(base, ports, [...dst(options.gfw_set), ...target]);
	if (options.chn != '0') add_port_rules(base, ports, [...dst(SET['chn' + suffix]), ...jump(options.chn, target, tproxy)]);
	if (options.shunt) add_port_rules(base, ports, [...dst(options.shunt_set), ...target]);
	if (options.mode != 'disable') add_port_rules(base, ports, target);
}

function icmp_targets(family, base, options) {
	let fake = family == 6 ? FAKE6 : FAKE4, suffix = family == 6 ? '6' : '';
	let target = redirect();
	if (options.fake == '1') run([...base, '-d', fake, ...target], true);
	if (options.proxy == '1') run([...base, ...dst(options.black), ...target], true);
	if (options.use_gfw == '1') run([...base, ...dst(options.gfw_set), ...target], true);
	if (options.chn != '0') run([...base, ...dst(SET['chn' + suffix]), ...jump(options.chn, target)], true);
	if (options.shunt) run([...base, ...dst(options.shunt_set), ...target], true);
	if (options.mode != 'disable') run([...base, ...target], true);
}

function load_acl_source(sid, s, source, global_cfg) {
	let iface = interface_device(s.interface), src = source_args(source, iface);
	if (src == null) return;
	let remarks = s.remarks ?? sid;
	let acl_mode = s.mode ?? '0';
	let tcp_no = acl_mode == '0' ? '1:65535' : (s.tcp_no_redir_ports == 'default' || !s.tcp_no_redir_ports ? env.TCP_NO_REDIR_PORTS : s.tcp_no_redir_ports);
	let udp_no = acl_mode == '0' ? '1:65535' : (s.udp_no_redir_ports == 'default' || !s.udp_no_redir_ports ? env.UDP_NO_REDIR_PORTS : s.udp_no_redir_ports);
	let tcp_drop = s.tcp_proxy_drop_ports == 'default' || !s.tcp_proxy_drop_ports ? env.TCP_PROXY_DROP_PORTS : s.tcp_proxy_drop_ports;
	let udp_drop = s.udp_proxy_drop_ports == 'default' || !s.udp_proxy_drop_ports ? env.UDP_PROXY_DROP_PORTS : s.udp_proxy_drop_ports;
	let tcp_ports = s.tcp_redir_ports == 'default' || !s.tcp_redir_ports ? env.TCP_REDIR_PORTS : s.tcp_redir_ports;
	let udp_ports = s.udp_redir_ports == 'default' || !s.udp_redir_ports ? env.UDP_REDIR_PORTS : s.udp_redir_ports;
	let tcp_mode = global_cfg ? env.TCP_PROXY_MODE : (s.tcp_proxy_mode ?? 'proxy');
	let udp_mode = global_cfg ? env.UDP_PROXY_MODE : (s.udp_proxy_mode ?? 'proxy');
	let direct = global_cfg ? env.USE_DIRECT_LIST : (s.use_direct_list ?? '1');
	let proxy = global_cfg ? env.USE_PROXY_LIST : (s.use_proxy_list ?? '1');
	let block = global_cfg ? env.USE_BLOCK_LIST : (s.use_block_list ?? '1');
	let gfw = global_cfg ? env.USE_GFW_LIST : (s.use_gfw_list ?? '1');
	let chn = global_cfg ? env.CHN_LIST : (s.chn_list ?? 'direct');
	let node = utils.get_cache_var('ACL_' + sid + '_node') ?? s.node;
	let effective_node = global_cfg ? env.NODE : node;
	let port = global_cfg && sid == 'default' ? env.REDIR_PORT : utils.get_cache_var('ACL_' + sid + '_redir_port');
	let udp_port = port;
	let dns = global_cfg && sid == 'default' ? env.DNS_REDIRECT_PORT : utils.get_cache_var('ACL_' + sid + '_dns_port');
	let fake = utils.get_cache_var('ACL_' + sid + '_fakedns') ?? (global_cfg ? env.USE_FAKEDNS : '0');
	let shunt = effective_node && cfg(effective_node, 'protocol') == '_shunt';
	let set_black = global_cfg ? SET.black : 'psw_' + sid + '_black';
	let set_black6 = global_cfg ? SET.black6 : 'psw_' + sid + '_black6';
	let set_gfw = global_cfg ? SET.gfw : 'psw_' + sid + '_gfw';
	let set_gfw6 = global_cfg ? SET.gfw6 : 'psw_' + sid + '_gfw6';
	let set_shunt = global_cfg ? SET.shunt : 'psw_' + sid + '_shunt';
	let set_shunt6 = global_cfg ? SET.shunt6 : 'psw_' + sid + '_shunt6';
	if (!global_cfg) {
		if (proxy) {
			create_set(set_black,4,true); create_set(set_black6,6,true);
			clone_static_set(SET.black, set_black); clone_static_set(SET.black6, set_black6);
		}
		if (gfw) { create_set(set_gfw,4,true); create_set(set_gfw6,6,true); }
		if (shunt) {
			create_set(set_shunt,4,true); create_set(set_shunt6,6,true);
			populate_shunt(node, set_shunt, set_shunt6);
		}
	}
	let base4tcp = [ipt, '-t', tproxy ? 'mangle' : 'nat', '-w', '-A', 'PSW', ...comment(remarks), ...src.args, '-p', 'tcp'];
	let base4udp = [ipt, '-t', 'mangle', '-w', '-A', 'PSW', ...comment(remarks), ...src.args, '-p', 'udp'];
	let base6tcp = [ip6t, '-t', 'mangle', '-w', '-A', 'PSW', ...comment(remarks), ...src.args, '-p', 'tcp'];
	let base6udp = [ip6t, '-t', 'mangle', '-w', '-A', 'PSW', ...comment(remarks), ...src.args, '-p', 'udp'];
	if (tcp_no != 'disable') {
		if (utils.has_1_65535(tcp_no)) port = null;
		else { add_port_rules(base4tcp, tcp_no, ['-j','RETURN']); if (!src.ipv4) add_port_rules(base6tcp,tcp_no,['-j','RETURN']); }
	}
	if (udp_no != 'disable') {
		if (utils.has_1_65535(udp_no)) udp_port = null;
		else { add_port_rules(base4udp,udp_no,['-j','RETURN']); if (!src.ipv4) add_port_rules(base6udp,udp_no,['-j','RETURN']); }
	}
	let active = effective_node && ((port && tcp_mode) || (udp_port && udp_mode));
	let dns_port = cfg('@global[0]','dns_redirect','1') == '1' ? '53' : '';
	if (active && dns) dns_port = dns;
	else if (!active && env.DIRECT_DNSMASQ_PORT) dns_port = env.DIRECT_DNSMASQ_PORT;
	if (dns_port) {
		for (let proto in ['udp','tcp']) {
			xt(4,'mangle',['-A','PSW',...comment(remarks),'-p',proto,...src.args,'--dport','53','-j','RETURN'],true);
			if (!src.ipv4) xt(6,'mangle',['-A','PSW',...comment(remarks),'-p',proto,...src.args,'--dport','53','-j','RETURN'],true);
			xt(4,'nat',['-A','PSW_DNS',...comment(remarks),'-p',proto,...src.args,'--dport','53',...redirect(dns_port)],true);
			if (!src.ipv4) xt(6,'nat',['-A','PSW_DNS',...comment(remarks),'-p',proto,...src.args,'--dport','53',...redirect(dns_port)],true);
		}
	}
	function targets(family, proto, mode, p, drop) {
		let base = drop
			? [family == 6 ? ip6t : ipt, '-t', 'mangle', '-w', '-A', 'PSW',
			   ...comment(remarks), ...src.args, '-p', proto]
			: (family == 6 ? (proto == 'tcp' ? base6tcp : base6udp) : (proto == 'tcp' ? base4tcp : base4udp));
		let target = drop ? ['-j','MARK','--set-mark','88'] :
			(proto == 'tcp' && !tproxy ? redirect(p) : ['-j','PSW_RULE']);
		list_targets(base, family, proto,
			drop ? (proto == 'tcp' ? tcp_drop : udp_drop) : (proto == 'tcp' ? tcp_ports : udp_ports),
			{ fake, proxy, use_gfw:gfw, chn, shunt, mode,
			  black: family == 6 ? set_black6 : set_black,
			  gfw_set: family == 6 ? set_gfw6 : set_gfw,
			  shunt_set: family == 6 ? set_shunt6 : set_shunt },
			target, drop);
	}
	if (effective_node && (port || udp_port)) {
		if (block == '1') xt(4,'mangle',['-A','PSW',...comment(remarks),...src.args,...dst(SET.block),'-j','MARK','--set-mark','88'],true);
		if (direct == '1') xt(4,tproxy?'mangle':'nat',['-A','PSW',...comment(remarks),...src.args,...dst(SET.white),'-j','RETURN'],true);
		if (!src.ipv4 && env.PROXY_IPV6=='1') {
			if (block == '1') xt(6,'mangle',['-A','PSW',...comment(remarks),...src.args,...dst(SET.block6),'-j','MARK','--set-mark','88'],true);
			if (direct == '1') xt(6,'mangle',['-A','PSW',...comment(remarks),...src.args,...dst(SET.white6),'-j','RETURN'],true);
		}
	}
	if (tcp_drop != 'disable') { targets(4,'tcp',tcp_mode,port,true); if (!src.ipv4 && env.PROXY_IPV6=='1') targets(6,'tcp',tcp_mode,port,true); }
	if (udp_drop != 'disable') { targets(4,'udp',udp_mode,udp_port,true); if (!src.ipv4 && env.PROXY_IPV6=='1') targets(6,'udp',udp_mode,udp_port,true); }
	if (tcp_drop != 'disable' || udp_drop != 'disable') {
		xt(4,'mangle',['-A','PSW',...comment(remarks),...src.args,'-m','mark','--mark','88','-j','ACCEPT'],true);
		if (!src.ipv4 && env.PROXY_IPV6=='1')
			xt(6,'mangle',['-A','PSW',...comment(remarks),...src.args,'-m','mark','--mark','88','-j','ACCEPT'],true);
	}
	if (effective_node && port && tcp_mode) {
		if (cfg('@global_forwarding[0]','accept_icmp','0') == '1')
			icmp_targets(4, [ipt,'-t','nat','-w','-A','PSW',...comment(remarks),'-p','icmp',...src.args],
				{ fake, proxy, use_gfw:gfw, chn, shunt, mode:tcp_mode, black:set_black, gfw_set:set_gfw, shunt_set:set_shunt });
		if (!src.ipv4 && env.PROXY_IPV6 == '1' && cfg('@global_forwarding[0]','accept_icmpv6','0') == '1')
			icmp_targets(6, [ip6t,'-t','nat','-w','-A','PSW',...comment(remarks),'-p','ipv6-icmp',...src.args],
				{ fake, proxy, use_gfw:gfw, chn, shunt, mode:tcp_mode, black:set_black6, gfw_set:set_gfw6, shunt_set:set_shunt6 });
		targets(4,'tcp',tcp_mode,port,false);
		if (tproxy) run([...base4tcp,...redirect(port,true)],true);
		if (!src.ipv4 && env.PROXY_IPV6=='1') { targets(6,'tcp',tcp_mode,port,false); run([...base6tcp,...redirect(port,true)],true); }
	}
	if (effective_node && udp_port && udp_mode) {
		targets(4,'udp',udp_mode,udp_port,false); run([...base4udp,...redirect(udp_port,true)],true);
		if (!src.ipv4 && env.PROXY_IPV6=='1') { targets(6,'udp',udp_mode,udp_port,false); run([...base6udp,...redirect(udp_port,true)],true); }
	}
	let ret4=[ipt,'-t',tproxy?'mangle':'nat','-w','-A','PSW',...comment(remarks),...src.args];
	let ret4m=[ipt,'-t','mangle','-w','-A','PSW',...comment(remarks),...src.args];
	if (!src.ipv4) {
		let ret6=[ip6t,'-t','mangle','-w','-A','PSW',...comment(remarks),...src.args];
		run([...ret6,'-p','tcp','-j','RETURN'],true); run([...ret6,'-p','udp','-j','RETURN'],true);
	}
	run([...ret4,'-p','tcp','-j','RETURN'],true);
	if (global_cfg && sid == 'default' && !tproxy)
		xt(4,'mangle',['-A','PSW',...comment(remarks),...src.args,'-p','tcp','-j','RETURN'],true);
	run([...ret4m,'-p','udp','-j','RETURN'],true);
}

function load_acl() {
	if (env.ENABLED_ACLS == '1') {
		for (let sid in fs.lsdir(ACL) ?? []) {
			if (sid == 'default' || fs.stat(ACL + '/' + sid)?.type != 'directory') continue;
			let s = section(sid), cached_node = utils.get_cache_var('ACL_' + sid + '_node');
			let selected_node = cached_node ?? s.node;
			let global_cfg = s.use_global_config == '1' || selected_node == 'default' || selected_node == env.NODE;
			for (let source in split(fs.readfile(ACL + '/' + sid + '/source_list') ?? '', '\n'))
				if (source) load_acl_source(sid, s, source, global_cfg);
		}
	}
	if (env.ENABLED_DEFAULT_ACL == '1' && env.CLIENT_PROXY == '1')
		load_acl_source('default', {
			remarks:'默认', mode:'1', tcp_no_redir_ports:env.TCP_NO_REDIR_PORTS,
			udp_no_redir_ports:env.UDP_NO_REDIR_PORTS, tcp_proxy_drop_ports:env.TCP_PROXY_DROP_PORTS,
			udp_proxy_drop_ports:env.UDP_PROXY_DROP_PORTS, tcp_redir_ports:env.TCP_REDIR_PORTS,
			udp_redir_ports:env.UDP_REDIR_PORTS, node:env.NODE
		}, 'any', true);
}

function setup_sets() {
	for (let key in ['local','wan','lan','vps']) create_set(SET[key],4,false);
	for (let key in ['shunt','gfw','chn','black','white','block']) create_set(SET[key],4,true);
	for (let key in ['local6','wan6','lan6','vps6']) create_set(SET[key],6,false);
	for (let key in ['shunt6','gfw6','chn6','black6','white6','block6']) create_set(SET[key],6,true);
	load_values(SET.chn, valid_ip_lines(fs.readfile(RULES + '/chnroute') ?? '', 4));
	load_values(SET.chn6, valid_ip_lines(fs.readfile(RULES + '/chnroute6') ?? '', 6));
	let all_direct = env.USE_DIRECT_LIST == '1', all_proxy = env.USE_PROXY_LIST == '1', all_block = env.USE_BLOCK_LIST == '1';
	api.uci_foreach_c('acl_rule', function(s) {
		if (s.enabled != '1' || s.use_global_config == '1') return;
		if ((s.use_direct_list ?? '1') == '1') all_direct = true;
		if ((s.use_proxy_list ?? '1') == '1') all_proxy = true;
		if ((s.use_block_list ?? '1') == '1') all_block = true;
	});
	use_geoview = cfg('@global_rules[0]','enable_geoview') == '1' &&
		utils.first_type(cfg('@global_app[0]','geoview_file'),'geoview') != '';
	if (all_direct) load_rule_file(USER_RULES + '/direct_ip',SET.white,SET.white6,true);
	if (all_proxy) load_rule_file(USER_RULES + '/proxy_ip',SET.black,SET.black6,true);
	if (all_block) load_rule_file(USER_RULES + '/block_ip',SET.block,SET.block6,true);
	use_shunt = env.NODE && cfg(env.NODE,'protocol') == '_shunt';
	if (use_shunt) {
		let group = cfg(env.NODE,'shunt_group'), codes = [];
		api.uci_foreach_c('shunt_rules', function(s) {
			if ((s.group ?? '') != group) return;
			load_values(SET.shunt,valid_ip_lines(s.ip_list,4)); load_values(SET.shunt6,valid_ip_lines(s.ip_list,6));
			for (let code in geo_codes(s.ip_list)) push(codes,code);
		});
		if (use_geoview && length(codes)) {
			load_values(SET.shunt,valid_ip_lines(utils.get_geoip(join(',',codes),'ipv4'),4));
			load_values(SET.shunt6,valid_ip_lines(utils.get_geoip(join(',',codes),'ipv6'),6));
		}
	}
	load_values(SET.local,utils.get_local_ips('ip4')); load_values(SET.local6,utils.get_local_ips('ip6'));
	load_values(SET.lan,utils.gen_lanlist('ip4')); load_values(SET.lan6,utils.gen_lanlist('ip6'));
	let lan_ifname = trim(output(['uci','-q','-p','/tmp/state','get','network.lan.ifname']));
	if (lan_ifname) {
		for (let line in split(output(['ip','-o','address','show','dev',lan_ifname]), '\n')) {
			let fields = words(line);
			if (length(fields) > 3 && fields[2] == 'inet') load_values(SET.lan, [fields[3]]);
			else if (length(fields) > 3 && fields[2] == 'inet6') load_values(SET.lan6, [fields[3]]);
		}
	}
	update_wan_sets('log');
	for (let ip in words(env.ISP_DNS)) ipset(['-!','add',SET.white,ip,'timeout','0'],true);
	for (let ip in words(env.ISP_DNS6)) ipset(['-!','add',SET.white6,ip,'timeout','0'],true);
	filter_vpsip(); filter_haproxy();
}

function base_chains() {
	for (let family in [4,6]) {
		let lan = family == 6 ? SET.lan6 : SET.lan;
		let vps = family == 6 ? SET.vps6 : SET.vps;
		let wan = family == 6 ? SET.wan6 : SET.wan;
		let white = family == 6 ? SET.white6 : SET.white;
		let block = family == 6 ? SET.block6 : SET.block;
		xt(family,'mangle',['-N','PSW_DIVERT'],true);
		xt(family,'mangle',['-A','PSW_DIVERT','-j','MARK','--set-mark',MARK],true);
		xt(family,'mangle',['-A','PSW_DIVERT','-j','ACCEPT'],true);
		xt(family,'mangle',['-N','PSW_RULE'],true);
		xt(family,'mangle',['-A','PSW_RULE','-m','mark','--mark','88','-j','RETURN'],true);
		xt(family,'mangle',['-A','PSW_RULE','-j','CONNMARK','--restore-mark'],true);
		xt(family,'mangle',['-A','PSW_RULE','-m','mark','--mark',MARK,'-j','RETURN'],true);
		xt(family,'mangle',['-A','PSW_RULE','-p','tcp','-m','tcp','--syn','-j','MARK','--set-xmark',MARK],true);
		xt(family,'mangle',['-A','PSW_RULE','-p','udp','-m','conntrack','--ctstate','NEW,RELATED','-j','MARK','--set-xmark',MARK],true);
		xt(family,'mangle',['-A','PSW_RULE','-j','CONNMARK','--save-mark'],true);
		for (let chain in ['PSW','PSW_OUTPUT']) xt(family,'mangle',['-N',chain],true);
		xt(family,'mangle',['-A','PSW',...dst(lan),'-j','RETURN'],true);
		xt(family,'mangle',['-A','PSW',...dst(vps),'-j','RETURN'],true);
		xt(family,'mangle',['-A','PSW','-m','conntrack','--ctdir','REPLY','-j','RETURN'],true);
		xt(family,'mangle',['-A','PSW',...comment(family == 6 ? 'WAN6_IP_RETURN' : 'WAN_IP_RETURN'),...dst(wan),'-j','RETURN'],true);
		if (family == 6) xt(family,'mangle',['-A','PSW_OUTPUT','-m','mark','--mark','0xff/0xff','-j','RETURN'],true);
		xt(family,'mangle',['-A','PSW_OUTPUT',...dst(lan),'-j','RETURN'],true);
		xt(family,'mangle',['-A','PSW_OUTPUT',...dst(vps),'-j','RETURN'],true);
		xt(family,'nat',['-N','PSW_DNS'],true);
		if (family == 4 || cfg('@global_forwarding[0]','accept_icmpv6','0') == '1') {
			xt(family,'nat',['-N','PSW'],true); xt(family,'nat',['-N','PSW_OUTPUT'],true);
			xt(family,'nat',['-A','PSW',...dst(lan),'-j','RETURN'],true);
			xt(family,'nat',['-A','PSW',...dst(vps),'-j','RETURN'],true);
			if (family == 4)
				xt(family,'nat',['-A','PSW',...comment('WAN_IP_RETURN'),...dst(wan),'-j','RETURN'],true);
			xt(family,'nat',['-A','PSW_OUTPUT',...dst(lan),'-j','RETURN'],true);
			xt(family,'nat',['-A','PSW_OUTPUT',...dst(vps),'-j','RETURN'],true);
			if (env.USE_DIRECT_LIST == '1')
				xt(family,'nat',['-A','PSW_OUTPUT',...dst(white),'-j','RETURN'],true);
			xt(family,'nat',['-A','PSW_OUTPUT','-m','mark','--mark','0xff/0xff','-j','RETURN'],true);
		}
	}
	insert_rule_before([ipt,'-t','mangle','-w'],'PREROUTING','mwan3',['-j','PSW']);
	insert_rule_before([ipt,'-t','mangle','-w'],'PREROUTING','PSW',['-p','tcp','-m','socket','--transparent','-j','PSW_DIVERT']);
	if (ip6t) {
		insert_rule_before([ip6t,'-t','mangle','-w'],'PREROUTING','mwan3',['-j','PSW']);
		insert_rule_before([ip6t,'-t','mangle','-w'],'PREROUTING','PSW',['-p','tcp','-m','socket','--transparent','-j','PSW_DIVERT']);
	}
	run(['ip','rule','add','fwmark',MARK,'table','999','priority','999'],true);
	run(['ip','route','add','local','0.0.0.0/0','dev','lo','table','999'],true);
	run(['ip','-6','rule','add','fwmark',MARK,'table','999','priority','999'],true);
	run(['ip','-6','route','add','local','::/0','dev','lo','table','999'],true);
}

function finalize_output_chains() {
	for (let family in [4,6]) {
		let block = family == 6 ? SET.block6 : SET.block;
		let white = family == 6 ? SET.white6 : SET.white;
		if (env.USE_BLOCK_LIST == '1')
			xt(family,'mangle',['-A','PSW_OUTPUT',...dst(block),'-j','MARK','--set-mark','88'],true);
		if (env.USE_DIRECT_LIST == '1')
			xt(family,'mangle',['-A','PSW_OUTPUT',...dst(white),'-j','RETURN'],true);
		xt(family,'mangle',['-A','PSW_OUTPUT','-m','conntrack','--ctdir','REPLY','-j','RETURN'],true);
		if (family == 4)
			xt(family,'mangle',['-A','PSW_OUTPUT','-m','mark','--mark','0xff/0xff','-j','RETURN'],true);
	}
}

function dns_prerouting() {
	for (let family in [4,6]) {
		let lan = family==6?SET.lan6:SET.lan, local = family==6?SET.local6:SET.local;
		let args = ['-I','PREROUTING','-m','set','--match-set',lan,'src'];
		if (cfg('@global[0]','dns_redirect','1') == '0') push(args,...dst(local));
		push(args,'-j','PSW_DNS'); xt(family,'nat',args,true);
	}
}

function direct_dns_rules() {
	for (let dns in split(env.IPT_APPEND_DNS,',')) {
		dns = trim(dns);
		if (!dns) continue;
		let hp = utils.get_ip_port_from(dns);
		hp.host = replace(hp.host, /^@/, '');
		let family = utils.is_ipv6(hp.host) ? 6 : 4;
		for (let proto in ['udp','tcp'])
			xt(family,'mangle',['-A','PSW_OUTPUT','-p',proto,'-d',hp.host,'--dport',hp.port||'53','-j','RETURN'],true);
		if (family == 4 && !tproxy)
			xt(4,'nat',['-A','PSW_OUTPUT','-p','tcp','-d',hp.host,'--dport',hp.port||'53','-j','RETURN'],true);
	}
}

function output_list_rules(family, proto, ports, mode, target, drop) {
	let base = [family == 6 ? ip6t : ipt, '-t', 'mangle', '-w', '-A', 'PSW_OUTPUT', '-p', proto];
	if (family == 4 && proto == 'tcp' && !tproxy && !drop)
		base = [ipt, '-t', 'nat', '-w', '-A', 'PSW_OUTPUT', '-p', 'tcp'];
	list_targets(base, family, proto, ports, {
		fake:env.USE_FAKEDNS, proxy:env.USE_PROXY_LIST, use_gfw:env.USE_GFW_LIST,
		chn:env.CHN_LIST, shunt:use_shunt, mode,
		black:family == 6 ? SET.black6 : SET.black,
		gfw_set:family == 6 ? SET.gfw6 : SET.gfw,
		shunt_set:family == 6 ? SET.shunt6 : SET.shunt
	}, target, drop);
}

function force_proxy_dns(proto) {
	utils.hosts_foreach(env.REMOTE_DNS, 53, function(value, host, port) {
		if (!host) return 0;
		let family = utils.is_ipv6(host) ? 6 : 4, lan = family == 6 ? SET.lan6 : SET.lan;
		if (ipset(['-q','test',lan,host],true) == 0) return 0;
		if (proto == 'tcp' && family == 4 && !tproxy) {
			xt(4,'nat',['-I','PSW_OUTPUT','-p','tcp','-d',host,'--dport',port,...redirect(env.REDIR_PORT)],true);
		} else {
			xt(family,'mangle',['-I','PSW_OUTPUT','-p',proto,'-d',host,'--dport',port,'-j','PSW_RULE'],true);
			let local_rule = ['-I','PSW',...comment('本机'),'-p',proto,'-i','lo','-d',host,'--dport',port];
			push(local_rule, ...redirect(env.REDIR_PORT,true));
			xt(family,'mangle',local_rule,true);
		}
		return 0;
	});
}

function output_icmp(family, mode) {
	let proto = family == 6 ? 'ipv6-icmp' : 'icmp';
	xt(family,'nat',['-A','OUTPUT','-p',proto,'-j','PSW_OUTPUT'],true);
	icmp_targets(family, [family == 6 ? ip6t : ipt,'-t','nat','-w','-A','PSW_OUTPUT','-p',proto], {
		fake:env.USE_FAKEDNS, proxy:env.USE_PROXY_LIST, use_gfw:env.USE_GFW_LIST,
		chn:env.CHN_LIST, shunt:use_shunt, mode:mode || 'disable',
		black:family == 6 ? SET.black6 : SET.black,
		gfw_set:family == 6 ? SET.gfw6 : SET.gfw,
		shunt_set:family == 6 ? SET.shunt6 : SET.shunt
	});
}

function output_rules() {
	let local_tcp = env.LOCALHOST_TCP_PROXY_MODE, local_udp = env.LOCALHOST_UDP_PROXY_MODE;
	if (env.ENABLED_DEFAULT_ACL != '1') return;
	let tcpbase = [ipt,'-t',tproxy?'mangle':'nat','-w','-A','PSW_OUTPUT','-p','tcp'];
	let udpbase = [ipt,'-t','mangle','-w','-A','PSW_OUTPUT','-p','udp'];
	if (env.TCP_NO_REDIR_PORTS != 'disable') {
		add_port_rules(tcpbase,env.TCP_NO_REDIR_PORTS,['-j','RETURN']);
		add_port_rules([ip6t,'-t','mangle','-w','-A','PSW_OUTPUT','-p','tcp'],env.TCP_NO_REDIR_PORTS,['-j','RETURN']);
		if (utils.has_1_65535(env.TCP_NO_REDIR_PORTS)) local_tcp = '';
	}
	if (env.UDP_NO_REDIR_PORTS != 'disable') {
		add_port_rules(udpbase,env.UDP_NO_REDIR_PORTS,['-j','RETURN']);
		add_port_rules([ip6t,'-t','mangle','-w','-A','PSW_OUTPUT','-p','udp'],env.UDP_NO_REDIR_PORTS,['-j','RETURN']);
		if (utils.has_1_65535(env.UDP_NO_REDIR_PORTS)) local_udp = '';
	}
	if (env.NODE && (local_tcp || local_udp) && env.DNS_REDIRECT_PORT) {
		for (let family in [4,6]) for (let proto in ['udp','tcp'])
			xt(family,'nat',['-A','OUTPUT',...comment('PSW_DNS'),'-p',proto,'-o','lo','--dport','53',
				...redirect(env.DNS_REDIRECT_PORT)],true);
	}
	if (local_tcp || local_udp) {
		if (env.TCP_PROXY_DROP_PORTS != 'disable') {
			output_list_rules(4,'tcp',env.TCP_PROXY_DROP_PORTS,local_tcp,['-j','MARK','--set-mark','88'],true);
			if (env.PROXY_IPV6 == '1') output_list_rules(6,'tcp',env.TCP_PROXY_DROP_PORTS,local_tcp,['-j','MARK','--set-mark','88'],true);
		}
		if (env.UDP_PROXY_DROP_PORTS != 'disable') {
			output_list_rules(4,'udp',env.UDP_PROXY_DROP_PORTS,local_udp,['-j','MARK','--set-mark','88'],true);
			if (env.PROXY_IPV6 == '1') output_list_rules(6,'udp',env.UDP_PROXY_DROP_PORTS,local_udp,['-j','MARK','--set-mark','88'],true);
		}
	}
	if (env.NODE) {
		if (env.TCP_PROXY_DNS) force_proxy_dns('tcp');
		if (cfg('@global_forwarding[0]','accept_icmp','0') == '1') output_icmp(4,local_tcp);
		if (cfg('@global_forwarding[0]','accept_icmpv6','0') == '1') output_icmp(6,local_tcp);
		if (local_tcp) {
			output_list_rules(4,'tcp',env.TCP_REDIR_PORTS,local_tcp,tproxy?['-j','PSW_RULE']:redirect(env.REDIR_PORT),false);
			if (tproxy) xt(4,'mangle',['-A','PSW',...comment('本机'),'-p','tcp','-i','lo',...redirect(env.REDIR_PORT,true)],true);
		}
		if (!tproxy) xt(4,'nat',['-A','OUTPUT','-p','tcp','-j','PSW_OUTPUT'],true);
		else {
			xt(4,'mangle',['-A','PSW',...comment('本机'),'-p','tcp','-i','lo','-j','RETURN'],true);
			insert_rule_before([ipt,'-t','mangle','-w'],'OUTPUT','mwan3',[...comment('mangle-OUTPUT-PSW'),'-p','tcp','-j','PSW_OUTPUT']);
		}
		if (env.PROXY_IPV6 == '1') {
			if (local_tcp) {
				output_list_rules(6,'tcp',env.TCP_REDIR_PORTS,local_tcp,['-j','PSW_RULE'],false);
				xt(6,'mangle',['-A','PSW',...comment('本机'),'-p','tcp','-i','lo',...redirect(env.REDIR_PORT,true)],true);
			}
			xt(6,'mangle',['-A','PSW',...comment('本机'),'-p','tcp','-i','lo','-j','RETURN'],true);
			insert_rule_before([ip6t,'-t','mangle','-w'],'OUTPUT','mwan3',[...comment('mangle-OUTPUT-PSW'),'-p','tcp','-j','PSW_OUTPUT']);
		}
		if (env.UDP_PROXY_DNS) force_proxy_dns('udp');
		if (local_udp) {
			output_list_rules(4,'udp',env.UDP_REDIR_PORTS,local_udp,['-j','PSW_RULE'],false);
			xt(4,'mangle',['-A','PSW',...comment('本机'),'-p','udp','-i','lo',...redirect(env.REDIR_PORT,true)],true);
		}
		xt(4,'mangle',['-A','PSW',...comment('本机'),'-p','udp','-i','lo','-j','RETURN'],true);
		insert_rule_before([ipt,'-t','mangle','-w'],'OUTPUT','mwan3',[...comment('mangle-OUTPUT-PSW'),'-p','udp','-j','PSW_OUTPUT']);
		if (env.PROXY_IPV6 == '1') {
			if (local_udp) {
				output_list_rules(6,'udp',env.UDP_REDIR_PORTS,local_udp,['-j','PSW_RULE'],false);
				xt(6,'mangle',['-A','PSW',...comment('本机'),'-p','udp','-i','lo',...redirect(env.REDIR_PORT,true)],true);
			}
			xt(6,'mangle',['-A','PSW',...comment('本机'),'-p','udp','-i','lo','-j','RETURN'],true);
			insert_rule_before([ip6t,'-t','mangle','-w'],'OUTPUT','mwan3',[...comment('mangle-OUTPUT-PSW'),'-p','udp','-j','PSW_OUTPUT']);
		}
	}
	for (let family in [4,6]) {
		xt(family,'mangle',['-I','OUTPUT',...comment('mangle-OUTPUT-PSW'),'-o','lo','-j','RETURN'],true);
		insert_rule_before([family==6?ip6t:ipt,'-t','mangle','-w'],'OUTPUT','mwan3',[...comment('mangle-OUTPUT-PSW'),'-m','mark','--mark',MARK,'-j','RETURN']);
	}
}

function add_firewall_rule() {
	api.log('开始加载 iptables 防火墙规则...');
	sysctl_tproxy(); setup_sets(); base_chains(); dns_prerouting(); direct_dns_rules();
	finalize_output_chains();
	let accept4=cfg('@global_forwarding[0]','accept_icmp','0'), accept6=cfg('@global_forwarding[0]','accept_icmpv6','0');
	for (let family in [4,6]) for (let chain in ['FORWARD','OUTPUT']) {
		xf(family,['-I',chain,...comment('PSW_REJECT'),'-m','mark','--mark','88','-p','tcp','-j','REJECT','--reject-with','tcp-reset'],true);
		xf(family,['-I',chain,...comment('PSW_REJECT'),'-m','mark','--mark','88','-p','udp','-j','REJECT'],true);
	}
	if (accept4=='1') insert_rule_after([ipt,'-t','nat','-w'],'PREROUTING','prerouting_rule',['-p','icmp','-j','PSW']);
	if (!tproxy) insert_rule_after([ipt,'-t','nat','-w'],'PREROUTING','prerouting_rule',['-p','tcp','-j','PSW']);
	if (accept6=='1') xt(6,'nat',['-A','PREROUTING','-p','ipv6-icmp','-j','PSW'],true);
	output_rules(); load_acl();
	for (let iface in fs.lsdir(IFACES) ?? []) {
		xt(4,'nat',['-A','PSW_OUTPUT','-o',iface,'-j','RETURN'],true);
		xt(4,'mangle',['-A','PSW_OUTPUT','-o',iface,'-j','RETURN'],true);
	}
	xt(4,'nat',['-I','PREROUTING',...comment('PSW'),'-m','mark','--mark',MARK,'-j','RETURN'],true);
	xt(6,'nat',['-I','PREROUTING',...comment('PSW'),'-m','mark','--mark',MARK,'-j','RETURN'],true);
	filter_direct_node_list();
	for (let family in [4,6]) for (let table in ['nat','mangle'])
		xt(family,table,['-I','OUTPUT',...comment('PSW_DIRECT'),'-m','owner','--gid-owner',''+utils.DIRECT_GID,'-j','RETURN'],true);
	api.log('防火墙规则加载完成！');
}

function delete_matching(family, table, chain, keyword) {
	while (true) {
		let indexes=matching_indexes([family==6?ip6t:ipt,'-t',table,'-w'],chain,keyword);
		if (!length(indexes)) break;
		xt(family,table,['-D',chain,''+indexes[0]],true);
	}
}

function del_firewall_rule() {
	for (let family in [4,6]) {
		for (let table in ['nat','mangle']) {
			for (let chain in ['PREROUTING','OUTPUT']) delete_matching(family,table,chain,'PSW');
			for (let chain in ['PSW','PSW_OUTPUT','PSW_DIVERT','PSW_DNS','PSW_RULE']) {
				xt(family,table,['-F',chain],true); xt(family,table,['-X',chain],true);
			}
		}
		for (let chain in ['FORWARD','INPUT','OUTPUT'])
			while (true) {
				let indexes=matching_indexes([family==6?ip6t:ipt,'-w'],chain,'PSW_REJECT');
				if (!length(indexes)) break;
				xf(family,['-D',chain,''+indexes[0]],true);
			}
	}
	run(['ip','rule','del','fwmark',MARK],true); run(['ip','route','del','local','0.0.0.0/0','dev','lo','table','999'],true);
	run(['ip','-6','rule','del','fwmark',MARK],true); run(['ip','-6','route','del','local','::/0','dev','lo','table','999'],true);
	for (let key in ['local','wan','lan','vps','block','white','local6','wan6','lan6','vps6','block6','white6'])
		destroy_ipset(SET[key]);
	api.log('删除 iptables 规则完成。');
}

function flush_ipset() {
	api.log('清空 IPSet。');
	for (let line in split(output(['ipset','list','-name']),'\n'))
		if (substr(line,0,4)=='psw_') destroy_ipset(line);
}

function flush_include() {
	if (fwi) fs.writefile(fwi,'#!/bin/sh\n');
}

function save_rules(family, table) {
	let binary=(family==6?ip6t:ipt)+'-save';
	let out=output([binary,'-t',table]), kept=[];
	for (let line in split(out,'\n')) {
		if (index(line,'PSW')<0 || index(line,'PSW_DIRECT')>=0 || match(line,/-j PSW$/)!=null ||
		    index(line,'mangle-OUTPUT-PSW')>=0 || match(line,/-m socket .*-j PSW_DIVERT$/)!=null) continue;
		if (substr(line,0,3)=='-A ') line=replace(line,/^-A (OUTPUT|PREROUTING|FORWARD)/,'-I $1 1');
		push(kept,line);
	}
	return '*'+table+'\n'+join('\n',kept)+'\nCOMMIT\n';
}

function gen_include() {
	flush_include();
	if (!fwi) return;
	let entry=LIBEXEC+'/iptables.uc', text='#!/bin/sh\n\n'+entry+' update_wan_sets\n';
	let accept4=cfg('@global_forwarding[0]','accept_icmp','0');
	let accept6=cfg('@global_forwarding[0]','accept_icmpv6','0');
	if (ipt) {
		text+='mangle_output_psw=$('+ipt+'-save -t mangle | grep PSW | grep mangle-OUTPUT-PSW | sed \"s#-A OUTPUT ##g\")\n';
		text+=ipt+'-save -c | grep -v PSW | '+ipt+'-restore -c\n'+ipt+'-restore -n <<\\EOT\n';
		for (let table in ['nat','mangle','filter']) text+=save_rules(4,table);
		text+='EOT\nwhile IFS= read -r line; do '+entry+' insert_rule_before \"'+ipt+' -t mangle -w\" OUTPUT mwan3 \"$line\"; done <<EOF\n$mangle_output_psw\nEOF\n';
		text+=ipt+' -t nat -w -I OUTPUT -m comment --comment PSW_DIRECT -m owner --gid-owner '+utils.DIRECT_GID+' -j RETURN\n';
		text+=ipt+' -t mangle -w -I OUTPUT -m comment --comment PSW_DIRECT -m owner --gid-owner '+utils.DIRECT_GID+' -j RETURN\n';
		if (accept4=='1') text+=entry+' insert_rule_after \"'+ipt+' -t nat -w\" PREROUTING prerouting_rule \"-p icmp -j PSW\"\n';
		if (!tproxy) text+=entry+' insert_rule_after \"'+ipt+' -t nat -w\" PREROUTING prerouting_rule \"-p tcp -j PSW\"\n';
		text+=entry+' insert_rule_before \"'+ipt+' -t mangle -w\" PREROUTING mwan3 \"-j PSW\"\n';
		text+=entry+' insert_rule_before \"'+ipt+' -t mangle -w\" PREROUTING PSW \"-p tcp -m socket --transparent -j PSW_DIVERT\"\n';
	}
	if (ip6t) {
		text+='mangle_output_psw=$('+ip6t+'-save -t mangle | grep PSW | grep mangle-OUTPUT-PSW | sed \"s#-A OUTPUT ##g\")\n';
		text+=ip6t+'-save -c | grep -v PSW | '+ip6t+'-restore -c\n'+ip6t+'-restore -n <<\\EOT\n';
		for (let table in ['nat','mangle','filter']) text+=save_rules(6,table);
		text+='EOT\nwhile IFS= read -r line; do '+entry+' insert_rule_before \"'+ip6t+' -t mangle -w\" OUTPUT mwan3 \"$line\"; done <<EOF\n$mangle_output_psw\nEOF\n';
		text+=ip6t+' -t nat -w -I OUTPUT -m comment --comment PSW_DIRECT -m owner --gid-owner '+utils.DIRECT_GID+' -j RETURN\n';
		text+=ip6t+' -t mangle -w -I OUTPUT -m comment --comment PSW_DIRECT -m owner --gid-owner '+utils.DIRECT_GID+' -j RETURN\n';
		if (accept6=='1') text+=ip6t+' -t nat -w -A PREROUTING -p ipv6-icmp -j PSW\n';
		text+=entry+' insert_rule_before \"'+ip6t+' -t mangle -w\" PREROUTING mwan3 \"-j PSW\"\n';
		text+=entry+' insert_rule_before \"'+ip6t+' -t mangle -w\" PREROUTING PSW \"-p tcp -m socket --transparent -j PSW_DIVERT\"\n';
	}
	text+='return 0\n';
	fs.writefile(fwi,text);
}

function get_ipt_bin() {
	return utils.first_type('iptables-legacy','iptables');
}

function get_ip6t_bin() {
	return utils.first_type('ip6tables-legacy','ip6tables');
}

function start() {
	if (env.ENABLED_DEFAULT_ACL=='0' && env.ENABLED_ACLS=='0') return 0;
	add_firewall_rule(); gen_include(); return 0;
}

function stop() {
	del_firewall_rule();
	if (cfg('@global[0]','flush_set_on_reboot','0')=='1' || cfg('@global[0]','flush_set','0')=='1') {
		api.uci_del_c('@global[0]','flush_set'); api.uci_save_c(true);
		flush_ipset();
		for (let name in fs.lsdir(utils.TMP_PATH2) ?? [])
			if (substr(name,0,7)=='singbox' || substr(name,0,7)=='dnsmasq' || name=='geo_output' || name=='user_rules')
				run(['rm','-rf',utils.TMP_PATH2+'/'+name],true);
	}
	flush_include(); return 0;
}

function main(argv) {
	load_env();
	let action=argv[0]??'';
	if (action=='start') return start();
	if (action=='stop') return stop();
	if (action=='update_wan_sets') return update_wan_sets(argv[1],argv[2]);
	if (action=='filter_direct_node_list') return filter_direct_node_list();
	if (action=='RULE_LAST_INDEX') {
		let index = RULE_LAST_INDEX(argv[1],argv[2],argv[3],argv[4]);
		if (index == null) return 1;
		print(index + '\n'); return 0;
	}
	if (action=='insert_rule_before') return insert_rule_before(argv[1],argv[2],argv[3],argv[4],argv[5]);
	if (action=='insert_rule_after') return insert_rule_after(argv[1],argv[2],argv[3],argv[4],argv[5]);
	if (action=='get_ipt_bin') { print(get_ipt_bin() + '\n'); return 0; }
	if (action=='get_ip6t_bin') { print(get_ip6t_bin() + '\n'); return 0; }
	return 0;
}

export {
	add_port_rules, insert_rule_before, insert_rule_after, RULE_LAST_INDEX,
	update_wan_sets, filter_direct_node_list, add_firewall_rule, del_firewall_rule,
	flush_ipset, flush_include, gen_include, get_ipt_bin, get_ip6t_bin,
	start, stop, main
};
