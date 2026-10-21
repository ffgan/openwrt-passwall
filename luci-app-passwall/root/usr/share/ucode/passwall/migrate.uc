'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import * as utils from 'passwall.utils';

const CLIENT_CONFIG = 'passwall';
const SERVER_CONFIG = 'passwall_server';
const RULE_NAMES = [
	'direct_host', 'direct_ip', 'proxy_host', 'proxy_ip', 'block_host', 'block_ip',
	'lanlist_ipv4', 'lanlist_ipv6', 'domains_excluded'
];

function copy_missing(src, dst) {
	if (fs.stat(dst) != null)
		return true;
	let data = fs.readfile(src);
	return data != null && fs.writefile(dst, data);
}

function mkdir_p(path) {
	if (path == '' || path == '/' || fs.stat(path)?.type == 'directory')
		return true;
	let parent = fs.dirname(path);
	if (parent != path && !mkdir_p(parent))
		return false;
	return fs.mkdir(path) || fs.stat(path)?.type == 'directory';
}

function rm_rf(path) {
	let st = fs.lstat(path);
	if (st == null)
		return;
	if (st.type == 'directory') {
		for (let name in fs.lsdir(path) ?? [])
			rm_rf(path + '/' + name);
		fs.rmdir(path);
	}
	else
		fs.unlink(path);
}

function random_suffix(count) {
	let fp = fs.open('/dev/urandom', 'r');
	let raw = fp == null ? '' : (fp.read(count * 8) ?? '');
	if (fp != null)
		fp.close();
	let out = '';
	for (let i = 0; i < length(raw) && length(out) < count; i++) {
		let n = ord(raw, i) % 62;
		out += n < 10 ? chr(48 + n) : (n < 36 ? chr(55 + n) : chr(61 + n));
	}
	while (length(out) < count)
		out += sprintf('%x', time() + length(out));
	return substr(out, 0, count);
}

function sections(cur, config, stype) {
	let out = [];
	cur.foreach(config, stype, function(s) { push(out, s); });
	return out;
}

function all_sections(cur, config) {
	let out = [];
	let all = cur.get_all(config);
	for (let name, s in all ?? {}) {
		if (type(s) != 'object')
			continue;
		if (s['.name'] == null)
			s['.name'] = name;
		push(out, s);
	}
	return out;
}

function option_exists(cur, config, section, option) {
	return cur.get(config, section, option) != null;
}

function migrate_option(cur, section, old_name, new_name) {
	if (option_exists(cur, CLIENT_CONFIG, section, new_name)) {
		cur.delete(CLIENT_CONFIG, section, old_name);
		return;
	}
	let value = cur.get(CLIENT_CONFIG, section, old_name);
	if (value != null) {
		cur.set(CLIENT_CONFIG, section, new_name, value);
		cur.delete(CLIENT_CONFIG, section, old_name);
	}
}

function replace_exact_references(cur, old_value, new_value) {
	for (let s in all_sections(cur, CLIENT_CONFIG)) {
		for (let key in keys(s)) {
			if (substr(key, 0, 1) == '.')
				continue;
			if (type(s[key]) == 'string' && s[key] == old_value)
				cur.set(CLIENT_CONFIG, s['.name'], key, new_value);
			else if (type(s[key]) == 'array') {
				let values = [], changed = false;
				for (let value in s[key]) {
					if (value == old_value) {
						push(values, new_value);
						changed = true;
					}
					else
						push(values, value);
				}
				if (changed)
					cur.set(CLIENT_CONFIG, s['.name'], key, values);
			}
		}
	}
}

function clean_luci_cache() {
	for (let path in fs.glob('/tmp/luci-indexcache*') ?? [])
		fs.unlink(path);
	rm_rf('/tmp/luci-modulecache');
	let killall = utils.first_type('killall') || '/usr/bin/killall';
	utils.run([ killall, '-HUP', 'rpcd' ], true);
}

function migrate_client() {
	let cur = cursor();

	cur.delete('firewall', 'passwall');
	cur.set('firewall', 'passwall', 'include');
	cur.set('firewall', 'passwall', 'type', 'script');
	cur.set('firewall', 'passwall', 'path', '/var/etc/passwall.include');

	let dnsmasq = null;
	cur.foreach('dhcp', 'dnsmasq', function(s) {
		if (dnsmasq == null)
			dnsmasq = s['.name'];
	});
	if (dnsmasq != null)
		cur.set('dhcp', dnsmasq, 'localuse', '1');
	cur.commit('dhcp');

	cur.set('uhttpd', 'main', 'max_requests', '50');
	cur.commit('uhttpd');

	cur.set('firewall', 'passwall', 'fw4_compatible', '1');
	cur.delete('firewall', 'passwall', 'reload');
	cur.commit('firewall');

	mkdir_p('/var/etc');
	if (fs.stat('/var/etc/passwall.include') == null) {
		fs.writefile('/var/etc/passwall.include', "#!/bin/sh\nreturn 0\n");
		fs.chmod('/var/etc/passwall.include', 0o755);
	}

	if ((fs.stat('/etc/config/passwall')?.size ?? 0) == 0) {
		let data = fs.readfile('/usr/share/passwall/0_default_config');
		if (data != null)
			fs.writefile('/etc/config/passwall', data);
	}

	mkdir_p('/etc/passwall/rules');
	for (let name in RULE_NAMES)
		copy_missing('/usr/share/passwall/rules/' + name, '/etc/passwall/rules/' + name);
	for (let path in fs.glob('/usr/libexec/passwall/*.uc') ?? [])
		fs.chmod(path, 0o755);

	if (cur.get(CLIENT_CONFIG, '@global_xray[0]', 'sniffing') == '1' &&
	    cur.get(CLIENT_CONFIG, '@global_xray[0]', 'route_only') != '1')
		cur.set(CLIENT_CONFIG, '@global_xray[0]', 'sniffing_override_dest', '1');
	cur.delete(CLIENT_CONFIG, '@global_xray[0]', 'sniffing');
	cur.delete(CLIENT_CONFIG, '@global_xray[0]', 'route_only');

	if (cur.get(CLIENT_CONFIG, '@global_haproxy[0]', 'health_check_type') == 'passwall_logic')
		cur.set(CLIENT_CONFIG, '@global_haproxy[0]', 'health_check_type', 'script_logic');
	cur.delete(CLIENT_CONFIG, '@global_forwarding[0]', 'prefer_nft');

	for (let s in sections(cur, CLIENT_CONFIG, 'socks')) {
		let sid = s['.name'];
		if (substr(sid, 0, 6) == 'socks_')
			continue;
		let new_id = 'socks_' + random_suffix(5);
		let old_ref = 'Socks_' + sid;
		cur.rename(CLIENT_CONFIG, sid, new_id);
		replace_exact_references(cur, old_ref, new_id);
	}
	for (let type_name, prefix in { acl_rule:'acl_', subscribe_list:'sub_' })
		for (let s in sections(cur, CLIENT_CONFIG, type_name))
			if (s['.anonymous'])
				cur.rename(CLIENT_CONFIG, s['.name'], prefix + random_suffix(5));

	migrate_option(cur, '@global[0]', 'tcp_node', 'node');
	cur.delete(CLIENT_CONFIG, '@global[0]', 'udp_node');
	migrate_option(cur, '@global[0]', 'tcp_node_socks_port', 'node_socks_port');
	migrate_option(cur, '@global[0]', 'tcp_node_socks_bind_local', 'node_socks_bind_local');
	migrate_option(cur, '@global[0]', 'log_tcp', 'log_node');
	cur.delete(CLIENT_CONFIG, '@global[0]', 'log_udp');
	for (let s in sections(cur, CLIENT_CONFIG, 'acl_rule')) {
		migrate_option(cur, s['.name'], 'tcp_node', 'node');
		cur.delete(CLIENT_CONFIG, s['.name'], 'udp_node');
	}
	cur.commit(CLIENT_CONFIG);

	let config_text = fs.readfile('/etc/config/passwall');
	if (config_text != null)
		fs.writefile('/etc/config/passwall', replace(config_text, /add_from/g, 'group'));

	clean_luci_cache();
	return 0;
}

function migrate_server() {
	let cur = cursor();
	for (let s in all_sections(cur, SERVER_CONFIG))
		if (s.type != null && s.type != '')
			if (s['.type'] == 'user')
				cur.set(SERVER_CONFIG, s['.name'], 'server');
	for (let s in all_sections(cur, SERVER_CONFIG))
		if (s.protocol == 'dokodemo-door')
			cur.set(SERVER_CONFIG, s['.name'], 'protocol', 'tunnel');
	cur.commit(SERVER_CONFIG);
	clean_luci_cache();
	return 0;
}

function main(argv) {
	if ((argv[0] ?? '') == 'client')
		return migrate_client();
	if ((argv[0] ?? '') == 'server')
		return migrate_server();
	return 1;
}

export { migrate_client, migrate_server, main };
