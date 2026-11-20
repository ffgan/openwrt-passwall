'use strict';

// Restart one HAProxy backend, or a missing dataplane process, without
// restarting PassWall. The local SOCKS port stays the one HAProxy already
// has, so existing listeners and the firewall rules are left in place.

import * as fs from 'fs';
import * as api from 'passwall.api';
import * as utils from 'passwall.utils';
import { kill_matching } from 'passwall.proc';

const TMP = '/tmp/etc/passwall';
const LIBEXEC = '/usr/libexec/passwall';

export function ports_in_config(text) {
	let ports = [];
	for (let line in split(text ?? '', '\n')) {
		if (match(line, /^[ \t]*server /) == null)
			continue;
		let found = match(line, /127\.0\.0\.1:([0-9]+)/);
		if (found != null)
			push(ports, found[1]);
	}
	return ports;
};

export function same_ports(left, right) {
	let have = {};
	let need = {};
	for (let port in left ?? [])
		have[port] = true;
	for (let port in right ?? [])
		need[port] = true;
	for (let port in have)
		if (!need[port])
			return false;
	for (let port in need)
		if (!have[port])
			return false;
	return true;
};

function ipv4(ip) {
	return match(ip ?? '', /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) != null;
};

function read_json(path) {
	let raw = fs.readfile(path);
	if (type(raw) != 'string' || raw == '')
		return null;
	try {
		let obj = json(raw);
		if (type(obj) == 'object' && obj != null)
			return obj;
	}
	catch (e) {}
	return null;
};

function json_server_ip(path) {
	let obj = read_json(path);
	if (obj == null)
		return null;
	if (type(obj.server) == 'string') {
		let found = match(obj.server, /^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):/);
		if (found != null)
			return found[1];
	}
	if (type(obj.servers) == 'array' && type(obj.servers[0]) == 'object' && ipv4(obj.servers[0].address))
		return obj.servers[0].address;
	return null;
};

function section_port(section) {
	if (match(section ?? '', /^[A-Za-z0-9_]+$/) == null)
		return null;
	let names = fs.lsdir(TMP);
	if (names == null)
		return null;
	let found = null;
	for (let name in names) {
		let got = match(name, regexp('^' + section + '_([0-9]+)\\.json$'));
		if (got != null)
			found = got[1];
	}
	return found;
};

function config_path(section, port) {
	return TMP + '/' + section + '_' + port + '.json';
};

function proc_has(pattern) {
	let text = api.proc_lines(pattern);
	return type(text) == 'string' && text != '';
};

function stop_backend(filename) {
	let pattern = replace(filename, /\./g, '\\.');
	kill_matching(pattern);
	utils.run(['sleep', '1'], true);
	return !proc_has(pattern);
};

function launch_saved(path, obj) {
	if (type(obj.servers) == 'array') {
		let bin = utils.first_type('sslocal');
		if (bin == '')
			return 1;
		return utils.launch([bin, '-c', path, '-v'], 'sslocal', '/dev/null');
	}
	let bin = utils.first_type('/usr/bin/reality');
	if (bin == '')
		return 1;
	return utils.launch([bin, '--config', path], 'reality', '/dev/null', { REALITY_OUTBOUND_MARK: '255' });
};

function regen(section, node_id, port) {
	return utils.run([
		'/usr/bin/ucode', LIBEXEC + '/app.uc', 'run_socks',
		'flag=' + port, 'node=' + node_id,
		'bind=127.0.0.1', 'socks_port=' + port,
		'config_file=' + section + '_' + port + '.json'
	], true);
};

function nft_element(action, ip) {
	if (!ipv4(ip))
		return 1;
	let got = api.exec_call('nft ' + action + ' element inet passwall psw_vps { ' + ip + ' }');
	let rc = type(got) == 'array' ? got[0] : got;
	return rc == null ? 1 : rc;
};

function address_used(ip, except_id) {
	let used = false;
	api.uci_foreach_c('nodes', function(node) {
		if (node['.name'] != except_id && node.address == ip)
			used = true;
	});
	return used;
};

function restart_member(section, node_id, port, old_ip, new_ip) {
	let path = config_path(section, port);
	if (old_ip == null)
		old_ip = json_server_ip(path);
	if (!stop_backend(section + '_' + port + '.json')) {
		api.log('后端 ' + section + ' 仍在运行，跳过热更新。');
		return 1;
	}
	if (ipv4(new_ip))
		nft_element('add', new_ip);
	let rc = regen(section, node_id, port);
	if (rc != 0) {
		api.log('后端 ' + section + ' 热更新失败。');
		return 1;
	}
	api.set_socks_port_to_cache(node_id, port);
	if (ipv4(old_ip) && ipv4(new_ip) && old_ip != new_ip && !address_used(old_ip, node_id))
		nft_element('delete', old_ip);
	api.log('后端 ' + section + ' 已热更新。');
	return 0;
};

function enabled_members() {
	let members = [];
	api.uci_foreach_c('haproxy_config', function(section) {
		if (section.enabled == '1' && section.lbss != null && section.lbss != '')
			push(members, section);
	});
	return members;
};

export function reload_address(node_id, old_ip, new_ip) {
	if (node_id == null || node_id == '')
		return 1;
	for (let section in enabled_members()) {
		if (section.lbss != node_id)
			continue;
		let port = section_port(section['.name']);
		if (port == null) {
			api.log('后端 ' + section['.name'] + ' 没有可复用的本地端口。');
			return 1;
		}
		if (restart_member(section['.name'], node_id, port, old_ip, new_ip) != 0)
			return 1;
	}
	return 0;
};

export function hot_reload_pool() {
	if (api.uci_get_c('@global_haproxy[0]', 'balancing_enable') != '1')
		return 1;
	let gid = api.uci_get_c('@global[0]', 'node');
	let node = api.uci_get_c(gid);
	if (type(node) != 'object' || node == null)
		return 1;
	if (lower(node.type ?? '') != 'socks' || node.address != '127.0.0.1')
		return 1;
	let members = enabled_members();
	if (length(members) == 0)
		return 1;
	let ports = {};
	let wanted = [];
	for (let section in members) {
		let port = section_port(section['.name']);
		if (port == null)
			return 1;
		ports[section['.name']] = port;
		push(wanted, port);
	}
	let cfg = fs.readfile(TMP + '/haproxy/config.cfg') ?? '';
	if (!same_ports(ports_in_config(cfg), wanted))
		return 1;
	for (let section in members) {
		let current = api.uci_get_c(section.lbss);
		let new_ip = type(current) == 'object' && current != null ? current.address : null;
		let path = config_path(section['.name'], ports[section['.name']]);
		if (restart_member(section['.name'], section.lbss, ports[section['.name']], json_server_ip(path), new_ip) != 0)
			return 1;
	}
	return 0;
};

function launch_named(bin, name, args, env) {
	if (bin == null || bin == '')
		return 1;
	let argv = [bin];
	for (let arg in args ?? [])
		push(argv, arg);
	api.log('拉起 ' + name);
	return utils.launch(argv, name, '/dev/null', env);
};

function relaunch_file(name) {
	let path = TMP + '/' + name;
	if (!proc_has(replace(name, /\./g, '\\.'))) {
		let obj = read_json(path);
		if (obj == null)
			return;
		launch_saved(path, obj);
	}
};

export function heal() {
	let cfg = TMP + '/haproxy/config.cfg';
	if (fs.stat(cfg) == null)
		return 1;
	if (!proc_has('/tmp/etc/passwall/bin/haproxy( |$)')) {
		let bin = utils.first_type('haproxy');
		launch_named(bin, 'haproxy', ['-f', cfg]);
	}
	if (!proc_has('/tmp/etc/passwall/bin/ipt2socks'))
		relaunch_ipt2socks();
	if (!proc_has('/tmp/etc/passwall/bin/chinadns-ng'))
		relaunch_chinadns();
	if (!proc_has('/tmp/etc/passwall/bin/socks-chain'))
		relaunch_chain();
	let names = fs.lsdir(TMP);
	if (names != null) {
		for (let name in names) {
			if (match(name, /^haproxy_[A-Za-z0-9_]+_[0-9]+\.json$/) != null)
				relaunch_file(name);
		}
	}
	return 0;
};

function relaunch_ipt2socks() {
	let node = api.uci_get_c(api.uci_get_c('@global[0]', 'node'));
	if (type(node) != 'object' || node == null || node.address == null || node.port == null)
		return 1;
	let redir = api.get_cache_var('ACL_GLOBAL_redir_port') ?? '1041';
	let args = ['-l', '' + redir, '-b', '0.0.0.0', '-B', '::', '-s', node.address, '-p', '' + node.port, '-o', '60', '-n', '65535', '-v'];
	if (node.username != null && node.username != '' && node.password != null)
		push(args, '-a', node.username, '-k', node.password);
	if (api.uci_get_c('@global_forwarding[0]', 'tcp_proxy_way') != 'tproxy')
		push(args, '-R');
	return launch_named(utils.first_type('ipt2socks'), 'ipt2socks_default_TCP_UDP', args);
};

function relaunch_chinadns() {
	let conf = TMP + '/acl/default/chinadns_ng.conf';
	if (fs.stat(conf) == null)
		return 1;
	return launch_named(utils.first_type('chinadns-ng'), 'chinadns-ng', ['-C', conf]);
};

function relaunch_chain() {
	let node = api.uci_get_c(api.uci_get_c('@global[0]', 'node'));
	if (type(node) != 'object' || node == null || lower(node.type ?? '') != 'socks')
		return 0;
	if (fs.access('/usr/bin/socks-chain', 'x') != true)
		return 0;
	let listen = api.get_cache_var('GLOBAL_SOCKS_server');
	if (listen == null || listen == '') {
		let port = api.uci_get_c('@global[0]', 'node_socks_port') ?? '1070';
		let bind = api.uci_get_c('@global[0]', 'node_socks_bind_local') == '0' ? '0.0.0.0' : '127.0.0.1';
		listen = bind + ':' + port;
	}
	return launch_named('/usr/bin/socks-chain', 'socks-chain', ['--listen', listen, '--upstream', node.address + ':' + node.port]);
};

export function main(argv) {
	let cmd = argv[0] ?? '';
	if (cmd == 'heal')
		return heal();
	if (cmd == 'address')
		return reload_address(argv[1], argv[2], argv[3]);
	return 1;
};
