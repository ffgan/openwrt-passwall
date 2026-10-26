'use strict';

import * as fs from 'fs';
import * as api from 'passwall.api';

let OWNER = '/var/lock/passwall.owner';
let BUDGET = '/tmp/passwall_ensure.budget';
let STUCK = 180;

function proxy_up() {
	let text = api.proc_lines('/tmp/etc/passwall/bin/');
	if (text == null)
		text = '';
	let lines = split(text, '\n');
	for (let line in lines) {
		if (index(line, 'xray') >= 0)
			return true;
		if (index(line, 'sing-box') >= 0)
			return true;
		if (index(line, 'sslocal') >= 0)
			return true;
		if (index(line, 'ssr-redir') >= 0)
			return true;
		if (index(line, 'hysteria') >= 0)
			return true;
	}
	return false;
}

function owner() {
	let raw = fs.readfile(OWNER);
	if (raw == null)
		raw = '';
	let parts = split(trim(raw), ' ');
	if (length(parts) < 2)
		return null;
	let since = int(parts[1]);
	if (since != since)
		return null;
	return [ parts[0], since ];
}

function restart_busy() {
	let got = api.exec_call('flock -n /var/lock/passwall.lock -c true');
	let code = got;
	if (type(got) == 'array')
		code = got[0];
	return code != 0;
}

function kill_restart() {
	let text = api.proc_lines('passwall/');
	if (text == null)
		text = '';
	let lines = split(text, '\n');
	for (let line in lines) {
		if (index(line, 'ensure.uc') >= 0)
			continue;
		if (index(line, 'app.uc') < 0 && index(line, 'service.uc') < 0)
			continue;
		let m = match(line, /^([0-9]+)/);
		if (m != null)
			api.exec_call('kill -9 ' + m[1]);
	}
}

function budget_ok() {
	let now = time();
	let raw = fs.readfile(BUDGET);
	if (raw == null)
		raw = '';
	let parts = split(trim(raw), ' ');
	let start = now;
	let count = 0;
	if (length(parts) >= 2) {
		start = int(parts[0]);
		count = int(parts[1]);
		if (start != start || count != count || now - start > 3600) {
			start = now;
			count = 0;
		}
	}
	if (count >= 3)
		return false;
	fs.writefile(BUDGET, start + ' ' + (count + 1) + '\n');
	return true;
}

function node_ok(id) {
	if (id == null || id == '')
		return false;
	let section = api.uci_get_c(id);
	if (section == null || type(section) != 'object')
		return false;
	let kind = section['.type'];
	if (kind == 'nodes')
		return true;
	if (kind == 'socks')
		return true;
	return false;
}

function run() {
	if (api.uci_get_c('@global[0]', 'enabled') != '1')
		return 0;
	let node = api.uci_get_c('@global[0]', 'node');
	if (!node_ok(node)) {
		api.log('总开关开着，但节点不存在，不自动拉起。');
		return 0;
	}
	if (proxy_up())
		return 0;
	let stamp = owner();
	let busy = restart_busy();
	if (busy) {
		if (stamp == null)
			return 0;
		let age = time() - stamp[1];
		if (age >= 0 && age < STUCK)
			return 0;
		if (!budget_ok()) {
			api.log('代理未在运行，本小时自动拉起已达上限。');
			return 0;
		}
		api.log('重启卡住，结束卡住的进程并重新启动。');
		kill_restart();
		api.exec_call('sleep 1');
	}
	else {
		if (!budget_ok()) {
			api.log('代理未在运行，本小时自动拉起已达上限。');
			return 0;
		}
		api.log('总开关开着但代理未在运行，重新启动。');
	}
	api.exec_call('/etc/init.d/passwall restart >/dev/null 2>&1');
	return 0;
}

export { run };
