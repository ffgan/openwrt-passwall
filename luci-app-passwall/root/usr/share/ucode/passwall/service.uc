'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import * as api from 'passwall.api';
import * as utils from 'passwall.utils';

const LOCK_DIR = '/var/lock';
const CLIENT_LOCK = LOCK_DIR + '/passwall.lock';
const UPDATE_LOCK = LOCK_DIR + '/passwall_sub_rule.lock';
const READY_LOCK = LOCK_DIR + '/passwall_ready.lock';
const uci = cursor();
// ucode 2026.01.16 does not hoist functions.
let client_locked;

function ensure_lock_dir() {
	return fs.stat(LOCK_DIR)?.type == 'directory' || fs.mkdir(LOCK_DIR);
}

function root_path(path) {
	let root = type(global.getenv) == 'function' ? (global.getenv('IPKG_INSTROOT') ?? '') : '';
	return root + path;
}

function sleep_for(seconds) {
	if (int(seconds) <= 0)
		return 0;
	return utils.run([ '/bin/sleep', '' + int(seconds) ], true);
}

function invoke_app(server, action, mode) {
	let entry = root_path(server
		? '/usr/libexec/passwall/server_app.uc'
		: '/usr/libexec/passwall/app.uc');
	let argv = [ '/usr/bin/ucode', entry, action ];
	if (mode != null && mode != '')
		push(argv, mode);
	return utils.run(argv, true);
}

function with_client_lock(action, args, wait) {
	if (!ensure_lock_dir()) {
		api.log(wait ? '无法取得停止锁，退出.' : '脚本已经在运行，不重复运行，退出.');
		return wait ? 1 : 0;
	}
	let lock = fs.open(CLIENT_LOCK, 'ae');
	if (lock == null || lock.lock(wait ? 'x' : 'xn') != true) {
		if (lock != null)
			lock.close();
		api.log(wait ? '无法取得停止锁，退出.' : '脚本已经在运行，不重复运行，退出.');
		return wait ? 1 : 0;
	}
	let rc = client_locked(action, args);
	lock.lock('u');
	lock.close();
	return rc == 0 ? 0 : 1;
}

function wait_for_updates() {
	if (!ensure_lock_dir())
		return 2;
	let lock = fs.open(UPDATE_LOCK, 'ae');
	if (lock == null)
		return 2;
	for (let i = 0; i < 300; i++) {
		if (lock.lock('xn') == true) {
			lock.lock('u');
			lock.close();
			return 0;
		}
		sleep_for(2);
	}
	lock.close();
	return 1;
}

client_locked = function(action, args) {
	let mode = args[0] ?? '';
	if (action == 'start') {
		invoke_app(false, 'start', mode);
		return 0;
	}
	if (action == 'stop') {
		invoke_app(false, 'stop', mode);
		return 0;
	}
	if (action == 'restart') {
		if (wait_for_updates() != 0) {
			api.log('等待订阅/规则更新结束失败或超时，取消重启.');
			return 2;
		}
		invoke_app(false, 'stop', mode);
		invoke_app(false, 'start', mode);
		return 0;
	}
	return 1;
};

function client(action, args) {
	if (action == 'boot') {
		fs.unlink(READY_LOCK);
		let delay = int(uci.get('passwall', '@global_delay[0]', 'start_delay') ?? '1');
		if (delay > 0) {
			api.log('执行启动延时 ' + delay + ' 秒后再启动!');
			sleep_for(delay);
		}
		let rc = with_client_lock('restart', [ 'boot' ], false);
		if (rc == 0)
			fs.writefile(READY_LOCK, '');
		return rc;
	}
	if (action == 'start')
		return with_client_lock('start', [ args[1] ?? '' ], false);
	if (action == 'stop')
		return with_client_lock('stop', [ args[1] ?? '' ], true);
	if (action == 'restart') {
		let mode = (args[1] ?? '') != '' ? args[1] : (args[0] ?? '');
		if (mode == 'restart')
			mode = '';
		// Wait. A non-blocking restart used to exit while another restart
		// held the lock, so a node change was saved and then never applied.
		return with_client_lock('restart', [ mode ], true);
	}
	if (action == 'reload') {
		print('Warning: This service does not support configuration reloading\n');
		print('Performing full restart instead...\n');
		return with_client_lock('restart', [ '' ], true);
	}
	return 1;
}

function server(action) {
	if (action == 'boot') {
		let raw = uci.get('passwall_server', 'global', 'start_delay') ?? '90';
		let delay = match('' + raw, /^[0-9]+$/) != null ? int(raw) : 90;
		if (delay > 600)
			delay = 90;
		sleep_for(delay);
		invoke_app(true, 'stop');
		return invoke_app(true, 'start');
	}
	if (action == 'start' || action == 'stop')
		return invoke_app(true, action);
	if (action == 'restart') {
		invoke_app(true, 'stop');
		return invoke_app(true, 'start');
	}
	if (action == 'reload') {
		print('Warning: This service does not support configuration reloading\n');
		print('Performing full restart instead...\n');
		invoke_app(true, 'stop');
		return invoke_app(true, 'start');
	}
	return 1;
}

function main(argv) {
	let name = argv[0] ?? '';
	let action = argv[1] ?? '';
	let args = [];
	for (let i = 2; i < length(argv); i++)
		push(args, argv[i]);
	if (name == 'client')
		return client(action, args);
	if (name == 'server')
		return server(action, args);
	return 1;
}

export { client, server, main };
