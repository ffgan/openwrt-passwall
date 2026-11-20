'use strict';
import { run } from 'passwall.ensure';
for (let name in ['reality', 'xray', 'sing-box', 'sslocal', 'ssr-redir', 'hysteria']) {
	global.ensure_processes = '123 root /tmp/etc/passwall/bin/' + name + ' --config /tmp/config.json\n';
	if (run() != 0) die('Healthy ' + name + ' failed');
}
print('6 healthy core types bypass self-heal restart checks\n');

import * as fs from 'fs';
if (fs.stat('/tmp/passwall-ensure-balance/haproxy') == null) {
	fs.mkdir('/tmp/passwall-ensure-balance');
	fs.mkdir('/tmp/passwall-ensure-balance/haproxy');
}
fs.writefile('/tmp/passwall-ensure-balance/haproxy/config.cfg', 'listen 1181\n');
global.ensure_tmp = '/tmp/passwall-ensure-balance';
global.ensure_balancing = '1';
global.ensure_allow_exec = true;
global.ensure_exec = '';
global.ensure_processes = '123 root /tmp/etc/passwall/bin/reality --config /tmp/config.json\n';
if (run() != 0)
	die('balance heal returned error');
if (index(global.ensure_exec, 'reload_backend.uc heal') < 0)
	die('expected dataplane heal, got ' + global.ensure_exec);
if (index(global.ensure_exec, 'passwall restart') >= 0)
	die('dataplane heal restarted the service');

global.ensure_tmp = '/tmp/passwall-ensure-missing';
global.ensure_exec = '';
if (fs.stat('/tmp/passwall_ensure.budget') != null)
	fs.unlink('/tmp/passwall_ensure.budget');
if (run() != 0)
	die('missing dataplane returned error');
if (index(global.ensure_exec, 'passwall restart') < 0)
	die('missing dataplane did not restart: ' + global.ensure_exec);
print('balancing dataplane is not treated as healthy from a reality process alone\n');
