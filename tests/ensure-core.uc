'use strict';
import { run } from 'passwall.ensure';
for (let name in ['reality', 'xray', 'sing-box', 'sslocal', 'ssr-redir', 'hysteria']) {
	global.ensure_processes = '123 root /tmp/etc/passwall/bin/' + name + ' --config /tmp/config.json\n';
	if (run() != 0) die('Healthy ' + name + ' failed');
}
print('6 healthy core types bypass self-heal restart checks\n');
