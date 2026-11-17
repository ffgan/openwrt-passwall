'use strict';
import * as api from 'passwall.api';
import { ubus_call, run } from 'passwall.utils';

export function instance_spec(file, args, output, env) {
	if (type(file) != 'string' || substr(file, 0, 1) != '/') die('Core path must be absolute');
	let command = [file, ...(args ?? [])];
	// exec preserves the procd-owned PID; quote every argument and log path.
	let script = 'exec ' + join(' ', map(command, api.shellquote)) + ' >' + api.shellquote(output || '/dev/null') + ' 2>&1';
	let clean_env = {};
	if (type(env) == 'object' && env != null) {
		for (let key, value in env) {
			if (match(key, /^[A-Za-z_][A-Za-z0-9_]*$/) == null)
				continue;
			clean_env[key] = '' + value;
		}
	}
	return {
		command: ['/bin/sh', '-c', script],
		env: clean_env,
		respawn: ['3600', '5', '0'],
		term_timeout: 5
	};
};

export function start(file, args, output, env) {
	let link = '/tmp/etc/passwall/bin/xray';
	if (run(['ln', '-sfn', file, link], true) != 0) die('Cannot prepare managed Xray executable');
	// service.set succeeds with an empty ubus payload. ubus_call maps that to
	// null, so verify the instance through service.list instead of the set result.
	ubus_call('service', 'set', {
		name: 'passwall_core',
		instances: { global: instance_spec(link, args, output, env) }
	});
	let ready = false;
	for (let attempt = 0; attempt < 10; attempt++) {
		let listed = ubus_call('service', 'list', { name: 'passwall_core' });
		let instance = listed?.passwall_core?.instances?.global;
		if (instance?.running == true && int(instance.pid) > 0 &&
		    instance.respawn?.threshold == 3600 && instance.respawn?.timeout == 5 && instance.respawn?.retry == 0) {
			ready = true;
			break;
		}
		run(['sleep', '1'], true);
	}
	if (!ready) {
		ubus_call('service', 'delete', { name: 'passwall_core' });
		die('procd Xray instance did not become ready with the requested respawn policy');
	}
	api.log('主 Xray 实例已交由 procd 托管。');
	return 0;
};

export function stop() {
	// Delete registration before legacy cleanup so procd cannot respawn a
	// core while its listener, DNS and policy rules are being removed.
	ubus_call('service', 'delete', { name: 'passwall_core' });
};
