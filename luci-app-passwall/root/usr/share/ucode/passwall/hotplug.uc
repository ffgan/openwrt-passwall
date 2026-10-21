'use strict';

import * as fs from 'fs';
import * as api from 'passwall.api';
import * as utils from 'passwall.utils';

function active() {
	return fs.stat('/var/lock/passwall_ready.lock') != null &&
		(utils.get_cache_var('ENABLED_DEFAULT_ACL') == '1' || utils.get_cache_var('ENABLED_ACLS') == '1');
}

function default_device(family) {
	let out = utils.output(family == 'ip6' ? ['ip', '-6', 'route', 'show', 'default'] : ['ip', 'route', 'show', 'default']);
	let m = match(out, /(^|[[:space:]])dev[[:space:]]+([^[:space:]]+)/);
	return m?.[2] ?? '';
}

export function iface(action, device, interface) {
	if ((action != 'ifup' && action != 'ifupdate') || !device || !active())
		return 0;
	if (default_device('ip4') != device && default_device('ip6') != device)
		return 0;
	if (action == 'ifupdate') {
		let table = utils.get_cache_var('USE_TABLES');
		if (table == 'nftables')
			return utils.run(['/usr/libexec/passwall/nftables.uc', 'update_wan_sets'], true);
		if (table == 'iptables')
			return utils.run(['/usr/bin/ucode', '/usr/libexec/passwall/iptables.uc', 'update_wan_sets'], true);
		return 0;
	}
	api.log('network: passwall restart when ' + (interface ?? '') + ' ifup');
	return utils.run(['/etc/init.d/passwall', 'restart'], true);
}

export function ntp(offset) {
	offset = int(split('' + (offset ?? 0), '.')[0]);
	if (offset < 0) offset = -offset;
	if (offset < 120 || !active() || fs.stat('/var/lock/passwall_ntp.lock') != null)
		return 0;
	fs.writefile('/var/lock/passwall_ntp.lock', 'locked\n');
	api.log('network: passwall restart after NTP time step (' + offset + 's)');
	return utils.run(['/etc/init.d/passwall', 'restart'], true);
}
