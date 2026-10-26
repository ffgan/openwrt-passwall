#!/usr/bin/ucode
'use strict';

import { run } from 'passwall.ensure';
import { popen } from 'fs';

if ((ARGV[0] ?? '') != '--locked') {
	let ph = popen("flock -n /var/lock/passwall_ensure.lock /usr/bin/ucode /usr/libexec/passwall/ensure.uc --locked", 'r');
	if (ph != null)
		ph.close();
	exit(0);
}

exit(run() ?? 0);
