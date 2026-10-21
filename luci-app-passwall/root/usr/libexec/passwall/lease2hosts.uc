#!/usr/bin/ucode
'use strict';

import { run } from 'passwall.lease2hosts';
import { popen } from 'fs';

let locked = (ARGV[0] ?? "") == "--locked";
if (!locked) {
	let argv = [
		"flock", "-n", "/var/lock/passwall_lease2hosts.lock",
		"/usr/bin/ucode", "/usr/libexec/passwall/lease2hosts.uc", "--locked"
	];
	if (type(global.system) == "function")
		global.system(argv);
	else {
		let ph = popen(argv, "r");
		if (ph != null)
			ph.close();
	}
	exit(0);
}

run();
