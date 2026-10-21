#!/usr/bin/ucode
'use strict';

import { run } from 'passwall.tasks';
import { popen } from 'fs';

if ((ARGV[0] ?? "") != "--locked") {
	let argv = [
		"flock", "-n", "/var/lock/passwall_tasks.lock",
		"/usr/bin/ucode", "/usr/libexec/passwall/tasks.uc", "--locked"
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
