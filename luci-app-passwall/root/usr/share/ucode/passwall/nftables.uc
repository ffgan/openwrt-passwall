'use strict';

import { popen } from 'fs';

let command_rc, main;

// The rule text stays in nftables.sh. This entry runs that program in its
// own shell with the variables app.sh wrote to nft.env, instead of sourcing
// the rules into the orchestrator.
command_rc = function(argv) {
	if (type(global.system) == "function") {
		let rc = global.system(argv);
		return rc == null ? 255 : rc;
	}
	let ph = popen(argv, "r");
	if (ph == null)
		return 255;
	let rc = ph.close();
	return rc == null ? 255 : rc;
};

main = function(argv) {
	let action = argv[0] ?? "";
	if (action != "start" && action != "stop")
		exit(1);
	let setup = ". /usr/share/passwall/utils.sh";
	if (action == "start")
		setup += "; . /tmp/etc/passwall/nft.env";
	setup += "; set -- " + action + "; . /usr/share/passwall/nftables.sh";
	exit(command_rc(["/bin/sh", "-c", setup]));
};

export { main };
