'use strict';

import * as api from 'passwall.api';
import { spawn, write_record, read_cmd } from 'passwall.proc';

let main;

// argv: binary, link name, output, optional JSON env object, then program arguments.
main = function(argv) {
	let file = argv[0] ?? "";
	let name = argv[1] ?? "";
	let output = argv[2] ?? "/dev/null";
	let env = {};
	let argi = 3;
	if (substr(argv[3] ?? "", 0, 1) == "{") {
		try {
			let parsed = json(argv[3]);
			if (type(parsed) == "object" && parsed != null)
				env = parsed;
		} catch (e) {}
		argi = 4;
	}
	let args = [];
	if (substr(name, 0, 7) == "dnsmasq")
		push(args, "-k");
	else if (name == "haproxy")
		push(args, "-db");
	for (let i = argi; i < length(argv); i++)
		push(args, argv[i]);

	let result = spawn({
		file: file,
		name: name,
		args: args,
		output: output,
		env: env,
		bindir: api.TMP_PATH + "/bin"
	});
	if (file == "")
		exit(1);
	let env_get = global.getenv;
	if (type(env_get) == "function" && env_get("NO_REC_PROCESS") == "1")
		exit(0);

	let dir = api.TMP_PATH + "/script_func";
	api.fs.mkdirr(dir);
	let made = read_cmd([ "mktemp", dir + "/XXXXXX" ]);
	if (made == null || trim(made.out) == "")
		exit(0);
	write_record(trim(made.out), result);
	exit(0);
};

export { main };
