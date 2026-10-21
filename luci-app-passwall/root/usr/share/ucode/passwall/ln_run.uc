'use strict';

import * as api from 'passwall.api';
import { popen, writefile, access } from 'fs';
import { start_time_of } from 'passwall.monitor';

let read_cmd, command_rc, is_link, main;

read_cmd = function(argv) {
	let ph = popen(argv, "r");
	if (ph == null)
		return null;
	let out = "";
	let chunk = ph.read(4096);
	while (chunk != null && chunk != "") {
		out += chunk;
		chunk = ph.read(4096);
	}
	let rc = ph.close();
	return { out: out, rc: rc == null ? 255 : rc };
};

command_rc = function(argv) {
	if (type(global.system) == "function") {
		let rc = global.system(argv);
		return rc == null ? 255 : rc;
	}
	let got = read_cmd(argv);
	return got == null ? 255 : got.rc;
};

is_link = function(path) {
	let got = read_cmd(["ls", "-ld", path]);
	if (got == null || got.rc != 0)
		return false;
	return substr(got.out, 0, 1) == "l";
};

// argv: binary, link name, output, then the program arguments.
main = function(argv) {
	let file = argv[0] ?? "";
	let name = argv[1] ?? "";
	let output = argv[2] ?? "/dev/null";
	let args = [];
	if (substr(name, 0, 7) == "dnsmasq")
		push(args, "-k");
	else if (name == "haproxy")
		push(args, "-db");
	for (let i = 3; i < length(argv); i++)
		push(args, argv[i]);

	if (file != "" && index(file, "/") >= 0 && !is_link(file)) {
		let dest = api.TMP_PATH + "/bin/" + name;
		api.fs.mkdirr(api.TMP_PATH + "/bin");
		command_rc(["ln", "-s", file, dest]);
		file = dest;
	}
	if (file == "") {
		api.log("  - 找不到 " + name + "，无法启动...");
		exit(1);
	}
	if (index(file, "/") >= 0 && access(file, "x") != true)
		api.log("  - " + file + " 没有执行权限，无法启动：" + file);

	let recorded = "ulimit -n 65535 2>/dev/null; exec " + api.shellquote(file);
	for (let arg in args)
		recorded += " " + api.shellquote(arg);
	recorded += " >" + api.shellquote(output) + " 2>&1";
	let started = read_cmd(["/bin/sh", "-c", recorded + " & echo $!"]);
	let pid = started == null ? "" : trim(started.out);
	let env_get = global.getenv;
	if (type(env_get) == "function" && env_get("NO_REC_PROCESS") == "1")
		exit(0);

	let dir = api.TMP_PATH + "/script_func";
	api.fs.mkdirr(dir);
	let made = read_cmd(["mktemp", dir + "/XXXXXX"]);
	if (made == null || trim(made.out) == "")
		exit(0);
	let path = trim(made.out);
	let record = pid + "\n" + start_time_of(pid) + "\n" + recorded + "\n";
	writefile(path, record);
	exit(0);
};

export { main };
