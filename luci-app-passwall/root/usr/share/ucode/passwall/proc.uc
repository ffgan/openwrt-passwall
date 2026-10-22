'use strict';

import * as fs from 'fs';
import * as api from 'passwall.api';
import { launch_script, render_proc_record } from 'passwall.state';

let read_cmd;

function command_rc(argv) {
	if (type(global.system) == "function") {
		let rc = global.system(argv);
		return rc == null ? 255 : rc;
	}
	let got = read_cmd(argv);
	return got == null ? 255 : got.rc;
}

read_cmd = function(argv) {
	let ph = api.command_pipe(argv, "r");
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

export function start_time_of(pid) {
	if (match(pid, /^[0-9]+$/) == null)
		return "";
	let text = fs.readfile("/proc/" + pid + "/stat");
	if (type(text) != "string")
		return "";
	let cut = -1;
	let n = length(text);
	for (let i = 0; i < n - 1; i++) {
		if (ord(text, i) == 41 && ord(text, i + 1) == 32)
			cut = i + 2;
	}
	if (cut < 0)
		return "";
	let fields = [];
	let cur = "";
	for (let i = cut; i < n; i++) {
		let c = ord(text, i);
		if (c == 32 || c == 9 || c == 10) {
			if (cur != "") {
				push(fields, cur);
				cur = "";
			}
		} else {
			cur += substr(text, i, 1);
		}
	}
	if (cur != "")
		push(fields, cur);
	if (length(fields) < 20)
		return "";
	return fields[19];
};

function is_link(path) {
	let target = fs.readlink(path);
	return type(target) == "string" && target != "";
}

export function shell_launch(file, args, output, env) {
	return launch_script(file, args, output, env);
};

export function background(script) {
	let started = read_cmd([ "/bin/sh", "-c", script + " & echo $!" ]);
	let pid = started == null ? "" : trim(started.out);
	return { pid: pid, starttime: start_time_of(pid) };
};

export function spawn(spec) {
	spec = spec ?? {};
	let file = spec.file ?? "";
	let name = spec.name ?? "";
	let args = [];
	for (let arg in spec.args ?? [])
		push(args, arg == null ? "" : "" + arg);
	let output = (spec.output == null || spec.output == "") ? "/dev/null" : "" + spec.output;
	let env = type(spec.env) == "object" && spec.env != null ? spec.env : {};
	let bindir = spec.bindir ?? "";
	if (bindir != "" && file != "" && index(file, "/") >= 0 && !is_link(file)) {
		api.fs.mkdirr(bindir);
		let dest = bindir + "/" + name;
		command_rc([ "ln", "-sfn", file, dest ]);
		file = dest;
	}
	if (file == "") {
		api.log("  - 找不到 " + name + "，无法启动...");
		return {
			pid: "", starttime: "", file: "", args: args, output: output, env: env
		};
	}
	if (index(file, "/") >= 0 && fs.access(file, "x") != true)
		api.log("  - " + file + " 没有执行权限，无法启动：" + file);
	let launched = background(shell_launch(file, args, output, env));
	return {
		pid: launched.pid,
		starttime: launched.starttime,
		file: file,
		args: args,
		output: output,
		env: env
	};
};

export function write_record(path, spec) {
	return fs.writefile(path, render_proc_record(spec) + "\n");
};

export function kill_matching(pattern) {
	let got = api.proc_lines(pattern);
	if (type(got) != "string" || got == "")
		return 0;
	for (let line in split(got, "\n")) {
		let pid = match(line, /^([0-9]+) /);
		if (pid == null)
			continue;
		command_rc([ "kill", "-9", pid[1] ]);
	}
	return 0;
};

export { read_cmd, command_rc };
