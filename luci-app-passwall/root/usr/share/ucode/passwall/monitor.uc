'use strict';

import * as api from 'passwall.api';
import { popen, readfile, writefile, stat, unlink, lsdir } from 'fs';

let read_cmd, command_rc, split_lines, start_time_of, ymd, run;

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

split_lines = function(text) {
	let rows = [];
	if (type(text) != "string" || text == "")
		return rows;
	let start = 0;
	let n = length(text);
	for (let i = 0; i <= n; i++) {
		if (i == n || ord(text, i) == 10) {
			let row = substr(text, start, i - start);
			if (length(row) > 0 && ord(row, length(row) - 1) == 13)
				row = substr(row, 0, length(row) - 1);
			push(rows, row);
			start = i + 1;
		}
	}
	return rows;
};

// Match the historical utility behavior: strip through the last ") ", then field 20.
start_time_of = function(pid) {
	if (match(pid, /^[0-9]+$/) == null)
		return "";
	let text = readfile("/proc/" + pid + "/stat");
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

ymd = function() {
	let got = read_cmd(["date", "+%Y%m%d"]);
	if (got == null)
		return "";
	return trim(got.out);
};

run = function() {
	let enabled_acl = api.get_cache_var("ENABLED_DEFAULT_ACL");
	let enabled_acls = api.get_cache_var("ENABLED_ACLS");
	if (enabled_acl != "1" && enabled_acls != "1")
		exit(1);
	let enabled = api.uci_get_c("@global_delay[0]", "start_daemon") ?? "0";
	if ("" + enabled != "1")
		exit(1);

	let stats_dir = api.TMP_PATH + "/script_rstats";
	api.fs.mkdirr(api.TMP_PATH);
	api.fs.mkdirr(stats_dir);
	let proc_dir = api.TMP_PATH + "/script_func";
	let last_day = ymd();
	command_rc(["sleep", "58s"]);

	while (true) {
		let names = lsdir(proc_dir);
		if (names != null) {
			for (let name in names) {
				let path = proc_dir + "/" + name;
				let st = stat(path);
				if (st == null || st.type != "file")
					continue;
				let text = readfile(path);
				if (type(text) != "string")
					continue;
				let rows = split_lines(text);
				if (length(rows) < 3)
					continue;
				let pid = rows[0];
				let saved = rows[1];
				let cmd = "";
				for (let i = 2; i < length(rows); i++) {
					if (i > 2)
						cmd += "\n";
					cmd += rows[i];
				}
				while (length(cmd) > 0 && (ord(cmd, length(cmd) - 1) == 10 || ord(cmd, length(cmd) - 1) == 13))
					cmd = substr(cmd, 0, length(cmd) - 1);
				if (cmd == "")
					continue;

				let count_path = stats_dir + "/" + name + ".count";
				let count_txt = readfile(count_path);
				let count = 0;
				if (type(count_txt) == "string" && match(trim(count_txt), /^[0-9]+$/) != null)
					count = int(trim(count_txt));
				if (count >= 10)
					continue;

				let current = start_time_of(pid);
				if (current == "" || current != saved) {
					count++;
					writefile(count_path, "" + count + "\n");
					let started = read_cmd(["/bin/sh", "-c", "nohup " + cmd + " & echo $!"]);
					let new_pid = started == null ? "" : trim(started.out);
					let born = start_time_of(new_pid);
					writefile(path, new_pid + "\n" + born + "\n" + cmd + "\n");
					command_rc(["sleep", "1"]);
				}
			}
		}

		let today = ymd();
		if (today != "" && today != last_day) {
			let stats = lsdir(stats_dir);
			if (stats != null) {
				for (let name in stats)
					unlink(stats_dir + "/" + name);
			}
			last_day = today;
		}
		command_rc(["sleep", "58s"]);
	}
};

export { run, start_time_of };
