'use strict';

import * as api from 'passwall.api';
import { readfile, writefile, stat, unlink, lsdir } from 'fs';
import { background, spawn, start_time_of, cmdline_of, write_record, command_rc } from 'passwall.proc';
import { parse_proc_record } from 'passwall.state';

let ymd, run;

ymd = function() {
	let t = localtime();
	return sprintf("%04d%02d%02d", t.year, t.mon, t.mday);
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
	command_rc([ "sleep", "58s" ]);

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
				let rec = parse_proc_record(text);
				if (rec == null || (rec.file == "" && rec.script == ""))
					continue;

				let count_path = stats_dir + "/" + name + ".count";
				let count_txt = readfile(count_path);
				let count = 0;
				if (type(count_txt) == "string" && match(trim(count_txt), /^[0-9]+$/) != null)
					count = int(trim(count_txt));

				// Start time alone is a poor liveness check: it is empty if it
				// was read before /proc was ready, and it changes when the pid
				// is reused. A still-running binary must not be started again.
				// Ten false restarts used to burn the daily budget, after which
				// a real exit was left down for the rest of the day.
				let current = start_time_of(rec.pid);
				let cmd = cmdline_of(rec.pid);
				let alive = false;
				if (rec.file != "" && cmd != "" && index(cmd, rec.file) >= 0)
					alive = true;
				else if (rec.file == "" && current != "" && current == rec.starttime)
					alive = true;
				if (alive) {
					if (current != "" && current != rec.starttime) {
						rec.starttime = current;
						write_record(path, rec);
					}
					if (count > 0)
						unlink(count_path);
					continue;
				}
				if (count >= 10)
					continue;

				count++;
				writefile(count_path, "" + count + "\n");
				let label = rec.file != "" ? rec.file : name;
				api.log("进程已退出，重新启动 " + label + "（" + count + "/10）。");
				if (rec.file != "") {
					let started = spawn({
						file: rec.file,
						name: name,
						args: rec.args,
						output: rec.output,
						env: rec.env
					});
					rec.pid = started.pid;
					rec.starttime = started.starttime;
					rec.file = started.file == "" ? rec.file : started.file;
				} else {
					let started = background(rec.script);
					rec.pid = started.pid;
					rec.starttime = started.starttime;
				}
				write_record(path, rec);
				if (count >= 10)
					api.log("进程 " + label + " 连续重启失败，今日不再拉起。");
				command_rc([ "sleep", "1" ]);
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
		command_rc([ "sleep", "58s" ]);
	}
};

export { run };
