'use strict';

import * as api from 'passwall.api';
import { readfile, writefile, stat, unlink, lsdir } from 'fs';
import { background, spawn, start_time_of, cmdline_of, write_record, command_rc } from 'passwall.proc';
import { retry_delay, chinadns_bind_port, chinadns_needs_start } from 'passwall.reliability';
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
	let retries = {};
	let dns_blind = {};
	command_rc([ "sleep", "5s" ]);

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
				if (alive && index(rec.file, "chinadns-ng") >= 0) {
					let conf = "";
					let args = rec.args ?? [];
					for (let i = 0; i < length(args); i++) {
						if (args[i] == "-C" && i + 1 < length(args))
							conf = args[i + 1];
					}
					let port = conf == "" ? "" : chinadns_bind_port(readfile(conf) ?? "");
					let open = port != "" && api.occupied_ports("tcp,udp")[port] == true;
					if (chinadns_needs_start(true, port, open)) {
						let since = dns_blind[name];
						if (since == null || time() - since < 20) {
							if (since == null)
								dns_blind[name] = time();
							continue;
						}
						api.log("ChinaDNS 进程在但端口未监听，重新启动。");
						command_rc([ "kill", "-9", rec.pid ]);
						delete dns_blind[name];
						alive = false;
					} else {
						delete dns_blind[name];
					}
				}
				if (alive) {
					if (current != "" && current != rec.starttime) {
						rec.starttime = current;
						write_record(path, rec);
					}
					let recovery = retries[name];
					if (recovery != null && time() - recovery.started >= 60) {
						delete retries[name];
						unlink(count_path);
					}
					continue;
				}
				let recovery = retries[name];
				if (recovery != null && time() < recovery.next) continue;
				count = recovery == null ? 1 : recovery.failures + 1;
				retries[name] = { failures: count, started: time(), next: time() + retry_delay(count) };
				writefile(count_path, "" + count + "\n");
				let label = rec.file != "" ? rec.file : name;
				api.log("进程已退出，重新启动 " + label + "（连续失败 " + count + " 次）。");
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
		command_rc([ "sleep", "5s" ]);
	}
};

export { run };
