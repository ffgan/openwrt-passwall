'use strict';

import * as api from 'passwall.api';
import { readfile, unlink, lsdir } from 'fs';
import { read_cmd, command_rc } from 'passwall.proc';

let words, retry_all, curl_code, check_process, test_proxy, cleanup_node, test_node, next_node, try_switch_backup, test_auto_switch, main;
let id = "";
let main_node = "";
let socks_port = "";
let delay = "30";
let connect_timeout = "3";
let retry_num = "1";
let restore_switch = "0";
let probe_url = "https://www.google.com/generate_204";
let backup_count = 0;

words = function(text) {
	let out = [];
	let cur = "";
	text = text == null ? "" : ("" + text);
	let n = length(text);
	for (let i = 0; i < n; i++) {
		let c = ord(text, i);
		if (c == 32 || c == 9 || c == 10 || c == 13) {
			if (cur != "") {
				push(out, cur);
				cur = "";
			}
		} else {
			cur += substr(text, i, 1);
		}
	}
	if (cur != "")
		push(out, cur);
	return out;
};

retry_all = function() {
	let got = read_cmd(["/usr/bin/curl", "--help", "all"]);
	if (got == null)
		return false;
	return match(got.out, /--retry-all-errors/) != null;
};

curl_code = function(url, tries, timeout, proxy, repeat) {
	let extra = retry_all();
	let once = function() {
		let max_time = timeout + 3;
		let retry_max = max_time * (tries + 1) + tries;
		let argv = ["/usr/bin/curl", "-skIL", "-o", "/dev/null"];
		if (extra)
			push(argv, "--retry-all-errors");
		push(argv,
			"--max-time", "" + max_time,
			"--connect-timeout", "" + timeout,
			"--retry", "" + tries,
			"--retry-delay", "1",
			"--retry-max-time", "" + retry_max,
			"-w", "%{http_code}");
		if (proxy != null && proxy != "")
			push(argv, "-x", proxy);
		push(argv, url);
		let got = read_cmd(argv);
		if (got == null || got.rc != 0)
			return "000";
		let status = trim(got.out);
		if (status == "204")
			return "200";
		if (status == "")
			return "000";
		return status;
	};
	let status = once();
	if (status == "200" && repeat) {
		command_rc(["sleep", "3s"]);
		status = once();
	}
	return status;
};

check_process = function() {
	while (true) {
		let got = read_cmd(["busybox", "pgrep", "-af", "passwall/"]);
		if (got == null || match(got.out, /(app|service)\.uc.*(start|stop|restart)|nftables\.uc|subscribe\.uc/) == null)
			return;
		command_rc(["sleep", "6s"]);
	}
};

test_proxy = function() {
	let status = curl_code(probe_url, int(retry_num), int(connect_timeout), "socks5h://127.0.0.1:" + socks_port, false);
	if (status == "200")
		return 0;
	let direct = curl_code("https://www.baidu.com", int(retry_num), int(connect_timeout), "", false);
	if (direct == "200")
		return 1;
	if (command_rc(["ping", "-c", "3", "-W", "1", "223.5.5.5"]) == 0)
		return 1;
	return 2;
};

cleanup_node = function(flag) {
	let tmp = api.TMP_PATH;
	let pid_txt = readfile(tmp + "/" + flag + "_plugin.pid");
	if (type(pid_txt) == "string") {
		let pid = match(trim(pid_txt), /^([0-9]+)/);
		if (pid != null)
			command_rc(["kill", "-9", pid[1]]);
	}
	let listed = read_cmd(["busybox", "pgrep", "-af", tmp + "/" + flag + "[._]"]);
	if (listed != null) {
		let text = listed.out;
		let start = 0;
		let n = length(text);
		for (let i = 0; i <= n; i++) {
			if (i != n && ord(text, i) != 10)
				continue;
			let line = substr(text, start, i - start);
			start = i + 1;
			if (match(line, /socks_auto_switch/) != null)
				continue;
			let pid = match(line, /^[ \t]*([0-9]+)/);
			if (pid != null)
				command_rc(["kill", "-9", pid[1]]);
		}
	}
	let names = lsdir(tmp);
	if (names == null)
		return;
	let prefix = flag;
	for (let name in names) {
		if (length(name) <= length(prefix) || substr(name, 0, length(prefix)) != prefix)
			continue;
		if (index(name, ".") >= 0)
			unlink(tmp + "/" + name);
	}
};

test_node = function(node_id) {
	let rc = command_rc([
		"flock", "-x", "/var/lock/passwall_socks_auto_switch_test.lock",
		"/usr/bin/ucode", "/usr/libexec/passwall/socks_auto_switch.uc",
		"--test-node", id, node_id, probe_url, retry_num, connect_timeout
	]);
	return rc == 0;
};

next_node = function(nodes, now) {
	let first = length(nodes) > 0 ? nodes[0] : "";
	let found = false;
	for (let node in nodes) {
		if (found)
			return node;
		if (node == now)
			found = true;
	}
	return first;
};

try_switch_backup = function(backup_nodes, now_node) {
	let nodes = words(backup_nodes);
	if (backup_count == 1)
		push(nodes, main_node);
	let total = length(nodes);
	let tried = 0;
	while (tried < total) {
		let new_node = next_node(nodes, now_node);
		if (new_node == null || new_node == "")
			break;
		let role = new_node == main_node ? "主节点" : "后备节点";
		let node_type = api.uci_get_c(new_node, "type") ?? "";
		let node_remarks = api.uci_get_c(new_node, "remarks") ?? "";
		api.log("Socks切换检测：端口[" + socks_port + "] 尝试" + role + "【" + node_type + "：[" + node_remarks + "]】");
		if (test_node(new_node)) {
			check_process();
			api.log("Socks切换检测：端口[" + socks_port + "]【" + node_type + "：[" + node_remarks + "]】正常，切换到此节点！");
			let rc = command_rc([
				"/usr/bin/env", "NO_REC_PROCESS=1",
				"/usr/bin/ucode", "/usr/libexec/passwall/app.uc", "socks_node_switch",
				"flag=" + id, "new_node=" + new_node
			]);
			if (rc == 0) {
				api.log("Socks切换检测：端口[" + socks_port + "] 节点切换完毕！");
				return 0;
			}
			api.log("Socks切换检测：端口[" + socks_port + "] 节点切换失败，继续尝试其他节点！");
		} else {
			api.log("Socks切换检测：端口[" + socks_port + "]【" + node_type + "：[" + node_remarks + "]】异常。");
		}
		now_node = new_node;
		tried++;
	}
	api.log("Socks切换检测：端口[" + socks_port + "] 所有节点均不可用或切换失败！");
	return 1;
};

test_auto_switch = function(backup_nodes) {
	let now_node = api.get_cache_var(id) ?? "";
	if (now_node == "")
		return 1;
	let status = test_proxy();
	if (status == 2) {
		api.log("Socks切换检测：无法连接到网络，请检查网络是否正常！");
		return 2;
	}
	if (restore_switch == "1" && main_node != "" && now_node != main_node && test_node(main_node)) {
		check_process();
		let node_type = api.uci_get_c(main_node, "type") ?? "";
		let node_remarks = api.uci_get_c(main_node, "remarks") ?? "";
		api.log("Socks切换检测：端口[" + socks_port + "] 主节点【" + node_type + "：[" + node_remarks + "]】正常，切换到主节点！");
		let rc = command_rc([
			"/usr/bin/env", "NO_REC_PROCESS=1",
			"/usr/bin/ucode", "/usr/libexec/passwall/app.uc", "socks_node_switch",
			"flag=" + id, "new_node=" + main_node
		]);
		if (rc == 0) {
			api.log("Socks切换检测：端口[" + socks_port + "] 节点切换完毕！");
			return 0;
		}
		api.log("Socks切换检测：端口[" + socks_port + "] 恢复主节点失败！");
		status = 1;
	}
	if (status == 0)
		return 0;
	let node_type = api.uci_get_c(now_node, "type") ?? "";
	let node_remarks = api.uci_get_c(now_node, "remarks") ?? "";
	api.log("Socks切换检测：端口[" + socks_port + "]【" + node_type + "：[" + node_remarks + "]】异常。");
	return try_switch_backup(backup_nodes, now_node);
};

main = function(argv) {
	if ((argv[0] ?? "") == "--test-node") {
		id = argv[1] ?? "";
		let node_id = argv[2] ?? "";
		probe_url = argv[3] ?? probe_url;
		retry_num = argv[4] ?? retry_num;
		connect_timeout = argv[5] ?? connect_timeout;
		let ntype = lc(trim(api.uci_get_c(node_id, "type") ?? ""));
		if (ntype == "")
			exit(1);
		check_process();
		let port = api.get_new_port(48800, "tcp,udp");
		if (port == null)
			exit(1);
		let flag = "test_node_" + id + "_" + node_id;
		command_rc([
			"/usr/bin/env", "NO_REC_PROCESS=1",
			"/usr/bin/ucode", "/usr/libexec/passwall/app.uc", "run_socks",
			"flag=" + flag, "node=" + node_id, "bind=127.0.0.1",
			"socks_port=" + port, "config_file=" + flag + ".json"
		]);
		command_rc(["sleep", "2s"]);
		let status = curl_code(probe_url, int(retry_num), int(connect_timeout), "socks5h://127.0.0.1:" + port, true);
		cleanup_node(flag);
		exit(status == "200" ? 0 : 1);
	}

	id = argv[0] ?? "";
	if (match(id, /^[A-Za-z0-9_]+$/) == null)
		exit(0);
	if ((argv[1] ?? "") != "--locked") {
		command_rc([
			"flock", "-n", "/var/lock/passwall_socks_auto_switch_" + id + ".lock",
			"/usr/bin/ucode", "/usr/libexec/passwall/socks_auto_switch.uc", id, "--locked"
		]);
		exit(0);
	}

	main_node = api.uci_get_c(id, "node") ?? "";
	socks_port = "" + (api.uci_get_c(id, "port") ?? "0");
	delay = "" + (api.uci_get_c(id, "autoswitch_testing_time") ?? "30");
	connect_timeout = "" + (api.uci_get_c(id, "autoswitch_connect_timeout") ?? "3");
	retry_num = "" + (api.uci_get_c(id, "autoswitch_retry_num") ?? "1");
	restore_switch = "" + (api.uci_get_c(id, "autoswitch_restore_switch") ?? "0");
	probe_url = api.uci_get_c(id, "autoswitch_probe_url") ?? "";
	if (probe_url == "")
		probe_url = "https://www.google.com/generate_204";
	if (match(delay, /^[0-9]+$/) == null)
		delay = "30";
	if (match(retry_num, /^[0-9]+$/) == null)
		retry_num = "1";
	if (match(connect_timeout, /^[0-9]+$/) == null)
		connect_timeout = "3";

	let backup = api.get_socks_backup_nodes(id) ?? "";
	let nodes = words(backup);
	backup_count = length(nodes);
	api.log("  - Socks切换检测：端口[" + socks_port + "] 后备节点数量：" + backup_count);
	if (backup_count == 0)
		exit(0);
	if (backup_count == 1 && main_node == nodes[0])
		exit(0);
	if (backup_count > 1 && restore_switch != "1") {
		let seen = false;
		for (let node in nodes) {
			if (node == main_node)
				seen = true;
		}
		if (!seen)
			backup = backup + " " + main_node;
	}

	while (true) {
		check_process();
		test_auto_switch(backup);
		command_rc(["sleep", delay]);
	}
};

export { main };
