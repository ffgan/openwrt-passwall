'use strict';

import * as api from 'passwall.api';
import { popen, readfile, unlink, lsdir } from 'fs';

let read_cmd, command_ok, bracket_host, curl_probe, split_lines, cleanup_socks, url_test_node;

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

command_ok = function(argv) {
	let got = read_cmd(argv);
	return got != null && got.rc == 0;
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

bracket_host = function(host) {
	if (match(host, /^\[.*\]$/) != null)
		return host;
	if (index(host, ":") >= 0)
		return "[" + host + "]";
	return host;
};

curl_probe = function(proxy, extra, url) {
	let argv = [
		"/usr/bin/curl", "--connect-timeout", "3", "--max-time", "5",
		"-o", "/dev/null", "-I", "-sk",
		"-w", "%{http_code}:%{time_pretransfer}:%{time_starttransfer}"
	];
	if (extra != null)
		push(argv, extra[0], extra[1]);
	push(argv, "-x", proxy, url);
	let got = read_cmd(argv);
	if (got == null || got.rc != 0)
		return "0";
	let text = trim(got.out);
	if (text == "")
		return "0";
	return text;
};

cleanup_socks = function(flag) {
	let tmp = api.TMP_PATH;
	let pid_file = tmp + "/" + flag + "_plugin.pid";
	let pid_txt = readfile(pid_file);
	if (type(pid_txt) == "string") {
		let pid = match(trim(pid_txt), /^([0-9]+)/);
		if (pid != null)
			command_ok(["kill", "-9", pid[1]]);
	}
	let listed = read_cmd(["busybox", "pgrep", "-af", tmp + "/" + flag + "[._]"]);
	if (listed != null) {
		let lines = split_lines(listed.out);
		for (let line in lines) {
			if (match(line, /test\.sh/) != null)
				continue;
			let pid = match(line, /^[ \t]*([0-9]+)/);
			if (pid != null)
				command_ok(["kill", "-9", pid[1]]);
		}
	}
	let names = lsdir(tmp);
	if (names != null) {
		let prefix = length(flag);
		for (let name in names) {
			if (length(name) <= prefix || substr(name, 0, prefix) != flag)
				continue;
			let mark = substr(name, prefix, 1);
			if (mark == "." || mark == "_")
				unlink(tmp + "/" + name);
		}
	}
};

url_test_node = function(node_id) {
	node_id = node_id == null ? "" : ("" + node_id);
	if (node_id == "")
		return "0";
	let ntype = lc(trim(api.uci_get_c(node_id, "type") ?? ""));
	if (ntype == "")
		return "0";

	let proxy = null;
	let extra = null;
	let flag = null;
	if (ntype == "socks") {
		let address = trim(api.uci_get_c(node_id, "address") ?? "");
		let port = trim("" + (api.uci_get_c(node_id, "port") ?? ""));
		if (address == "" || port == "")
			return "0";
		proxy = "socks5h://" + bracket_host(address) + ":" + port;
		let username = api.uci_get_c(node_id, "username") ?? "";
		let password = api.uci_get_c(node_id, "password") ?? "";
		if (username != "" && password != "")
			extra = ["--proxy-user", username + ":" + password];
	} else {
		let base = 48900 + api.rand_int(0, 200);
		let port = api.get_new_port(base, "tcp,udp");
		if (port == null)
			return "0";
		flag = "url_test_" + replace(node_id, /[^A-Za-z0-9_]/g, "_") + "_" + api.rand_int(10000, 99999);
		command_ok([
			"/usr/bin/env", "NO_REC_PROCESS=1",
			"/usr/bin/ucode", "/usr/libexec/passwall/app.uc", "run_socks",
			"flag=" + flag,
			"node=" + node_id,
			"bind=127.0.0.1",
			"socks_port=" + port,
			"config_file=" + flag + ".json"
		]);
		proxy = "socks5h://127.0.0.1:" + port;
	}

	command_ok(["/bin/sleep", "2"]);
	let probe = trim(api.uci_get_c("@global_other[0]", "url_test_url") ?? "");
	if (probe == "")
		probe = "https://www.google.com/generate_204";
	let result = curl_probe(proxy, extra, probe);
	if (ntype != "socks" && flag != null)
		cleanup_socks(flag);
	return result;
};

export { url_test_node };
