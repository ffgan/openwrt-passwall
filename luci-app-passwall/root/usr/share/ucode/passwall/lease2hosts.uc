'use strict';

import * as api from 'passwall.api';
import { readfile, writefile, stat, unlink, lsdir } from 'fs';

let command_rc, fields, split_lines, valid_name, static_hosts, dnsmasq_hosts, odhcpd_hosts, unique_text, hup_pidfile, walk_pids, publish, run;

command_rc = function(argv) {
	if (type(global.system) == "function") {
		let rc = global.system(argv);
		return rc == null ? 255 : rc;
	}
	let ph = api.command_pipe(argv, "r");
	if (ph == null)
		return 255;
	let rc = ph.close();
	return rc == null ? 255 : rc;
};

fields = function(line) {
	let parts = [];
	let cur = "";
	let n = length(line);
	for (let i = 0; i < n; i++) {
		let c = ord(line, i);
		if (c == 32 || c == 9 || c == 13) {
			if (cur != "") {
				push(parts, cur);
				cur = "";
			}
		} else {
			cur += substr(line, i, 1);
		}
	}
	if (cur != "")
		push(parts, cur);
	return parts;
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

valid_name = function(name) {
	return match(name, /^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/) != null;
};

static_hosts = function() {
	let lines = [];
	api.uci.foreach("dhcp", "host", function(section) {
		let name = section.name;
		let ip = section.ip;
		if (type(name) == "array")
			name = name[0];
		if (type(ip) == "array")
			ip = ip[0];
		if (type(name) == "string" && type(ip) == "string" && name != "" && name != "*" && ip != "" && ip != "ignore")
			push(lines, ip + " " + name);
	});
	return lines;
};

dnsmasq_hosts = function(path) {
	let lines = [];
	let text = readfile(path);
	if (type(text) != "string" || text == "")
		return lines;
	let rows = split_lines(text);
	for (let row in rows) {
		let part = fields(row);
		if (length(part) >= 4 && part[3] != "*")
			push(lines, part[2] + " " + part[3]);
	}
	return lines;
};

odhcpd_hosts = function(path) {
	let lines = [];
	let text = readfile(path);
	if (type(text) != "string" || text == "")
		return lines;
	let now = time();
	let rows = split_lines(text);
	for (let row in rows) {
		let part = fields(row);
		if (length(part) == 0)
			continue;
		if (part[0] == "#") {
			if (length(part) < 9 || !valid_name(part[4]))
				continue;
			if (part[5] != "-1") {
				if (match(part[5], /^-?[0-9]+$/) == null || int(part[5]) <= now)
					continue;
			}
			let ipv4 = part[3] == "ipv4" && part[7] == "32";
			let other = part[3] != "ipv4" && part[7] == "128";
			if (!ipv4 && !other)
				continue;
			for (let i = 8; i < length(part); i++) {
				let slash = index(part[i], "/");
				let addr = slash >= 0 ? substr(part[i], 0, slash) : part[i];
				push(lines, addr + " " + part[4]);
			}
			continue;
		}
		if (match(part[0], /^[0-9a-fA-F:.]+$/) == null)
			continue;
		for (let i = 1; i < length(part); i++) {
			if (match(part[i], /^#/) != null)
				break;
			if (valid_name(part[i]))
				push(lines, part[0] + " " + part[i]);
		}
	}
	return lines;
};

unique_text = function(lines) {
	let seen = {};
	for (let line in lines) {
		if (line != null && line != "")
			seen[line] = true;
	}
	let keys = [];
	for (let key in seen)
		push(keys, key);
	sort(keys);
	if (length(keys) == 0)
		return "";
	return join("\n", keys) + "\n";
};

hup_pidfile = function(path) {
	let text = readfile(path);
	if (type(text) != "string")
		return;
	let pid = match(trim(text), /^([0-9]+)/);
	if (pid == null)
		return;
	if (command_rc(["kill", "-0", pid[1]]) == 0)
		command_rc(["kill", "-HUP", pid[1]]);
};

walk_pids = function(dir) {
	let names = lsdir(dir);
	if (names == null)
		return;
	for (let name in names) {
		let path = dir + "/" + name;
		let st = stat(path);
		if (st == null)
			continue;
		if (st.type == "directory")
			walk_pids(path);
		else if (st.type == "file" && name == "dnsmasq.pid")
			hup_pidfile(path);
	}
};

publish = function(hosts_file, tmp_file, content) {
	if (content != "") {
		if (writefile(tmp_file, content) == null)
			return;
		let prev = readfile(hosts_file);
		if (type(prev) != "string" || prev != content) {
			if (command_rc(["mv", "-f", tmp_file, hosts_file]) == 0)
				walk_pids(api.TMP_PATH + "/acl");
		} else {
			unlink(tmp_file);
		}
		return;
	}
	unlink(tmp_file);
	let prev = readfile(hosts_file);
	if (type(prev) == "string" && length(prev) > 0) {
		writefile(hosts_file, "");
		walk_pids(api.TMP_PATH + "/acl");
	}
};

run = function() {
	let lease = api.uci_get("dhcp", "@dnsmasq[0]", "leasefile");
	if (type(lease) != "string" || lease == "")
		lease = "/tmp/dhcp.leases";
	let odhcpd = api.uci_get("dhcp", "odhcpd", "leasefile");
	if (type(odhcpd) != "string" || odhcpd == "")
		odhcpd = "/tmp/odhcpd.leases";
	let dir = api.CACHE_PATH;
	api.fs.mkdirr(dir);
	let hosts_file = dir + "/dhcp-hosts";
	let tmp_file = "/tmp/dhcp-hosts.tmp";
	let fixed = static_hosts();
	while (true) {
		let lines = [];
		for (let line in fixed)
			push(lines, line);
		for (let line in dnsmasq_hosts(lease))
			push(lines, line);
		for (let line in odhcpd_hosts(odhcpd))
			push(lines, line);
		publish(hosts_file, tmp_file, unique_text(lines));
		command_rc(["/bin/sleep", "60"]);
	}
};

export { run };
