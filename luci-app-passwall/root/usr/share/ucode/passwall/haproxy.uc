'use strict';

import * as api from 'passwall.api';
import * as fs from 'fs';
import * as utils from 'passwall.utils';
let ltruth, tonumber, gmatch, leading_int, get_ip_port_from, server_endpoint, main;

ltruth = function(v) {
	return v != null && v !== false;
};

tonumber = function(v) {
	if (type(v) == "int")
		return v;
	if (type(v) == "double")
		return (v == v) ? v : null;
	if (type(v) != "string")
		return null;
	let s = trim(v);
	if (match(s, /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/) == null)
		return null;
	if (index(s, ".") >= 0 || index(lc(s), "e") >= 0)
		return s * 1;
	return int(s);
};

gmatch = function(s, pattern) {
	if (s == null || s === false)
		return [];
	let found = match("" + s, pattern);
	if (found == null)
		return [];
	let out = [];
	for (let m in found)
		push(out, m[0]);
	return out;
};

leading_int = function(v) {
	let m = match("" + v, /^[0-9]+/);
	if (m == null)
		return null;
	return tonumber(m[0]);
};

get_ip_port_from = function(str) {
	let result_port = api.sys.exec("echo -n " + str + " | sed -n 's/^.*[:#]\\([0-9]*\\)$/\\1/p'");
	let result_ip = api.sys.exec(sprintf("__host=%s;__varport=%s;", str, result_port) + "echo -n ${__host%%${__varport:+[:#]${__varport}*}}");
	return [result_ip, result_port];
};

server_endpoint = function(o) {
	let address = replace(o.server_address, /^\[(.*)\]$/, "$1");
	if (index(address, ":") >= 0)
		address = "[" + address + "]";
	return address + ":" + o.server_port;
};

// argv is -path <dir> -conf <file>, parsed by api.get_args. No script name in argv.
main = function(argv) {
	let appname = api.appname;
	let log = api.log;
	let vmap = api.get_args(argv ?? []);
	let haproxy_path = vmap["-path"];
	let haproxy_conf = vmap["-conf"];
	let haproxy_dns = "127.0.0.1";

	let cpu_thread = api.sys.exec('echo -n $(cat /proc/cpuinfo | grep "processor" | wc -l)');
	if (cpu_thread == null || cpu_thread === false)
		cpu_thread = "1";
	let health_check_type = api.uci_get_c("@global_haproxy[0]", "health_check_type") ?? "tcp";
	let health_check_inter = api.uci_get_c("@global_haproxy[0]", "health_check_inter") ?? "60";
	let balancingStrategy = api.uci_get_c("@global_haproxy[0]", "balancingStrategy") ?? "roundrobin";
	let console_port = api.uci_get_c("@global_haproxy[0]", "console_port") ?? "1188";
	let bind_local = api.uci_get_c("@global_haproxy[0]", "bind_local") ?? "0";
	let bind_address = "0.0.0.0";
	if (bind_local == "1")
		bind_address = "127.0.0.1";

	log("HAPROXY 负载均衡：");
	log(sprintf("  * 控制台端口：%s", console_port));
	fs.mkdir(haproxy_path);
	let haproxy_file = haproxy_path + "/" + haproxy_conf;

	let haproxy_config = `global
	daemon
	log 127.0.0.1 local2
	maxconn 60000
	stats socket {{path}}/haproxy.sock
	nbthread {{nbthread}}
	external-check
	insecure-fork-wanted
	spread-checks 20
	tune.max-checks-per-thread 5

defaults
	mode tcp
	log global
	option tcplog
	option dontlognull
	option abortonclose
	#option forwardfor except 127.0.0.0/8
	option redispatch
	retries 2
	timeout http-request 10s
	timeout queue 1m
	timeout connect 10s
	timeout client 1m
	timeout server 1m
	timeout http-keep-alive 10s
	timeout check 10s
	maxconn 3000

resolvers mydns
	resolve_retries 1
	timeout resolve 5s
	hold valid 600s
{{dns}}
`;

	haproxy_config = replace(haproxy_config, "{{path}}", haproxy_path);
	haproxy_config = replace(haproxy_config, "{{nbthread}}", cpu_thread);

	let mydns = "";
	let dns_index = 0;
	for (let w in gmatch(haproxy_dns, /[^,]+/g)) {
		dns_index = dns_index + 1;
		let s = replace(w, "#", ":");
		if (index(s, ":") < 0)
			s = s + ":53";
		mydns = mydns + (dns_index > 1 ? "\n" : "") + "	" + sprintf("nameserver dns%s %s", dns_index, s);
	}
	haproxy_config = replace(haproxy_config, "{{dns}}", mydns);

	let body = haproxy_config;
	let listens = {};

	api.uci_foreach_c("haproxy_config", (t) => {
		if (t.enabled == "1") {
			let server_remark = null;
			let server_address = null;
			let server_port = null;
			let lbss = t.lbss;
			let listen_port = tonumber(t.haproxy_port);
			if (listen_port == null)
				listen_port = 0;
			let server_node = api.uci_get_c(lbss);
			let hop = null;
			if (health_check_type == "script_logic" && server_node != null)
				hop = server_node.hysteria_hop ?? server_node.hysteria2_hop;
			if (hop != null)
				hop = replace(hop, ":", "-");
			if (server_node != null && ltruth(server_node.address) && (ltruth(server_node.port) || ltruth(hop))) {
				server_remark = server_node.address + ":" + (server_node.port ?? hop);
				server_address = server_node.address;
				server_port = server_node.port ?? hop;
				t.origin_address = server_address;
				t.origin_port = server_port;
				if (health_check_type == "script_logic") {
					if (server_node.type != "Socks") {
						let new_port = null;
						let cache = api.get_socks_port_by_cache(server_node[".name"]);
						if (ltruth(cache)) {
							new_port = cache;
						} else {
							new_port = api.get_new_port();
							let config_file = sprintf("%s_%s.json", t[".name"], new_port);
							utils.run([
								"/usr/bin/ucode", "/usr/libexec/passwall/app.uc", "run_socks",
								"flag=" + new_port, "node=" + server_node[".name"],
								"bind=127.0.0.1", "socks_port=" + new_port,
								"config_file=" + config_file
							], true);
							api.set_socks_port_to_cache(server_node[".name"], new_port);
						}
						server_address = "127.0.0.1";
						server_port = new_port;
					}
				}
			} else {
				let ip_port = get_ip_port_from(lbss);
				server_address = ip_port[0];
				server_port = ip_port[1];
				server_remark = server_address + ":" + server_port;
				t.origin_address = server_address;
				t.origin_port = server_port;
			}
			if (ltruth(server_address) && ltruth(server_port) && listen_port > 0) {
				let key = "" + listen_port;
				if (listens[key] == null)
					listens[key] = [];
				t.server_remark = server_remark;
				t.server_address = server_address;
				t.server_port = server_port;
				push(listens[key], t);
			} else {
				log("  - 丢弃1个明显无效的节点");
			}
		}
	});

	let inter = leading_int(health_check_inter);
	if (inter == null)
		inter = 60;
	inter = max(inter, 20);
	let fastinter = max(10, min(15, inter / 2));
	let downinter = int(inter * 1.5);
	if (downinter < inter * 1.5)
		downinter++;
	let inter_arg = sprintf("inter %ds fastinter %ds downinter %ds", inter, fastinter, downinter);

	let sortTable = [];
	for (let i in listens) {
		if (i != null)
			push(sortTable, i);
	}
	sort(sortTable, (a, b) => int(a) - int(b));

	let check_counts = {};
	if (health_check_type == "script_logic") {
		for (let port in sortTable) {
			for (let o in listens[port]) {
				if (api.is_ip(o.server_address)) {
					let endpoint = server_endpoint(o);
					check_counts[endpoint] = (check_counts[endpoint] ?? 0) + 1;
				}
			}
		}
	}
	let shared_checks = [];
	let shared_check_names = {};

	for (let port in sortTable) {
		log(sprintf("  +  入口 %s:%s", bind_address, port));
		body += "\n" + sprintf("listen %s\n\tbind %s:%s\n\tmode tcp\n\tbalance %s\n", port, bind_address, port, balancingStrategy);

		if (health_check_type == "script_logic") {
			body += sprintf("	option external-check\n	external-check command \"/usr/libexec/%s/haproxy_check.uc\"\n", appname);
		}

		let count_M = 1;
		let count_B = 1;
		for (let o in listens[port]) {
			let remark = replace(o.server_remark ?? "", /[\[\]]/g, "");
			if (("" + o.backup) != "1") {
				remark = "M" + count_M + "-" + remark;
				count_M = count_M + 1;
			} else {
				remark = "B" + count_B + "-" + remark;
				count_B = count_B + 1;
			}
			let server = server_endpoint(o);
			let check_arg = "check " + inter_arg + " rise 2 fall 2";
			if ((check_counts[server] ?? 0) > 1) {
				let name = shared_check_names[server];
				if (name == null) {
					name = "check_" + (length(shared_checks) + 1);
					shared_check_names[server] = name;
					push(shared_checks, { name: name, server: server });
				}
				check_arg = "track " + appname + "_health_checks/" + name;
			}
			let resolvers = "resolvers mydns";
			if (api.is_ip(o.server_address))
				resolvers = "";
			let backup = (("" + o.backup) == "1") ? "backup" : "";
			let server_conf = "server " + remark + " " + server + " weight " + o.lbweight + " " + resolvers + " " + check_arg + " " + backup;
			body += "	" + api.trim(server_conf) + "\n";

			if (o.export != "0")
				utils.add_ip2route(o.origin_address, o.export);

			log(sprintf("  | - 出口节点：%s:%s，权重：%s", o.origin_address, o.origin_port, o.lbweight));
		}
	}

	if (length(shared_checks) > 0) {
		body += sprintf("\nbackend %s_health_checks\n\tmode tcp\n\toption external-check\n\texternal-check command \"/usr/libexec/%s/haproxy_check.uc\"\n", appname, appname);
		for (let check in shared_checks)
			body += sprintf("\tserver %s %s check %s rise 2 fall 2\n", check.name, check.server, inter_arg);
	}

	let console_user = api.uci_get_c("@global_haproxy[0]", "console_user");
	let console_password = api.uci_get_c("@global_haproxy[0]", "console_password");
	let auth = "";
	if (ltruth(console_user) && console_user != "" && ltruth(console_password) && console_password != "")
		auth = "stats auth " + console_user + ":" + console_password;
	body += "\n" + sprintf("listen console\n\tbind 0.0.0.0:%s\n\tmode http\n\tstats refresh 30s\n\tstats uri /\n\tstats admin if TRUE\n\t%s\n", console_port, auth);

	let prev = api.fs.readfile(haproxy_file);
	if (prev == null)
		prev = "";
	api.fs.writefile(haproxy_file, prev + body);

	if (health_check_type == "script_logic") {
		let probeUrl = api.trim(api.uci_get_c("@global_haproxy[0]", "health_probe_url") ?? "");
		if (probeUrl == "")
			probeUrl = "https://www.google.com/generate_204";
		api.set_cache_var("HAPROXY_PROBE_URL", probeUrl);
	}
};
export { get_ip_port_from, main };
