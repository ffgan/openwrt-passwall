'use strict';

import * as api from 'passwall.api';
import * as fs from 'fs';
import { truth as ltruth, lua_or as lor, to_number as tonumber } from 'passwall.text';
let set_if, gen_config_server, gen_config, print_result, dispatch, main;

let plugin_sh = null;
let plugin_bin = null;

set_if = function(obj, key, val) {
	if (val != null)
		obj[key] = val;
};

gen_config_server = function(node) {
	let user = null;
	if (ltruth(node.user))
		user = api.uci_get_s(node.user);
	let config = {};
	set_if(config, "server_port", tonumber(node.port));
	if (ltruth(user) && user.password != null && user.password !== false)
		config.password = user.password;
	else
		config.password = "";
	set_if(config, "timeout", tonumber(node.timeout));
	config.fast_open = node.tcp_fast_open === "1";
	set_if(config, "method", node.method);

	if (node.type == "SS-Rust") {
		config.server = "::";
		config.mode = "tcp_and_udp";
	} else {
		config.server = ["[::0]", "0.0.0.0"];
	}

	if (node.type == "SSR") {
		set_if(config, "protocol", node.protocol);
		set_if(config, "protocol_param", node.protocol_param);
		set_if(config, "obfs", node.obfs);
		set_if(config, "obfs_param", node.obfs_param);
	}

	return config;
};

gen_config = function(var) {
	let node_id = var["node"];
	if (node_id == null || node_id === false) {
		print("node 不能为空\n");
		return null;
	}
	let node = api.uci_get_c(node_id);
	let server_host = var["server_host"];
	if (server_host == null || server_host === false)
		server_host = lc(lor(node.address, ""));
	let server_port = lor(var["server_port"], node.port);
	let local_addr = var["local_addr"];
	let local_port = var["local_port"];
	let local_socks_address = lor(var["local_socks_address"], "0.0.0.0");
	let local_socks_port = var["local_socks_port"];
	let local_http_address = lor(var["local_http_address"], "0.0.0.0");
	let local_http_port = var["local_http_port"];
	let local_redir_port = var["local_redir_port"];
	let local_redir_address = lor(var["local_redir_address"], "0.0.0.0");
	let loglevel = var["loglevel"];

	if (api.is_ipv6(server_host))
		server_host = api.get_ipv6_only(server_host);
	let server = server_host;

	let plugin_file = null;
	if (ltruth(node.plugin) && node.plugin != "" && node.plugin != "none") {
		plugin_sh = lor(var["plugin_sh"], "");
		plugin_file = (plugin_sh != "") ? plugin_sh : node.plugin;
		plugin_bin = node.plugin;
	}

	let config = {
		server: server,
		fast_open: node.tcp_fast_open === "1",
		reuse_port: true
	};
	set_if(config, "server_port", tonumber(server_port));
	set_if(config, "local_address", local_addr);
	set_if(config, "local_port", tonumber(local_port));
	set_if(config, "password", node.password);
	set_if(config, "method", node.method);
	set_if(config, "timeout", tonumber(node.timeout));
	if (ltruth(var["tcp_tproxy"]))
		config.tcp_tproxy = true;

	if (node.type == "SSR") {
		set_if(config, "protocol", node.protocol);
		set_if(config, "protocol_param", node.protocol_param);
		set_if(config, "obfs", node.obfs);
		set_if(config, "obfs_param", node.obfs_param);
	} else if (node.type == "SS-Rust") {
		let server_entry = { address: server };
		set_if(server_entry, "port", tonumber(server_port));
		set_if(server_entry, "method", node.method);
		set_if(server_entry, "password", node.password);
		set_if(server_entry, "timeout", tonumber(node.timeout));
		if (ltruth(plugin_file)) {
			server_entry.plugin = plugin_file;
			if (node.plugin_opts != null && node.plugin_opts !== false)
				server_entry.plugin_opts = node.plugin_opts;
		}
		config = {
			servers: [server_entry],
			locals: [],
			fast_open: node.tcp_fast_open === "1",
			log: {
				level: (loglevel == "debug") ? 1 : 0
			}
		};
		if (ltruth(local_socks_address) && ltruth(local_socks_port)) {
			let socks = {
				local_address: local_socks_address,
				mode: "tcp_and_udp"
			};
			set_if(socks, "local_port", tonumber(local_socks_port));
			push(config.locals, socks);
		}
		if (ltruth(local_http_address) && ltruth(local_http_port)) {
			let http = {
				protocol: "http",
				local_address: local_http_address
			};
			set_if(http, "local_port", tonumber(local_http_port));
			push(config.locals, http);
		}
		if (ltruth(local_redir_address) && ltruth(local_redir_port)) {
			let redir = {
				protocol: "redir",
				mode: "tcp_and_udp",
				local_address: local_redir_address
			};
			set_if(redir, "local_port", tonumber(local_redir_port));
			if (ltruth(var["tcp_tproxy"]))
				redir.tcp_redir = "tproxy";
			push(config.locals, redir);
		}
	}

	return api.jsonc.stringify(config, 1);
};

print_result = function(result) {
	if (result == null)
		print("nil\n");
	else if (type(result) == "string")
		print(result, "\n");
	else
		print(api.jsonc.stringify(result, 1), "\n");
};

dispatch = function(name) {
	if (name == "gen_config")
		return gen_config;
	if (name == "gen_config_server")
		return gen_config_server;
	return null;
};

// argv[0] = gen_config | gen_config_server; argv[1] = JSON object string.
main = function(argv) {
	if (argv == null || length(argv) < 1 || argv[0] == null || argv[0] === false)
		return;
	let func = dispatch(argv[0]);
	if (func == null)
		return;
	let parsed = null;
	if (length(argv) > 1 && argv[1] != null)
		parsed = api.jsonc.parse(argv[1]);
	print_result(func(parsed));
	if (plugin_sh != null && plugin_sh != "" && ltruth(plugin_bin)) {
		let pidfile = replace(plugin_sh, /\.sh$/, ".pid");
		let body = "#!/bin/sh\n"
			+ "export PATH=/usr/sbin:/usr/bin:/sbin:/bin:/root/bin:\$PATH\n"
			+ api.shellquote(plugin_bin) + " \"\$@\" &\n"
			+ "echo \$! > " + api.shellquote(pidfile) + "\n"
			+ "wait\n";
		let fh = fs.open(plugin_sh, "w");
		fh.write(body);
		fh.close();
		api.sys.call("chmod +x " + api.shellquote(plugin_sh));
	}
};
export { gen_config_server, gen_config, main };
