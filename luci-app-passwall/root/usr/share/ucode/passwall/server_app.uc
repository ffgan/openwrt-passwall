'use strict';

import * as api from 'passwall.api';
import * as fs from 'fs';
import { spawn, kill_matching } from 'passwall.proc';
import { gen_config_server as ss_gen_config_server } from 'passwall.util_shadowsocks';
import { gen_config_server as xray_gen_config_server } from 'passwall.util_xray';
import { gen_config_server as singbox_gen_config_server } from 'passwall.util_singbox';
import { gen_config_server as hy2_gen_config_server } from 'passwall.util_hysteria2';
import { truth as ltruth, to_number as tonumber } from 'passwall.text';
let log, launch_server, remove_firewall_rules, nonempty, start, lor_src, stop, main;

let CONFIG = api.s_config;
let CONFIG_PATH = api.S_TMP_PATH;
let LOG_APP_FILE = "/tmp/log/" + CONFIG + ".log";
let TMP_BIN_PATH = CONFIG_PATH + "/bin";

log = function(...args) {
	let fh = fs.open(LOG_APP_FILE, "a");
	if (fh == null)
		return;
	let t = localtime();
	let parts = [];
	for (let a in args) {
		if (a == null)
			push(parts, "");
		else
			push(parts, "" + a);
	}
	let str = sprintf("%04d-%02d-%02d %02d:%02d:%02d: ", t.year, t.mon, t.mday, t.hour, t.min, t.sec) + join(" ", parts);
	fh.write(str + "\n");
	fh.close();
};

launch_server = function(file, name, args, output) {
	return spawn({
		file: file ?? "",
		name: name,
		args: args,
		output: output ?? "/dev/null",
		bindir: TMP_BIN_PATH
	});
};

remove_firewall_rules = function(defer_commit) {
	let uci = api.uci;
	let to_delete = [];
	uci.foreach("firewall", "rule", (rule) => {
		let name = rule[".name"];
		if (name != null && index(name, CONFIG) == 0)
			push(to_delete, name);
	});
	if (length(to_delete) > 0) {
		for (let name in to_delete)
			uci.delete("firewall", name);
		if (defer_commit == null || defer_commit === false)
			api.uci_save(uci, "firewall", true, true);
		return true;
	}
	return false;
};

nonempty = function(obj) {
	if (obj == null)
		return false;
	if (type(obj) != "object" && type(obj) != "array")
		return false;
	return length(obj) > 0;
};

start = function() {
	let enabled_raw = api.uci_get_s("@global[0]", "enable");
	if (enabled_raw == null || enabled_raw === false)
		enabled_raw = 0;
	let enabled = tonumber(enabled_raw);
	if (enabled == null || enabled == 0)
		return;

	let fw_changed = remove_firewall_rules(true);
	let uci = api.uci;

	api.fs.mkdirr(CONFIG_PATH);
	api.fs.mkdirr(TMP_BIN_PATH);
	if (fs.stat(LOG_APP_FILE) == null) {
		api.fs.mkdirr("/tmp/log");
		fs.writefile(LOG_APP_FILE, "");
	}
	let firewall_num = 0;
	api.uci_foreach_s("server", (server) => {
		let id = server[".name"];
		let enable = server.enable;
		if (ltruth(enable) && tonumber(enable) == 1) {
			let enable_log = server.log;
			let log_path = null;
			if (ltruth(enable_log) && enable_log == "1")
				log_path = CONFIG_PATH + "/" + id + ".log";
			let remarks = server.remarks;
			let port = tonumber(server.port);
			let launch = null;
			let config = {};
			let config_file = CONFIG_PATH + "/" + id + ".json";
			let server_type = server.type;
			if (server_type == null || server_type === false)
				server_type = "";

			if (server_type == "Socks") {
				let args = ["-i", "::", "-p", port == null ? "" : "" + port];
				if (ltruth(server.auth) && server.auth == "1") {
					let user = null;
					if (ltruth(server.user))
						user = api.uci_get_s(server.user);
					let username = (ltruth(user) && user.username != null && user.username !== false) ? user.username : "";
					let password = (ltruth(user) && user.password != null && user.password !== false) ? user.password : "";
					if (username != "" && password != "") {
						push(args, "-u", username);
						push(args, "-P", password);
					}
				}
				launch = { file: "/usr/bin/microsocks", name: "microsocks_" + id, args: args };
			} else if (server_type == "SSR") {
				if (server.custom === "1" && ltruth(server.config_str))
					config = api.jsonc.parse(api.base64Decode(server.config_str));
				else
					config = ss_gen_config_server(server);
				let args = ["-c", config_file];
				let udp_forward = tonumber(server.udp_forward);
				if (udp_forward == null)
					udp_forward = 1;
				if (udp_forward == 1)
					push(args, "-u");
				let bin_type = lc(server_type);
				launch = { file: "/usr/bin/" + bin_type + "-server", name: bin_type + "-server", args: args };
			} else if (server_type == "SS-Rust") {
				if (server.custom === "1" && ltruth(server.config_str))
					config = api.jsonc.parse(api.base64Decode(server.config_str));
				else
					config = ss_gen_config_server(server);
				launch = { file: "/usr/bin/ssserver", name: "ssserver", args: ["-c", config_file] };
			} else if (server_type == "Xray") {
				if (server.custom === "1" && ltruth(server.config_str)) {
					config = api.jsonc.parse(api.base64Decode(server.config_str));
					if (log_path != null) {
						if (config.log == null)
							config.log = {};
						config.log.loglevel = server.loglevel;
					}
				} else {
					config = xray_gen_config_server(server);
				}
				launch = { file: api.get_app_path("xray"), name: "xray", args: ["run", "-c", config_file] };
			} else if (server_type == "sing-box") {
				if (server.custom === "1" && ltruth(server.config_str)) {
					config = api.jsonc.parse(api.base64Decode(server.config_str));
					if (log_path != null) {
						if (config.log == null)
							config.log = {};
						config.log.timestamp = true;
						config.log.disabled = false;
						config.log.level = server.loglevel;
						config.log.output = log_path;
					}
				} else {
					config = singbox_gen_config_server(server);
				}
				launch = { file: api.get_app_path("sing-box"), name: "sing-box", args: ["run", "-c", config_file] };
			} else if (server_type == "Hysteria2") {
				if (server.custom === "1" && ltruth(server.config_str))
					config = api.jsonc.parse(api.base64Decode(server.config_str));
				else
					config = hy2_gen_config_server(server);
				launch = { file: api.get_app_path("hysteria"), name: "hysteria", args: ["-c", config_file, "server"] };
			}

			if (nonempty(config)) {
				let fh = fs.open(config_file, "w");
				if (fh != null) {
					fh.write(api.jsonc.stringify(config, 1));
					fh.close();
				}
				log(sprintf("%s 生成配置文件并运行 - %s", remarks, config_file));
			}

			if (launch != null)
				launch_server(launch.file, launch.name, launch.args, log_path);

			let firewall_allow = server.firewall_allow;
			if (firewall_allow == "1") {
				firewall_num = firewall_num + 1;
				let uid = CONFIG + "_" + id;
				uci.section("firewall", "rule", uid);
				uci.set("firewall", uid, "name", uid);
				uci.set("firewall", uid, "src", lor_src(server.firewall_allow_src));
				uci.set("firewall", uid, "dest_port", port);
				uci.set("firewall", uid, "target", "ACCEPT");
			}
		}
	});
	if (firewall_num > 0 || fw_changed)
		api.uci_save(uci, "firewall", true, true);
};

lor_src = function(v) {
	if (v == null || v === false)
		return "wan";
	return v;
};

stop = function() {
	kill_matching(CONFIG_PATH + "/");
	remove_firewall_rules();
	api.remove(CONFIG_PATH, LOG_APP_FILE);
};

// argv[0] = start | stop.
main = function(argv) {
	if (argv == null || length(argv) < 1)
		return;
	let action = argv[0];
	if (action == "start")
		start();
	else if (action == "stop")
		stop();
};
export { start, stop, main };
