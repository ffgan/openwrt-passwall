'use strict';

import * as api from 'passwall.api';
import * as fs from 'fs';

let CONFIG = api.s_config;
let CONFIG_PATH = api.S_TMP_PATH;
let LOG_APP_FILE = "/tmp/log/" + CONFIG + ".log";
let TMP_BIN_PATH = CONFIG_PATH + "/bin";

function ltruth(v) {
	return v != null && v !== false;
}

function tonumber(v) {
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
}

function log(...args) {
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
}

function cmd(command) {
	api.sys.call(command);
}

function ln_run(s, d, command, output) {
	if (output == null || output === false)
		output = "/dev/null";
	d = TMP_BIN_PATH + "/" + d;
	cmd(sprintf('[ ! -f "%s" ] && ln -s %s %s 2>/dev/null', d, s, d));
	return sprintf("%s >%s 2>&1 &", d + " " + command, output);
}

function remove_firewall_rules(defer_commit) {
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
}

function nonempty(obj) {
	if (obj == null)
		return false;
	if (type(obj) != "object" && type(obj) != "array")
		return false;
	return length(obj) > 0;
}

export function start() {
	let enabled_raw = api.uci_get_s("@global[0]", "enable");
	if (enabled_raw == null || enabled_raw === false)
		enabled_raw = 0;
	let enabled = tonumber(enabled_raw);
	if (enabled == null || enabled == 0)
		return;

	let fw_changed = remove_firewall_rules(true);
	let uci = api.uci;

	cmd(sprintf("mkdir -p %s %s", CONFIG_PATH, TMP_BIN_PATH));
	cmd(sprintf("touch %s", LOG_APP_FILE));
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
			let bin = null;
			let config = {};
			let config_file = CONFIG_PATH + "/" + id + ".json";
			let server_type = server.type;
			if (server_type == null || server_type === false)
				server_type = "";

			if (server_type == "Socks") {
				let auth = "";
				if (ltruth(server.auth) && server.auth == "1") {
					let user = null;
					if (ltruth(server.user))
						user = api.uci_get_s(server.user);
					let username = (ltruth(user) && user.username != null && user.username !== false) ? user.username : "";
					let password = (ltruth(user) && user.password != null && user.password !== false) ? user.password : "";
					if (username != "" && password != "") {
						username = "-u " + username;
						password = "-P " + password;
						auth = username + " " + password;
					}
				}
				bin = ln_run("/usr/bin/microsocks", "microsocks_" + id, sprintf("-i :: -p %s %s", port, auth), log_path);
			} else if (server_type == "SSR") {
				if (server.custom === "1" && ltruth(server.config_str))
					config = api.jsonc.parse(api.base64Decode(server.config_str));
				else
					config = import("passwall.util_shadowsocks").gen_config_server(server);
				let udp_param = "";
				let udp_forward = tonumber(server.udp_forward);
				if (udp_forward == null)
					udp_forward = 1;
				if (udp_forward == 1)
					udp_param = "-u";
				let bin_type = lc(server_type);
				bin = ln_run("/usr/bin/" + bin_type + "-server", bin_type + "-server", "-c " + config_file + " " + udp_param, log_path);
			} else if (server_type == "SS-Rust") {
				if (server.custom === "1" && ltruth(server.config_str))
					config = api.jsonc.parse(api.base64Decode(server.config_str));
				else
					config = import("passwall.util_shadowsocks").gen_config_server(server);
				bin = ln_run("/usr/bin/ssserver", "ssserver", "-c " + config_file, log_path);
			} else if (server_type == "Xray") {
				if (server.custom === "1" && ltruth(server.config_str)) {
					config = api.jsonc.parse(api.base64Decode(server.config_str));
					if (log_path != null) {
						if (config.log == null)
							config.log = {};
						config.log.loglevel = server.loglevel;
					}
				} else {
					config = import("passwall.util_xray").gen_config_server(server);
				}
				bin = ln_run(api.get_app_path("xray"), "xray", "run -c " + config_file, log_path);
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
					config = import("passwall.util_sing-box").gen_config_server(server);
				}
				bin = ln_run(api.get_app_path("sing-box"), "sing-box", "run -c " + config_file, log_path);
			} else if (server_type == "Hysteria2") {
				if (server.custom === "1" && ltruth(server.config_str))
					config = api.jsonc.parse(api.base64Decode(server.config_str));
				else
					config = import("passwall.util_hysteria2").gen_config_server(server);
				bin = ln_run(api.get_app_path("hysteria"), "hysteria", "-c " + config_file + " server", log_path);
			}

			if (nonempty(config)) {
				let fh = fs.open(config_file, "w");
				if (fh != null) {
					fh.write(api.jsonc.stringify(config, 1));
					fh.close();
				}
				log(sprintf("%s 生成配置文件并运行 - %s", remarks, config_file));
			}

			if (bin != null)
				cmd(bin);

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
}

function lor_src(v) {
	if (v == null || v === false)
		return "wan";
	return v;
}

export function stop() {
	cmd(sprintf("/bin/busybox top -bn1 | grep -v 'grep' | grep '%s/' | awk '{print $1}' | xargs kill -9 >/dev/null 2>&1", CONFIG_PATH));
	remove_firewall_rules();
	api.remove(CONFIG_PATH, LOG_APP_FILE);
}

// argv[0] = start | stop.
export function main(argv) {
	if (argv == null || length(argv) < 1)
		return;
	let action = argv[0];
	if (action == "start")
		start();
	else if (action == "stop")
		stop();
}
