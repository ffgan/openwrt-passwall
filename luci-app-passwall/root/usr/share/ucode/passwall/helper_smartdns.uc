'use strict';

import * as api from 'passwall.api';
import * as fs from 'fs';
import { truth as ltruth, to_number as tonumber, lua_quote, gmatch, lines_of } from 'passwall.text';
let exec_pair, read_lines, is_file_nonzero, insert_unique, merge_array, insert_array_before, insert_array_after, tail_after_colon, geosite_file, get_geosite, write_lines, ucfirst, make_server_param, main;

exec_pair = function(cmd) {
	let ret = api.exec_call(cmd);
	if (type(ret) == "array")
		return [ret[0], ret[1]];
	if (type(ret) == "object" && ret != null)
		return [ret.code ?? ret[0], ret.out ?? ret.stdout ?? ret[1]];
	return [ret, ""];
};

read_lines = function(path) {
	return lines_of(api.fs.readfile(path));
};

is_file_nonzero = function(path) {
	if (type(path) != "string" || length(path) <= 1)
		return null;
	let size = api.fs.stat(path, "size");
	if (type(size) != "int" && type(size) != "double")
		return null;
	if (size <= 0)
		return null;
	return true;
};

insert_unique = function(dest_table, value, lookup_table) {
	if (!lookup_table[value]) {
		push(dest_table, value);
		lookup_table[value] = true;
	}
};

merge_array = function(array1, array2) {
	for (let line in array2)
		push(array1, line);
};

insert_array_before = function(array1, array2, target) {
	for (let i = 0; i < length(array1); i++) {
		if (array1[i] == target) {
			for (let j = length(array2) - 1; j >= 0; j--)
				splice(array1, i, 0, array2[j]);
			return;
		}
	}
	merge_array(array1, array2);
};

insert_array_after = function(array1, array2, target) {
	for (let i = 0; i < length(array1); i++) {
		if (array1[i] == target) {
			for (let j = 0; j < length(array2); j++)
				splice(array1, i + 1 + j, 0, array2[j]);
			return;
		}
	}
	merge_array(array1, array2);
};

tail_after_colon = function(line) {
	let m = match(line, /:([^:]+)$/);
	if (m == null)
		return null;
	return m[1];
};

geosite_file = function() {
	let geosite_path = api.uci_get_c("@global_rules[0]", "v2ray_location_asset");
	if (geosite_path == null || geosite_path === false)
		geosite_path = "/usr/share/v2ray/";
	let m = match(geosite_path, /^(.*)\//);
	return (m != null ? m[1] : geosite_path) + "/geosite.dat";
};

get_geosite = function(list_arg, out_path) {
	let geosite_path = geosite_file();
	if (!is_file_nonzero(geosite_path))
		return [1, "File geosite.dat not found"];
	if (list_arg == null || list_arg === false || list_arg == "")
		return [1, "Site list cannot be empty"];
	if (out_path == null || out_path === false || out_path == "")
		return [1, "Output path cannot be empty"];
	let bin = api.finded_com("geoview");
	let cmd = sprintf("%s -type geosite -append=true -input %s -list %s -output %s -lowmem=true",
		lua_quote(bin), lua_quote(geosite_path), lua_quote(list_arg), lua_quote(out_path));
	return exec_pair(cmd);
};

write_lines = function(path, lines) {
	let data = "";
	for (let line in lines)
		data += line + "\n";
	api.fs.writefile(path, data);
};

ucfirst = function(s) {
	if (type(s) != "string" || s == "")
		return s;
	let first = substr(s, 0, 1);
	if (match(first, /^[a-z]/) == null)
		return s;
	return uc(first) + substr(s, 1);
};

make_server_param = function(endpoint) {
	let dns = api.split(api.trim(endpoint), ",");
	if (type(dns) != "array")
		dns = [];
	let address = api.trim(dns[0] ?? "");
	if (address == "")
		return null;
	let proto_m = match(address, /^([A-Za-z0-9_]+):\/\/(.+)$/);
	let protocol = null;
	if (proto_m != null) {
		protocol = lc(proto_m[1]);
		address = proto_m[2];
	}
	let hp = match(address, /^(.*)#([0-9]+)$/);
	if (hp != null) {
		let host = hp[1];
		let port = hp[2];
		if (index(host, ":") >= 0 && index(host, "[") < 0)
			host = "[" + host + "]";
		address = host + ":" + port;
	} else if (api.datatypes.ip6addr(address) && index(address, "[") < 0) {
		address = "[" + address + "]";
	}
	let server_param = "server " + (protocol != null ? (protocol + "://") : "") + address;
	if (dns[1] != null && dns[1] != "")
		server_param = server_param + " -host-ip " + replace(api.trim(dns[1]), /^\[(.*)\]$/, "$1");
	return server_param;
};

// argv is -FLAG value pairs, same as lua arg after the script name. Parsed by api.get_args.
main = function(argv) {
	let vmap = api.get_args(argv ?? []);
	let FLAG = vmap["-FLAG"];
	let DIRECT_DNS = vmap["-DIRECT_DNS"];
	let LOCAL_PORT = tonumber(vmap["-LOCAL_PORT"]);
	if (LOCAL_PORT == null)
		LOCAL_PORT = 0;
	let REMOTE_PROXY_SERVER = vmap["-REMOTE_PROXY_SERVER"];
	let USE_DEFAULT_DNS = vmap["-USE_DEFAULT_DNS"];
	let REMOTE_DNS = vmap["-REMOTE_DNS"];
	let TUN_DNS = vmap["-TUN_DNS"];
	let DNS_MODE = vmap["-DNS_MODE"];
	let NODE = vmap["-NODE"];
	let USE_DIRECT_LIST = vmap["-USE_DIRECT_LIST"];
	let USE_PROXY_LIST = vmap["-USE_PROXY_LIST"];
	let USE_BLOCK_LIST = vmap["-USE_BLOCK_LIST"];
	let USE_GFW_LIST = vmap["-USE_GFW_LIST"];
	let CHN_LIST = vmap["-CHN_LIST"];
	let DEFAULT_PROXY_MODE = vmap["-DEFAULT_PROXY_MODE"];
	let NO_PROXY_IPV6 = vmap["-NO_PROXY_IPV6"];
	let NO_LOGIC_LOG = vmap["-NO_LOGIC_LOG"];
	let NFTFLAG = "1";
	let SUBNET = vmap["-SUBNET"];
	let LISTEN_PORT = vmap["-LISTEN_PORT"];
	let DNS_REDIRECT = vmap["-DNS_REDIRECT"] == "1";
	let LOG = vmap["-LOG"] == "1";
	let LOG_LEVEL = vmap["-LOG_LEVEL"] ?? "error";
	let LOG_SIZE = tonumber(vmap["-LOG_SIZE"]);
	if (LOG_SIZE == null)
		LOG_SIZE = 1;
	let UI = vmap["-UI"] == "1";
	let UI_PORT = tonumber(vmap["-UI_PORT"]);
	if (UI_PORT == null)
		UI_PORT = 9880;
	let UI_DATA_DIR = vmap["-UI_DATA_DIR"];
	let UI_LOG_MAX_AGE = tonumber(vmap["-UI_LOG_MAX_AGE"]);
	if (UI_LOG_MAX_AGE == null)
		UI_LOG_MAX_AGE = 7;

	let TMP_PATH = api.TMP_PATH;
	let RULES_PATH = "/usr/share/passwall/rules";
	let USER_RULES_PATH = "/etc/passwall/rules";
	let CACHE_RULES_PATH = api.CACHE_PATH + "/user_rules";
	let FLAG_PATH = TMP_PATH + "/acl/" + FLAG;
	let TMP_CONF_FILE = FLAG_PATH + "/smartdns.conf";
	let SMARTDNS_DATA_PATH = api.CACHE_PATH + "/smartdns";
	let config_lines = [];
	let tmp_lines = [];
	let USE_GEOVIEW = api.uci_get_c("@global_rules[0]", "enable_geoview");
	let IS_SHUNT_NODE = api.uci_get_c(NODE, "protocol") == "_shunt";

	if (!api.is_finded("geoview"))
		USE_GEOVIEW = "0";

	function log(...args) {
		if (NO_LOGIC_LOG == "1")
			return;
		api.log(...args);
	}

	api.fs.mkdirr(FLAG_PATH);
	api.fs.mkdirr(CACHE_RULES_PATH);
	api.fs.mkdirr(SMARTDNS_DATA_PATH);

	let LOG_LEVELS = { off: true, fatal: true, error: true, warn: true, notice: true, info: true, debug: true };
	if (!LOG_LEVELS[LOG_LEVEL])
		LOG_LEVEL = "error";
	if (LOG_SIZE < 1 || LOG_SIZE % 1 != 0)
		LOG_SIZE = 1;
	if (UI_PORT < 1 || UI_PORT > 65535 || UI_PORT % 1 != 0)
		UI_PORT = 9880;
	if (UI_LOG_MAX_AGE < 1 || UI_LOG_MAX_AGE % 1 != 0)
		UI_LOG_MAX_AGE = 7;
	if (UI_DATA_DIR == null || UI_DATA_DIR === false || UI_DATA_DIR == "")
		UI_DATA_DIR = SMARTDNS_DATA_PATH;
	let UI_PLUGIN = "/usr/lib/smartdns_ui.so";
	if (!api.fs.access(UI_PLUGIN))
		UI_PLUGIN = "/usr/lib/smartdns/smartdns_ui.so";
	let ENABLE_UI = UI && api.fs.access(UI_PLUGIN);
	let data_dir = ENABLE_UI ? UI_DATA_DIR : SMARTDNS_DATA_PATH;
	if (data_dir != SMARTDNS_DATA_PATH)
		api.fs.mkdirr(data_dir);

	let DIRECT_SERVERS = [];
	let direct_src = (DIRECT_DNS == null || DIRECT_DNS === false) ? "" : DIRECT_DNS;
	for (let endpoint in gmatch(direct_src, /[^|]+/g)) {
		let server_param = make_server_param(endpoint);
		if (server_param != null)
			push(DIRECT_SERVERS, server_param + " -set-mark 255");
	}
	if (length(DIRECT_SERVERS) == 0) {
		log("  * 注意：SmartDNS 没有可用的直连 DNS 服务器，DNS 将无法正常工作！！！");
		exit(1);
	}

	let AUTO_GROUP = "auto";
	let auto_config_lines = [];
	let DIRECT_RULE_OPTIONS = " -enable-cache -address -6 -speed-check-mode ping,tcp:80,tcp:443 -response-mode first-ping -d yes";
	let DEFAULT_DNS_GROUP = (USE_DEFAULT_DNS == "direct") ? "direct" : ((USE_DEFAULT_DNS == "remote") ? "proxy" : ((USE_DEFAULT_DNS == "auto") ? AUTO_GROUP : null));
	let only_global = (DEFAULT_PROXY_MODE == "proxy" && CHN_LIST == "0" && USE_GFW_LIST == "0") ? 1 : false;
	if (only_global == 1)
		DEFAULT_DNS_GROUP = "proxy";
	let AUTO_DIRECT_PORT = 0;
	if (DEFAULT_DNS_GROUP == AUTO_GROUP) {
		AUTO_DIRECT_PORT = api.get_new_port(15350);
		for (let n = 0; n < 2; n++) {
			if (AUTO_DIRECT_PORT == null || AUTO_DIRECT_PORT === false || (AUTO_DIRECT_PORT != tonumber(LISTEN_PORT) && AUTO_DIRECT_PORT != LOCAL_PORT))
				break;
			AUTO_DIRECT_PORT = api.get_new_port(AUTO_DIRECT_PORT + 1);
		}
	}
	let force_https_soa = api.uci_get_c("@global[0]", "force_https_soa");
	if (force_https_soa == null || force_https_soa === false)
		force_https_soa = 0;
	let force_qtype_soa = (tonumber(force_https_soa) == 1) ? "force-qtype-SOA 65" : "force-qtype-SOA -,65";
	let proxy_server_name = "psw-proxy-server";
	let listen_address = "[::]:" + LISTEN_PORT + (DNS_REDIRECT ? "" : "@lo");
	let local_domain = DNS_REDIRECT ? api.uci_get("dhcp", "@dnsmasq[0]", "domain") : null;
	let listen_n = tonumber(LISTEN_PORT);
	config_lines = [
		(listen_n != 0) ? ("bind " + listen_address) : "",
		(listen_n != 0) ? ("bind-tcp " + listen_address) : "",
		(LOCAL_PORT > 0) ? ("bind [::]:" + LOCAL_PORT + "@lo -group direct -no-rules") : "",
		(LOCAL_PORT > 0) ? ("bind-tcp [::]:" + LOCAL_PORT + "@lo -group direct -no-rules") : "",
		(AUTO_DIRECT_PORT > 0) ? ("bind [::]:" + AUTO_DIRECT_PORT + "@lo -group auto-direct") : "",
		"log-level " + LOG_LEVEL,
		"log-num " + (LOG ? "1" : "0"),
		LOG ? sprintf("log-file %s", lua_quote(FLAG_PATH + "/smartdns.log")) : "",
		LOG ? ("log-size " + LOG_SIZE + "M") : "",
		sprintf("cache-file %s", lua_quote(SMARTDNS_DATA_PATH + "/smartdns.cache")),
		sprintf("data-dir %s", lua_quote(data_dir)),
		"server 223.5.5.5 -bootstrap-dns -set-mark 255",
		(local_domain != null && local_domain !== false && local_domain != "") ? ("local-domain " + local_domain) : "",
		DNS_REDIRECT ? "hosts-file /tmp/hosts/*" : "",
		is_file_nonzero("/etc/hosts") ? "hosts-file /etc/hosts" : "",
		(DNS_MODE == "socks") ? sprintf("proxy-server socks5://%s -name %s", REMOTE_PROXY_SERVER, proxy_server_name) : ""
	];
	if (ENABLE_UI) {
		merge_array(config_lines, [
			"plugin " + UI_PLUGIN,
			"smartdns-ui.www-root /usr/share/smartdns/wwwroot",
			"smartdns-ui.ip http://[::]:" + UI_PORT,
			"smartdns-ui.max-query-log-age " + (UI_LOG_MAX_AGE * 86400)
		]);
	}
	if (DNS_REDIRECT) {
		let hosts = [];
		api.uci.foreach("dhcp", "host", (s) => {
			if (api.datatypes.hostname(s.name ?? "") && api.datatypes.ip4addr(s.ip ?? ""))
				push(hosts, s.ip + " " + s.name);
		});
		let hosts_file = FLAG_PATH + "/dhcp-static-hosts";
		let wrote = api.fs.writefile(hosts_file, join("\n", hosts) + "\n");
		if (ltruth(wrote) && length(hosts) > 0)
			push(config_lines, sprintf("hosts-file %s", lua_quote(hosts_file)));
		let lease_file = api.uci_get("dhcp", "@dnsmasq[0]", "leasefile");
		if (lease_file == null || lease_file === false || lease_file == "")
			lease_file = "/tmp/dhcp.leases";
		push(config_lines, sprintf("dnsmasq-lease-file %s", lua_quote(lease_file)));
		let odhcpd_lease = api.uci_get("dhcp", "odhcpd", "leasefile");
		if (ltruth(odhcpd_lease) && odhcpd_lease != "")
			push(config_lines, sprintf("odhcpd-lease-file %s", lua_quote(odhcpd_lease)));
	}
	for (let server_param in DIRECT_SERVERS)
		push(config_lines, server_param + " -group direct -exclude-default-group");
	if (DEFAULT_DNS_GROUP == AUTO_GROUP) {
		push(auto_config_lines, "server 127.0.0.1:" + AUTO_DIRECT_PORT + " -group " + AUTO_GROUP + " -exclude-default-group -whitelist-ip");
		push(auto_config_lines, "group-begin auto-direct -inherit none");
		merge_array(auto_config_lines, DIRECT_SERVERS);
		merge_array(auto_config_lines, ["force-no-CNAME yes", "group-end"]);
	}

	function add_remote_server(server_param) {
		push(config_lines, server_param + " -group proxy -exclude-default-group");
		if (DEFAULT_DNS_GROUP == AUTO_GROUP) {
			let auto_param = server_param + " -group " + AUTO_GROUP + " -exclude-default-group -fallback";
			if (NO_PROXY_IPV6 == "1")
				auto_param = auto_param + " -blacklist-ip";
			push(auto_config_lines, auto_param);
		}
	}

	if (DNS_MODE == "socks") {
		for (let w in gmatch(REMOTE_DNS, /[^|]+/g)) {
			let server_param = make_server_param(w);
			if (!api.is_local_ip(w))
				server_param = server_param + " -proxy " + proxy_server_name;
			if (ltruth(SUBNET) && SUBNET != "" && SUBNET != "0")
				server_param = server_param + " -subnet " + SUBNET;
			add_remote_server(server_param);
		}
	} else {
		add_remote_server("server " + replace(TUN_DNS, "#", ":"));
		log("  - " + ucfirst(DNS_MODE) + " " + TUN_DNS + " -> 分组(proxy)");
	}

	if (DEFAULT_DNS_GROUP == AUTO_GROUP) {
		if (NO_PROXY_IPV6 == "1")
			push(auto_config_lines, "ip-rules ::/0 -blacklist-ip");
		for (let name in ["chnroute", "chnroute6"]) {
			let path = RULES_PATH + "/" + name;
			if (is_file_nonzero(path)) {
				let set_name = AUTO_GROUP + "-" + name;
				push(auto_config_lines, sprintf("ip-set -name %s -file %s", set_name, path));
				let ip_rules = "ip-rules ip-set:" + set_name + " -whitelist-ip";
				if (name == "chnroute6" && NO_PROXY_IPV6 == "1")
					ip_rules = ip_rules + " -blacklist-ip";
				push(auto_config_lines, ip_rules);
			} else {
				log("  * 注意：SmartDNS 自动模式大陆 IP 列表不存在或为空：" + path);
			}
		}
		merge_array(config_lines, auto_config_lines);
	}

	push(config_lines, force_qtype_soa);

	if (ltruth(DEFAULT_DNS_GROUP)) {
		let domain_rules_str = "domain-rules /./ -nameserver " + DEFAULT_DNS_GROUP;
		if (DEFAULT_DNS_GROUP == "proxy") {
			domain_rules_str = domain_rules_str + " -no-cache -speed-check-mode none -d no";
			let addr = "-6";
			if (!(only_global && IS_SHUNT_NODE))
				addr = (NO_PROXY_IPV6 == "1") ? "#6" : "-6";
			domain_rules_str = domain_rules_str + " -address " + addr;
		}
		push(config_lines, domain_rules_str);
	}

	let setflag = (NFTFLAG == "1") ? "inet#passwall#" : "";
	let set_type = "-nftset";

	for (let i = 1; i <= 10; i++)
		push(config_lines, "#--" + i);

	let file_block_host = CACHE_RULES_PATH + "/block_host";
	if (!api.fs.access(file_block_host + "_ok"))
		api.remove(file_block_host + "*");
	let block_geosite_flag = api.fs.access(file_block_host) && api.fs.access(file_block_host + "_ok") && api.fs.access(file_block_host + "_geo");
	if (USE_BLOCK_LIST == "1" && !api.fs.access(file_block_host)) {
		let block_domain = [];
		let lookup_block_domain = {};
		let geosite_arg = "";
		let lines = read_lines(USER_RULES_PATH + "/block_host");
		if (lines != null) {
			for (let line in lines) {
				if (index(line, "#") < 0 && index(line, "geosite:") >= 0) {
					let tag = tail_after_colon(line);
					if (tag != null)
						geosite_arg = geosite_arg + (geosite_arg != "" ? "," : "") + tag;
				} else {
					line = api.get_std_domain(line);
					if (line != "" && index(line, "#") < 0)
						insert_unique(block_domain, line, lookup_block_domain);
				}
			}
		}
		if (length(block_domain) > 0)
			write_lines(file_block_host, block_domain);
		let success = true;
		if (USE_GEOVIEW == "1" && geosite_arg != "") {
			let result = get_geosite(geosite_arg, file_block_host);
			if (result[0] == 0) {
				log("  - 解析[屏蔽列表] Geosite 到屏蔽域名表(blocklist)完成");
				api.sys.call("touch " + file_block_host + "_geo");
			} else {
				log("  - 解析[屏蔽列表] Geosite 到屏蔽域名表(blocklist)失败！[" + result[1] + "]");
				success = false;
			}
		}
		if (success && api.fs.access(file_block_host))
			api.sys.call("touch " + file_block_host + "_ok");
	}
	if (USE_BLOCK_LIST == "1" && is_file_nonzero(file_block_host)) {
		if (block_geosite_flag)
			log("  - [屏蔽列表] Geosite 使用缓存结果，跳过重复解析");
		let domain_set_name = "psw-block";
		tmp_lines = [
			sprintf("domain-set -name %s -file %s", domain_set_name, file_block_host),
			sprintf("domain-rules /domain-set:%s/ -a #", domain_set_name)
		];
		insert_array_after(config_lines, tmp_lines, "#--8");
	}

	let file_vpslist = TMP_PATH + "/vpslist";
	if (!is_file_nonzero(file_vpslist)) {
		let written = {};
		let lines = [];
		function process_address(address) {
			address = lc(address ?? "");
			if (api.vps_domain_exclude(address))
				return;
			if (api.datatypes.hostname(address) && !written[address]) {
				push(lines, address);
				written[address] = true;
			}
		}
		api.uci_foreach_c("nodes", (t) => {
			process_address(t.address);
			process_address(t.download_address);
		});
		write_lines(file_vpslist, lines);
	}
	if (is_file_nonzero(file_vpslist)) {
		let domain_set_name = "psw-vpslist";
		tmp_lines = [sprintf("domain-set -name %s -file %s", domain_set_name, file_vpslist)];
		let sets = [
			"#4:" + setflag + "psw_vps",
			"#6:" + setflag + "psw_vps6"
		];
		let domain_rules_str = sprintf("domain-rules /domain-set:%s/ -nameserver direct", domain_set_name) + DIRECT_RULE_OPTIONS;
		domain_rules_str = domain_rules_str + " -rr-ttl-max 30 -no-serve-expired";
		domain_rules_str = domain_rules_str + " " + set_type + " " + join(",", sets);
		push(tmp_lines, domain_rules_str);
		insert_array_after(config_lines, tmp_lines, "#--9");
		log("  - 节点列表中的域名(vpslist)使用分组：direct");
	}

	let file_direct_host = CACHE_RULES_PATH + "/direct_host";
	if (!api.fs.access(file_direct_host + "_ok"))
		api.remove(file_direct_host + "*");
	let direct_geosite_flag = api.fs.access(file_direct_host) && api.fs.access(file_direct_host + "_ok") && api.fs.access(file_direct_host + "_geo");
	if (USE_DIRECT_LIST == "1" && !api.fs.access(file_direct_host)) {
		let direct_domain = [];
		let lookup_direct_domain = {};
		let geosite_arg = "";
		let lines = read_lines(USER_RULES_PATH + "/direct_host");
		if (lines != null) {
			for (let line in lines) {
				if (index(line, "#") < 0 && index(line, "geosite:") >= 0) {
					let tag = tail_after_colon(line);
					if (tag != null)
						geosite_arg = geosite_arg + (geosite_arg != "" ? "," : "") + tag;
				} else {
					line = api.get_std_domain(line);
					if (line != "" && index(line, "#") < 0 && index(line, ":") < 0)
						insert_unique(direct_domain, line, lookup_direct_domain);
				}
			}
		}
		if (length(direct_domain) > 0)
			write_lines(file_direct_host, direct_domain);
		let success = true;
		if (USE_GEOVIEW == "1" && geosite_arg != "") {
			let result = get_geosite(geosite_arg, file_direct_host);
			if (result[0] == 0) {
				log("  - 解析[直连列表] Geosite 到域名白名单(whitelist)完成");
				api.sys.call("touch " + file_direct_host + "_geo");
			} else {
				log("  - 解析[直连列表] Geosite 到域名白名单(whitelist)失败！[" + result[1] + "]");
				success = false;
			}
		}
		if (success && api.fs.access(file_direct_host))
			api.sys.call("touch " + file_direct_host + "_ok");
	}
	if (USE_DIRECT_LIST == "1" && is_file_nonzero(file_direct_host)) {
		if (direct_geosite_flag)
			log("  - [直连列表] Geosite 使用缓存结果，跳过重复解析");
		let domain_set_name = "psw-directlist";
		tmp_lines = [sprintf("domain-set -name %s -file %s", domain_set_name, file_direct_host)];
		let sets = [
			"#4:" + setflag + "psw_white",
			"#6:" + setflag + "psw_white6"
		];
		let domain_rules_str = sprintf("domain-rules /domain-set:%s/ -nameserver direct", domain_set_name) + DIRECT_RULE_OPTIONS;
		domain_rules_str = domain_rules_str + " " + set_type + " " + join(",", sets);
		push(tmp_lines, domain_rules_str);
		insert_array_after(config_lines, tmp_lines, "#--7");
		log("  - 域名白名单(whitelist)使用分组：direct");
	}

	let file_proxy_host = CACHE_RULES_PATH + "/proxy_host";
	if (!api.fs.access(file_proxy_host + "_ok"))
		api.remove(file_proxy_host + "*");
	let proxy_geosite_flag = api.fs.access(file_proxy_host) && api.fs.access(file_proxy_host + "_ok") && api.fs.access(file_proxy_host + "_geo");
	if (USE_PROXY_LIST == "1" && !api.fs.access(file_proxy_host)) {
		let proxy_domain = [];
		let lookup_proxy_domain = {};
		let geosite_arg = "";
		let lines = read_lines(USER_RULES_PATH + "/proxy_host");
		if (lines != null) {
			for (let line in lines) {
				if (index(line, "#") < 0 && index(line, "geosite:") >= 0) {
					let tag = tail_after_colon(line);
					if (tag != null)
						geosite_arg = geosite_arg + (geosite_arg != "" ? "," : "") + tag;
				} else {
					line = api.get_std_domain(line);
					if (line != "" && index(line, "#") < 0 && index(line, ":") < 0)
						insert_unique(proxy_domain, line, lookup_proxy_domain);
				}
			}
		}
		if (length(proxy_domain) > 0)
			write_lines(file_proxy_host, proxy_domain);
		let success = true;
		if (USE_GEOVIEW == "1" && geosite_arg != "") {
			let result = get_geosite(geosite_arg, file_proxy_host);
			if (result[0] == 0) {
				log("  - 解析[代理列表] Geosite 到代理域名表(blacklist)完成");
				api.sys.call("touch " + file_proxy_host + "_geo");
			} else {
				log("  - 解析[代理列表] Geosite 到代理域名表(blacklist)失败！[" + result[1] + "]");
				success = false;
			}
		}
		if (success && api.fs.access(file_proxy_host))
			api.sys.call("touch " + file_proxy_host + "_ok");
	}
	if (USE_PROXY_LIST == "1" && is_file_nonzero(file_proxy_host)) {
		if (proxy_geosite_flag)
			log("  - [代理列表] Geosite 使用缓存结果，跳过重复解析");
		let domain_set_name = "psw-proxylist";
		tmp_lines = [sprintf("domain-set -name %s -file %s", domain_set_name, file_proxy_host)];
		let domain_rules_str = sprintf("domain-rules /domain-set:%s/ -nameserver proxy", domain_set_name);
		domain_rules_str = domain_rules_str + " -no-cache -speed-check-mode none -d no";
		let sets = ["#4:" + setflag + "psw_black"];
		if (NO_PROXY_IPV6 == "1")
			domain_rules_str = domain_rules_str + " -address #6 " + set_type + " " + join(",", sets);
		else {
			push(sets, "#6:" + setflag + "psw_black6");
			domain_rules_str = domain_rules_str + " -address -6 " + set_type + " " + join(",", sets);
		}
		push(tmp_lines, domain_rules_str);
		insert_array_after(config_lines, tmp_lines, "#--6");
		log("  - 代理域名表(blacklist)使用分组：proxy");
	}

	if (USE_GFW_LIST == "1" && is_file_nonzero(RULES_PATH + "/gfwlist")) {
		let domain_set_name = "psw-gfwlist";
		tmp_lines = [sprintf("domain-set -name %s -file %s", domain_set_name, RULES_PATH + "/gfwlist")];
		let domain_rules_str = sprintf("domain-rules /domain-set:%s/ -nameserver proxy", domain_set_name);
		domain_rules_str = domain_rules_str + " -no-cache -speed-check-mode none -d no";
		let sets = ["#4:" + setflag + "psw_gfw"];
		if (NO_PROXY_IPV6 == "1")
			domain_rules_str = domain_rules_str + " -address #6 " + set_type + " " + join(",", sets);
		else {
			push(sets, "#6:" + setflag + "psw_gfw6");
			domain_rules_str = domain_rules_str + " -address -6 " + set_type + " " + join(",", sets);
		}
		push(tmp_lines, domain_rules_str);
		insert_array_after(config_lines, tmp_lines, "#--5");
		log("  - 防火墙域名表(gfwlist)使用分组：proxy");
	}

	if (CHN_LIST != "0" && is_file_nonzero(RULES_PATH + "/chnlist")) {
		let domain_set_name = "psw-chnlist";
		tmp_lines = [sprintf("domain-set -name %s -file %s", domain_set_name, RULES_PATH + "/chnlist")];
		if (CHN_LIST == "direct") {
			let sets = [
				"#4:" + setflag + "psw_chn",
				"#6:" + setflag + "psw_chn6"
			];
			let domain_rules_str = sprintf("domain-rules /domain-set:%s/ -nameserver direct", domain_set_name) + DIRECT_RULE_OPTIONS;
			domain_rules_str = domain_rules_str + " " + set_type + " " + join(",", sets);
			push(tmp_lines, domain_rules_str);
			insert_array_after(config_lines, tmp_lines, "#--4");
			log("  - 中国域名表(chnlist)使用分组：direct");
		}
		if (CHN_LIST == "proxy") {
			tmp_lines = [sprintf("domain-set -name %s -file %s", domain_set_name, RULES_PATH + "/chnlist")];
			let domain_rules_str = sprintf("domain-rules /domain-set:%s/ -nameserver proxy", domain_set_name);
			domain_rules_str = domain_rules_str + " -no-cache -speed-check-mode none -d no";
			let sets = ["#4:" + setflag + "psw_chn"];
			if (NO_PROXY_IPV6 == "1")
				domain_rules_str = domain_rules_str + " -address #6 " + set_type + " " + join(",", sets);
			else {
				push(sets, "#6:" + setflag + "psw_chn6");
				domain_rules_str = domain_rules_str + " -address -6 " + set_type + " " + join(",", sets);
			}
			push(tmp_lines, domain_rules_str);
			insert_array_after(config_lines, tmp_lines, "#--4");
			log("  - 中国域名表(chnlist)使用分组：proxy");
		}
	}

	if (IS_SHUNT_NODE && !only_global) {
		let direct_domain = [];
		let lookup_direct_domain = {};
		let proxy_domain = [];
		let lookup_proxy_domain = {};
		let black_domain = [];
		let lookup_black_domain = {};
		let CACHE_FLAG_PATH = CACHE_RULES_PATH + "/" + FLAG;
		let shunt_direct_host = CACHE_FLAG_PATH + "/shunt_direct_host";
		let shunt_proxy_host = CACHE_FLAG_PATH + "/shunt_proxy_host";
		let shunt_black_host = CACHE_FLAG_PATH + "/shunt_black_host";
		let geosite_direct_arg = "";
		let geosite_proxy_arg = "";
		let geosite_black_arg = "";
		let SHUNT_LIST = "";

		let t = api.uci_get_c(NODE);
		let default_node_id = t["default_node"];
		if (default_node_id == null || default_node_id === false)
			default_node_id = "_direct";
		api.uci_foreach_c("shunt_rules", (s) => {
			let _node_id = t[s[".name"]];
			if (ltruth(_node_id) && t["shunt_group"] == s.group) {
				if (_node_id == "_default")
					_node_id = default_node_id;
				let domain_list = s.domain_list;
				if (domain_list == null || domain_list === false)
					domain_list = "";
				for (let line in gmatch(domain_list, /[^\r\n]+/g)) {
					if (line != "" && index(line, "#") < 0 && index(line, "regexp:") < 0 && index(line, "ext:") < 0 && index(line, "rule-set:") < 0 && index(line, "rs:") < 0) {
						if (index(line, "geosite:") >= 0) {
							let tag = tail_after_colon(line);
							if (tag != null) {
								if (_node_id == "_direct")
									geosite_direct_arg = geosite_direct_arg + (geosite_direct_arg != "" ? "," : "") + tag;
								else if (_node_id == "_blackhole")
									geosite_black_arg = geosite_black_arg + (geosite_black_arg != "" ? "," : "") + tag;
								else
									geosite_proxy_arg = geosite_proxy_arg + (geosite_proxy_arg != "" ? "," : "") + tag;
							}
						} else {
							if (index(line, "domain:") >= 0 || index(line, "full:") >= 0) {
								let tag = tail_after_colon(line);
								if (tag != null)
									line = tag;
							}
							line = api.get_std_domain(line);
							if (line != "" && index(line, "#") < 0) {
								if (_node_id == "_direct")
									insert_unique(direct_domain, line, lookup_direct_domain);
								else if (_node_id == "_blackhole")
									insert_unique(black_domain, line, lookup_black_domain);
								else
									insert_unique(proxy_domain, line, lookup_proxy_domain);
							}
						}
					}
				}
				let node_tag = (substr(_node_id, 0, 1) == "_") ? "not-node" : "node";
				SHUNT_LIST = SHUNT_LIST + domain_list + node_tag;
				if (_node_id != "_direct" && _node_id != "_blackhole")
					log(sprintf("  - Sing-Box/Xray分流规则(%s)使用分组：proxy", s.remarks));
			}
		});

		let MD5_FILE = CACHE_FLAG_PATH + "/md5.txt";
		let cache_md5 = "";
		let USE_CACHE = true;
		if (api.fs.access(MD5_FILE)) {
			let raw = api.fs.readfile(MD5_FILE);
			if (raw != null)
				cache_md5 = raw;
		}
		let new_md5 = api.md5_string(SHUNT_LIST);
		if (cache_md5 == "" || new_md5 == "" || cache_md5 != new_md5) {
			api.remove(CACHE_FLAG_PATH);
			api.fs.mkdirr(CACHE_FLAG_PATH);
			api.fs.writefile(MD5_FILE, new_md5);
			USE_CACHE = false;
		}
		if (!is_file_nonzero(shunt_direct_host) && length(direct_domain) > 0)
			write_lines(shunt_direct_host, direct_domain);
		if (!is_file_nonzero(shunt_proxy_host) && length(proxy_domain) > 0)
			write_lines(shunt_proxy_host, proxy_domain);
		if (!is_file_nonzero(shunt_black_host) && length(black_domain) > 0)
			write_lines(shunt_black_host, black_domain);

		if (!USE_CACHE && USE_GEOVIEW == "1") {
			let ok = true;
			function resolve(arg, dest) {
				if (arg == "")
					return;
				let result = get_geosite(arg, dest);
				if (result[0] != 0) {
					ok = false;
					log("  - 解析[分流节点] Geosite 失败！[" + result[1] + "]");
				}
			}
			resolve(geosite_direct_arg, shunt_direct_host);
			resolve(geosite_proxy_arg, shunt_proxy_host);
			resolve(geosite_black_arg, shunt_black_host);
			if (ok)
				log("  - 解析[分流节点] Geosite 完成");
			else
				api.remove(MD5_FILE);
		}
		if (USE_CACHE && USE_GEOVIEW == "1" && (geosite_direct_arg != "" || geosite_proxy_arg != "" || geosite_black_arg != ""))
			log("  - [分流节点] Geosite 使用缓存结果，跳过重复解析");

		function shunt_rules(domain_set_name, host_file, marker) {
			tmp_lines = [sprintf("domain-set -name %s -file %s", domain_set_name, host_file)];
			let domain_rules_str = sprintf("domain-rules /domain-set:%s/ -nameserver proxy", domain_set_name);
			domain_rules_str = domain_rules_str + " -no-cache -speed-check-mode none -d no";
			let sets = [
				"#4:" + setflag + "psw_shunt",
				"#6:" + setflag + "psw_shunt6"
			];
			domain_rules_str = domain_rules_str + " -address -6 " + set_type + " " + join(",", sets);
			push(tmp_lines, domain_rules_str);
			insert_array_after(config_lines, tmp_lines, marker);
		}
		if (is_file_nonzero(shunt_direct_host))
			shunt_rules("psw-shunt-direct", shunt_direct_host, "#--1");
		if (is_file_nonzero(shunt_proxy_host))
			shunt_rules("psw-shunt-proxy", shunt_proxy_host, "#--2");
		if (is_file_nonzero(shunt_black_host))
			shunt_rules("psw-shunt-black", shunt_black_host, "#--3");
	}

	if (length(config_lines) > 0) {
		let out = [];
		for (let line in config_lines) {
			if (line != "" && match(line, /^#--/) == null)
				push(out, line);
		}
		write_lines(TMP_CONF_FILE, out);
	}

	if (ltruth(DEFAULT_DNS_GROUP))
		log(sprintf("  - 默认 DNS 分组：%s", (DEFAULT_DNS_GROUP == AUTO_GROUP) ? "自动" : DEFAULT_DNS_GROUP));

	if (DNS_REDIRECT)
		log("  - DNS 重定向直接使用 SmartDNS，DHCP 租约由 SmartDNS 自动加载。");
	else
		log("  - SmartDNS已作为Dnsmasq上游，如果你自行配置了错误的DNS流程，将会导致域名(直连/代理)分流失效！！！");
};
export { main };
