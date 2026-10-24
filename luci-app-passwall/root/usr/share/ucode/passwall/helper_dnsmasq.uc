'use strict';

import * as api from 'passwall.api';
import * as fs from 'fs';
import { truth as ltruth, lua_quote, gmatch, lines_of, quoted_option_blob } from 'passwall.text';
let exec_pair, read_lines, file_size, tinsert, backup_servers, restore_servers, stretch, restart, logic_restart, copy_instance, geosite_dat, foreach_geosite, tail_after_colon, add_rule, dispatch, main;

let seen_pairs = [];

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

file_size = function(path) {
	let st = api.fs.stat(path, "size");
	if (st == null)
		return null;
	if (type(st) == "object")
		return st.size ?? null;
	return st;
};

tinsert = function(table_name, val) {
	if (table_name == null || type(table_name) != "array")
		return false;
	let lookup = null;
	for (let pair in seen_pairs) {
		if (pair[0] === table_name) {
			lookup = pair[1];
			break;
		}
	}
	if (lookup == null) {
		lookup = {};
		push(seen_pairs, [table_name, lookup]);
	}
	if (lookup[val])
		return false;
	push(table_name, val);
	lookup[val] = true;
	return true;
};

backup_servers = function() {
	let DNSMASQ_DNS = api.uci_get("dhcp", "@dnsmasq[0]", "server");
	if (type(DNSMASQ_DNS) == "array" && length(DNSMASQ_DNS) > 0) {
		api.uci_set_c("@global[0]", "dnsmasq_servers", DNSMASQ_DNS);
		api.uci_save_c(true);
	}
};

restore_servers = function() {
	let dns_table = [];
	let DNSMASQ_DNS = api.uci_get("dhcp", "@dnsmasq[0]", "server");
	if (type(DNSMASQ_DNS) == "array" && length(DNSMASQ_DNS) > 0) {
		for (let v in DNSMASQ_DNS)
			tinsert(dns_table, v);
	}
	let OLD_SERVER = api.uci_get(api.c_config, "@global[0]", "dnsmasq_servers");
	if (type(OLD_SERVER) == "array" && length(OLD_SERVER) > 0) {
		for (let v in OLD_SERVER)
			tinsert(dns_table, v);
		api.uci_del_c("@global[0]", "dnsmasq_servers");
		api.uci_save_c(true);
	}
	if (length(dns_table) > 0) {
		api.uci_set("dhcp", "@dnsmasq[0]", "server", dns_table);
		api.uci_save(null, "dhcp", true);
	}
};

stretch = function() {
	let dnsmasq_server = api.uci_get("dhcp", "@dnsmasq[0]", "server");
	let dnsmasq_noresolv = api.uci_get("dhcp", "@dnsmasq[0]", "noresolv");
	let flag = false;
	if (type(dnsmasq_server) == "array" && length(dnsmasq_server) > 0) {
		for (let v in dnsmasq_server) {
			if (index(v, "/") < 0)
				flag = true;
		}
	}
	if (!flag && dnsmasq_noresolv == "1") {
		api.uci_del("dhcp", "@dnsmasq[0]", "noresolv");
		let RESOLVFILE = "/tmp/resolv.conf.d/resolv.conf.auto";
		let size = file_size(RESOLVFILE);
		if (size == null || size == 0)
			RESOLVFILE = "/tmp/resolv.conf.auto";
		api.uci_set("dhcp", "@dnsmasq[0]", "resolvfile", RESOLVFILE);
		api.uci_save(null, "dhcp", true);
	}
};

restart = function(var) {
	let LOG = var["-LOG"];
	api.sys.call("/etc/init.d/dnsmasq restart >/dev/null 2>&1");
	if (LOG == "1")
		api.log("重启 dnsmasq 服务");
};

logic_restart = function(var) {
	let LOG = var["-LOG"];
	let DEFAULT_DNS = api.get_cache_var("DEFAULT_DNS");
	if (ltruth(DEFAULT_DNS)) {
		backup_servers();
		let dns_table = [];
		let dnsmasq_server = api.uci_get("dhcp", "@dnsmasq[0]", "server");
		if (type(dnsmasq_server) == "array" && length(dnsmasq_server) > 0) {
			for (let v in dnsmasq_server) {
				if (index(v, "/") >= 0)
					tinsert(dns_table, v);
			}
			api.uci_set("dhcp", "@dnsmasq[0]", "server", dns_table);
			api.uci_save(null, "dhcp", true);
		}
		api.sys.call("/etc/init.d/dnsmasq restart >/dev/null 2>&1");
		restore_servers();
	} else {
		api.sys.call("/etc/init.d/dnsmasq restart >/dev/null 2>&1");
	}
	if (LOG == "1")
		api.log("重启 dnsmasq 服务");
};

copy_instance = function(var) {
	let LISTEN_PORT = var["-LISTEN_PORT"];
	let TMP_DNSMASQ_PATH = var["-TMP_DNSMASQ_PATH"];
	let conf_lines = [];
	let DEFAULT_DNSMASQ_CFGID = "";
	api.uci.foreach("dhcp", "dnsmasq", function(section) {
		if (DEFAULT_DNSMASQ_CFGID == "")
			DEFAULT_DNSMASQ_CFGID = section[".name"] ?? "";
	});
	let conf_file = "/var/etc/dnsmasq.conf." + DEFAULT_DNSMASQ_CFGID;

	let retry = 5;
	while (!api.fs.access(conf_file) && retry > 0) {
		sleep(1000);
		retry = retry - 1;
	}

	if (api.fs.access(conf_file)) {
		let lines = read_lines(conf_file) ?? [];
		for (let line in lines) {
			let filter = false;
			if (index(line, "passwall") >= 0)
				filter = true;
			if (index(line, "ubus") >= 0)
				filter = true;
			if (index(line, "dhcp") >= 0)
				filter = true;
			if (index(line, "server=") == 0)
				filter = true;
			if (index(line, "port=") == 0)
				filter = true;
			if (index(line, "min-cache-ttl") == 0)
				filter = true;
			if (index(line, "conf-dir=") == 0) {
				filter = true;
				if (ltruth(TMP_DNSMASQ_PATH)) {
					let tmp_path = substr(line, length("conf-dir="));
					api.sys.call(sprintf("cp -r %s/* %s/ 2>/dev/null", tmp_path, TMP_DNSMASQ_PATH));
				}
			}
			if (index(line, "address=") == 0 || (index(line, "server=") == 0 && index(line, "/") >= 0))
				filter = false;
			if (!filter)
				tinsert(conf_lines, line);
		}
	} else {
		api.sys.call("logger -t passwall 'ERROR: dnsmasq config " + conf_file + " not found after 5s wait! DNS hijacking will fail.'");
	}

	tinsert(conf_lines, "port=" + LISTEN_PORT);
	if (ltruth(TMP_DNSMASQ_PATH))
		api.remove(TMP_DNSMASQ_PATH + "/*passwall*");
	if (var["-return"] == "1")
		return conf_lines;
	if (length(conf_lines) > 0) {
		let DNSMASQ_CONF = var["-DNSMASQ_CONF"];
		api.fs.writefile(DNSMASQ_CONF, join("\n", conf_lines) + "\n");
	}
	return null;
};

geosite_dat = function() {
	let geosite_path = api.uci_get_c("@global_rules[0]", "v2ray_location_asset");
	if (geosite_path == null || geosite_path === false)
		geosite_path = "/usr/share/v2ray/";
	let m = match(geosite_path, /^(.*)\//);
	return (m != null ? m[1] : geosite_path) + "/geosite.dat";
};

foreach_geosite = function(list_arg, callback) {
	let geosite_path = geosite_dat();
	if (!api.fs.access(geosite_path))
		return [1, "File geosite.dat not found"];
	if (list_arg == null || list_arg === false || list_arg == "")
		return [1, "Site list cannot be empty"];
	let bin = api.finded_com("geoview");
	let cmd = sprintf("%s -type geosite -action extract -input %s -list %s -lowmem=true",
		lua_quote(bin), lua_quote(geosite_path), lua_quote(list_arg));
	let pair = exec_pair(cmd);
	if (pair[0] != 0)
		return [pair[0], pair[1]];
	let lines = match(pair[1] ?? "", /[^\r\n]+/g);
	if (lines != null) {
		for (let m in lines)
			callback(m[0]);
	}
	return [0, null];
};

tail_after_colon = function(line) {
	let m = match(line, /:([^:]+)$/);
	if (m == null)
		return null;
	return m[1];
};

add_rule = function(var) {
	let FLAG = var["-FLAG"];
	let TMP_DNSMASQ_PATH = var["-TMP_DNSMASQ_PATH"];
	let DNSMASQ_CONF_FILE = var["-DNSMASQ_CONF_FILE"];
	let LISTEN_PORT = var["-LISTEN_PORT"];
	let DEFAULT_DNS = var["-DEFAULT_DNS"];
	let LOCAL_DNS = var["-LOCAL_DNS"];
	let TUN_DNS = var["-TUN_DNS"];
	let USE_DEFAULT_DNS = var["-USE_DEFAULT_DNS"];
	let CHINADNS_DNS = var["-CHINADNS_DNS"];
	let NODE = var["-NODE"];
	let USE_DIRECT_LIST = var["-USE_DIRECT_LIST"];
	let USE_PROXY_LIST = var["-USE_PROXY_LIST"];
	let USE_BLOCK_LIST = var["-USE_BLOCK_LIST"];
	let USE_GFW_LIST = var["-USE_GFW_LIST"];
	let CHN_LIST = var["-CHN_LIST"];
	let DEFAULT_PROXY_MODE = var["-DEFAULT_PROXY_MODE"];
	let NO_PROXY_IPV6 = var["-NO_PROXY_IPV6"];
	let NO_LOGIC_LOG = var["-NO_LOGIC_LOG"];
	let NFTFLAG = "1";
	let CACHE_PATH = api.CACHE_PATH;
	let CACHE_FLAG = "dnsmasq_" + FLAG;
	let CACHE_DNS_PATH = CACHE_PATH + "/" + CACHE_FLAG;
	let CACHE_TEXT_FILE = CACHE_DNS_PATH + ".txt";
	let USE_CHINADNS_NG = "0";
	let IS_SHUNT_NODE = api.uci_get_c(NODE, "protocol") == "_shunt";
	let USE_GEOVIEW = api.uci_get_c("@global_rules[0]", "enable_geoview");

	let list1 = {};
	let excluded_domain = {};

	if (!api.is_finded("geoview"))
		USE_GEOVIEW = "0";

	function log(...args) {
		if (NO_LOGIC_LOG == "1")
			return;
		api.log(...args);
	}

	function bad_domain(domain) {
		return domain == "" || (type(domain) == "string" && index(domain, "#") >= 0);
	}

	function check_dns(domain, dns) {
		if (bad_domain(domain))
			return false;
		if (dns == null || dns === false)
			return null;
		for (let v in list1[domain].dns) {
			if (dns == v)
				return true;
		}
		return false;
	}

	function check_ipset(domain, ipset) {
		if (bad_domain(domain))
			return false;
		if (ipset == null || ipset === false)
			return null;
		for (let v in list1[domain].ipsets) {
			if (ipset == v)
				return true;
		}
		return false;
	}

	function ensure_domain(domain) {
		if (list1[domain] == null) {
			list1[domain] = {
				dns: [],
				ipsets: []
			};
		}
	}

	function set_domain_address(domain, address) {
		if (bad_domain(domain))
			return;
		ensure_domain(domain);
		if (list1[domain].address == null)
			list1[domain].address = address;
	}

	function set_domain_dns(domain, dns) {
		if (bad_domain(domain))
			return;
		if (dns == null || dns === false)
			return;
		ensure_domain(domain);
		for (let line in gmatch(dns, /[^,]+/g)) {
			if (!check_dns(domain, line))
				push(list1[domain].dns, line);
		}
	}

	function set_domain_ipset(domain, ipset) {
		if (bad_domain(domain))
			return;
		if (ipset == null || ipset === false)
			return;
		ensure_domain(domain);
		for (let line in gmatch(ipset, /[^,]+/g)) {
			if (!check_ipset(domain, line))
				push(list1[domain].ipsets, line);
		}
	}

	function add_excluded_domain(domain) {
		if (bad_domain(domain))
			return;
		excluded_domain[domain] = true;
	}

	function check_excluded_domain(domain) {
		if (bad_domain(domain))
			return false;
		if (excluded_domain[domain])
			return true;
		let pos = index(domain, ".");
		while (pos >= 0) {
			if (excluded_domain[substr(domain, pos + 1)])
				return true;
			let rest = substr(domain, pos + 1);
			let rel = index(rest, ".");
			pos = rel < 0 ? -1 : rel + pos + 1;
		}
		return false;
	}

	function get_dns_config_key() {
		let address_md5 = api.md5_string(quoted_option_blob(api.uci_show("passwall")));
		let new_rules = "";
		let rule_files = [
			"/usr/share/passwall/rules/chnlist",
			"/usr/share/passwall/rules/gfwlist",
			"/etc/passwall/rules/direct_host",
			"/etc/passwall/rules/proxy_host",
			"/etc/passwall/rules/block_host"
		];
		for (let rule_file in rule_files) {
			if (api.fs.stat(rule_file, "type") == "reg")
				new_rules += api.md5_file(rule_file);
		}
		let SHUNT_LIST = "";
		if (IS_SHUNT_NODE) {
			let t = api.uci_get_c(NODE);
			api.uci_foreach_c("shunt_rules", (s) => {
				let _node_id = t[s[".name"]];
				if (ltruth(_node_id) && t["shunt_group"] == s.group) {
					let node_tag = (substr(_node_id, 0, 1) == "_") ? "not-node" : "node";
					let domain_list = s.domain_list;
					if (domain_list == null || domain_list === false)
						domain_list = "";
					SHUNT_LIST = SHUNT_LIST + domain_list + node_tag;
				}
			});
		}
		new_rules = new_rules + api.md5_string(SHUNT_LIST);
		return "" + TMP_DNSMASQ_PATH + DNSMASQ_CONF_FILE + DEFAULT_DNS + LOCAL_DNS + TUN_DNS + USE_DEFAULT_DNS + CHINADNS_DNS + USE_DIRECT_LIST + USE_PROXY_LIST + USE_BLOCK_LIST + USE_GFW_LIST + CHN_LIST + DEFAULT_PROXY_MODE + NO_PROXY_IPV6 + address_md5 + new_rules + NFTFLAG;
	}

	function collect_geosite(path, on_plain) {
		let geosite_arg = "";
		let lines = read_lines(path);
		if (lines != null) {
			for (let line in lines) {
				if (index(line, "#") < 0 && index(line, "geosite:") >= 0) {
					let tag = tail_after_colon(line);
					if (tag != null)
						geosite_arg = geosite_arg + (geosite_arg != "" ? "," : "") + tag;
				} else if (on_plain != null) {
					on_plain(line);
				}
			}
		}
		return geosite_arg;
	}

	let dnsmasq_default_dns = null;
	if (USE_DEFAULT_DNS !== "nil") {
		if (USE_DEFAULT_DNS == "direct")
			dnsmasq_default_dns = LOCAL_DNS;
		if (USE_DEFAULT_DNS == "remote")
			dnsmasq_default_dns = TUN_DNS;
		if (USE_DEFAULT_DNS == "remote" && CHN_LIST == "direct")
			dnsmasq_default_dns = TUN_DNS;
	}

	let only_global = null;
	if (DEFAULT_PROXY_MODE == "proxy" && CHN_LIST == "0" && USE_GFW_LIST == "0") {
		dnsmasq_default_dns = TUN_DNS;
		only_global = 1;
	}
	if (USE_DEFAULT_DNS == "chinadns_ng" && CHINADNS_DNS != "0") {
		dnsmasq_default_dns = CHINADNS_DNS;
		USE_CHINADNS_NG = "1";
	}

	let setflag_4 = (NFTFLAG == "1") ? "4#inet#passwall#" : "";
	let setflag_6 = (NFTFLAG == "1") ? "6#inet#passwall#" : "";

	let new_text = "";
	if (USE_CHINADNS_NG == "0") {
		let cache_text = "";
		if (api.fs.access(CACHE_TEXT_FILE)) {
			let lines = read_lines(CACHE_TEXT_FILE) ?? [];
			for (let line in lines)
				cache_text = line;
		}
		new_text = get_dns_config_key();
		if (cache_text == "" || new_text == "" || cache_text != new_text)
			api.remove(CACHE_DNS_PATH + "*");
	} else {
		api.remove(CACHE_DNS_PATH + "*");
	}

	if (!api.fs.access(CACHE_DNS_PATH)) {
		fs.mkdir(CACHE_DNS_PATH);
		let GEO_SUCCESS = true;

		if (USE_CHINADNS_NG == "0" && USE_BLOCK_LIST == "1") {
			let geosite_arg = collect_geosite("/etc/passwall/rules/block_host", (line) => {
				line = api.get_std_domain(line);
				if (line != "" && index(line, "#") < 0 && index(line, ":") < 0)
					set_domain_address(line, "");
			});
			if (USE_GEOVIEW == "1" && geosite_arg != "") {
				let result = foreach_geosite(geosite_arg, (line) => {
					set_domain_address(line, "");
				});
				if (result[0] == 0)
					log("  - 解析[屏蔽列表] Geosite 到屏蔽域名表(blocklist)完成");
				else {
					log("  - 解析[屏蔽列表] Geosite 到屏蔽域名表(blocklist)失败！[" + result[1] + "]");
					GEO_SUCCESS = false;
				}
			}
		}

		let fwd_dns = null;

		if (true) {
			fwd_dns = LOCAL_DNS;
			if (USE_CHINADNS_NG == "1") {
				fwd_dns = null;
			} else {
				let sets = [
					setflag_4 + "psw_vps",
					setflag_6 + "psw_vps6"
				];
				function process_address(address) {
					address = lc(address ?? "");
					if (api.vps_domain_exclude(address))
						return;
					if (api.datatypes.hostname(address)) {
						set_domain_dns(address, fwd_dns);
						set_domain_ipset(address, join(",", sets));
					}
				}
				api.uci_foreach_c("nodes", (t) => {
					process_address(t.address);
					process_address(t.download_address);
				});
				log(sprintf("  - 节点列表中的域名(vpslist)：%s", fwd_dns ?? "默认"));
			}
		}

		if (USE_DIRECT_LIST == "1") {
			fwd_dns = LOCAL_DNS;
			if (USE_CHINADNS_NG == "1")
				fwd_dns = null;
			if (ltruth(fwd_dns)) {
				let sets = [
					setflag_4 + "psw_white",
					setflag_6 + "psw_white6"
				];
				let geosite_arg = collect_geosite("/etc/passwall/rules/direct_host", (line) => {
					line = api.get_std_domain(line);
					if (line != "" && index(line, "#") < 0 && index(line, ":") < 0) {
						add_excluded_domain(line);
						set_domain_dns(line, fwd_dns);
						set_domain_ipset(line, join(",", sets));
					}
				});
				if (read_lines("/etc/passwall/rules/direct_host") != null)
					log(sprintf("  - 域名白名单(whitelist)：%s", fwd_dns ?? "默认"));
				if (USE_GEOVIEW == "1" && geosite_arg != "") {
					let result = foreach_geosite(geosite_arg, (line) => {
						add_excluded_domain(line);
						set_domain_dns(line, fwd_dns);
						set_domain_ipset(line, join(",", sets));
					});
					if (result[0] == 0)
						log("  - 解析[直连列表] Geosite 到域名白名单(whitelist)完成");
					else {
						log("  - 解析[直连列表] Geosite 到域名白名单(whitelist)失败！[" + result[1] + "]");
						GEO_SUCCESS = false;
					}
				}
			}
		}

		if (USE_PROXY_LIST == "1") {
			fwd_dns = TUN_DNS;
			if (USE_CHINADNS_NG == "1")
				fwd_dns = null;
			if (ltruth(fwd_dns)) {
				let set_name = "psw_black";
				let set6_name = "psw_black6";
				if (FLAG != "default") {
					set_name = "psw_" + FLAG + "_black";
					set6_name = "psw_" + FLAG + "_black6";
				}
				let sets = [setflag_4 + set_name];
				if (NO_PROXY_IPV6 != "1")
					push(sets, setflag_6 + set6_name);
				let geosite_arg = collect_geosite("/etc/passwall/rules/proxy_host", (line) => {
					line = api.get_std_domain(line);
					if (line != "" && index(line, "#") < 0 && index(line, ":") < 0) {
						add_excluded_domain(line);
						if (NO_PROXY_IPV6 == "1")
							set_domain_address(line, "::");
						set_domain_dns(line, fwd_dns);
						set_domain_ipset(line, join(",", sets));
					}
				});
				if (read_lines("/etc/passwall/rules/proxy_host") != null)
					log(sprintf("  - 代理域名表(blacklist)：%s", fwd_dns ?? "默认"));
				if (USE_GEOVIEW == "1" && geosite_arg != "") {
					let result = foreach_geosite(geosite_arg, (line) => {
						add_excluded_domain(line);
						if (NO_PROXY_IPV6 == "1")
							set_domain_address(line, "::");
						set_domain_dns(line, fwd_dns);
						set_domain_ipset(line, join(",", sets));
					});
					if (result[0] == 0)
						log("  - 解析[代理列表] Geosite 到代理域名表(blacklist)完成");
					else {
						log("  - 解析[代理列表] Geosite 到代理域名表(blacklist)失败！[" + result[1] + "]");
						GEO_SUCCESS = false;
					}
				}
			}
		}

		if (USE_GFW_LIST == "1") {
			fwd_dns = TUN_DNS;
			if (USE_CHINADNS_NG == "1")
				fwd_dns = null;
			if (ltruth(fwd_dns)) {
				let set_name = "psw_gfw";
				let set6_name = "psw_gfw6";
				if (FLAG != "default") {
					set_name = "psw_" + FLAG + "_gfw";
					set6_name = "psw_" + FLAG + "_gfw6";
				}
				let sets = [setflag_4 + set_name];
				if (NO_PROXY_IPV6 != "1")
					push(sets, setflag_6 + set6_name);
				let lines = read_lines("/usr/share/passwall/rules/gfwlist");
				if (lines != null) {
					for (let line in lines) {
						if (line != "" && index(line, "#") < 0 && !check_excluded_domain(line)) {
							if (NO_PROXY_IPV6 == "1")
								set_domain_address(line, "::");
							if (dnsmasq_default_dns == fwd_dns)
								fwd_dns = null;
							else
								set_domain_dns(line, fwd_dns);
							set_domain_ipset(line, join(",", sets));
						}
					}
					log(sprintf("  - 防火墙域名表(gfwlist)：%s", fwd_dns ?? "默认"));
				}
			}
		}

		if (CHN_LIST != "0") {
			fwd_dns = null;
			if (CHN_LIST == "direct")
				fwd_dns = LOCAL_DNS;
			if (CHN_LIST == "proxy")
				fwd_dns = TUN_DNS;
			if (USE_CHINADNS_NG == "1")
				fwd_dns = null;
			if (ltruth(fwd_dns)) {
				let sets = [
					setflag_4 + "psw_chn",
					setflag_6 + "psw_chn6"
				];
				if (CHN_LIST == "proxy" && NO_PROXY_IPV6 == "1")
					sets = [setflag_4 + "psw_chn"];
				let lines = read_lines("/usr/share/passwall/rules/chnlist");
				if (lines != null) {
					for (let line in lines) {
						if (line != "" && index(line, "#") < 0 && !check_excluded_domain(line)) {
							if (CHN_LIST == "proxy" && NO_PROXY_IPV6 == "1")
								set_domain_address(line, "::");
							if (dnsmasq_default_dns == fwd_dns)
								fwd_dns = null;
							else
								set_domain_dns(line, fwd_dns);
							set_domain_ipset(line, join(",", sets));
						}
					}
					log(sprintf("  - 中国域名表(chnlist)：%s", fwd_dns ?? "默认"));
				}
			}
		}

		if (IS_SHUNT_NODE && USE_CHINADNS_NG == "0" && only_global != 1) {
			let t = api.uci_get_c(NODE);
			let default_node_id = t["default_node"];
			if (default_node_id == null || default_node_id === false)
				default_node_id = "_direct";
			api.uci_foreach_c("shunt_rules", (s) => {
				let _node_id = t[s[".name"]];
				if (ltruth(_node_id) && t["shunt_group"] == s.group) {
					if (_node_id == "_default")
						_node_id = default_node_id;
					fwd_dns = TUN_DNS;
					let sets = [
						setflag_4 + "psw_shunt",
						setflag_6 + "psw_shunt6"
					];
					if (FLAG != "default") {
						sets = [
							setflag_4 + "psw_" + FLAG + "_shunt",
							setflag_6 + "psw_" + FLAG + "_shunt6"
						];
					}
					let domain_list = s.domain_list;
					if (domain_list == null || domain_list === false)
						domain_list = "";
					let geosite_arg = "";
					for (let line in gmatch(domain_list, /[^\r\n]+/g)) {
						if (line != "" && index(line, "#") < 0 && index(line, "regexp:") < 0 && index(line, "ext:") < 0 && index(line, "rule-set:") < 0 && index(line, "rs:") < 0) {
							if (index(line, "geosite:") >= 0) {
								let tag = tail_after_colon(line);
								if (tag != null)
									geosite_arg = geosite_arg + (geosite_arg != "" ? "," : "") + tag;
							} else {
								if (index(line, "domain:") >= 0 || index(line, "full:") >= 0) {
									let tag = tail_after_colon(line);
									if (tag != null)
										line = tag;
								}
								line = api.get_std_domain(line);
								add_excluded_domain(line);
								set_domain_dns(line, fwd_dns);
								set_domain_ipset(line, join(",", sets));
							}
						}
					}
					if (USE_GFW_LIST == "1" && CHN_LIST == "0" && USE_GEOVIEW == "1" && geosite_arg != "") {
						let result = foreach_geosite(geosite_arg, (line) => {
							add_excluded_domain(line);
							set_domain_dns(line, fwd_dns);
							set_domain_ipset(line, join(",", sets));
						});
						if (result[0] == 0)
							log(sprintf("  - 解析分流规则(%s) Geosite 完成", s.remarks));
						else {
							log(sprintf("  - 解析分流规则(%s) Geosite 失败！[" + result[1] + "]", s.remarks));
							GEO_SUCCESS = false;
						}
					}
					if (_node_id != "_direct" && _node_id != "_blackhole")
						log(sprintf("  - Sing-Box/Xray分流规则(%s)：%s", s.remarks, fwd_dns ?? "默认"));
				}
			});
		} else if (only_global == 1 && NO_PROXY_IPV6 == "1") {
			list1["#"] = {
				dns: [],
				ipsets: [],
				address: "::"
			};
		}

		if (length(list1) > 0) {
			let address_lines = [];
			let server_lines = [];
			let ipset_lines = [];
			let set_name = "nftset";
			for (let key, value in list1) {
				if (value.address != null && value.address !== false) {
					let domain = "." + key;
					if (key == "#")
						domain = key;
					push(address_lines, sprintf("address=/%s/%s", domain, value.address));
				}
				if (type(value.dns) == "array" && length(value.dns) > 0) {
					for (let dns in value.dns)
						push(server_lines, sprintf("server=/.%s/%s", key, dns));
				}
				if (type(value.ipsets) == "array" && length(value.ipsets) > 0) {
					push(ipset_lines, sprintf("%s=/.%s/%s", set_name, key, join(",", value.ipsets)));
				}
			}
			api.fs.writefile(CACHE_DNS_PATH + "/000-address.conf", join("\n", address_lines) + (length(address_lines) > 0 ? "\n" : ""));
			api.fs.writefile(CACHE_DNS_PATH + "/001-server.conf", join("\n", server_lines) + (length(server_lines) > 0 ? "\n" : ""));
			fs.unlink(CACHE_DNS_PATH + "/ipset.conf");
			api.fs.writefile(CACHE_DNS_PATH + "/nftset.conf", join("\n", ipset_lines) + (length(ipset_lines) > 0 ? "\n" : ""));
		}

		if (!GEO_SUCCESS)
			new_text = "";
		api.fs.writefile(CACHE_TEXT_FILE, new_text);
	} else {
		log("  - 从缓存加载 Dnsmasq 域名分流规则。");
	}

	if (USE_CHINADNS_NG == "0") {
		api.remove(TMP_DNSMASQ_PATH);
		fs.symlink(CACHE_DNS_PATH, TMP_DNSMASQ_PATH);
	}

	if (DNSMASQ_CONF_FILE !== "nil") {
		let conf_lines = [];
		if (ltruth(LISTEN_PORT)) {
			conf_lines = copy_instance({
				"-LISTEN_PORT": LISTEN_PORT,
				"-TMP_DNSMASQ_PATH": TMP_DNSMASQ_PATH,
				"-return": "1"
			});
			let hosts = api.CACHE_PATH + "/dhcp-hosts";
			api.sys.call("touch " + hosts);
			tinsert(conf_lines, "addn-hosts=" + hosts);
		}
		if (USE_CHINADNS_NG == "0")
			tinsert(conf_lines, sprintf("conf-dir=%s", TMP_DNSMASQ_PATH));
		if (ltruth(dnsmasq_default_dns)) {
			for (let s in gmatch(dnsmasq_default_dns, /[^,]+/g))
				tinsert(conf_lines, sprintf("server=%s", s));
			tinsert(conf_lines, "all-servers");
			tinsert(conf_lines, "no-poll");
			tinsert(conf_lines, "no-resolv");
			if (USE_CHINADNS_NG == "0")
				log(sprintf("  - 默认：%s", dnsmasq_default_dns));
			if (FLAG == "default")
				api.set_cache_var("DEFAULT_DNS", DEFAULT_DNS);
		}
		if (type(conf_lines) == "array" && length(conf_lines) > 0)
			api.fs.writefile(DNSMASQ_CONF_FILE, join("\n", conf_lines) + "\n");
	}

	if (USE_CHINADNS_NG == "0")
		log("  - PassWall必须依赖于Dnsmasq，如果你自行配置了错误的DNS流程，将会导致域名(直连/代理)分流失效！！！");
};

dispatch = function(name) {
	if (name == "stretch")
		return stretch;
	if (name == "restart")
		return restart;
	if (name == "logic_restart")
		return logic_restart;
	if (name == "copy_instance")
		return copy_instance;
	if (name == "add_rule")
		return add_rule;
	return null;
};

// argv[0] = stretch | restart | logic_restart | copy_instance | add_rule
// argv[1...] = -FLAG value pairs, parsed by api.get_function_args (argv[0] is skipped).
main = function(argv) {
	if (argv == null || length(argv) < 1 || argv[0] == null || argv[0] === false)
		return;
	let func = dispatch(argv[0]);
	if (func == null)
		return;
	func(api.get_function_args(argv));
};
export { stretch, restart, logic_restart, copy_instance, add_rule, main };
