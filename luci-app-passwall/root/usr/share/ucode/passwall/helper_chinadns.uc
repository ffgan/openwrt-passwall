'use strict';

import * as api from 'passwall.api';
import * as fs from 'fs';
import { truth as ltruth, to_number as tonumber, lua_quote, gmatch, lines_of, lua_or as lua_or_str } from 'passwall.text';
let exec_pair, read_lines, is_file_nonzero, insert_unique, merge_array, insert_array_before, insert_array_after, tail_after_colon, geosite_file, get_geosite, write_lines, main;

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

// argv is -FLAG value pairs. api.get_args treats argv[0] as the first flag.
main = function(argv) {
	let vmap = api.get_args(argv ?? []);
	let FLAG = vmap["-FLAG"];
	let LISTEN_PORT = vmap["-LISTEN_PORT"];
	let DNS_LOCAL = vmap["-DNS_LOCAL"];
	let DNS_TRUST = vmap["-DNS_TRUST"];
	let USE_DIRECT_LIST = vmap["-USE_DIRECT_LIST"];
	let USE_PROXY_LIST = vmap["-USE_PROXY_LIST"];
	let USE_BLOCK_LIST = vmap["-USE_BLOCK_LIST"];
	let GFWLIST = vmap["-GFWLIST"];
	let CHNLIST = vmap["-CHNLIST"];
	let NO_IPV6_TRUST = vmap["-NO_IPV6_TRUST"];
	let DEFAULT_MODE = vmap["-DEFAULT_MODE"];
	let DEFAULT_TAG = vmap["-DEFAULT_TAG"];
	let NO_LOGIC_LOG = vmap["-NO_LOGIC_LOG"];
	let NODE = vmap["-NODE"];
	let NFTFLAG = "1";
	let FILTER_HTTPS = vmap["-FILTER_HTTPS"];
	let LOG_FILE = vmap["-LOG_FILE"];

	let TMP_PATH = api.TMP_PATH;
	let RULES_PATH = "/usr/share/passwall/rules";
	let USER_RULES_PATH = "/etc/passwall/rules";
	let CACHE_RULES_PATH = api.CACHE_PATH + "/user_rules";
	let FLAG_PATH = TMP_PATH + "/acl/" + FLAG;
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

	function load_user_domains(filename, reject_colon) {
		let domains = [];
		let lookup = {};
		let geosite_arg = "";
		let lines = read_lines(USER_RULES_PATH + "/" + filename);
		if (lines != null) {
			for (let line in lines) {
				if (index(line, "#") < 0 && index(line, "geosite:") >= 0) {
					let tag = tail_after_colon(line);
					if (tag != null)
						geosite_arg = geosite_arg + (geosite_arg != "" ? "," : "") + tag;
				} else {
					line = api.get_std_domain(line);
					if (line != "" && index(line, "#") < 0 && (!reject_colon || index(line, ":") < 0))
						insert_unique(domains, line, lookup);
				}
			}
		}
		return [domains, geosite_arg];
	}

	function refresh_cache(file_host, user_file, reject_colon, ok_msg, fail_msg) {
		let loaded = load_user_domains(user_file, reject_colon);
		let domains = loaded[0];
		let geosite_arg = loaded[1];
		if (length(domains) > 0)
			write_lines(file_host, domains);
		let success = true;
		if (USE_GEOVIEW == "1" && geosite_arg != "") {
			let result = get_geosite(geosite_arg, file_host);
			if (result[0] == 0) {
				log(ok_msg);
				api.sys.call("touch " + file_host + "_geo");
			} else {
				log(fail_msg + "[" + result[1] + "]");
				success = false;
			}
		}
		if (success && api.fs.access(file_host))
			api.sys.call("touch " + file_host + "_ok");
	}

	api.fs.mkdirr(FLAG_PATH);
	api.fs.mkdirr(CACHE_RULES_PATH);

	let setflag = (NFTFLAG == "1") ? "inet@passwall@" : "";
	let only_global = (DEFAULT_MODE == "proxy" && CHNLIST == "0" && GFWLIST == "0") ? 1 : false;

	config_lines = [
		(LOG_FILE != "/dev/null") ? "verbose" : "",
		"bind-addr ::",
		"bind-port " + LISTEN_PORT,
		"china-dns " + DNS_LOCAL,
		"trust-dns " + DNS_TRUST,
		(tonumber(FILTER_HTTPS) == 1) ? "filter-qtype 65" : ""
	];
	for (let i = 1; i <= 6; i++)
		push(config_lines, "#--" + i);

	let file_block_host = CACHE_RULES_PATH + "/block_host";
	if (!api.fs.access(file_block_host + "_ok"))
		api.remove(file_block_host + "*");
	let block_geosite_flag = api.fs.access(file_block_host) && api.fs.access(file_block_host + "_ok") && api.fs.access(file_block_host + "_geo");
	if (USE_BLOCK_LIST == "1" && !api.fs.access(file_block_host)) {
		refresh_cache(file_block_host, "block_host", false,
			"  - 解析[屏蔽列表] Geosite 到屏蔽域名表(blocklist)完成",
			"  - 解析[屏蔽列表] Geosite 到屏蔽域名表(blocklist)失败！");
	}
	if (USE_BLOCK_LIST == "1" && is_file_nonzero(file_block_host)) {
		if (block_geosite_flag)
			log("  - [屏蔽列表] Geosite 使用缓存结果，跳过重复解析");
		tmp_lines = [
			"group null",
			"group-dnl " + file_block_host
		];
		insert_array_after(config_lines, tmp_lines, "#--5");
	}

	let file_vpslist = TMP_PATH + "/vpslist";
	if (!is_file_nonzero(file_vpslist)) {
		let written_domains = {};
		let lines = [];
		function process_address(address) {
			if (address == null || address === false)
				address = "";
			else
				address = lc("" + address);
			if (api.vps_domain_exclude(address))
				return;
			if (api.datatypes.hostname(address) && !written_domains[address]) {
				push(lines, address);
				written_domains[address] = true;
			}
		}
		api.uci_foreach_c("nodes", (t) => {
			process_address(t.address);
			process_address(t.download_address);
		});
		write_lines(file_vpslist, lines);
	}
	if (is_file_nonzero(file_vpslist)) {
		let sets = [
			setflag + "psw_vps",
			setflag + "psw_vps6"
		];
		tmp_lines = [
			"group vpslist",
			"group-dnl " + file_vpslist,
			"group-upstream " + DNS_LOCAL,
			"group-ipset " + join(",", sets)
		];
		insert_array_after(config_lines, tmp_lines, "#--6");
		log(sprintf("  - 节点列表中的域名(vpslist)：%s", lua_or_str(DNS_LOCAL, "默认")));
	}

	let file_direct_host = CACHE_RULES_PATH + "/direct_host";
	if (!api.fs.access(file_direct_host + "_ok"))
		api.remove(file_direct_host + "*");
	let direct_geosite_flag = api.fs.access(file_direct_host) && api.fs.access(file_direct_host + "_ok") && api.fs.access(file_direct_host + "_geo");
	if (USE_DIRECT_LIST == "1" && !api.fs.access(file_direct_host)) {
		refresh_cache(file_direct_host, "direct_host", true,
			"  - 解析[直连列表] Geosite 到域名白名单(whitelist)完成",
			"  - 解析[直连列表] Geosite 到域名白名单(whitelist)失败！");
	}
	if (USE_DIRECT_LIST == "1" && is_file_nonzero(file_direct_host)) {
		if (direct_geosite_flag)
			log("  - [直连列表] Geosite 使用缓存结果，跳过重复解析");
		let sets = [
			setflag + "psw_white",
			setflag + "psw_white6"
		];
		tmp_lines = [
			"group directlist",
			"group-dnl " + file_direct_host,
			"group-upstream " + DNS_LOCAL,
			"group-ipset " + join(",", sets)
		];
		insert_array_after(config_lines, tmp_lines, "#--4");
		log(sprintf("  - 域名白名单(whitelist)：%s", lua_or_str(DNS_LOCAL, "默认")));
	}

	let file_proxy_host = CACHE_RULES_PATH + "/proxy_host";
	if (!api.fs.access(file_proxy_host + "_ok"))
		api.remove(file_proxy_host + "*");
	let proxy_geosite_flag = api.fs.access(file_proxy_host) && api.fs.access(file_proxy_host + "_ok") && api.fs.access(file_proxy_host + "_geo");
	if (USE_PROXY_LIST == "1" && !api.fs.access(file_proxy_host)) {
		refresh_cache(file_proxy_host, "proxy_host", true,
			"  - 解析[代理列表] Geosite 到代理域名表(blacklist)完成",
			"  - 解析[代理列表] Geosite 到代理域名表(blacklist)失败！");
	}
	if (USE_PROXY_LIST == "1" && is_file_nonzero(file_proxy_host)) {
		if (proxy_geosite_flag)
			log("  - [代理列表] Geosite 使用缓存结果，跳过重复解析");
		let sets = [
			setflag + "psw_black",
			setflag + "psw_black6"
		];
		if (FLAG != "default") {
			sets = [
				setflag + "psw_" + FLAG + "_black",
				setflag + "psw_" + FLAG + "_black6"
			];
		}
		tmp_lines = [
			"group proxylist",
			"group-dnl " + file_proxy_host,
			"group-upstream " + DNS_TRUST,
			"group-ipset " + join(",", sets)
		];
		if (NO_IPV6_TRUST == "1")
			push(tmp_lines, "no-ipv6 tag:proxylist");
		insert_array_after(config_lines, tmp_lines, "#--3");
		log(sprintf("  - 代理域名表(blacklist)：%s", lua_or_str(DNS_TRUST, "默认")));
	}

	if (GFWLIST == "1" && is_file_nonzero(RULES_PATH + "/gfwlist")) {
		let sets = [
			setflag + "psw_gfw",
			setflag + "psw_gfw6"
		];
		if (FLAG != "default") {
			sets = [
				setflag + "psw_" + FLAG + "_gfw",
				setflag + "psw_" + FLAG + "_gfw6"
			];
		}
		tmp_lines = [
			"gfwlist-file " + RULES_PATH + "/gfwlist",
			"add-taggfw-ip " + join(",", sets)
		];
		if (NO_IPV6_TRUST == "1")
			push(tmp_lines, "no-ipv6 tag:gfw");
		merge_array(config_lines, tmp_lines);
		log(sprintf("  - 防火墙域名表(gfwlist)：%s", lua_or_str(DNS_TRUST, "默认")));
	}

	if (CHNLIST != "0" && is_file_nonzero(RULES_PATH + "/chnlist")) {
		if (CHNLIST == "direct") {
			let sets = [
				setflag + "psw_chn",
				setflag + "psw_chn6"
			];
			let suffix = (NFTFLAG == "1") ? "_static" : "";
			tmp_lines = [
				"chnlist-file " + RULES_PATH + "/chnlist",
				"ipset-name4 " + setflag + "psw_chn" + suffix,
				"ipset-name6 " + setflag + "psw_chn6" + suffix,
				"add-tagchn-ip" + ((NFTFLAG == "1") ? (" " + join(",", sets)) : "")
			];
			merge_array(config_lines, tmp_lines);
			log(sprintf("  - 中国域名表(chnlist)：%s", lua_or_str(DNS_LOCAL, "默认")));
		}
		if (CHNLIST == "proxy") {
			let sets = [
				setflag + "psw_chn",
				setflag + "psw_chn6"
			];
			tmp_lines = [
				"group chn_proxy",
				"group-dnl " + RULES_PATH + "/chnlist",
				"group-upstream " + DNS_TRUST,
				"group-ipset " + join(",", sets)
			];
			if (NO_IPV6_TRUST == "1")
				push(tmp_lines, "no-ipv6 tag:chn_proxy");
			insert_array_after(config_lines, tmp_lines, "#--1");
			log(sprintf("  - 中国域名表(chnlist)：%s", lua_or_str(DNS_TRUST, "默认")));
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
		let shunt_direct_host_tmp = shunt_direct_host + "_tmp";
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
							if (index(line, "domain:") >= 0 || index(line, "full:") >= 0)
								line = tail_after_colon(line);
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
					log(sprintf("  - Sing-Box/Xray分流规则(%s)：%s", s.remarks, lua_or_str(DNS_TRUST, "默认")));
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

		if (!is_file_nonzero(shunt_direct_host_tmp) && length(direct_domain) > 0)
			write_lines(shunt_direct_host_tmp, direct_domain);
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
			resolve(geosite_direct_arg, shunt_direct_host_tmp);
			resolve(geosite_proxy_arg, shunt_proxy_host);
			resolve(geosite_black_arg, shunt_black_host);
			if (ok)
				log("  - 解析[分流节点] Geosite 完成");
			else
				api.remove(MD5_FILE);
		}
		if (USE_CACHE && USE_GEOVIEW == "1" && (geosite_direct_arg != "" || geosite_proxy_arg != "" || geosite_black_arg != ""))
			log("  - [分流节点] Geosite 使用缓存结果，跳过重复解析");

		if (is_file_nonzero(shunt_direct_host_tmp) && CHNLIST != "0" && is_file_nonzero(RULES_PATH + "/chnlist")) {
			let chn_domain_set = {};
			let chn_lines = read_lines(RULES_PATH + "/chnlist");
			if (chn_lines != null) {
				for (let line in chn_lines) {
					if (line != "")
						chn_domain_set[line] = true;
				}
			}
			let in_lines = read_lines(shunt_direct_host_tmp);
			let out_fh = fs.open(shunt_direct_host, "w");
			if (in_lines != null && out_fh != null) {
				for (let line in in_lines) {
					line = lc(line);
					let valid_domain = line != "" && index(line, ".") >= 0 && substr(line, 0, 1) != ".";
					if (valid_domain && !chn_domain_set[line])
						out_fh.write(line + "\n");
				}
			}
			if (out_fh != null)
				out_fh.close();
			api.remove(shunt_direct_host_tmp);
		} else if (is_file_nonzero(shunt_direct_host_tmp)) {
			fs.rename(shunt_direct_host_tmp, shunt_direct_host);
		}

		let shunt_file = null;
		if (is_file_nonzero(shunt_black_host))
			shunt_file = shunt_black_host;
		if (is_file_nonzero(shunt_direct_host))
			shunt_file = (shunt_file != null && shunt_file !== false ? shunt_file + "," : "") + shunt_direct_host;
		if (is_file_nonzero(shunt_proxy_host))
			shunt_file = (shunt_file != null && shunt_file !== false ? shunt_file + "," : "") + shunt_proxy_host;

		if (shunt_file != null && shunt_file !== false) {
			let sets = [
				setflag + "psw_shunt",
				setflag + "psw_shunt6"
			];
			if (FLAG != "default") {
				sets = [
					setflag + "psw_" + FLAG + "_shunt",
					setflag + "psw_" + FLAG + "_shunt6"
				];
			}
			tmp_lines = [
				"group shuntlist",
				"group-dnl " + shunt_file,
				"group-upstream " + DNS_TRUST,
				"group-ipset " + join(",", sets)
			];
			insert_array_after(config_lines, tmp_lines, "#--2");
		}
	}

	if (GFWLIST == "1" && CHNLIST == "0")
		DEFAULT_TAG = "chn";
	if (CHNLIST == "proxy")
		DEFAULT_TAG = "chn";
	if (only_global) {
		DEFAULT_TAG = "gfw";
		if (NO_IPV6_TRUST == "1" && !IS_SHUNT_NODE)
			push(config_lines, "no-ipv6");
	}
	if (DEFAULT_TAG == "none_noip")
		push(config_lines, "noip-as-chnip");
	if (DEFAULT_TAG == null || DEFAULT_TAG === false || DEFAULT_TAG == "smart" || DEFAULT_TAG == "none_noip")
		DEFAULT_TAG = "none";
	push(config_lines, "default-tag " + DEFAULT_TAG);
	if (DEFAULT_TAG == "none")
		push(config_lines, "verdict-cache 5000");
	push(config_lines, "hosts");

	if (DEFAULT_TAG == "chn")
		log(sprintf("  - 默认 DNS ：%s", DNS_LOCAL));
	else if (DEFAULT_TAG == "gfw")
		log(sprintf("  - 默认 DNS ：%s", DNS_TRUST));
	else
		log(sprintf("  - 默认 DNS ：%s", "智能匹配"));

	if (length(config_lines) > 0) {
		for (let line in config_lines) {
			if (line != "" && match(line, /^#--/) == null)
				print(line + "\n");
		}
	}

	log("  - ChinaDNS-NG已作为Dnsmasq上游，如果你自行配置了错误的DNS流程，将会导致域名(直连/代理)分流失效！！！");
};
export { main };
