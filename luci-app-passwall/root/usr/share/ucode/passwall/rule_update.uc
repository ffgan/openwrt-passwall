'use strict';

import * as api from 'passwall.api';
import * as fs from 'fs';
let ltruth, lor, tonumber, parse_uint, read_lines, file_size, gmatch, each_global_match, replace_all_literal, stack_string, url_list, is_ws, main;

ltruth = function(v) {
	return v != null && v !== false;
};

lor = function(a, b) {
	if (a == null || a === false)
		return b;
	return a;
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

parse_uint = function(s) {
	if (type(s) == "int")
		return s;
	if (type(s) == "double")
		return (s == s) ? int(s) : null;
	if (type(s) != "string" || match(s, /^[0-9]+$/) == null)
		return null;
	return int(s);
};

read_lines = function(path) {
	let data = api.fs.readfile(path);
	if (data == null)
		return null;
	if (data == "")
		return [];
	if (substr(data, -1) == "\n")
		data = substr(data, 0, length(data) - 1);
	if (data == "")
		return [""];
	return split(data, "\n");
};

file_size = function(path) {
	let st = api.fs.stat(path, "size");
	if (st == null)
		return null;
	if (type(st) == "object")
		return st.size ?? null;
	return st;
};

gmatch = function(s, pattern) {
	if (s == null || s === false)
		return [];
	let found = match("" + s, pattern);
	if (found == null)
		return [];
	let out = [];
	for (let m in found) {
		if (type(m) == "array")
			push(out, m[0]);
		else
			push(out, m);
	}
	return out;
};

each_global_match = function(found, fn) {
	if (found == null)
		return;
	if (type(found) != "array")
		return;
	if (length(found) > 0 && type(found[0]) != "array") {
		fn(found);
		return;
	}
	for (let m in found)
		fn(m);
};

replace_all_literal = function(hay, needle, repl) {
	if (type(hay) != "string")
		hay = "" + (hay ?? "");
	if (type(needle) != "string")
		needle = "" + (needle ?? "");
	if (needle == "")
		return hay;
	let out = "";
	let rest = hay;
	while (true) {
		let p = index(rest, needle);
		if (p < 0) {
			out += rest;
			break;
		}
		out += substr(rest, 0, p) + repl;
		rest = substr(rest, p + length(needle));
	}
	return out;
};

stack_string = function(e) {
	if (e == null)
		return "";
	if (type(e) == "string")
		return e;
	let st = e.stacktrace ?? e.stack;
	if (type(st) == "string")
		return st;
	if (type(st) != "array")
		return "";
	let lines = [];
	for (let frame in st) {
		if (type(frame) == "string")
			push(lines, frame);
		else if (type(frame) == "object" && frame != null)
			push(lines, (frame.filename ?? frame.source ?? "?") + ":" + (frame.line ?? "?") + ": " + (frame["function"] ?? frame.name ?? ""));
		else
			push(lines, "" + frame);
	}
	return join("\n", lines);
};

url_list = function(v, fallback) {
	if (v == null || v === false)
		return fallback;
	if (type(v) == "array")
		return v;
	if (type(v) == "string")
		return [v];
	return fallback;
};

is_ws = function(b) {
	return b == 32 || b == 9 || b == 10 || b == 11 || b == 12 || b == 13;
};

// argv[0] = log | print (or anything else, which stays silent)
// argv[1] = comma-separated target list; omitted/null reads UCI flags
// argv[2] = cron | rollback | omitted
// cron clears the target list so UCI flags are used.
// rollback marks geo files current, parses the target list, then clears it.
main = function(argv) {
	if (argv == null)
		argv = [];
	let arg1 = argv[0];
	let arg2 = argv[1];
	let arg3 = argv[2];

	let lock_path = api.LOCK_PREFIX + "_sub_rule.lock";
	if (api.fs.stat(lock_path) == null) {
		let created = fs.open(lock_path, "w");
		if (created != null)
			created.close();
	}
	let update_lock = fs.open(lock_path, "r+");
	if (update_lock == null) {
		api.log("无法打开订阅/规则更新锁，退出。");
		exit(1);
	}
	if (!update_lock.lock("xn")) {
		if (arg3 != "cron") {
			api.log("订阅或规则更新正在运行，本次请求跳过。");
			exit(0);
		}
		let mark = update_lock.read(1);
		let running_map = { s: "订阅", r: "规则更新" };
		let running = running_map[mark];
		if (running == null)
			running = "订阅/规则更新";
		update_lock.seek(0);
		api.log("[" + running + "]实例正在运行，[规则更新]进入队列等待...");
		if (!update_lock.lock("x")) {
			api.log("无法取得更新锁，计划任务失败。");
			exit(1);
		}
	}
	update_lock.write("r");
	update_lock.seek(0);
	api.uci.revert(api.c_config);

	let nftable_name = "inet passwall";
	let rule_path = "/usr/share/passwall/rules";
	let reboot = 0;
	let gfwlist_update = "0";
	let chnroute_update = "0";
	let chnroute6_update = "0";
	let chnlist_update = "0";
	let geoip_update = "0";
	let geosite_update = "0";

	let excluded_domain = ["apple.com", "sina.cn", "sina.com.cn", "baidu.com", "byr.cn", "jlike.com", "weibo.com", "zhongsou.com", "youdao.com", "sogou.com", "so.com", "soso.com", "aliyun.com", "taobao.com", "jd.com", "qq.com", "bing.com"];
	let excluded_map = {};
	for (let d in excluded_domain)
		excluded_map[d] = true;

	let gfwlist_url = url_list(api.uci_get_c("@global_rules[0]", "gfwlist_url"), ["https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt"]);
	let chnroute_url = url_list(api.uci_get_c("@global_rules[0]", "chnroute_url"), ["https://ispip.clang.cn/all_cn.txt"]);
	let chnroute6_url = url_list(api.uci_get_c("@global_rules[0]", "chnroute6_url"), ["https://ispip.clang.cn/all_cn_ipv6.txt"]);
	let chnlist_url = url_list(api.uci_get_c("@global_rules[0]", "chnlist_url"), [
		"https://fastly.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/accelerated-domains.china.conf",
		"https://fastly.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/apple.china.conf",
		"https://fastly.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/google.china.conf"
	]);
	let geoip_url = api.uci_get_c("@global_rules[0]", "geoip_url");
	if (geoip_url == null || geoip_url === false)
		geoip_url = "https://github.com/Loyalsoldier/geoip/releases/latest/download/geoip.dat";
	let geosite_url = api.uci_get_c("@global_rules[0]", "geosite_url");
	if (geosite_url == null || geosite_url === false)
		geosite_url = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat";
	let asset_location = api.uci_get_c("@global_rules[0]", "v2ray_location_asset");
	if (asset_location == null || asset_location === false)
		asset_location = "/usr/share/v2ray/";
	let geo2rule = api.uci_get_c("@global_rules[0]", "geo2rule");
	if (geo2rule == null || geo2rule === false)
		geo2rule = "0";
	let geoip_update_ok = false;
	let geosite_update_ok = false;
	if (match("" + asset_location, /\/$/) == null)
		asset_location = asset_location + "/";
	let backup_path = "/tmp/bak_v2ray/";
	let rollback = false;

	if (arg3 == "cron")
		arg2 = null;
	else if (arg3 == "rollback") {
		rollback = true;
		geoip_update_ok = true;
		geosite_update_ok = true;
	}

	function log(...args) {
		if (arg1 == null || arg1 === false)
			return;
		if (arg1 == "log") {
			api.log(...args);
		} else if (arg1 == "print") {
			let parts = [];
			for (let a in args) {
				if (a == null)
					push(parts, "nil");
				else
					push(parts, "" + a);
			}
			let t = localtime();
			let stamp = sprintf("%04d-%02d-%02d %02d:%02d:%02d: ", t.year, t.mon, t.mday, t.hour, t.min, t.sec);
			print(stamp + join(" ", parts) + "\n");
		}
	}

	function gen_cache(set_name, ip_type, input_file, output_file) {
		let tmp_set_name = set_name + "_tmp_" + time();
		let final_set_name = set_name + "_static";
		let lines = read_lines(input_file);
		if (lines == null)
			return false;
		let nft_pipe = fs.popen("nft -f -", "w");
		if (nft_pipe == null)
			return false;
		let script = "#!/usr/sbin/nft -f\n";
		script += sprintf("add table %s\n", nftable_name);
		script += sprintf("add set %s %s { type %s; flags interval; auto-merge; }\n", nftable_name, tmp_set_name, ip_type);
		script += sprintf("add element %s %s { ", nftable_name, tmp_set_name);
		let count = 0;
		let batch_size = 500;
		for (let line in lines) {
			let ip = trim(line);
			if (ip != null && ip != "") {
				script += ip + ", ";
				count++;
				if (count % batch_size == 0) {
					script += "}\n";
					script += sprintf("add element %s %s { ", nftable_name, tmp_set_name);
				}
			}
		}
		script += "}\n";
		nft_pipe.write(script);
		let success = nft_pipe.close();
		if (!(success === true || success == 0)) {
			api.sys.call(sprintf("nft delete set %s %s 2>/dev/null", nftable_name, tmp_set_name));
			return false;
		}
		api.sys.call(sprintf("nft list set %s %s | sed \"s/%s/%s/g\" > %s", nftable_name, tmp_set_name, tmp_set_name, final_set_name, output_file));
		api.sys.call(sprintf("nft delete set %s %s 2>/dev/null", nftable_name, tmp_set_name));
	}

	function split_body_code(result) {
		if (type(result) != "string" || result == "")
			return null;
		let i = length(result) - 1;
		let endb = ord(result, i);
		if (endb < 48 || endb > 57)
			return null;
		while (i >= 0 && ord(result, i) >= 48 && ord(result, i) <= 57)
			i--;
		let code = substr(result, i + 1);
		while (i >= 0 && is_ws(ord(result, i)))
			i--;
		return [substr(result, 0, i + 1), code];
	}

	function curl(url, file) {
		let http_code = 0;
		let header_str = "";
		let args = [
			"-fskL",
			"--retry 3",
			"--connect-timeout 3",
			"--max-time 300",
			"--speed-limit 51200 --speed-time 15",
			"-H 'Accept: */*'",
			"-A \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36\"",
			"--dump-header -",
			"-w '\\n%{http_code}'"
		];
		if (ltruth(file))
			push(args, "-o " + file);
		let ret = api.curl_auto(url, null, args);
		let return_code = null;
		let result = null;
		if (type(ret) == "array") {
			return_code = ret[0];
			result = ret[1];
		} else if (type(ret) == "object" && ret != null) {
			return_code = ret.code ?? ret[0];
			result = ret.out ?? ret.stdout ?? ret[1];
		} else {
			return_code = ret;
		}
		if (result != null && result !== false && result != "") {
			let parts = split_body_code("" + result);
			if (parts != null) {
				let parsed = parse_uint(parts[1]);
				http_code = (parsed == null) ? 0 : parsed;
				header_str = parts[0];
			} else {
				let m = match("" + result, /([0-9]+)[[:space:]]*$/);
				let parsed = (m == null) ? null : parse_uint(m[1]);
				http_code = (parsed == null) ? 0 : parsed;
			}
		}
		if (header_str != "")
			header_str = replace(header_str, /\r/g, "");
		return [return_code, http_code, header_str];
	}

	function check_excluded_domain(value) {
		if (value == null || value === false || value == "")
			return false;
		value = lc("" + value);
		let eq_pos = index(value, "=");
		if (eq_pos >= 0)
			value = substr(value, eq_pos + 1);
		if (substr(value, 0, 1) == "/")
			value = substr(value, 1);
		let slash_pos = index(value, "/");
		let colon_pos = index(value, ":");
		let cut_pos = null;
		if (slash_pos >= 0 && colon_pos >= 0)
			cut_pos = (slash_pos < colon_pos) ? slash_pos : colon_pos;
		else if (slash_pos >= 0)
			cut_pos = slash_pos;
		else if (colon_pos >= 0)
			cut_pos = colon_pos;
		if (cut_pos != null)
			value = substr(value, 0, cut_pos);
		while (length(value) > 0 && ord(value, 0) == 46)
			value = substr(value, 1);
		while (length(value) > 0 && ord(value, length(value) - 1) == 46)
			value = substr(value, 0, length(value) - 1);
		while (value != null) {
			if (excluded_map[value])
				return true;
			let dot_pos = index(value, ".");
			if (dot_pos < 0)
				break;
			value = substr(value, dot_pos + 1);
		}
		return false;
	}

	function is_comment_line(s) {
		if (s == null || s === false || s == "")
			return false;
		let b = ord(s, 0);
		if (b == 35 || b == 33 || b == 92 || b == 91 || b == 64)
			return true;
		return false;
	}

	function is_ipv4(s, check_cidr) {
		if (type(s) != "string")
			return false;
		let dot = 0;
		let seg_start = 0;
		let len = length(s);
		let mask_start = null;
		let i = 0;
		while (i < len) {
			let b = ord(s, i);
			if (b >= 48 && b <= 57) {
			} else if (b == 46) {
				dot++;
				if (dot > 3 || i == seg_start)
					return false;
				let seg = parse_uint(substr(s, seg_start, i - seg_start));
				if (seg == null || seg > 255)
					return false;
				seg_start = i + 1;
			} else if (b == 47) {
				if (!check_cidr)
					return false;
				if (dot != 3 || i == seg_start)
					return false;
				let seg = parse_uint(substr(s, seg_start, i - seg_start));
				if (seg == null || seg > 255)
					return false;
				mask_start = i + 1;
				break;
			} else {
				return false;
			}
			i++;
		}
		if (!check_cidr || mask_start == null) {
			if (dot != 3 || seg_start >= len)
				return false;
			let seg = parse_uint(substr(s, seg_start));
			return seg != null && seg <= 255;
		}
		if (mask_start >= len)
			return false;
		let mask = parse_uint(substr(s, mask_start));
		return mask != null && mask >= 0 && mask <= 32;
	}

	function is_ipv4_cidr(s) {
		return is_ipv4(s, true);
	}

	function is_ipv6(s, check_cidr) {
		if (type(s) != "string" || s == "")
			return false;
		let first = ord(s, 0);
		let last = ord(s, length(s) - 1);
		if (first == 91 && last == 93)
			s = substr(s, 1, length(s) - 2);
		let len = length(s);
		let i = 0;
		let seg_len = 0;
		let segs = 0;
		let saw_dc = false;
		while (i < len) {
			let b = ord(s, i);
			if (b == 47) {
				if (!check_cidr)
					return false;
				if (seg_len > 0)
					segs++;
				if ((!saw_dc && segs != 8) || (saw_dc && segs > 8))
					return false;
				i++;
				if (i >= len)
					return false;
				let mask = 0;
				while (i < len) {
					b = ord(s, i);
					if (b < 48 || b > 57)
						return false;
					mask = mask * 10 + (b - 48);
					if (mask > 128)
						return false;
					i++;
				}
				return true;
			}
			if (b == 58) {
				let nextb = (i + 1 < len) ? ord(s, i + 1) : 0;
				if (nextb == 58) {
					if (saw_dc)
						return false;
					saw_dc = true;
					if (seg_len > 0)
						segs++;
					seg_len = 0;
					i += 2;
				} else {
					if (seg_len == 0)
						return false;
					segs++;
					seg_len = 0;
					i++;
				}
			} else {
				let is_hex = (b >= 48 && b <= 57) || (b >= 65 && b <= 70) || (b >= 97 && b <= 102);
				if (!is_hex)
					return false;
				seg_len++;
				if (seg_len > 4)
					return false;
				i++;
			}
		}
		if (seg_len > 0)
			segs++;
		if (!saw_dc)
			return segs == 8;
		return segs <= 8;
	}

	function is_ipv6_cidr(s) {
		return is_ipv6(s, true);
	}

	function has_colon(s) {
		if (type(s) != "string")
			return false;
		for (let i = 0; i < length(s); i++) {
			if (ord(s, i) == 58)
				return true;
		}
		return false;
	}

	function extract_domain(s) {
		if (s == null || s === false || s == "")
			return null;
		let len = length(s);
		let start = null;
		let last_dot = null;
		for (let i = 0; i < len; i++) {
			let b = ord(s, i);
			if ((b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || b == 45 || b == 46) {
				if (start == null)
					start = i;
				if (b == 46)
					last_dot = i;
			} else if (start != null) {
				if (last_dot != null && last_dot > start) {
					let domain = substr(s, start, i - start);
					while (length(domain) > 0 && ord(domain, 0) == 46)
						domain = substr(domain, 1);
					return domain;
				}
				start = null;
				last_dot = null;
			}
		}
		if (start != null && last_dot != null && last_dot > start) {
			let domain = substr(s, start);
			while (length(domain) > 0 && ord(domain, 0) == 46)
				domain = substr(domain, 1);
			return domain;
		}
		return null;
	}

	function non_file_check(file_path, header_content) {
		let remote_file_size = null;
		let local_file_size = file_size(file_path);
		if (local_file_size == null)
			local_file_size = 0;
		local_file_size = tonumber(local_file_size);
		if (local_file_size == null)
			local_file_size = 0;
		if (local_file_size == 0) {
			log("下载文件为空或读取出错。");
			return true;
		}
		if (header_content != null && header_content !== false && header_content != "") {
			let found = match(header_content, /[Cc]ontent-[Ll]ength:[[:space:]]*([0-9]+)/g);
			each_global_match(found, (m) => {
				let size_s = (type(m) == "array") ? m[1] : null;
				let s = parse_uint(size_s);
				if (s != null && s > 0)
					remote_file_size = s;
			});
		}
		if (remote_file_size != null && remote_file_size != local_file_size) {
			log(sprintf("校验出错：远程 %dB, 下载 %dB", remote_file_size, local_file_size));
			return true;
		}
		return false;
	}

	function GeoToRule(rule_name, rule_type, out_path) {
		let bin = api.finded_com("geoview");
		if (!(ltruth(bin) && api.compare_versions(api.get_app_version("geoview"), ">=", "0.1.10"))) {
			log("[警告] Geoview 组件缺失或版本过低，规则生成流程已被跳过。");
			return false;
		}
		let geosite_path = asset_location + "geosite.dat";
		let geoip_path = asset_location + "geoip.dat";
		let file_path = (rule_type == "domain") ? geosite_path : geoip_path;
		let geo_arg = null;
		if (rule_type == "domain") {
			if (rule_name == "gfwlist")
				geo_arg = "-type geosite -list gfw";
			else
				geo_arg = "-type geosite -list cn";
		} else if (rule_type == "ip4") {
			geo_arg = "-type geoip -list cn -ipv6=false";
		} else if (rule_type == "ip6") {
			geo_arg = "-type geoip -list cn -ipv4=false";
		}
		let cmd = bin + sprintf(" -input '%s' %s -lowmem=true -output '%s'", file_path, geo_arg, out_path);
		api.sys.exec(cmd);
		let local_file_size = file_size(out_path);
		if (local_file_size == null)
			local_file_size = 0;
		local_file_size = tonumber(local_file_size);
		if (local_file_size == null)
			local_file_size = 0;
		if (local_file_size == 0) {
			api.remove(out_path);
			log(rule_name + " 生成失败，请确保 Geo 文件正确且包含目标规则。");
			return false;
		}
		return true;
	}

	function is_0dot(s) {
		return type(s) == "string" && length(s) >= 2 && ord(s, 0) == 48 && ord(s, 1) == 46;
	}

	function is_double_colon_cidr(s) {
		if (type(s) != "string" || length(s) < 2 || ord(s, 0) != 58 || ord(s, 1) != 58)
			return false;
		let l = length(s);
		if (l == 2)
			return true;
		if (l == 3 || ord(s, 2) != 47)
			return false;
		for (let i = 3; i < l; i++) {
			let b = ord(s, i);
			if (b < 48 || b > 57)
				return false;
		}
		return true;
	}

	function consume_domain_line(rule_dataset, line, exclude_domain) {
		line = replace(line, /full:/g, "");
		if (!(is_comment_line(line) || is_ipv4(line, false) || has_colon(line) || (exclude_domain && check_excluded_domain(line)))) {
			let found = extract_domain(line);
			if (found != null && !is_ipv4(found, false))
				rule_dataset[found] = true;
		}
	}

	function fetch_rule(rule_name, rule_type, url, exclude_domain, max_retries) {
		let sret = 0;
		let max_attempts = max_retries;
		if (max_attempts == null || max_attempts === false)
			max_attempts = 2;
		let rule_dataset = {};
		let file_tmp = "/tmp/" + rule_name + "_tmp";
		let rule_final_path = rule_path + "/" + rule_name;
		if (geo2rule == "1") {
			url = ["geo2rule"];
			log(rule_name + " 开始生成...");
		} else {
			log(rule_name + " 开始更新...");
		}
		if (type(url) == "string")
			url = [url];
		if (type(url) != "array")
			url = [];

		for (let k = 0; k < length(url); k++) {
			let v = url[k];
			let current_file = "/tmp/" + rule_name + "_dl" + (k + 1);
			let success = false;
			if (v != "geo2rule") {
				for (let i = 1; i <= max_attempts; i++) {
					let curled = curl(v, current_file);
					let return_code = curled[0];
					let http_code = curled[1];
					let header = curled[2];
					if (return_code == 0 && !non_file_check(current_file, header)) {
						success = true;
						break;
					}
					api.remove(current_file);
					log(sprintf("%s 第%d条规则下载失败 (HTTP:%s)，正在进行第%d次尝试...", rule_name, k + 1, "" + http_code, i));
				}
			} else {
				if (!GeoToRule(rule_name, rule_type, current_file))
					return 1;
				success = true;
			}

			if (success) {
				if (rule_name == "gfwlist" && geo2rule == "0") {
					let raw = api.fs.readfile(current_file);
					if (raw != null) {
						let decode = api.base64Decode(raw);
						for (let line in gmatch(decode, /[^\r\n]+/g))
							consume_domain_line(rule_dataset, line, exclude_domain);
					}
				} else {
					let lines = read_lines(current_file);
					if (lines != null) {
						for (let line in lines) {
							if (rule_type == "domain")
								consume_domain_line(rule_dataset, line, exclude_domain);
							else if (rule_type == "ip4") {
								if (is_ipv4_cidr(line) && !is_0dot(line))
									rule_dataset[line] = true;
							} else if (rule_type == "ip6") {
								if (is_ipv6_cidr(line) && !is_double_colon_cidr(line))
									rule_dataset[line] = true;
							}
						}
					}
				}
			} else {
				sret = 1;
				log(sprintf("%s 第%d条规则: %s 下载失败！", rule_name, k + 1, v));
			}
			api.remove(current_file);
		}

		if (sret == 0) {
			let result_list = [];
			for (let line in keys(rule_dataset))
				push(result_list, line);
			sort(result_list);
			let data = "";
			for (let line in result_list)
				data += line + "\n";
			api.fs.writefile(file_tmp, data);
			let old_md5 = api.md5_file(rule_final_path);
			let new_md5 = api.md5_file(file_tmp);
			if (old_md5 != new_md5) {
				if (api.is_finded("fw4") && (rule_type == "ip4" || rule_type == "ip6")) {
					let nft_file = file_tmp + ".nft";
					let set_name = "psw_" + rule_name;
					if (rule_name == "chnroute")
						set_name = "psw_chn";
					else if (rule_name == "chnroute6")
						set_name = "psw_chn6";
					let addr_type = (rule_type == "ip4") ? "ipv4_addr" : "ipv6_addr";
					gen_cache(set_name, addr_type, file_tmp, nft_file);
					api.sys.call(sprintf("mv -f %s %s.nft", nft_file, rule_final_path));
				}
				api.sys.call(sprintf("mv -f %s %s", file_tmp, rule_final_path));
				if (!rollback)
					reboot = 1;
				log(sprintf("%s 更新成功，总规则数 %d 条。", rule_name, length(result_list)));
			} else {
				log(rule_name + " 版本一致，无需更新。");
				api.remove(file_tmp);
			}
		} else {
			log(rule_name + " 更新失败（部分或全部资源无法下载）。");
			api.remove(file_tmp);
		}
		return 0;
	}

	function fetch_geofile(geo_name, geo_type, url) {
		let tmp_path = "/tmp/" + geo_name;
		let asset_path = asset_location + geo_name;
		let fm = match("" + url, /^.*\/([^\/?#]+)/);
		if (fm == null)
			die("attempt to index a nil value");
		let down_filename = fm[1];
		let sha_url = replace_all_literal("" + url, down_filename, down_filename + ".sha256sum");
		let sha_path = tmp_path + ".sha256sum";

		function verify_sha256(sha_file) {
			return api.sys.call("sha256sum -c " + sha_file + " > /dev/null 2>&1") == 0;
		}

		let sha_curled = curl(sha_url, sha_path);
		let sha_verify = sha_curled[0] == 0;
		if (sha_verify) {
			let raw = api.fs.readfile(sha_path);
			if (raw != null) {
				let content = raw;
				let nl = index(content, "\n");
				if (nl >= 0)
					content = substr(content, 0, nl);
				if (substr(content, -1) == "\r")
					content = substr(content, 0, length(content) - 1);
				let hm = match(content, /([0-9A-Fa-f]+)[[:space:]]+.+/);
				if (hm != null) {
					let pre = index(content, hm[0]);
					if (pre < 0)
						pre = 0;
					content = substr(content, 0, pre) + hm[1] + "  " + tmp_path + substr(content, pre + length(hm[0]));
				}
				api.fs.writefile(sha_path, content);
			}
			if (api.fs.access(asset_path)) {
				api.sys.call(sprintf("cp -f %s %s", asset_path, tmp_path));
				if (verify_sha256(sha_path)) {
					log(geo_type + " 版本一致，无需更新。");
					return 0;
				}
			}
		}

		let curled = curl(url, tmp_path);
		let sret_tmp = curled[0];
		let header = curled[2];
		if (sret_tmp == 0 && non_file_check(tmp_path, header)) {
			log(geo_type + " 下载文件过程出错，尝试重新下载。");
			api.remove(tmp_path);
			curled = curl(url, tmp_path);
			sret_tmp = curled[0];
			header = curled[2];
			if (sret_tmp == 0 && non_file_check(tmp_path, header)) {
				sret_tmp = 1;
				log(geo_type + " 下载文件过程出错，请检查网络或下载链接后重试！");
			}
		}
		if (sret_tmp == 0) {
			if (sha_verify) {
				if (verify_sha256(sha_path)) {
					api.sys.call(sprintf("mkdir -p %s && mv -f %s %s", backup_path, asset_path, backup_path));
					api.sys.call(sprintf("mkdir -p %s && mv -f %s %s", asset_location, tmp_path, asset_path));
					reboot = 1;
					log(geo_type + " 更新成功。");
					if (geo_type == "geoip")
						geoip_update_ok = true;
					else
						geosite_update_ok = true;
				} else {
					log(geo_type + " 更新失败，请稍后重试或更换更新URL。");
					return 1;
				}
			} else {
				if (api.fs.access(asset_path) && api.sys.call(sprintf("cmp -s %s %s", tmp_path, asset_path)) == 0) {
					log(geo_type + " 版本一致，无需更新。");
					return 0;
				}
				api.sys.call(sprintf("mkdir -p %s && mv -f %s %s", backup_path, asset_path, backup_path));
				api.sys.call(sprintf("mkdir -p %s && mv -f %s %s", asset_location, tmp_path, asset_path));
				reboot = 1;
				log(geo_type + " 更新成功。");
				if (geo_type == "geoip")
					geoip_update_ok = true;
				else
					geosite_update_ok = true;
			}
		} else {
			log(geo_type + " 更新失败，请稍后重试或更换更新URL。");
			return 1;
		}
		return 0;
	}

	function fetch_gfwlist() {
		fetch_rule("gfwlist", "domain", gfwlist_url, true);
	}
	function fetch_chnroute() {
		fetch_rule("chnroute", "ip4", chnroute_url, false);
	}
	function fetch_chnroute6() {
		fetch_rule("chnroute6", "ip6", chnroute6_url, false);
	}
	function fetch_chnlist() {
		fetch_rule("chnlist", "domain", chnlist_url, false);
	}
	function fetch_geoip() {
		fetch_geofile("geoip.dat", "geoip", geoip_url);
	}
	function fetch_geosite() {
		fetch_geofile("geosite.dat", "geosite", geosite_url);
	}

	if (arg2 != null && arg2 !== false) {
		for (let w in gmatch("" + arg2, /[^,]+/g)) {
			if (w == "gfwlist")
				gfwlist_update = "1";
			if (w == "chnroute")
				chnroute_update = "1";
			if (w == "chnroute6")
				chnroute6_update = "1";
			if (w == "chnlist")
				chnlist_update = "1";
			if (w == "geoip")
				geoip_update = "1";
			if (w == "geosite")
				geosite_update = "1";
		}
		if (rollback)
			arg2 = null;
	} else {
		gfwlist_update = lor(api.uci_get_c("@global_rules[0]", "gfwlist_update"), "1");
		chnroute_update = lor(api.uci_get_c("@global_rules[0]", "chnroute_update"), "1");
		chnroute6_update = lor(api.uci_get_c("@global_rules[0]", "chnroute6_update"), "1");
		chnlist_update = lor(api.uci_get_c("@global_rules[0]", "chnlist_update"), "1");
		geoip_update = lor(api.uci_get_c("@global_rules[0]", "geoip_update"), "1");
		geosite_update = lor(api.uci_get_c("@global_rules[0]", "geosite_update"), "1");
	}

	if (geo2rule != "1" && gfwlist_update == "0" && chnroute_update == "0" && chnroute6_update == "0" && chnlist_update == "0" && geoip_update == "0" && geosite_update == "0") {
		update_lock.close();
		return;
	}

	log("开始更新规则...");

	function safe_call(func, err_msg) {
		try {
			func();
		} catch (e) {
			let msg = e;
			if (e != null && type(e) == "object")
				msg = e.message ?? e;
			log(msg);
			log(stack_string(e));
			log(err_msg);
		}
	}

	function remove_tmp_geofile(name) {
		api.remove("/tmp/" + name + ".dat");
		api.remove("/tmp/" + name + ".dat.sha256sum");
	}

	if (geo2rule == "1") {
		if (geoip_update == "1" && !rollback) {
			log("geoip 开始更新...");
			safe_call(fetch_geoip, "更新geoip发生错误...");
			remove_tmp_geofile("geoip");
		}
		if (geosite_update == "1" && !rollback) {
			log("geosite 开始更新...");
			safe_call(fetch_geosite, "更新geosite发生错误...");
			remove_tmp_geofile("geosite");
		}
		if (arg2 != null && arg2 !== false) {
			geoip_update_ok = true;
			geosite_update_ok = true;
		}
		if (!rollback) {
			chnroute_update = "1";
			chnroute6_update = "1";
			gfwlist_update = "1";
			chnlist_update = "1";
		}
		if (geoip_update_ok) {
			if (api.fs.access(asset_location + "geoip.dat")) {
				if (chnroute_update == "1")
					safe_call(fetch_chnroute, "生成chnroute发生错误...");
				if (chnroute6_update == "1")
					safe_call(fetch_chnroute6, "生成chnroute6发生错误...");
			} else {
				log("geoip.dat 文件不存在,跳过规则生成。");
			}
		}
		if (geosite_update_ok) {
			if (api.fs.access(asset_location + "geosite.dat")) {
				if (gfwlist_update == "1")
					safe_call(fetch_gfwlist, "生成gfwlist发生错误...");
				if (chnlist_update == "1")
					safe_call(fetch_chnlist, "生成chnlist发生错误...");
			} else {
				log("geosite.dat 文件不存在,跳过规则生成。");
			}
		}
	} else {
		if (gfwlist_update == "1")
			safe_call(fetch_gfwlist, "更新gfwlist发生错误...");
		if (chnroute_update == "1")
			safe_call(fetch_chnroute, "更新chnroute发生错误...");
		if (chnroute6_update == "1")
			safe_call(fetch_chnroute6, "更新chnroute6发生错误...");
		if (chnlist_update == "1")
			safe_call(fetch_chnlist, "更新chnlist发生错误...");
		if (geoip_update == "1") {
			log("geoip 开始更新...");
			safe_call(fetch_geoip, "更新geoip发生错误...");
			remove_tmp_geofile("geoip");
		}
		if (geosite_update == "1") {
			log("geosite 开始更新...");
			safe_call(fetch_geosite, "更新geosite发生错误...");
			remove_tmp_geofile("geosite");
		}
	}

	if (!rollback) {
		api.uci_set_c("@global_rules[0]", "gfwlist_update", gfwlist_update);
		api.uci_set_c("@global_rules[0]", "chnroute_update", chnroute_update);
		api.uci_set_c("@global_rules[0]", "chnroute6_update", chnroute6_update);
		api.uci_set_c("@global_rules[0]", "chnlist_update", chnlist_update);
		api.uci_set_c("@global_rules[0]", "geoip_update", geoip_update);
		api.uci_set_c("@global_rules[0]", "geosite_update", geosite_update);
		api.uci_save_c(true);
	}

	if (reboot == 1) {
		log("重启服务，应用新的规则。");
		api.uci_set_c("@global[0]", "flush_set", "1");
		api.uci_save_c(true);
	}
	log("规则更新完毕...\n");
	update_lock.close();
	if (reboot == 1) {
		let action = (arg3 == "cron") ? " cron" : "";
		api.sys.call("/etc/init.d/passwall restart" + action + " > /dev/null 2>&1 &");
	}
};
export { main };
