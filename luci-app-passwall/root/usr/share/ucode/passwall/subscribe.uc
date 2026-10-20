'use strict';

import * as fs from 'fs';
import * as api from 'passwall.api';
import { parseClashNode, parse_clash_sub_info } from 'passwall.clash_subconverter';
let luaOr, present, nonempty, luaNot, uci_get, uci_set, uci_del, uci_foreach, uci_save, str, log, flush_log_buffer, splitLit, at, last, parseQuery, slashQ, headTail, hostPort, cutHash, tlsAllow, asList, setFinalmask, normNet, setXhttpExtra, finishRemarks, singboxTransportBlocked, split_filter_keywords, prepare_keyword_filter, match_filter_keywords, is_filter_keyword, formatDate, get_subscribe_info, set_ss_implementation, applyWsHttp, fillCommonTransport, applySecurity, parseSSR, parseVmess, isURLEncodedPassword, parseShadowTLSParams, parseSS, parseTrojan, parseVless, parseHysteria, parseHysteria2, parseTuic, parseAnytls, parseNaive, parseSnell, processData, invokeCurl, splitCurlResult, passwallUaVersion, curl, groupAll, sameGroup, truncate_nodes, select_node, update_subscribe_info, listOf, new_node_id, update_node, blankLine, parse_link, nodeOrSocks, is_ip_port, build_config, init_state, execute, log_traceback, acquire_lock, release_lock, main;

let cli = [];
let restart_required = false;
let has_ss_rust = false;
let has_ssr = false;
let has_singbox = false;
let has_xray = false;
let has_hysteria2 = false;
let DEFAULT_ALLOWINSECURE = true;
let DEFAULT_FILTER_KEYWORD = { mode: "0", discard_list: [], keep_list: [] };
let DEFAULT_SS_TYPE = null;
let DEFAULT_TROJAN_TYPE = null;
let DEFAULT_VMESS_TYPE = null;
let DEFAULT_VLESS_TYPE = null;
let DEFAULT_HYSTERIA2_TYPE = null;
let core_has = {};
let nodeResult = [];
let isDebug = false;
let log_buffer = null;
let nodes_table = [];
let CONFIG = [];
let subscribe_info = {};
let curl_http_code = null;
let curl_header = null;
let update_lock = null;

luaOr = function(a, b) {
	if (a !== null && a !== false)
		return a;
	return b;
};

present = function(v) {
	return v !== null && v !== false;
};

nonempty = function(v) {
	return v !== null && v !== false && v !== "";
};

luaNot = function(v) {
	return v === null || v === false;
};

uci_get = function(section, option) {
	return api.uci_get_c(section, option);
};

uci_set = function(section, option, value) {
	if (type(value) == "int" || type(value) == "double")
		value = "" + value;
	else if (type(value) == "bool")
		value = value ? "1" : "0";
	return api.uci_set_c(section, option, value);
};

uci_del = function(section, option) {
	return api.uci_del_c(section, option);
};

uci_foreach = function(stype, fn) {
	return api.uci_foreach_c(stype, fn);
};

uci_save = function(commit, apply) {
	return api.uci_save_c(commit, apply);
};

str = function(v) {
	if (v === null || v === false)
		return "";
	if (type(v) == "string")
		return v;
	return "" + v;
};

log = function(...args) {
	let parts = [];
	for (let a in args)
		push(parts, str(a));
	let msg = length(args) == 1 ? str(args[0]) : join(" ", parts);
	if (log_buffer !== null) {
		push(log_buffer, msg);
	} else if (isDebug === true) {
		let t = localtime();
		printf("%04d-%02d-%02d %02d:%02d:%02d: %s\n", t.year, t.mon, t.mday, t.hour, t.min, t.sec, msg);
	} else {
		api.log(...args);
	}
};

flush_log_buffer = function() {
	let buffered = log_buffer;
	log_buffer = null;
	if (type(buffered) == "array") {
		for (let msg in buffered)
			log(msg);
	}
};

splitLit = function(full, sep) {
	if (type(full) != "string")
		return [];
	let parts = api.split(full, sep);
	return type(parts) == "array" ? parts : [];
};

at = function(arr, i) {
	if (type(arr) != "array" || i < 0 || i >= length(arr))
		return null;
	return arr[i];
};

last = function(arr, back) {
	if (type(arr) != "array" || length(arr) == 0)
		return null;
	return arr[length(arr) - 1 - back];
};

parseQuery = function(q, lowerKeys, decodeVal, decodeKey) {
	let params = {};
	if (type(q) != "string" || q === "")
		return params;
	for (let v in splitLit(q, "&")) {
		if (type(v) != "string")
			continue;
		let s = index(v, "=");
		if (s > 0) {
			let key = substr(v, 0, s);
			let val = substr(v, s + 1);
			if (decodeKey)
				key = api.UrlDecode(key);
			if (lowerKeys)
				key = lc(key);
			if (decodeVal)
				val = api.UrlDecode(val);
			params[key] = val;
		}
	}
	return params;
};

slashQ = function(s) {
	if (type(s) != "string")
		return "";
	return replace(s, /\/\?/g, "?");
};

headTail = function(s, sep) {
	let parts = splitLit(s, sep);
	return [at(parts, 0) ?? "", length(parts) > 1 ? at(parts, 1) : null];
};

hostPort = function(host_port, defaultPort) {
	if (type(host_port) != "string")
		die("bad host");
	let address = host_port;
	let port = defaultPort;
	if (index(host_port, ":") >= 0) {
		let sp = splitLit(host_port, ":");
		port = last(sp, 0);
		if (api.is_ipv6addrport(host_port))
			address = api.get_ipv6_only(host_port);
		else
			address = at(sp, 0);
	}
	return [address, port];
};

cutHash = function(content) {
	let idx = index(content, "#");
	if (idx < 0)
		return [content, ""];
	return [substr(content, 0, idx), api.UrlDecode(substr(content, idx + 1))];
};

tlsAllow = function(insecure, subAllow) {
	if (insecure === "1" || insecure === "0")
		return insecure;
	return subAllow ? "1" : "0";
};

asList = function(v) {
	if (nonempty(v))
		return [v];
	return null;
};

setFinalmask = function(result, fm) {
	if (nonempty(fm)) {
		result.use_finalmask = "1";
		result.finalmask = api.base64Encode(fm);
	} else {
		result.use_finalmask = null;
		result.finalmask = null;
	}
};

normNet = function(result, net) {
	net = lc(net);
	if (result.type == "sing-box" && net == "raw")
		return "tcp";
	if (result.type == "Xray" && net == "tcp")
		return "raw";
	return net;
};

setXhttpExtra = function(result, extra) {
	result.use_xhttp_extra = nonempty(extra) ? "1" : null;
	result.xhttp_extra = nonempty(extra) ? api.base64Encode(extra) : null;
	if (!nonempty(extra))
		return;
	let Data = null;
	try {
		Data = api.jsonc.parse(extra);
	} catch (e) {
		Data = null;
	}
	if (type(Data) != "object" || Data === null)
		return;
	let address = null;
	if (Data.extra && Data.extra.downloadSettings && present(Data.extra.downloadSettings.address))
		address = Data.extra.downloadSettings.address;
	else if (Data.downloadSettings && present(Data.downloadSettings.address))
		address = Data.downloadSettings.address;
	if (nonempty(address))
		result.download_address = replace(replace("" + address, /^\[/, ""), /\]$/, "");
};

finishRemarks = function(result) {
	if (!present(result.remarks) || result.remarks === "") {
		if (present(result.address) && present(result.port))
			result.remarks = str(result.address) + ":" + str(result.port);
		else
			result.remarks = "NULL";
	}
	return result;
};

singboxTransportBlocked = function(result, szType) {
	if (result.type == "sing-box" && (result.transport == "mkcp" || result.transport == "xhttp")) {
		log("跳过节点：" + result.remarks + "，因 Sing-Box 不支持 " + szType + " 协议的 " + result.transport + " 传输方式，需更换 Xray。");
		return true;
	}
	return false;
};

split_filter_keywords = function(list) {
	let keywords = [];
	let seen = {};
	if (type(list) == "string")
		list = [list];
	if (type(list) != "array")
		return keywords;
	for (let row in list) {
		if (type(row) != "string")
			continue;
		let parts = match(row, /[^|]+/g);
		if (parts === null)
			continue;
		for (let part in parts) {
			let keyword = part[0];
			if (seen[keyword] !== true) {
				seen[keyword] = true;
				push(keywords, keyword);
			}
		}
	}
	return keywords;
};

prepare_keyword_filter = function(sub_cfg) {
	let mode = sub_cfg ? sub_cfg.filter_keyword_mode : null;
	if (mode === "0" || mode === "1" || mode === "2" || mode === "3" || mode === "4") {
		return {
			mode: mode,
			discard_list: split_filter_keywords(sub_cfg.filter_discard_list),
			keep_list: split_filter_keywords(sub_cfg.filter_keep_list)
		};
	}
	return DEFAULT_FILTER_KEYWORD;
};

match_filter_keywords = function(value, keywords) {
	if (type(value) != "string")
		return false;
	for (let keyword in keywords) {
		if (index(value, keyword) >= 0)
			return true;
	}
	return false;
};

is_filter_keyword = function(filter, value) {
	if (filter.mode === "1")
		return match_filter_keywords(value, filter.discard_list);
	if (filter.mode === "2")
		return !match_filter_keywords(value, filter.keep_list);
	if (filter.mode === "3")
		return match_filter_keywords(value, filter.discard_list) && !match_filter_keywords(value, filter.keep_list);
	if (filter.mode === "4")
		return match_filter_keywords(value, filter.discard_list) || !match_filter_keywords(value, filter.keep_list);
	return false;
};

formatDate = function(s) {
	let m = match(s, /([0-9]{4})[-/]?([0-9]{1,2})[-/]?([0-9]{1,2})/);
	if (m)
		return m[1] + "." + m[2] + "." + m[3];
	return s;
};

get_subscribe_info = function(cfgid, value) {
	if (type(cfgid) != "string" || cfgid === "" || type(value) != "string")
		return;
	let info = subscribe_info[cfgid];
	if (info && nonempty(info.expired_date) && nonempty(info.rem_traffic))
		return;
	value = replace(value, /\s+/g, "");
	let date_patterns = [/套餐到期：(.+)/, /过期时间：(.+)/, /有效期至：(.+)/, /到期时间：(.+)/, /截止日期：(.+)/];
	let rem_patterns = [/剩余流量：(.+)/, /流量剩余：(.+)/, /可用流量：(.+)/, /套餐剩余：(.+)/];
	let expired_date = null;
	for (let p in date_patterns) {
		let m = match(value, p);
		expired_date = m ? m[1] : expired_date;
	}
	let rem_traffic = null;
	for (let p in rem_patterns) {
		let m = match(value, p);
		rem_traffic = m ? m[1] : rem_traffic;
	}
	if (subscribe_info[cfgid] === null)
		subscribe_info[cfgid] = { expired_date: "", rem_traffic: "" };
	if (expired_date !== null)
		subscribe_info[cfgid].expired_date = formatDate(expired_date);
	if (rem_traffic !== null)
		subscribe_info[cfgid].rem_traffic = rem_traffic;
};

set_ss_implementation = function(ss_type, result) {
	if (ss_type == "shadowsocks-rust" && has_ss_rust) {
		result.type = "SS-Rust";
	} else if (ss_type == "xray" && has_xray) {
		result.type = "Xray";
		result.protocol = "shadowsocks";
		result.transport = "raw";
	} else if (ss_type == "sing-box" && has_singbox) {
		result.type = "sing-box";
		result.protocol = "shadowsocks";
	} else {
		log("跳过 SS 节点，因未适配到 SS 核心程序，或未正确设置节点使用类型。");
		return null;
	}
	return result;
};

applyWsHttp = function(result, net, host, path, headerType, opt) {
	if (net == "ws") {
		result.ws_host = host;
		result.ws_path = path;
	}
	if (net == "http") {
		if (result.type == "sing-box" || (opt && opt.vmessSingbox)) {
			if (result.type != "Xray") {
				result.transport = "http";
				result.http_host = asList(host);
				result.http_path = path;
			}
		}
		if (result.type == "Xray") {
			result.transport = result.transport == "raw" && opt && opt.keepRaw ? "raw" : "xhttp";
			if (!(opt && opt.keepRaw && result.transport == "raw")) {
				result.xhttp_mode = "stream-one";
				result.xhttp_host = host;
				result.xhttp_path = path;
			}
		}
		if (result.type != "Xray" && result.type != "sing-box" && !(opt && opt.vmessSingbox)) {
			result.http_host = asList(host);
			result.http_path = path;
		}
	}
};

fillCommonTransport = function(result, net, p, opt) {
	let host = p.host;
	let path = p.path;
	let headerType = luaOr(p.headerType, "none");
	if (net == "ws") {
		result.ws_host = host;
		result.ws_path = path;
	}
	if (net == "http") {
		if (result.type == "sing-box") {
			result.transport = "http";
			result.http_host = asList(host);
			result.http_path = path;
		} else if (result.type == "Xray") {
			result.transport = "xhttp";
			result.xhttp_mode = "stream-one";
			result.xhttp_host = host;
			result.xhttp_path = path;
		}
	}
	if (net == "raw" || net == "tcp") {
		result.tcp_guise = headerType;
		result.tcp_guise_http_host = asList(host);
		result.tcp_guise_http_path = asList(path);
	}
	if (net == "kcp" || net == "mkcp") {
		result.transport = "mkcp";
		result.mkcp_guise = headerType;
		result.mkcp_seed = p.seed;
	}
	if (net == "quic") {
		result.quic_guise = headerType;
		result.quic_key = p.key;
		result.quic_security = luaOr(p.quicSecurity, "none");
	}
	if (net == "grpc") {
		if (opt && opt.grpcPreferPath) {
			if (present(path))
				result.grpc_serviceName = path;
			if (present(p.serviceName))
				result.grpc_serviceName = p.serviceName;
		} else {
			result.grpc_serviceName = luaOr(p.serviceName, path);
		}
		if (!(opt && opt.noGrpcMode))
			result.grpc_mode = luaOr(p.mode, "gun");
	}
	if (net == "xhttp") {
		result.xhttp_host = host;
		result.xhttp_path = path;
		if (opt && opt.xhttpMode)
			result.xhttp_mode = luaOr(p.mode, "auto");
		if (opt && opt.xhttpExtra)
			setXhttpExtra(result, p.extra);
		if (opt && opt.xhttpRequireXray && result.type != "Xray")
			result.error_msg = "请更换 Xray 以支持 xhttp 传输方式。";
	}
	if (net == "httpupgrade" && opt && opt.httpupgrade) {
		result.httpupgrade_host = host;
		result.httpupgrade_path = path;
	}
};

applySecurity = function(result, params, subAllow, opt) {
	result.tls = "0";
	if (params.security == "tls" || params.security == "reality") {
		result.tls = "1";
		if (opt && opt.sniPeer)
			result.tls_serverName = luaOr(luaOr(params.peer, params.sni), "");
		else if (opt && opt.sniOrHost)
			result.tls_serverName = nonempty(params.sni) ? params.sni : params.host;
		else
			result.tls_serverName = nonempty(params.sni) ? params.sni : params.host;
		result.alpn = params.alpn;
		if (nonempty(params.fp)) {
			result.utls = "1";
			result.fingerprint = params.fp;
		}
		if (nonempty(params.ech)) {
			result.ech = "1";
			result.ech_config = params.ech;
		}
		result.tls_pinSHA256 = params.pcs;
		result.tls_CertByName = params.vcn;
		if (params.security == "reality") {
			result.reality = "1";
			result.reality_publicKey = params.pbk ?? null;
			result.reality_shortId = params.sid ?? null;
			if (opt && opt.realityFull) {
				result.reality_spiderX = params.spx ?? null;
				result.use_mldsa65Verify = nonempty(params.pqv) ? "1" : null;
				result.reality_mldsa65Verify = params.pqv ?? null;
			}
		}
	}
	let insecure = luaOr(luaOr(params.allowinsecure, params.allowInsecure), params.insecure);
	if (opt && opt.insecureExtra)
		insecure = luaOr(insecure, params.allow_insecure);
	result.tls_allowInsecure = tlsAllow(insecure, subAllow);
};

parseSSR = function(content, result) {
	if (!has_ssr) {
		log("跳过 SSR 节点，因未安装 SSR 核心程序 shadowsocksr-libev。");
		return null;
	}
	result.type = "SSR";
	let dat = splitLit(slashQ(content), "?");
	let main = at(dat, 0) ?? "";
	let hostInfo = splitLit(main, ":");
	let bracket = match(main, /\[(.*)\]/);
	if (bracket)
		result.address = bracket[1];
	else
		result.address = last(hostInfo, 5);
	result.port = last(hostInfo, 4);
	result.protocol = last(hostInfo, 3);
	result.method = last(hostInfo, 2);
	result.obfs = last(hostInfo, 1);
	result.password = api.base64Decode(last(hostInfo, 0));
	let params = parseQuery(at(dat, 1), false, false, false);
	result.obfs_param = api.base64Decode(params.obfsparam);
	result.protocol_param = api.base64Decode(params.protoparam);
	result.remarks = api.base64Decode(params.remarks);
	return result;
};

parseVmess = function(content, result, subAllow) {
	if (result.type === null) {
		// type is chosen by the caller before entry
	}
	let info = null;
	try {
		info = api.jsonc.parse(content);
	} catch (e) {
		info = null;
	}
	if (type(info) != "object" || info === null) {
		if (index(content, "?") >= 0) {
			info = {};
			let Info = splitLit(slashQ(content), "?");
			let sp = splitLit(api.base64Decode(at(Info, 0) ?? ""), "@");
			let id_info = splitLit(at(sp, 0) ?? "", ":");
			info.security = (length(id_info) > 1 && at(id_info, 0) !== "") ? at(id_info, 0) : "auto";
			info.id = last(id_info, 0);
			let addr = at(sp, 1);
			let port = "443";
			if (api.is_ipv6addrport(addr)) {
				let m = match(addr, /^\[(.+)\]:([0-9]+)$/);
				if (m) {
					addr = m[1];
					port = m[2];
				}
				addr = api.get_ipv6_only(addr);
			} else {
				let host_port = splitLit(addr ?? "", ":");
				addr = at(host_port, 0);
				if (length(host_port) > 1)
					port = last(host_port, 0);
			}
			info.add = addr;
			info.port = port;
			let params = parseQuery(at(Info, 1), false, true, false);
			info.ps = luaOr(params.remark, params.remarks);
			info.net = params.obfs == "websocket" ? "ws" : luaOr(params.obfs, "tcp");
			info.path = params.path;
			info.aid = luaOr(params.alterId, "0");
			info.tls = params.tls;
			info.sni = params.peer;
			info.tfo = params.tfo;
			let op_info = null;
			try {
				op_info = api.jsonc.parse(params.obfsParam);
			} catch (e) {
				op_info = null;
			}
			if (type(op_info) == "object" && op_info !== null) {
				if (present(op_info.header))
					info.type = op_info.header;
				if (present(op_info.Host))
					info.host = op_info.Host;
			} else {
				info.host = params.obfsParam;
			}
			info.allowinsecure = params.allowInsecure;
		} else {
			log("跳过 VMess 节点，该节点 URI 格式无法解析。");
			return null;
		}
	}

	result.alter_id = info.aid;
	result.address = info.add;
	result.port = info.port;
	result.protocol = "vmess";
	result.uuid = info.id;
	result.remarks = info.ps;
	info.path = nonempty(info.path) ? api.UrlDecode(str(info.path)) : null;
	if (!present(info.net))
		info.net = "tcp";
	info.net = lc(str(info.net));
	if (result.type == "sing-box" && info.net == "raw")
		info.net = "tcp";
	else if (result.type == "Xray" && info.net == "tcp")
		info.net = "raw";
	// Clash 'network: http' is TCP + HTTP header obfuscation, not xhttp.
	if (info.net == "http" && result.type == "Xray") {
		info.net = "raw";
		info.type = "http";
		result.transport = "raw";
	} else if (info.net == "h2" || info.net == "http") {
		info.net = "http";
		result.transport = result.type == "Xray" ? "xhttp" : "http";
	} else {
		result.transport = info.net;
	}
	if (info.net == "ws") {
		result.ws_host = info.host;
		result.ws_path = info.path;
	}
	if (info.net == "http") {
		if (result.type == "Xray") {
			result.xhttp_mode = "stream-one";
			result.xhttp_host = info.host;
			result.xhttp_path = info.path;
		} else {
			result.http_host = asList(info.host);
			result.http_path = info.path;
		}
	}
	if (info.net == "raw" || info.net == "tcp") {
		if (present(info.type) && info.type != "http")
			info.type = "none";
		result.tcp_guise = info.type;
		result.tcp_guise_http_host = asList(info.host);
		result.tcp_guise_http_path = asList(info.path);
	}
	if (info.net == "kcp" || info.net == "mkcp") {
		info.net = "mkcp";
		result.mkcp_guise = info.type;
		result.mkcp_seed = info.seed;
	}
	if (info.net == "quic") {
		result.quic_guise = info.type;
		result.quic_key = info.key;
		result.quic_security = info.securty;
	}
	if (info.net == "grpc")
		result.grpc_serviceName = info.path;
	if (info.net == "xhttp") {
		result.xhttp_host = info.host;
		result.xhttp_path = info.path;
	}
	if (info.net == "httpupgrade") {
		result.httpupgrade_host = info.host;
		result.httpupgrade_path = info.path;
	}
	result.security = luaOr(luaOr(info.security, info.scy), "auto");
	if (info.tls == "tls" || info.tls == "1") {
		result.tls = "1";
		result.alpn = info.alpn;
		if (nonempty(info.fp)) {
			result.utls = "1";
			result.fingerprint = info.fp;
		}
		result.tls_serverName = nonempty(info.sni) ? info.sni : info.host;
		result.tls_pinSHA256 = info.pcs;
		result.tls_CertByName = info.vcn;
		let insecure = luaOr(luaOr(info.allowinsecure, info.allowInsecure), info.insecure);
		result.tls_allowInsecure = tlsAllow(insecure, subAllow);
	} else {
		result.tls = "0";
	}
	if (nonempty(info.ech)) {
		result.ech = "1";
		result.ech_config = info.ech;
	}
	result.tcp_fast_open = info.tfo;
	info.fm = nonempty(info.fm) ? api.UrlDecode(str(info.fm)) : null;
	setFinalmask(result, info.fm);
	if (result.type == "sing-box" && (result.transport == "mkcp" || result.transport == "xhttp")) {
		log("跳过节点:" + result.remarks + "，因Sing-Box不支持" + "vmess" + "协议的" + result.transport + "传输方式，需更换Xray。");
		return null;
	}
	return result;
};

isURLEncodedPassword = function(pwd) {
	if (type(pwd) != "string" || match(pwd, /%[0-9A-Fa-f][0-9A-Fa-f]/) === null)
		return false;
	try {
		let decoded = api.UrlDecode(pwd);
		return api.UrlEncode(decoded) == pwd;
	} catch (e) {
		return false;
	}
};

parseShadowTLSParams = function(b64str, out) {
	let data = null;
	try {
		data = api.jsonc.parse(api.base64Decode(b64str));
	} catch (e) {
		data = null;
	}
	if (type(data) != "object" || data === null)
		return "";
	if (type(out) == "object" && out !== null) {
		for (let k, v in data)
			out[k] = v;
	}
	let t = [];
	if (present(data.version))
		push(t, "v" + data.version + "=1");
	if (present(data.password))
		push(t, "passwd=" + data.password);
	for (let k, v in data) {
		if (k != "version" && k != "password")
			push(t, k + "=" + str(v));
	}
	return join(";", t);
};

parseSS = function(content, result, subAllow, subSsType) {
	result = set_ss_implementation(subSsType, result);
	if (result === null)
		return null;
	let idx = index(content, "#");
	let alias = "";
	let info;
	if (idx >= 0)
		alias = substr(content, idx + 1);
	result.remarks = api.UrlDecode(alias);
	if (idx < 0)
		info = content;
	else
		info = substr(content, 0, idx);
	info = slashQ(info);
	let params = {};
	let qpos = index(info, "?");
	if (qpos >= 0) {
		let query = splitLit(info, "?");
		params = parseQuery(at(query, 1), false, true, false);
		if (present(params.plugin)) {
			let plugin_info = params.plugin;
			let idx_pn = index(plugin_info, ";");
			if (idx_pn >= 0) {
				result.plugin = substr(plugin_info, 0, idx_pn);
				result.plugin_opts = substr(plugin_info, idx_pn + 1);
				result.plugin_opts = replace(result.plugin_opts, /^password=/, "passwd=");
				result.plugin_opts = replace(result.plugin_opts, /;password=/g, ";passwd=");
				result.plugin_opts = replace(result.plugin_opts, /^version=([123])/, "v$1=1");
				result.plugin_opts = replace(result.plugin_opts, /;version=([123])/g, ";v$1=1");
			} else {
				result.plugin = plugin_info;
			}
		}
		if (result.plugin === "simple-obfs")
			result.plugin = "obfs-local";
		info = substr(info, 0, qpos);
	}

	let hostInfo = splitLit(api.base64Decode(api.UrlDecode(info)), "@");
	if (type(hostInfo) == "array" && length(hostInfo) > 0) {
		let host_port = last(hostInfo, 0);
		if (index(host_port, ":") >= 0) {
			let sp = splitLit(host_port, ":");
			result.port = last(sp, 0);
			if (api.is_ipv6addrport(host_port))
				result.address = api.get_ipv6_only(host_port);
			else
				result.address = at(sp, 0);
		} else {
			result.address = host_port;
		}
		let userinfo = null;
		if (length(hostInfo) > 2) {
			let chunks = [];
			for (let i = 0; i < length(hostInfo) - 1; i++)
				push(chunks, hostInfo[i]);
			userinfo = join("@", chunks);
		} else {
			userinfo = api.base64Decode(at(hostInfo, 0));
		}
		let method = null;
		let password = null;
		let colon = index(userinfo ?? "", ":");
		if (colon >= 0) {
			method = substr(userinfo, 0, colon);
			password = substr(userinfo, colon + 1);
		} else {
			password = at(hostInfo, 0);
		}
		let decoded = api.UrlDecode(password ?? "");
		if (isURLEncodedPassword(password) && decoded !== null && decoded !== false)
			password = decoded;
		let _method = lc(luaOr(method, "none"));
		method = _method == "chacha20-poly1305" ? "chacha20-ietf-poly1305" : (_method == "xchacha20-poly1305" ? "xchacha20-ietf-poly1305" : _method);
		result.method = method;
		result.ss_method = method;
		result.password = password;
		result.tcp_fast_open = params.tfo;
		setFinalmask(result, params.fm);

		let need_upgrade = result.type != "Xray" && result.type != "sing-box" && present(params.type) && params.type != "tcp" && present(params.headerType) && params.headerType != "none";
		if (has_xray && (need_upgrade || params.type == "xhttp")) {
			result.type = "Xray";
			result.protocol = "shadowsocks";
		} else if (has_singbox && need_upgrade) {
			result.type = "sing-box";
			result.protocol = "shadowsocks";
		}

		if (present(result.plugin)) {
			if (result.type == "Xray") {
				if (result.plugin != "obfs-local") {
					result.error_msg = "Xray 不支持 SS " + result.plugin + " 插件。";
				} else {
					let opts = result.plugin_opts ?? "";
					let m1 = match(opts, /(^|;)obfs=([^;]+)/);
					let m2 = match(opts, /(^|;)obfs-host=([^;]+)/);
					let obfs = m1 ? m1[2] : "";
					let obfs_host = m2 ? m2[2] : "";
					if (obfs == "" || obfs_host == "")
						result.error_msg = "SS " + result.plugin + " 插件选项不完整。";
					if (obfs == "http") {
						result.transport = "raw";
						result.tcp_guise = "http";
						result.tcp_guise_http_host = asList(obfs_host);
						result.tcp_guise_http_path = ["/"];
					} else if (obfs == "tls") {
						result.tls = "1";
						result.tls_serverName = obfs_host;
						result.tls_allowInsecure = "1";
					}
					result.plugin = null;
					result.plugin_opts = null;
				}
			} else if (result.type == "sing-box") {
				if (result.plugin != "obfs-local" && result.plugin != "v2ray-plugin" && result.plugin != "shadow-tls") {
					result.error_msg = "Sing-Box 不支持 SS " + result.plugin + " 插件。";
				} else {
					result.plugin_enabled = "1";
					if (result.plugin == "shadow-tls") {
						let items = match(result.plugin_opts ?? "", /[^;]+/g) ?? [];
						for (let item in items) {
							let kv = match(item[0], /^([^=]+)=(.*)$/);
							if (kv === null)
								continue;
							if (kv[1] == "host")
								result.shadowtls_serverName = kv[2];
							if (kv[1] == "passwd")
								result.shadowtls_password = kv[2];
							if (match(kv[1], /^v[123]$/))
								result.shadowtls_version = substr(kv[1], 1, 1);
						}
						result.shadowtls = "1";
						result.plugin_opts = null;
						result.plugin_enabled = null;
					}
				}
			} else {
				result.plugin_enabled = "1";
			}
		}

		if (present(params.type)) {
			params.type = lc(params.type);
			params.type = normNet(result, params.type);
			if (params.type == "h2" || params.type == "http") {
				params.type = "http";
				result.transport = result.type == "Xray" ? "xhttp" : "http";
			} else {
				result.transport = params.type;
			}
			if (result.type != "SS-Rust") {
				fillCommonTransport(result, params.type, {
					host: params.host,
					path: params.path,
					headerType: params.headerType,
					seed: params.seed,
					key: params.key,
					quicSecurity: params.quicSecurity,
					serviceName: params.serviceName,
					mode: params.mode,
					extra: params.extra
				}, { grpcPreferPath: true, xhttpMode: true, xhttpExtra: true, xhttpRequireXray: true });
				applySecurity(result, params, subAllow, { sniOrHost: true, realityFull: true });
				result.uot = params.udp;
			} else {
				result.error_msg = "请更换 Xray 或 Sing-Box 来支持 SS 更多的传输方式。";
			}
		}

		if (present(params["shadow-tls"])) {
			if (result.type != "sing-box" && result.type != "SS-Rust") {
				result.error_msg = subSsType + " 不支持 shadow-tls 插件。";
			} else if (result.type == "SS-Rust") {
				result.plugin_enabled = "1";
				result.plugin = "shadow-tls";
				result.plugin_opts = parseShadowTLSParams(params["shadow-tls"]);
			} else if (result.type == "sing-box") {
				let shadowtlsOpt = {};
				parseShadowTLSParams(params["shadow-tls"], shadowtlsOpt);
				if (length(shadowtlsOpt) > 0) {
					result.shadowtls = "1";
					result.shadowtls_version = luaOr(shadowtlsOpt.version, "1");
					result.shadowtls_password = shadowtlsOpt.password;
					result.shadowtls_serverName = shadowtlsOpt.host;
					if (present(shadowtlsOpt.fingerprint)) {
						result.shadowtls_utls = "1";
						result.shadowtls_fingerprint = luaOr(shadowtlsOpt.fingerprint, "chrome");
					}
				}
			}
		}
	}
	return result;
};

parseTrojan = function(content, result, subAllow) {
	let cut = cutHash(content);
	content = cut[0];
	result.remarks = cut[1];
	if (index(content, "@") < 0)
		return result;
	let Info = splitLit(content, "@");
	result.password = api.UrlDecode(at(Info, 0) ?? "");
	let port = "443";
	let right = slashQ(at(Info, 1) ?? "");
	let query = splitLit(right, "?");
	let host_port = at(query, 0) ?? "";
	let params = parseQuery(at(query, 1), false, true, false);
	let hp = hostPort(host_port, port);
	result.address = hp[0];
	result.port = hp[1];
	params.security = luaOr(params.security, "tls");
	if (params.security == "tls" || params.security == "reality") {
		result.tls = "1";
		result.tls_serverName = luaOr(luaOr(params.peer, params.sni), "");
		result.alpn = params.alpn;
		if (nonempty(params.fp)) {
			result.utls = "1";
			result.fingerprint = params.fp;
		}
		if (params.security == "reality") {
			result.reality = "1";
			result.reality_publicKey = params.pbk ?? null;
			result.reality_shortId = params.sid ?? null;
		}
		if (nonempty(params.ech)) {
			result.ech = "1";
			result.ech_config = params.ech;
		}
		result.tls_pinSHA256 = params.pcs;
		result.tls_CertByName = params.vcn;
		let insecure = luaOr(luaOr(params.allowinsecure, params.allowInsecure), params.insecure);
		result.tls_allowInsecure = tlsAllow(insecure, subAllow);
	}
	if (!present(params.type))
		params.type = "tcp";
	params.type = normNet(result, lc(params.type));
	if (params.type == "h2" || params.type == "http") {
		params.type = "http";
		result.transport = result.type == "Xray" ? "xhttp" : "http";
	} else {
		result.transport = params.type;
	}
	fillCommonTransport(result, params.type, {
		host: params.host,
		path: params.path,
		headerType: params.headerType,
		seed: params.seed,
		key: params.key,
		quicSecurity: params.quicSecurity,
		serviceName: params.serviceName,
		mode: params.mode
	}, { httpupgrade: true });
	result.tcp_fast_open = params.tfo;
	setFinalmask(result, params.fm);
	if (singboxTransportBlocked(result, "trojan"))
		return null;
	return result;
};

parseVless = function(content, result, subAllow) {
	result.protocol = "vless";
	let cut = cutHash(content);
	content = cut[0];
	result.remarks = cut[1];
	if (index(content, "@") < 0)
		return result;
	let Info = splitLit(content, "@");
	result.uuid = api.UrlDecode(at(Info, 0) ?? "");
	let port = "443";
	let right = slashQ(at(Info, 1) ?? "");
	let query = splitLit(right, "?");
	let host_port = at(query, 0) ?? "";
	let params = parseQuery(at(query, 1), false, true, false);
	let hp = hostPort(host_port, port);
	result.address = hp[0];
	port = hp[1];
	if (!present(params.type))
		params.type = "tcp";
	params.type = lc(params.type);
	if ((params.type == "xhttp" || params.type == "kcp" || params.type == "mkcp") && result.type != "Xray" && has_xray)
		result.type = "Xray";
	params.type = normNet(result, params.type);
	if (params.type == "h2" || params.type == "http") {
		params.type = "http";
		result.transport = result.type == "Xray" ? "xhttp" : "http";
	} else {
		result.transport = params.type;
	}
	fillCommonTransport(result, params.type, {
		host: params.host,
		path: params.path,
		headerType: params.headerType,
		seed: params.seed,
		key: params.key,
		quicSecurity: params.quicSecurity,
		serviceName: params.serviceName,
		mode: params.mode,
		extra: params.extra
	}, { grpcPreferPath: true, xhttpMode: true, xhttpExtra: true, httpupgrade: true });
	result.encryption = luaOr(params.encryption, "none");
	result.flow = params.flow;
	if ((!present(params.security) || params.security === "") && present(params.flow))
		params.security = "tls";
	applySecurity(result, params, subAllow, { sniOrHost: true, realityFull: true });
	result.port = port;
	result.tcp_fast_open = params.tfo;
	setFinalmask(result, params.fm);
	if (singboxTransportBlocked(result, "vless"))
		return null;
	return result;
};

parseHysteria = function(content, result, subAllow, subUp, subDown) {
	let cut = cutHash(content);
	content = cut[0];
	result.remarks = cut[1];
	let query = splitLit(slashQ(content), "?");
	let host_port = at(query, 0) ?? "";
	let params = parseQuery(at(query, 1), false, false, false);
	let hp = hostPort(host_port, null);
	result.address = hp[0];
	result.port = hp[1];
	result.hysteria_obfs = params.obfsParam;
	result.hysteria_auth_type = "string";
	result.hysteria_auth_password = params.auth;
	result.tls_serverName = luaOr(luaOr(params.peer, params.sni), "");
	result.tls_pinSHA256 = luaOr(params.pcs, params.pinSHA256);
	let insecure = luaOr(luaOr(params.allowinsecure, params.allowInsecure), params.insecure);
	result.tls_allowInsecure = tlsAllow(insecure, subAllow);
	result.alpn = params.alpn;
	result.hysteria_up_mbps = luaOr(params.upmbps, subUp);
	result.hysteria_down_mbps = luaOr(params.downmbps, subDown);
	result.hysteria_hop = params.mport;
	return result;
};

parseHysteria2 = function(content, result, subAllow, subCfg, subUp, subDown, subHy2Type) {
	let cut = cutHash(content);
	content = cut[0];
	result.remarks = cut[1];
	let Info = content;
	if (index(content, "@") >= 0) {
		let contents = splitLit(content, "@");
		result.hysteria2_auth_password = api.UrlDecode(at(contents, 0) ?? "");
		Info = slashQ(at(contents, 1) ?? "");
	}
	let query = splitLit(Info, "?");
	let host_port = at(query, 0) ?? "";
	let params = parseQuery(at(query, 1), true, true, false);
	let hp = hostPort(host_port, null);
	result.address = hp[0];
	result.port = hp[1];
	result.tls_serverName = params.sni;
	result.tls_pinSHA256 = luaOr(params.pcs, params.pinsha256);
	result.tls_CertByName = params.vcn;
	result.hysteria2_up_mbps = luaOr(params.upmbps, subCfg ? subUp : null);
	result.hysteria2_down_mbps = luaOr(params.downmbps, subCfg ? subDown : null);
	result.hysteria2_hop = params.mport;
	if (nonempty(params.ech)) {
		result.ech = "1";
		result.ech_config = params.ech;
	}
	if (present(params["obfs-password"]) || present(params.obfs_password)) {
		result.hysteria2_obfs_type = luaOr(params.obfs, "salamander");
		result.hysteria2_obfs_password = luaOr(params["obfs-password"], params.obfs_password);
	}
	if (params.obfs == "gecko") {
		result.hysteria2_obfs_MinPacketSize = luaOr(params.minpacketsize, "512");
		result.hysteria2_obfs_MaxPacketSize = luaOr(params.maxpacketsize, "1200");
	}
	if ((subHy2Type == "sing-box" && has_singbox) || (subHy2Type == "xray" && has_xray)) {
		let is_singbox = subHy2Type == "sing-box" && has_singbox;
		result.type = is_singbox ? "sing-box" : "Xray";
		result.protocol = "hysteria2";
		setFinalmask(result, params.fm);
	} else if (has_hysteria2) {
		result.type = "Hysteria2";
	} else {
		log("跳过 Hysteria2 节点，因未适配到 Hysteria2 核心程序，或未正确设置节点使用类型。");
		return null;
	}
	let insecure = luaOr(params.allowinsecure, params.insecure);
	result.tls_allowInsecure = tlsAllow(insecure, subAllow);
	return result;
};

parseTuic = function(content, result, subAllow) {
	let cut = cutHash(content);
	content = cut[0];
	result.remarks = cut[1];
	let Info = content;
	if (index(content, "@") >= 0) {
		let contents = splitLit(content, "@");
		let auth = at(contents, 0) ?? "";
		let idx = index(auth, ":");
		if (idx < 0) {
			auth = api.UrlDecode(auth);
			idx = index(auth, ":");
		}
		if (idx >= 0) {
			result.uuid = api.UrlDecode(substr(auth, 0, idx));
			result.password = api.UrlDecode(substr(auth, idx + 1));
		}
		Info = slashQ(at(contents, 1) ?? "");
	}
	let query = splitLit(Info, "?");
	let host_port = at(query, 0) ?? "";
	let params = parseQuery(at(query, 1), true, true, false);
	let hp = hostPort(host_port, null);
	result.address = hp[0];
	result.port = hp[1];
	result.tls_serverName = params.sni;
	result.tls_disable_sni = params.disable_sni;
	result.tls_pinSHA256 = luaOr(params.pcs, params.pinsha256);
	result.tuic_alpn = luaOr(params.alpn, "h3");
	result.tuic_congestion_control = luaOr(params.congestion_control, "cubic");
	result.tuic_udp_relay_mode = luaOr(params.udp_relay_mode, "native");
	let insecure = luaOr(luaOr(params.allowinsecure, params.insecure), params.allow_insecure);
	result.tls_allowInsecure = tlsAllow(insecure, subAllow);
	return result;
};

parseAnytls = function(content, result, subAllow) {
	let cut = cutHash(content);
	content = cut[0];
	result.remarks = cut[1];
	if (index(content, "@") < 0)
		return result;
	let Info = splitLit(content, "@");
	result.password = api.UrlDecode(at(Info, 0) ?? "");
	let port = "443";
	let right = slashQ(at(Info, 1) ?? "");
	let query = splitLit(right, "?");
	let host_port = at(query, 0) ?? "";
	let params = parseQuery(at(query, 1), true, true, false);
	let hp = hostPort(host_port, port);
	result.address = hp[0];
	port = hp[1];
	result.tls = "0";
	if (!present(params.security) || params.security === "")
		params.security = "tls";
	if (params.security == "tls" || params.security == "reality") {
		result.tls = "1";
		result.tls_serverName = luaOr(params.sni, params.peer);
		result.tls_pinSHA256 = luaOr(params.pcs, params.pinsha256);
		result.alpn = params.alpn;
		if (nonempty(params.fp)) {
			result.utls = "1";
			result.fingerprint = params.fp;
		}
		if (params.security == "reality") {
			result.reality = "1";
			result.reality_publicKey = params.pbk ?? null;
			result.reality_shortId = params.sid ?? null;
		}
		if (nonempty(params.ech)) {
			result.ech = "1";
			result.ech_config = params.ech;
		}
	}
	result.port = port;
	let insecure = luaOr(params.allowinsecure, params.insecure);
	result.tls_allowInsecure = tlsAllow(insecure, subAllow);
	return result;
};

parseNaive = function(content, result, szType) {
	let cut = cutHash(content);
	content = cut[0];
	result.remarks = cut[1];
	let Info = content;
	if (index(content, "@") >= 0) {
		let contents = splitLit(content, "@");
		let auth = at(contents, 0) ?? "";
		let idx = index(auth, ":");
		if (idx < 0) {
			auth = api.UrlDecode(auth);
			idx = index(auth, ":");
		}
		if (idx >= 0) {
			result.username = api.UrlDecode(substr(auth, 0, idx));
			result.password = api.UrlDecode(substr(auth, idx + 1));
		}
		Info = slashQ(at(contents, 1) ?? "");
	}
	let query = splitLit(Info, "?");
	let host_port = at(query, 0) ?? "";
	let params = parseQuery(at(query, 1), false, true, false);
	let hp = hostPort(host_port, null);
	result.address = hp[0];
	result.port = hp[1];
	result.tls_serverName = params.sni;
	result.uot = params.uot;
	result.naive_insecure_concurrency = luaOr(params["insecure-concurrency"], "0");
	if (nonempty(params.ech)) {
		result.ech = "1";
		result.ech_config = params.ech;
	}
	if (szType == "naive+quic") {
		result.naive_quic = "1";
		result.naive_congestion_control = luaOr(params.congestion_control, "bbr");
	}
	return result;
};

parseSnell = function(content, result) {
	let cut = cutHash(content);
	content = cut[0];
	result.remarks = cut[1];
	let Info = content;
	if (index(content, "@") >= 0) {
		let info = splitLit(content, "@");
		result.snell_psk = api.UrlDecode(at(info, 0) ?? "");
		Info = at(info, 1);
	}
	Info = slashQ(Info ?? "");
	let query = splitLit(Info, "?");
	let host_port = at(query, 0) ?? "";
	let params = parseQuery(at(query, 1), true, true, true);
	result.port = "443";
	let hp = hostPort(host_port, "443");
	result.address = hp[0];
	result.port = hp[1];
	result.snell_psk = luaOr(params.psk, result.snell_psk);
	result.password = params.userkey;
	result.snell_version = luaOr(params.version, "4");
	if (result.snell_version == "4") {
		result.snell_obfs_mode = luaOr(params.obfs, "none");
		result.snell_obfs_host = luaOr(params["obfs-host"], params.obfs_host);
	} else {
		result.snell_mode = luaOr(params.mode, "default");
	}
	result.snell_reuse = params.reuse === "1" ? "1" : "0";
	return result;
};

processData = function(szType, content, add_mode, group, sub_cfg) {
	let subAllow = DEFAULT_ALLOWINSECURE;
	let subSs = DEFAULT_SS_TYPE;
	let subTrojan = DEFAULT_TROJAN_TYPE;
	let subVmess = DEFAULT_VMESS_TYPE;
	let subVless = DEFAULT_VLESS_TYPE;
	let subHy2 = DEFAULT_HYSTERIA2_TYPE;
	let subUp = 1000;
	let subDown = 1000;
	if (sub_cfg) {
		if (present(sub_cfg.allowInsecure) && sub_cfg.allowInsecure !== "1")
			subAllow = null;
		let ss_type = luaOr(sub_cfg.ss_type, "global");
		if (ss_type != "global" && core_has[ss_type])
			subSs = ss_type;
		let trojan_type = luaOr(sub_cfg.trojan_type, "global");
		if (trojan_type != "global" && core_has[trojan_type])
			subTrojan = trojan_type;
		let vmess_type = luaOr(sub_cfg.vmess_type, "global");
		if (vmess_type != "global" && core_has[vmess_type])
			subVmess = vmess_type;
		let vless_type = luaOr(sub_cfg.vless_type, "global");
		if (vless_type != "global" && core_has[vless_type])
			subVless = vless_type;
		let hysteria2_type = luaOr(sub_cfg.hysteria2_type, "global");
		if (hysteria2_type != "global" && core_has[hysteria2_type])
			subHy2 = hysteria2_type;
		subUp = sub_cfg.hysteria_up_mbps;
		subDown = sub_cfg.hysteria_down_mbps;
	}
	let result = {
		timeout: 60,
		add_mode: add_mode,
		group: group
	};
	let parsed = null;
	if (szType == "ssr") {
		parsed = parseSSR(content, result);
	} else if (szType == "vmess") {
		if (subVmess == "sing-box" && has_singbox)
			result.type = "sing-box";
		else if (subVmess == "xray" && has_xray)
			result.type = "Xray";
		else {
			log("跳过 VMess 节点，因未适配到 VMess 核心程序，或未正确设置节点使用类型。");
			return null;
		}
		parsed = parseVmess(content, result, subAllow);
	} else if (szType == "ss") {
		parsed = parseSS(content, result, subAllow, subSs);
	} else if (szType == "trojan") {
		if (subTrojan == "sing-box" && has_singbox) {
			result.type = "sing-box";
			result.protocol = "trojan";
		} else if (subTrojan == "xray" && has_xray) {
			result.type = "Xray";
			result.protocol = "trojan";
		} else {
			log("跳过 Trojan 节点，因未适配到 Trojan 核心程序，或未正确设置节点使用类型。");
			return null;
		}
		parsed = parseTrojan(content, result, subAllow);
	} else if (szType == "ssd") {
		parsed = set_ss_implementation(subSs, result);
		if (parsed === null)
			return null;
		parsed.address = content.server;
		parsed.port = content.port;
		parsed.password = content.password;
		parsed.method = content.encryption;
		parsed.ss_method = content.encryption;
		parsed.plugin = content.plugin;
		parsed.plugin_opts = content.plugin_options;
		parsed.group = content.airport;
		parsed.remarks = content.remarks;
	} else if (szType == "vless") {
		if (subVless == "sing-box" && has_singbox)
			result.type = "sing-box";
		else if (subVless == "xray" && has_xray)
			result.type = "Xray";
		else {
			log("跳过 VLESS 节点，因未适配到 VLESS 核心程序，或未正确设置节点使用类型。");
			return null;
		}
		parsed = parseVless(content, result, subAllow);
	} else if (szType == "hysteria") {
		if (has_singbox) {
			result.type = "sing-box";
			result.protocol = "hysteria";
		} else {
			log("跳过 Hysteria 节点，因未安装 Hysteria 核心程序 Sing-box。");
			return null;
		}
		parsed = parseHysteria(content, result, subAllow, subUp, subDown);
	} else if (szType == "hysteria2" || szType == "hy2") {
		parsed = parseHysteria2(content, result, subAllow, sub_cfg, subUp, subDown, subHy2);
	} else if (szType == "tuic") {
		if (has_singbox) {
			result.type = "sing-box";
			result.protocol = "tuic";
		} else {
			log("跳过 Tuic 节点，因未安装 Tuic 核心程序 Sing-box。");
			return null;
		}
		parsed = parseTuic(content, result, subAllow);
	} else if (szType == "anytls") {
		if (has_singbox) {
			result.type = "sing-box";
			result.protocol = "anytls";
		} else {
			log("跳过 AnyTLS 节点，因未安装 AnyTLS 核心程序 Sing-box 1.12。");
			return null;
		}
		parsed = parseAnytls(content, result, subAllow);
	} else if (szType == "naive+https" || szType == "naive+quic") {
		if (has_singbox) {
			result.type = "sing-box";
			result.protocol = "naive";
		} else {
			log("跳过 NaïveProxy 节点，因未安装 NaïveProxy 核心程序 Sing-box。");
			return null;
		}
		parsed = parseNaive(content, result, szType);
	} else if (szType == "snell") {
		if (has_singbox) {
			result.type = "sing-box";
			result.protocol = "snell";
		} else {
			log("跳过 Snell 节点，因未安装 Snell 核心程序 Sing-box 1.14。");
			return null;
		}
		parsed = parseSnell(content, result);
	} else {
		log("暂时不支持 " + szType + " 类型的节点订阅，跳过此节点。");
		return null;
	}
	if (parsed === null)
		return null;
	return finishRemarks(parsed);
};

invokeCurl = function(mode, url, file, args) {
	let fn = null;
	if (mode == "direct")
		fn = api.curl_direct;
	else if (mode == "proxy")
		fn = api.curl_proxy;
	else
		fn = api.curl_auto ?? api.curl_logic;
	if (fn === null)
		return [null, null];
	let ret = fn(url, file, args);
	if (type(ret) == "array")
		return [at(ret, 0), length(ret) > 1 ? at(ret, 1) : null];
	if (type(ret) == "object" && ret !== null)
		return [luaOr(ret.code, ret.return_code), luaOr(luaOr(ret.result, ret.stdout), ret.body)];
	return [ret, null];
};

splitCurlResult = function(result) {
	let m = match(result, /([0-9]+)[ \t]*$/);
	if (m === null)
		return [null, null];
	let body = substr(result, 0, length(result) - length(m[0]));
	body = replace(body, /[ \t\r\n]+$/, "");
	return [body, m[1]];
};

passwallUaVersion = function() {
	let ver = "";
	if (api.get_version)
		ver = api.get_version();
	else if (api.get_app_version)
		ver = api.get_app_version();
	if (type(ver) != "string")
		ver = "";
	let m = match(ver, /^([^-]+)/);
	return m ? m[1] : ver;
};

curl = function(url, file, ua, mode) {
	if (!present(url) || url === "")
		return [22, 404, null];
	let curl_args = [
		"-fskL", "--retry 3", "--connect-timeout 3",
		"-H 'Accept: */*'", "-H 'Accept-Encoding: identity'",
		"--dump-header -", "-w '\\n%{http_code}'"
	];
	if (!present(ua) || ua === "")
		ua = "passwall";
	if (ua === "passwall")
		ua = "passwall/" + passwallUaVersion();
	push(curl_args, "--user-agent \"" + ua + "\"");
	let cookie_file = "/tmp/cookie_" + api.gen_random_char(5);
	push(curl_args, "-c \"" + cookie_file + "\" -b \"" + cookie_file + "\"");
	let got = invokeCurl(mode, url, file, curl_args);
	let return_code = got[0];
	let result = got[1];
	if (present(result) && result !== "") {
		let parsed = splitCurlResult(result);
		if (parsed[1] !== null) {
			let code = int(parsed[1]);
			curl_http_code = code == code ? code : 0;
			curl_header = parsed[0];
		} else {
			curl_http_code = 0;
		}
	}
	if (present(curl_header) && curl_header !== "")
		curl_header = replace(curl_header, /\r/g, "");
	api.remove(cookie_file);
	return [return_code, curl_http_code, curl_header];
};

groupAll = function(group) {
	return group === null || group === false;
};

sameGroup = function(group, value) {
	if (groupAll(group))
		return true;
	return lc(str(group)) == lc(str(value));
};

truncate_nodes = function(group) {
	for (let config in CONFIG) {
		if (config === null)
			continue;
		if (type(config.currentNodes) == "array" && length(config.currentNodes) > 0) {
			let newNodes = [];
			let removeNodesSet = {};
			for (let v in config.currentNodes) {
				if (v && v.currentNode && v.currentNode.add_mode == "2") {
					if (sameGroup(group, v.currentNode.group))
						removeNodesSet[v.currentNode[".name"]] = true;
				}
			}
			for (let value in config.currentNodes) {
				if (value && value.currentNode && removeNodesSet[value.currentNode[".name"]] !== true)
					push(newNodes, value.currentNode[".name"]);
			}
			if (config.set)
				config.set(config, newNodes);
		} else if (config.currentNode && config.currentNode.add_mode == "2") {
			if (sameGroup(group, config.currentNode.group)) {
				if (config.delete)
					config.delete(config);
				else if (config.set)
					config.set(config, "");
			}
		}
	}
	uci_foreach("nodes", function(node) {
		if (node.add_mode == "2" && sameGroup(group, node.group))
			uci_del(node[".name"]);
	});
	uci_foreach("subscribe_list", function(o) {
		if (sameGroup(group, o.remark))
			uci_del(o[".name"], "md5");
	});
	uci_save(true);
};

select_node = function(nodes, config, parentConfig) {
	if (config.currentNode) {
		let server = null;
		if (present(config.currentNode.Socks))
			server = config.currentNode.Socks;
		if (present(config.currentNode[".name"])) {
			for (let node in nodes) {
				if (node[".name"] == config.currentNode[".name"]) {
					if (config.log === null || config.log === true)
						log("更新【" + config.remarks + "】匹配节点：" + node.remarks);
					server = node[".name"];
					break;
				}
			}
		}
		if (!present(server)) {
			for (let node in nodes) {
				if (present(config.currentNode.type) && present(config.currentNode.remarks) && present(config.currentNode.address) && present(config.currentNode.port)) {
					if (present(node.type) && present(node.remarks) && present(node.address) && present(node.port)) {
						if (node.type == config.currentNode.type && node.remarks == config.currentNode.remarks && (str(node.address) + ":" + str(node.port) == str(config.currentNode.address) + ":" + str(config.currentNode.port)) && node.group == config.currentNode.group) {
							if (config.log === null || config.log === true)
								log("更新【" + config.remarks + "】第一匹配节点：" + node.remarks);
							server = node[".name"];
							break;
						}
					}
				}
			}
		}
		if (!present(server)) {
			for (let node in nodes) {
				if (present(config.currentNode.type) && present(config.currentNode.address) && present(config.currentNode.port)) {
					if (present(node.type) && present(node.address) && present(node.port)) {
						if (node.type == config.currentNode.type && (str(node.address) + ":" + str(node.port) == str(config.currentNode.address) + ":" + str(config.currentNode.port)) && node.group == config.currentNode.group) {
							if (config.log === null || config.log === true)
								log("更新【" + config.remarks + "】第二匹配节点：" + node.remarks);
							server = node[".name"];
							break;
						}
					}
				}
			}
		}
		if (!present(server)) {
			for (let node in nodes) {
				if (present(config.currentNode.address) && present(config.currentNode.port)) {
					if (present(node.address) && present(node.port)) {
						if (str(node.address) + ":" + str(node.port) == str(config.currentNode.address) + ":" + str(config.currentNode.port) && node.group == config.currentNode.group) {
							if (config.log === null || config.log === true)
								log("更新【" + config.remarks + "】第三匹配节点：" + node.remarks);
							server = node[".name"];
							break;
						}
					}
				}
			}
		}
		if (!present(server)) {
			for (let node in nodes) {
				if (present(config.currentNode.address) && present(node.address)) {
					if (node.address == config.currentNode.address && node.group == config.currentNode.group) {
						if (config.log === null || config.log === true)
							log("更新【" + config.remarks + "】第四匹配节点：" + node.remarks);
						server = node[".name"];
						break;
					}
				}
			}
		}
		if (!present(server)) {
			for (let node in nodes) {
				if (present(config.currentNode.remarks) && present(node.remarks)) {
					if (node.remarks == config.currentNode.remarks && node.group == config.currentNode.group) {
						if (config.log === null || config.log === true)
							log("更新【" + config.remarks + "】第五匹配节点：" + node.remarks);
						server = node[".name"];
						break;
					}
				}
			}
		}
		if (!present(parentConfig) && !present(server)) {
			if (length(nodes_table) > 0) {
				if (config.log === null || config.log === true)
					log("【" + config.remarks + "】" + "无法找到最匹配的节点，当前已更换为：" + nodes_table[0].remarks);
				server = nodes_table[0][".name"];
			}
		}
		if (present(server)) {
			if (present(parentConfig))
				config.set(parentConfig, server);
			else
				config.set(config, server);
		}
	} else if (!present(parentConfig)) {
		config.set(config, "");
	}
};

update_subscribe_info = function() {
	let changed = {};
	for (let cfgid, info in subscribe_info) {
		if (type(info) != "object" || info === null)
			continue;
		for (let key, value in info) {
			value = nonempty(value) ? value : null;
			if (uci_get(cfgid, key) !== value) {
				if (present(value))
					uci_set(cfgid, key, value);
				else
					uci_del(cfgid, key);
				changed[cfgid] = true;
			}
		}
	}
	return changed;
};

listOf = function(v) {
	if (v === null || v === false)
		return [];
	if (type(v) == "string")
		return v === "" ? [] : [v];
	if (type(v) == "array")
		return v;
	if (type(v) == "object") {
		let out = [];
		for (let k, val in v)
			push(out, val);
		return out;
	}
	return [];
};

new_node_id = function() {
	let name = api.gen_random_char();
	if (api.uci && api.uci.section) {
		let made = api.uci.section(api.c_config, "nodes", name);
		if (type(made) == "string" && made !== "")
			return made;
	}
	return name;
};

update_node = function(manual) {
	if (length(nodeResult) == 0) {
		log("没有可用的节点信息更新。");
		return false;
	}
	let group = {};
	for (let v in nodeResult)
		group[lc(v.remark)] = true;
	if (manual == 0 && length(group) > 0) {
		uci_foreach("nodes", function(node) {
			if (node.add_mode == "2" && present(node.group) && group[lc(node.group)] === true)
				uci_del(node[".name"]);
		});
	}
	for (let v in nodeResult) {
		let sub_cfg = v.sub_cfg;
		let domain_resolver = null;
		let domain_resolver_dns = null;
		let domain_resolver_dns_https = null;
		let domain_strategy = null;
		let preproxy_node_group = "";
		let to_node_group = "";
		let outbound_iface_group = "";
		let chain_node_type = "";
		function valid_chain_node(node) {
			if (!present(node))
				return "";
			let cp = luaOr(uci_get(node, "chain_proxy"), "");
			let am = luaOr(uci_get(node, "add_mode"), "0");
			chain_node_type = (cp === "" && am !== "2") ? luaOr(uci_get(node, "type"), "") : "";
			if (chain_node_type != "Xray" && chain_node_type != "sing-box") {
				chain_node_type = "";
				return "";
			}
			return node;
		}
		if (sub_cfg) {
			domain_resolver = sub_cfg.domain_resolver;
			domain_resolver_dns = sub_cfg.domain_resolver_dns;
			domain_resolver_dns_https = sub_cfg.domain_resolver_dns_https;
			let map = { UseIPv4v6: 1, UseIPv6v4: 1, UseIPv4: 1, UseIPv6: 1 };
			domain_strategy = (present(sub_cfg.domain_strategy) && map[sub_cfg.domain_strategy]) ? sub_cfg.domain_strategy : null;
			preproxy_node_group = sub_cfg.chain_proxy == "1" ? valid_chain_node(sub_cfg.preproxy_node) : "";
			to_node_group = sub_cfg.chain_proxy == "2" ? valid_chain_node(sub_cfg.to_node) : "";
			outbound_iface_group = sub_cfg.chain_proxy == "3" ? luaOr(sub_cfg.outbound_iface, "") : "";
			chain_node_type = outbound_iface_group !== "" ? "iface" : chain_node_type;
		}
		for (let vv in v.list) {
			let cfgid = new_node_id();
			for (let kkk, vvv in vv) {
				if (vvv === null)
					continue;
				let isTable = type(vvv) == "array" || type(vvv) == "object";
				if (isTable && length(vvv) > 0) {
					uci_set(cfgid, kkk, vvv);
				} else {
					if (kkk != "group" || vvv != "default")
						uci_set(cfgid, kkk, vvv);
					if (kkk == "type" && (vvv == "Xray" || vvv == "sing-box")) {
						if (present(domain_resolver)) {
							uci_set(cfgid, "domain_resolver", domain_resolver);
							if (present(domain_resolver_dns))
								uci_set(cfgid, "domain_resolver_dns", domain_resolver_dns);
							else if (present(domain_resolver_dns_https))
								uci_set(cfgid, "domain_resolver_dns_https", domain_resolver_dns_https);
						}
						if (present(domain_strategy)) {
							let ds = domain_strategy;
							if (vvv == "sing-box") {
								let smap = { UseIPv4v6: "prefer_ipv4", UseIPv6v4: "prefer_ipv6", UseIPv4: "ipv4_only", UseIPv6: "ipv6_only" };
								ds = luaOr(smap[ds], "");
							}
							uci_set(cfgid, "domain_strategy", ds);
						}
					}
					if (chain_node_type !== "" && kkk == "type" && (vvv == "Xray" || vvv == "sing-box")) {
						if (preproxy_node_group !== "") {
							uci_set(cfgid, "chain_proxy", "1");
							uci_set(cfgid, "preproxy_node", preproxy_node_group);
						} else if (to_node_group !== "") {
							uci_set(cfgid, "chain_proxy", "2");
							uci_set(cfgid, "to_node", to_node_group);
						} else if (outbound_iface_group !== "") {
							uci_set(cfgid, "chain_proxy", "3");
							uci_set(cfgid, "outbound_iface", outbound_iface_group);
						}
					}
				}
			}
		}
	}
	if (length(CONFIG) > 0) {
		let nodes = [];
		uci_foreach("nodes", function(node) {
			push(nodes, node);
		});
		for (let config in CONFIG) {
			if (config === null)
				continue;
			if (type(config.currentNodes) == "array" && length(config.currentNodes) > 0) {
				if (present(config.remarks) && config.currentNodes[0].log !== false)
					log("----【" + config.remarks + "】----");
				for (let vv in config.currentNodes)
					select_node(nodes, vv, config);
				config.set(config);
			} else {
				select_node(nodes, config);
			}
		}
	}
	return true;
};

blankLine = function(v) {
	return type(v) == "string" && match(v, /^[[:space:]]*$/) !== null;
};

parse_link = function(raw, add_mode, group, sub_cfg) {
	if (present(raw) && length(raw) > 0) {
		let cfgid = sub_cfg ? sub_cfg[".name"] : null;
		let keyword_filter = add_mode == "2" ? prepare_keyword_filter(sub_cfg) : null;
		let nodes = null;
		let szType = null;
		let node_list = [];
		if (index(raw, "ssd://") >= 0) {
			szType = "ssd";
			let nEnd = index(raw, "ssd://") + length("ssd://");
			nodes = api.jsonc.parse(api.base64Decode(substr(raw, nEnd)));
			let extra = {
				airport: nodes.airport,
				port: nodes.port,
				encryption: nodes.encryption,
				password: nodes.password
			};
			let servers = [];
			for (let server in nodes.servers) {
				let merged = {};
				for (let k, val in extra) {
					if (val !== null)
						merged[k] = val;
				}
				if (type(server) == "object") {
					for (let k, val in server) {
						if (val !== null)
							merged[k] = val;
					}
				}
				push(servers, merged);
			}
			nodes = servers;
		} else if (add_mode == "1") {
			nodes = splitLit(raw, "\n");
		} else {
			nodes = splitLit(replace(api.base64Decode(raw), /\r\n/g, "\n"), "\n");
		}
		for (let v in nodes) {
			if (present(v) && (szType == "ssd" || !blankLine(v))) {
				try {
					let result = null;
					if (szType == "ssd") {
						result = processData(szType, v, add_mode, group, sub_cfg);
					} else if (szType === null) {
						let node = api.trim(v);
						let dat = splitLit(node, "://");
						if (length(dat) >= 2 && present(at(dat, 0)) && at(dat, 0) !== "" && at(dat, 1) !== null) {
							if (at(dat, 0) == "vmess" || at(dat, 0) == "ssr") {
								let link = at(dat, 1);
								let h = index(link, "#");
								if (h >= 0)
									link = substr(link, 0, h);
								result = processData(at(dat, 0), api.base64Decode(api.trim(link)), add_mode, group, sub_cfg);
							} else {
								let link = replace(at(dat, 1), /&amp;/g, "&");
								link = replace(link, /\s*#\s*/g, "#");
								result = processData(at(dat, 0), link, add_mode, group, sub_cfg);
							}
						}
					} else {
						log("跳过未知类型：" + szType);
					}
					if (result) {
						if (present(result.error_msg))
							log("丢弃节点：" + result.remarks + " ，原因：" + result.error_msg);
						else if (!present(result.type))
							log("丢弃节点：" + result.remarks + " ，找不到可使用二进制。");
						else if ((add_mode == "2" && keyword_filter && is_filter_keyword(keyword_filter, result.remarks)) || !present(result.address) || result.remarks == "NULL" || result.address == "127.0.0.1" || result.address == "0.0.0.0" || (luaNot(api.datatypes.hostname(result.address)) && luaNot(api.is_ip(result.address))))
							log("丢弃过滤节点：" + result.type + " 节点，" + result.remarks);
						else
							push(node_list, result);
						if (add_mode == "2")
							get_subscribe_info(cfgid, result.remarks);
					}
				} catch (err) {
					log(v, "解析错误，跳过此节点。");
				}
			}
		}
		if (length(node_list) > 0 && add_mode != "2")
			push(nodeResult, { remark: group, list: node_list, sub_cfg: sub_cfg });
		log("成功解析【" + group + "】节点数量：" + length(node_list));
		return node_list;
	}
	if (add_mode == "2")
		log("获取到的【" + group + "】订阅内容为空，可能是订阅地址无效，或是网络问题，请诊断！");
	return [];
};

nodeOrSocks = function(id) {
	if (!present(id))
		return null;
	let section = uci_get(id);
	if (section === null)
		return null;
	if (section[".type"] == "socks")
		return { Socks: id };
	return section;
};

is_ip_port = function(str) {
	if (type(str) != "string")
		return false;
	let m = match(str, /^([0-9.]+):([0-9]+)$/);
	if (m === null)
		return false;
	let port = int(m[2]);
	if (port != port || port > 65535)
		return false;
	return !luaNot(api.datatypes.ipaddr(m[1]));
};

build_config = function() {
	CONFIG = [];
	let szType = "@global[0]";
	let option = "node";
	let node_id = uci_get(szType, option);
	push(CONFIG, {
		log: true,
		remarks: "全局节点",
		currentNode: nodeOrSocks(node_id),
		set: function(o, server) {
			uci_set(szType, option, server);
			o.newNodeId = server;
		}
	});

	let socksIndex = 0;
	uci_foreach("socks", function(t) {
		socksIndex++;
		let idx = socksIndex;
		let id = t[".name"];
		let opt = "node";
		let currentId = t[opt];
		push(CONFIG, {
			log: true,
			id: id,
			remarks: "Socks节点列表[" + idx + "]",
			currentNode: present(currentId) ? uci_get(currentId) : null,
			set: function(o, server) {
				if (!present(server) || server === "") {
					if (length(nodes_table) > 0)
						server = nodes_table[0][".name"];
				}
				uci_set(t[".name"], opt, server);
				o.newNodeId = server;
			}
		});
		let backups = listOf(t.autoswitch_backup_node);
		if (length(backups) > 0) {
			let flag = "Socks节点列表[" + idx + "]备用节点的列表";
			let currentNodes = [];
			let newNodes = [];
			let n = 0;
			for (let asb_node_id in backups) {
				n++;
				if (present(asb_node_id)) {
					let currentNode = luaOr(uci_get(asb_node_id), {});
					if (currentNode[".type"] == "nodes") {
						let label = flag + "[" + n + "]";
						push(currentNodes, {
							log: true,
							remarks: label,
							currentNode: currentNode,
							set: function(o, server) {
								if (present(server) && server !== "nil")
									push(o.newNodes, server);
							}
						});
					}
				}
			}
			push(CONFIG, {
				remarks: flag,
				currentNodes: currentNodes,
				newNodes: newNodes,
				set: function(o, nodes) {
					if (o) {
						if (!present(nodes))
							nodes = o.newNodes;
						uci_set(id, "autoswitch_backup_node", luaOr(nodes, []));
					}
				}
			});
		}
	});

	let haIndex = 0;
	uci_foreach("haproxy_config", function(t) {
		haIndex++;
		let idx = haIndex;
		let opt = "lbss";
		let currentId = t[opt];
		let sectionName = t[".name"];
		push(CONFIG, {
			log: true,
			id: sectionName,
			remarks: "HAProxy负载均衡节点列表[" + idx + "]",
			currentNode: present(currentId) ? uci_get(currentId) : null,
			set: function(o, server) {
				if (!is_ip_port(t[opt])) {
					uci_set(sectionName, opt, server);
					o.newNodeId = server;
				}
			},
			delete: function(o) {
				if (!is_ip_port(t[opt]))
					uci_del(sectionName);
			}
		});
	});

	let aclIndex = 0;
	uci_foreach("acl_rule", function(t) {
		aclIndex++;
		let idx = aclIndex;
		let opt = "node";
		let currentId = t[opt];
		let sectionName = t[".name"];
		push(CONFIG, {
			log: true,
			id: sectionName,
			remarks: "访问控制列表[" + idx + "]",
			currentNode: nodeOrSocks(currentId),
			set: function(o, server) {
				uci_set(sectionName, opt, server);
				o.newNodeId = server;
			}
		});
	});

	uci_foreach("nodes", function(node) {
		let nodeId = node[".name"];
		if (node.protocol === "_shunt") {
			let rules = [];
			uci_foreach("shunt_rules", function(e) {
				if (present(e[".name"]) && present(e.remarks)) {
					push(rules, e);
					push(rules, {
						".name": e[".name"] + "_proxy_tag",
						remarks: e.remarks + " 前置代理"
					});
				}
			});
			push(rules, { ".name": "default_node", remarks: "默认" });
			push(rules, { ".name": "default_proxy_tag", remarks: "默认 前置代理" });
			for (let e in rules) {
				let ruleName = e[".name"];
				let ruleRemarks = e.remarks;
				let linked = node[ruleName];
				if (present(linked)) {
					let section = luaOr(uci_get(linked), {});
					if (section[".type"] == "nodes") {
						push(CONFIG, {
							log: false,
							currentNode: section,
							remarks: "分流" + ruleRemarks + "节点",
							set: function(o, server) {
								if (!present(server))
									server = "";
								uci_set(nodeId, ruleName, server);
								o.newNodeId = server;
							}
						});
					}
				}
			}
		} else if (node.protocol === "_balancing") {
			let flag = "Xray负载均衡节点[" + nodeId + "]列表";
			let currentNodes = [];
			let newNodes = [];
			for (let b_node_id in listOf(node.balancing_node)) {
				let bid = b_node_id;
				push(currentNodes, {
					log: true,
					node: bid,
					currentNode: (function() {
						let section = luaOr(uci_get(bid), {});
						if (section[".type"] == "socks")
							return { Socks: bid };
						return section;
					})(),
					remarks: bid,
					set: function(o, server) {
						if (o && present(server) && server !== "nil")
							push(o.newNodes, server);
					}
				});
			}
			push(CONFIG, {
				remarks: flag,
				currentNodes: currentNodes,
				newNodes: newNodes,
				set: function(o, nodes) {
					if (o) {
						if (!present(nodes))
							nodes = o.newNodes;
						uci_set(nodeId, "balancing_node", luaOr(nodes, []));
					}
				}
			});
			if (present(node.fallback_node)) {
				let section = luaOr(uci_get(node.fallback_node), {});
				if (section[".type"] == "nodes") {
					push(CONFIG, {
						log: true,
						id: nodeId,
						remarks: "Xray负载均衡节点[" + nodeId + "]后备节点",
						currentNode: section,
						set: function(o, server) {
							uci_set(nodeId, "fallback_node", server);
							o.newNodeId = server;
						},
						delete: function(o) {
							uci_del(nodeId, "fallback_node");
						}
					});
				}
			}
		} else if (node.protocol === "_urltest") {
			let flag = "Sing-Box URLTest节点[" + nodeId + "]列表";
			let currentNodes = [];
			let newNodes = [];
			for (let u_node_id in listOf(node.urltest_node)) {
				let uid = u_node_id;
				push(currentNodes, {
					log: true,
					node: uid,
					currentNode: (function() {
						let section = luaOr(uci_get(uid), {});
						if (section[".type"] == "socks")
							return { Socks: uid };
						return section;
					})(),
					remarks: uid,
					set: function(o, server) {
						if (o && present(server) && server !== "nil")
							push(o.newNodes, server);
					}
				});
			}
			push(CONFIG, {
				remarks: flag,
				currentNodes: currentNodes,
				newNodes: newNodes,
				set: function(o, nodes) {
					if (o) {
						if (!present(nodes))
							nodes = o.newNodes;
						uci_set(nodeId, "urltest_node", luaOr(nodes, []));
					}
				}
			});
		} else {
			if (present(node.preproxy_node)) {
				let section = luaOr(uci_get(node.preproxy_node), {});
				if (section[".type"] == "nodes") {
					push(CONFIG, {
						log: true,
						id: nodeId,
						remarks: "节点[" + nodeId + "]前置代理节点",
						currentNode: uci_get(node.preproxy_node),
						set: function(o, server) {
							uci_set(nodeId, "preproxy_node", server);
							o.newNodeId = server;
						},
						delete: function(o) {
							uci_del(nodeId, "preproxy_node");
						}
					});
				}
			}
			if (present(node.to_node)) {
				let section = luaOr(uci_get(node.to_node), {});
				if (section[".type"] == "nodes") {
					push(CONFIG, {
						log: true,
						id: nodeId,
						remarks: "节点[" + nodeId + "]落地节点",
						currentNode: uci_get(node.to_node),
						set: function(o, server) {
							uci_set(nodeId, "to_node", server);
							o.newNodeId = server;
						},
						delete: function(o) {
							uci_del(nodeId, "to_node");
						}
					});
				}
			}
		}
	});

	for (let k, v in CONFIG) {
		if (v === null)
			continue;
		if (type(v.currentNodes) == "array") {
			let kept = [];
			for (let vv in v.currentNodes) {
				if (vv !== null && vv.currentNode !== null)
					push(kept, vv);
			}
			v.currentNodes = kept;
		} else if (v.currentNode === null) {
			if (v.delete)
				v.delete();
			CONFIG[k] = null;
		}
	}
};

init_state = function() {
	restart_required = false;
	nodeResult = [];
	subscribe_info = {};
	log_buffer = null;
	curl_http_code = null;
	curl_header = null;
	if (api.uci && api.uci.revert)
		api.uci.revert(api.c_config);

	has_ss_rust = api.is_finded("sslocal") ? true : false;
	has_ssr = (api.is_finded("ssr-local") && api.is_finded("ssr-redir")) ? true : false;
	has_singbox = present(api.finded_com("sing-box"));
	has_xray = present(api.finded_com("xray"));
	has_hysteria2 = present(api.finded_com("hysteria"));
	DEFAULT_ALLOWINSECURE = true;
	core_has = {
		"xray": has_xray,
		"sing-box": has_singbox,
		"shadowsocks-rust": has_ss_rust,
		"hysteria2": has_hysteria2
	};
	DEFAULT_FILTER_KEYWORD = {
		mode: luaOr(uci_get("@global_subscribe[0]", "filter_keyword_mode"), "0"),
		discard_list: split_filter_keywords(uci_get("@global_subscribe[0]", "filter_discard_list")),
		keep_list: split_filter_keywords(uci_get("@global_subscribe[0]", "filter_keep_list"))
	};
	DEFAULT_SS_TYPE = api.get_core("ss_type", [[has_ss_rust, "shadowsocks-rust"], [has_singbox, "sing-box"], [has_xray, "xray"]]);
	DEFAULT_TROJAN_TYPE = api.get_core("trojan_type", [[has_singbox, "sing-box"], [has_xray, "xray"]]);
	DEFAULT_VMESS_TYPE = api.get_core("vmess_type", [[has_xray, "xray"], [has_singbox, "sing-box"]]);
	DEFAULT_VLESS_TYPE = api.get_core("vless_type", [[has_xray, "xray"], [has_singbox, "sing-box"]]);
	DEFAULT_HYSTERIA2_TYPE = api.get_core("hysteria2_type", [[has_hysteria2, "hysteria2"], [has_singbox, "sing-box"], [has_xray, "xray"]]);

	nodes_table = [];
	let valid = api.get_valid_nodes();
	if (type(valid) == "array") {
		for (let e in valid) {
			if (e && e.node_type == "normal")
				push(nodes_table, e);
		}
	}
	build_config();
};

execute = function() {
	let subscribe_list = [];
	let fail_list = [];
	if (cli[1] != "all") {
		let ids = match(cli[1] ?? "", /[^,]+/g) ?? [];
		for (let w in ids)
			push(subscribe_list, luaOr(uci_get(w[0]), {}));
	} else {
		uci_foreach("subscribe_list", function(o) {
			push(subscribe_list, o);
		});
	}
	let manual_sub = cli[2] === "manual";
	for (let value in subscribe_list) {
		let cfgid = value[".name"];
		let remark = luaOr(value.remark, "");
		let url = luaOr(value.url, "");
		let tmp_file = null;
		let headers = null;
		let url_is_local = false;
		if (api.fs.access(url)) {
			log("正在订阅:【" + remark + "】" + url);
			url_is_local = true;
			tmp_file = url;
		} else {
			let ua = value.user_agent;
			let access_mode = value.access_mode;
			let result = !present(access_mode) ? "自动" : (access_mode == "direct" ? "直连" : (access_mode == "proxy" ? "代理" : "自动"));
			log("正在订阅:【" + remark + "】" + url + " [" + result + "]");
			tmp_file = "/tmp/" + cfgid;
			let got = curl(url, tmp_file, ua, access_mode);
			let return_code = got[0];
			value.http_code = got[1];
			headers = got[2];
			if (return_code !== 0) {
				push(fail_list, value);
				api.remove(tmp_file);
			}
		}
		if (api.fs.access(tmp_file)) {
			if (api.sys.call("[ -f " + tmp_file + " ] && sed -i -e '/^[ \t]*$/d' -e '/^[ \t]*\r$/d' " + tmp_file) === 0) {
				let stdout = api.fs.readfile(tmp_file);
				if (stdout === null)
					stdout = "";
				let raw_data = api.trim(stdout);
				raw_data = parseClashNode(raw_data);
				if (present(headers) && headers !== "") {
					let info = parse_clash_sub_info(headers);
					if (info)
						subscribe_info[cfgid] = info;
					else
						delete subscribe_info[cfgid];
				}
				log_buffer = [];
				let parsed_nodes = parse_link(raw_data, "2", remark, value);
				let old_md5 = luaOr(value.md5, "");
				let new_md5 = length(parsed_nodes) > 0 ? api.md5_string(api.jsonc.stringify(parsed_nodes)) : "";
				if (!manual_sub && new_md5 !== "" && old_md5 == new_md5) {
					log_buffer = null;
					log("订阅:【" + remark + "】没有变化，无需更新。");
				} else {
					flush_log_buffer();
					if (length(parsed_nodes) > 0) {
						push(nodeResult, {
							remark: remark,
							list: parsed_nodes,
							sub_cfg: value,
							md5: new_md5
						});
					}
				}
			} else {
				push(fail_list, value);
			}
			if (!url_is_local)
				api.remove(tmp_file);
		}
	}
	if (length(fail_list) > 0) {
		for (let value in fail_list)
			log(sprintf("【%s】订阅失败，可能是订阅地址无效，或是网络问题，请诊断！[%s]", luaOr(value.remark, ""), str(value.http_code ?? 0)));
	}
	let nodes_changed = update_node(0);
	let info_changed = update_subscribe_info();
	for (let result in nodeResult)
		uci_set(result.sub_cfg[".name"], "md5", result.md5);
	if (nodes_changed || length(info_changed) > 0) {
		uci_save(true);
		restart_required = nodes_changed;
		for (let value in subscribe_list) {
			if (info_changed[value[".name"]])
				log(sprintf("刷新订阅【%s】账户用量与到期时间信息。", luaOr(value.remark, "")));
		}
	}
};

log_traceback = function() {
	try {
		let debugmod = require("debug");
		if (debugmod && debugmod.traceback) {
			let tb = debugmod.traceback();
			if (tb !== null)
				log(type(tb) == "string" ? tb : sprintf("%J", tb));
		}
	} catch (e) {
	}
};

acquire_lock = function(argv) {
	let prefix = api.LOCK_PREFIX;
	if (type(prefix) != "string" || prefix === "")
		prefix = "/var/lock/" + luaOr(api.c_config, "passwall");
	let path = prefix + "_sub_rule.lock";
	if (fs.access(path) === null)
		fs.writefile(path, "");
	let fh = fs.open(path, "r+");
	if (fh === null) {
		api.log("无法打开订阅/规则更新锁，退出。");
		exit(1);
	}
	if (fh.lock("xn") !== true) {
		let cron = length(argv) > 2 && argv[2] === "cron";
		if (!cron) {
			api.log("订阅或规则更新正在运行，本次请求跳过。");
			fh.close();
			exit(0);
		}
		let mark = fh.read(1);
		fh.seek(0);
		let names = { s: "订阅", r: "规则更新" };
		let running = names[mark] ?? "订阅/规则更新";
		api.log("[" + running + "]实例正在运行，[订阅]进入队列等待...");
		if (fh.lock("x") !== true) {
			api.log("无法取得更新锁，计划任务失败。");
			fh.close();
			exit(1);
		}
	}
	fh.write("s");
	fh.seek(0);
	return fh;
};

release_lock = function() {
	if (update_lock !== null) {
		update_lock.close();
		update_lock = null;
	}
};

main = function(argv) {
	if (argv === null || type(argv) != "array" || length(argv) == 0 || argv[0] === null || argv[0] === false)
		exit(0);
	cli = argv;
	update_lock = acquire_lock(argv);
	try {
		init_state();
		if (argv[0] === "start") {
			log("开始订阅...");
			try {
				execute();
			} catch (e) {
				flush_log_buffer();
				log(e.message ?? e);
				log_traceback();
				log("订阅发生错误。");
			}
			log("订阅完毕...\n");
		} else if (argv[0] === "add") {
			let raw = api.fs.readfile("/tmp/links.conf");
			if (raw === null)
				die("cannot open /tmp/links.conf");
			parse_link(raw, "1", argv[1]);
			if (update_node(1))
				uci_save(true);
			api.remove("/tmp/links.conf");
		} else if (argv[0] === "truncate") {
			truncate_nodes(length(argv) > 1 ? argv[1] : null);
		}
	} catch (e) {
		release_lock();
		die(e.message ?? str(e));
	}
	release_lock();
	if (restart_required) {
		let action = (length(argv) > 2 && argv[2] === "cron") ? " cron" : "";
		api.sys.call("/etc/init.d/passwall restart" + action + " > /dev/null 2>&1 &");
	}
};
export { main };
