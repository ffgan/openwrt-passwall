'use strict';

import * as api from 'passwall.api';

let ech_domain = {};
let local_version = null;
let version_ge_1_14_0 = false;
let version_ge_1_15_0 = false;
let version_inited = false;

let GLOBAL = {
	DNS_SERVER: {},
	DNS_HOSTNAME: {},
	VPS_EXCLUDE: {}
};

let GEO_VAR = {
	OK: null,
	DIR: null,
	SITE_PATH: null,
	IP_PATH: null,
	SITE_TAGS: {},
	IP_TAGS: {},
	TO_SRS_PATH: api.CACHE_PATH + "/singbox_srss/"
};

let NO_RUN = null;
let TMP_PORT = null;
let inner_fakedns = null;
let remote_strategy = null;
let fakedns_tag = null;
let hosts_predefined = null;
let remote_server_domain_resolver = null;
let direct_strategy = null;

function ltruth(v) {
	return v != null && v !== false;
}

function lor(a, b) {
	if (a == null || a === false)
		return b;
	return a;
}

function or_nil(v) {
	return ltruth(v) ? v : null;
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

function set_if(obj, key, val) {
	if (val != null)
		obj[key] = val;
}

function leading_int(v) {
	let m = match("" + v, /^[0-9]+/);
	if (m == null)
		return null;
	return tonumber(m[0]);
}

function gmatch(s, pattern) {
	if (s == null || s === false)
		return [];
	let found = match("" + s, pattern);
	if (found == null)
		return [];
	let out = [];
	for (let m in found)
		push(out, m[0]);
	return out;
}

function nonempty(arr) {
	if (type(arr) == "array" && length(arr) > 0)
		return arr;
	return null;
}

function has_keys(o) {
	return (type(o) == "object" || type(o) == "array") && length(o) > 0;
}

function is_table(v) {
	let t = type(v);
	return t == "object" || t == "array";
}

function lua_quote(s) {
	if (s == null || s === false)
		s = "";
	else
		s = "" + s;
	let out = "\"";
	for (let i = 0; i < length(s); i++) {
		let c = substr(s, i, 1);
		let b = ord(s, i);
		if (c == "\\" || c == "\"")
			out += "\\" + c;
		else if (c == "\n")
			out += "\\n";
		else if (c == "\r")
			out += "\\r";
		else if (b < 32)
			out += sprintf("\\%03d", b);
		else
			out += c;
	}
	return out + "\"";
}

function exec_pair(cmd) {
	let ret = api.exec_call(cmd);
	if (type(ret) == "array")
		return [ret[0], ret[1]];
	if (type(ret) == "object" && ret != null)
		return [ret.code ?? ret[0], ret.out ?? ret.stdout ?? ret[1]];
	return [ret, ""];
}

function lua_tostring(v) {
	if (v == null)
		return "nil";
	if (type(v) == "bool")
		return v ? "true" : "false";
	return "" + v;
}

function finalize(v) {
	let t = type(v);
	if (t == "array") {
		for (let i = 0; i < length(v); i++)
			v[i] = finalize(v[i]);
		if (length(v) == 0)
			return {};
		return v;
	}
	if (t == "object") {
		let drop = [];
		for (let k, val in v) {
			if (val == null)
				push(drop, k);
			else
				v[k] = finalize(val);
		}
		for (let k in drop)
			delete v[k];
		return v;
	}
	return v;
}

function drop_underscore(obj) {
	if (type(obj) != "object")
		return;
	let drop = [];
	for (let k in obj) {
		if (type(k) == "string" && index(k, "_") == 0)
			push(drop, k);
	}
	for (let k in drop)
		delete obj[k];
}

function pem_lines(s) {
	return api.split(replace(s, "\\n", "\n"), "\n");
}

function both_set(a, b) {
	return ltruth(a) && ltruth(b);
}

function ensure_version() {
	if (version_inited)
		return;
	version_inited = true;
	let raw = api.get_app_version("sing-box");
	if (type(raw) == "string") {
		let m = match(raw, /[^v]+/);
		local_version = m ? m[0] : null;
	}
	version_ge_1_14_0 = api.compare_versions(local_version, ">=", "1.14.0");
	version_ge_1_15_0 = api.compare_versions(local_version, ">=", "1.15.0");
}

function get_log_level(s) {
	if (s == "warning")
		return "warn";
	return s;
}

function asset_dir(path) {
	let m = match("" + path, /^(.*)\//);
	return m ? m[1] : null;
}

export function check_geoview() {
	if (GEO_VAR.OK == null) {
		let bin = api.finded_com("geoview");
		let ge_ok = false;
		if (ltruth(bin))
			ge_ok = api.compare_versions(api.get_app_version("geoview"), ">=", "0.1.10");
		GEO_VAR.OK = ge_ok ? 1 : 0;
	}
	if (GEO_VAR.OK == 0) {
		api.log("！！！注意：缺少 Geoview 组件或版本过低，Sing-Box 分流无法启用！");
	} else {
		GEO_VAR.DIR = lor(GEO_VAR.DIR, asset_dir(lor(api.uci_get_c("@global_rules[0]", "v2ray_location_asset"), "/usr/share/v2ray/")));
		if (GEO_VAR.SITE_PATH == null || GEO_VAR.SITE_PATH === false)
			GEO_VAR.SITE_PATH = GEO_VAR.DIR + "/geosite.dat";
		if (GEO_VAR.IP_PATH == null || GEO_VAR.IP_PATH === false)
			GEO_VAR.IP_PATH = GEO_VAR.DIR + "/geoip.dat";
		if (!ltruth(api.fs.access(GEO_VAR.TO_SRS_PATH)))
			api.fs.mkdir(GEO_VAR.TO_SRS_PATH);
	}
	return GEO_VAR.OK;
}

export function geo_convert_srs(var) {
	if (check_geoview() != 1)
		return null;
	let geo_path = var["geo_path"];
	let prefix = var["prefix"];
	let rule_name = var["rule_name"];
	let output_srs_file = GEO_VAR.TO_SRS_PATH + prefix + "-" + rule_name + ".srs";
	let bin = api.finded_com("geoview");
	if (!ltruth(api.fs.access(output_srs_file)) && ltruth(bin)) {
		let cmd = lua_quote(bin) + " -type " + lua_quote(prefix) + " -action convert -input " + lua_quote(geo_path) + " -list " + lua_quote(rule_name) + " -output " + lua_quote(output_srs_file) + " -lowmem=true";
		let rc = exec_pair(cmd);
		let code = rc[0];
		let out = rc[1];
		if (code != 0 || !ltruth(api.fs.access(output_srs_file)))
			api.log(sprintf("  - %s:%s 转换为srs格式：%s [%s]", prefix, rule_name, "failed!", lua_tostring(out)));
	}
	return null;
}

function convert_geofile() {
	if (check_geoview() != 1)
		return;
	function convert(file_path, prefix, tags) {
		if (has_keys(tags) && ltruth(api.fs.access(file_path))) {
			for (let k in tags)
				geo_convert_srs({ geo_path: file_path, prefix: prefix, rule_name: k });
		}
	}
	convert(GEO_VAR.SITE_PATH, "geosite", GEO_VAR.SITE_TAGS);
	convert(GEO_VAR.IP_PATH, "geoip", GEO_VAR.IP_TAGS);
}

function get_ech_domain(s) {
	let m = match(s, /^([^+]+)\+(.+)$/);
	if (m == null)
		return null;
	let domain = m[1];
	let dns = m[2];
	if (!(match(dns, /^https?:\/\//) || match(dns, /^tcp:\/\//) || match(dns, /^udp:\/\//) || match(dns, /^h2c:\/\//)))
		return null;
	if (match(domain, /^[A-Za-z0-9_.-]+\.[A-Za-z]+$/) == null)
		return null;
	return domain;
}

function build_ech(node) {
	let ech = { enabled: true };
	let config = node.ech_config;
	let qname = node.ech_query_server_name;
	if (ltruth(config) && !ltruth(qname)) {
		qname = get_ech_domain(config);
		if (!ltruth(qname) && !(match(config, /-+[[:space:]]*BEGIN/) && match(config, /-+[[:space:]]*END/)))
			config = "-----BEGIN ECH CONFIGS-----\n" + replace(config, /[[:space:]]+/g, "") + "\n-----END ECH CONFIGS-----";
	}
	if (ltruth(qname)) {
		ech.query_server_name = qname;
		ech_domain[qname] = true;
	} else if (ltruth(config)) {
		ech.config = pem_lines(config);
	} else if (ltruth(node.tls_serverName) && node.tls_serverName != "") {
		ech_domain[node.tls_serverName] = true;
	}
	return ech;
}

function alpn_list(s) {
	if (!(ltruth(s) && s != "default"))
		return null;
	let list = gmatch(s, /[^,]+/g);
	return nonempty(list);
}

function hysteria2_obfs(node, t) {
	if (t == null || t === false || t == "")
		return null;
	let o = {
		type: t,
		password: node.hysteria2_obfs_password
	};
	if (t == "gecko") {
		let min = lor(tonumber(node.hysteria2_obfs_MinPacketSize), 512);
		let max = lor(tonumber(node.hysteria2_obfs_MaxPacketSize), 1200);
		if (min <= 0 || min > max || max > 2048) {
			min = 512;
			max = 1200;
		}
		o.min_packet_size = min;
		o.max_packet_size = max;
	}
	return o;
}

function hysteria2_idle(t) {
	if (!version_ge_1_14_0)
		return null;
	let n = leading_int(lor(t, "30"));
	return (n != null && n >= 4 && n <= 120) ? (n + "s") : "30s";
}

function hysteria2_keepalive(t) {
	if (!version_ge_1_14_0)
		return null;
	let n = leading_int(lor(t, "0"));
	return (n != null && n >= 2 && n <= 60) ? (n + "s") : null;
}

function opt_num(v) {
	let n = tonumber(v);
	if (ltruth(v) && n != null)
		return n;
	return null;
}

function mb_window(v) {
	let n = tonumber(v);
	if (n == null)
		return null;
	return n + " MB";
}

function collect_hop_ports(hop) {
	let ports = [];
	hop = replace(hop, "-", ":");
	for (let range in gmatch(hop, /[^,]+/g)) {
		if (match(range, /^[0-9]+:[0-9]+$/) != null)
			push(ports, range);
	}
	return [hop, ports];
}

function hysteria_hop_interval(ports, node) {
	if (!has_keys(ports))
		return null;
	let n = leading_int(lor(node.hysteria_hop_interval, "30"));
	return (n != null && n >= 5) ? (n + "s") : "30s";
}

function hysteria2_hop_times(ports, node) {
	if (!has_keys(ports))
		return [null, null];
	let interval = "30s";
	let interval_max = null;
	let t = "" + lor(node.hysteria2_hop_interval, "30s");
	if (index(t, "-") >= 0) {
		let mm = match(t, /^([0-9]+)-([0-9]+)$/);
		if (mm != null) {
			let min = tonumber(mm[1]);
			let max = tonumber(mm[2]);
			if (min != null && max != null) {
				min = (min >= 5) ? min : 5;
				max = (max >= min) ? max : min;
				interval = min + "s";
				interval_max = max + "s";
			}
		}
	} else {
		let n = leading_int(t);
		n = (n != null && n >= 5) ? n : 30;
		interval = n + "s";
	}
	return [interval, interval_max];
}

function client_realm(node, result) {
	result.server = null;
	result.server_port = null;
	let realm = api.parse_realm_uri(node.hysteria2_realm_url);
	if (realm == null)
		return null;
	realm.server_url = (realm.scheme == "realm+http" ? "http://" : "https://") + realm.server_url;
	realm.stun_servers = lor(realm.stun_servers, node.hysteria2_realm_stun);
	realm.scheme = null;
	realm.address = null;
	realm.port = null;
	realm.port_mapping = (node.hysteria2_realm_upnp == "1") ? { enabled: true } : null;
	realm.http_client = "direct_http_client";
	return realm;
}

function server_realm(node) {
	let realm = api.parse_realm_uri(node.hysteria2_realm_url);
	if (realm == null)
		return null;
	realm.server_url = (realm.scheme == "realm+http" ? "http://" : "https://") + realm.server_url;
	realm.stun_servers = lor(realm.stun_servers, node.hysteria2_realm_stun);
	realm.scheme = null;
	realm.address = null;
	realm.port = null;
	realm.stun_domain_resolver = "direct";
	realm.port_mapping = (node.hysteria2_realm_upnp == "1") ? { enabled: true } : null;
	realm.http_client = { detour: "direct" };
	return realm;
}

function decode_reserved(text) {
	let bytes = [];
	if (match(text, /[^0-9,]+/) == null) {
		for (let b in gmatch(text, /[0-9]+/g))
			push(bytes, tonumber(b));
	} else {
		let decoded = api.base64Decode(text);
		if (type(decoded) == "string") {
			for (let i = 0; i < length(decoded); i++)
				push(bytes, ord(decoded, i));
		}
	}
	return nonempty(bytes);
}

function masque_header_map(node) {
	let headers = {};
	if (ltruth(node.user_agent) && node.user_agent != "")
		headers["user-agent"] = [node.user_agent];
	let text = replace(lor(node.masque_headers, ""), "\\n", "\n");
	for (let line in gmatch(text, /[^\r\n]+/g)) {
		let m = match(line, /^[[:space:]]*([^:]+):[[:space:]]*(.*)[[:space:]]*$/);
		if (m != null) {
			let value = trim(m[2]);
			headers[lc(api.trim(m[1]))] = [value];
		}
	}
	return headers;
}

function ws_early_data(transport, ws_path) {
	let path = api.UrlDecode(ws_path);
	let path_dat = api.split(path, "?");
	if (path_dat == null)
		path_dat = [];
	let params = {};
	let parts = api.split(path_dat[1], "&");
	if (parts == null)
		parts = [];
	for (let v in parts) {
		let t = api.split(v, "=");
		if (t == null)
			t = [];
		if (t[0] != null)
			params[t[0]] = t[1];
	}
	let ed = tonumber(params.ed);
	if (ed != null) {
		transport.path = path_dat[0];
		transport.max_early_data = ed;
	}
	transport.early_data_header_name = lor(params.eh, "Sec-WebSocket-Protocol");
}

function ua_headers(ua) {
	if (!ltruth(ua))
		return null;
	return { "User-Agent": ua };
}

function http_host_path(node) {
	let host = lor(node.http_host, {});
	let path = lor(node.http_path, "/");
	let headers = ua_headers(node.user_agent);
	let transport = {
		type: "http",
		host: host,
		path: path
	};
	set_if(transport, "headers", headers);
	return transport;
}

function build_client_transport(node) {
	let transport = null;
	if (node.transport == "tcp" && node.tcp_guise == "http" && lor(node.tcp_guise_http_host, "") != "") {
		let path = "/";
		if (ltruth(node.tcp_guise_http_path)) {
			let first = node.tcp_guise_http_path[0];
			path = (first == "" || !ltruth(first)) ? "/" : first;
		}
		transport = {
			type: "http",
			host: node.tcp_guise_http_host,
			path: path
		};
		set_if(transport, "headers", ua_headers(node.user_agent));
	}
	if (node.transport == "http") {
		transport = http_host_path(node);
		if (node.http_h2_health_check == "1") {
			transport.idle_timeout = api.format_go_time(node.http_h2_read_idle_timeout, "15s");
			transport.ping_timeout = api.format_go_time(node.http_h2_health_check_timeout, "15s");
		}
	}
	if (node.transport == "ws") {
		transport = {
			type: "ws",
			path: lor(node.ws_path, "/")
		};
		if (ltruth(node.ws_host) || ltruth(node.user_agent)) {
			transport.headers = {
				Host: node.ws_host,
				"User-Agent": node.user_agent
			};
		}
		ws_early_data(transport, node.ws_path);
	}
	if (node.transport == "httpupgrade") {
		transport = {
			type: "httpupgrade",
			host: node.httpupgrade_host,
			path: lor(node.httpupgrade_path, "/")
		};
		set_if(transport, "headers", ua_headers(node.user_agent));
	}
	if (node.transport == "quic")
		transport = { type: "quic" };
	if (node.transport == "grpc") {
		transport = {
			type: "grpc",
			service_name: node.grpc_serviceName
		};
		if (node.grpc_health_check == "1") {
			transport.idle_timeout = api.format_go_time(node.grpc_idle_timeout, "15s");
			transport.ping_timeout = api.format_go_time(node.grpc_health_check_timeout, "15s");
		}
		if (node.grpc_permit_without_stream == "1")
			transport.permit_without_stream = true;
	}
	return transport;
}

function build_server_transport(node) {
	let transport = null;
	if (node.transport == "http")
		transport = {
			type: "http",
			host: lor(node.http_host, {}),
			path: lor(node.http_path, "/")
		};
	if (node.transport == "ws") {
		transport = {
			type: "ws",
			path: lor(node.ws_path, "/"),
			early_data_header_name: ltruth(node.ws_earlyDataHeaderName) ? node.ws_earlyDataHeaderName : "Sec-WebSocket-Protocol"
		};
		if (node.ws_host != null)
			transport.headers = { Host: node.ws_host };
	}
	if (node.transport == "httpupgrade")
		transport = {
			type: "httpupgrade",
			host: node.httpupgrade_host,
			path: lor(node.httpupgrade_path, "/")
		};
	if (node.transport == "quic")
		transport = { type: "quic" };
	if (node.transport == "grpc")
		transport = {
			type: "grpc",
			service_name: node.grpc_serviceName
		};
	return transport;
}

function build_client_mux(node) {
	if (node.mux != "1")
		return null;
	return {
		enabled: true,
		protocol: lor(node.mux_type, "h2mux"),
		max_connections: (node.tcpbrutal == "1") ? 1 : lor(tonumber(node.mux_concurrency), 4),
		padding: node.mux_padding == "1",
		brutal: {
			enabled: node.tcpbrutal == "1",
			up_mbps: lor(tonumber(node.tcpbrutal_up_mbps), 10),
			down_mbps: lor(tonumber(node.tcpbrutal_down_mbps), 50)
		}
	};
}

function build_server_mux(node) {
	if (node.mux != "1")
		return null;
	return {
		enabled: true,
		padding: node.mux_padding == "1",
		brutal: {
			enabled: node.tcpbrutal == "1",
			up_mbps: lor(tonumber(node.tcpbrutal_up_mbps), 10),
			down_mbps: lor(tonumber(node.tcpbrutal_down_mbps), 50)
		}
	};
}

function build_client_tls(node, fragment, record_fragment) {
	if (node.tls != "1")
		return null;
	let tls = {
		enabled: true,
		disable_sni: node.tls_disable_sni == "1",
		insecure: node.tls_allowInsecure == "1"
	};
	set_if(tls, "server_name", node.tls_serverName);
	set_if(tls, "alpn", alpn_list(node.alpn));
	set_if(tls, "fragment", fragment);
	set_if(tls, "record_fragment", record_fragment);
	if (node.tls_certificate == "1" && node.tls_certificate_pem != null && node.tls_certificate_pem != "")
		tls.certificate = pem_lines(node.tls_certificate_pem);
	if (ltruth(node.cipherSuites) && node.cipherSuites != "")
		tls.cipher_suites = api.split(node.cipherSuites, ":");
	if (node.ech == "1")
		tls.ech = build_ech(node);
	if (node.utls == "1" || node.reality == "1") {
		tls.utls = {
			enabled: true,
			fingerprint: lor(node.fingerprint, "chrome")
		};
	}
	if (node.reality == "1") {
		tls.reality = { enabled: true };
		set_if(tls.reality, "public_key", node.reality_publicKey);
		set_if(tls.reality, "short_id", node.reality_shortId);
	}
	if (version_ge_1_15_0) {
		if (ltruth(node.tls_pinSHA256) && node.tls_pinSHA256 != "")
			tls.certificate_sha256 = [api.sha256_xray_sb(node.tls_pinSHA256)];
	} else {
		tls.insecure = node.tls_allowInsecure == "1" || (ltruth(node.tls_pinSHA256) && node.tls_pinSHA256 != "");
	}
	return tls;
}

function uot_obj() {
	return { enabled: true, version: 2 };
}

function apply_node_dns(node, result) {
	if (!(api.datatypes.hostname(node.address) && ltruth(node.domain_resolver) && (ltruth(node.domain_resolver_dns) || ltruth(node.domain_resolver_dns_https))))
		return;
	let dns_proto = node.domain_resolver;
	let server_address = null;
	let server_port = null;
	let server_path = null;
	if (dns_proto == "https") {
		let parsed = api.parseDoH(node.domain_resolver_dns_https);
		if (parsed != null) {
			server_address = parsed.hostname;
			server_port = lor(parsed.port, 443);
			server_path = lor(parsed.pathname, "");
			if (ltruth(parsed.hostname) && api.datatypes.hostname(parsed.hostname))
				GLOBAL.DNS_HOSTNAME[parsed.hostname] = true;
		}
	} else {
		server_address = node.domain_resolver_dns;
		server_port = 53;
		let parts = api.split(server_address, ":");
		if (parts != null && length(parts) > 1) {
			server_address = parts[0];
			server_port = tonumber(parts[length(parts) - 1]);
		}
	}
	let dns_key = dns_proto + "|" + lua_tostring(server_address) + "|" + lua_tostring(server_port) + "|" + lua_tostring(lor(server_path, ""));
	if (GLOBAL.DNS_SERVER[dns_key] == null) {
		GLOBAL.DNS_SERVER[dns_key] = {
			server: {
				tag: "dns-node-" + api.gen_random_char(),
				type: dns_proto,
				server: server_address,
				server_port: server_port,
				path: server_path,
				domain_resolver: "direct",
				detour: "direct"
			},
			domain: []
		};
	}
	let exists = false;
	for (let d in GLOBAL.DNS_SERVER[dns_key].domain) {
		if (d == node.address) {
			exists = true;
			break;
		}
	}
	if (!exists)
		push(GLOBAL.DNS_SERVER[dns_key].domain, node.address);
	result.domain_resolver.server = GLOBAL.DNS_SERVER[dns_key].server.tag;
	GLOBAL.VPS_EXCLUDE[node.address] = true;
}

function fill_client_protocol(node, result, tls, mux, transport) {
	if (node.protocol == "socks") {
		result.version = "5";
		if (both_set(node.username, node.password)) {
			result.username = node.username;
			result.password = node.password;
		}
		if (node.uot == "1")
			result.udp_over_tcp = uot_obj();
	}
	if (node.protocol == "http") {
		if (both_set(node.username, node.password)) {
			result.username = node.username;
			result.password = node.password;
		}
		set_if(result, "tls", tls);
	}
	if (node.protocol == "shadowsocks") {
		set_if(result, "method", or_nil(node.method));
		result.password = lor(node.password, "");
		if (ltruth(node.plugin_enabled) && ltruth(node.plugin))
			result.plugin = node.plugin;
		if (ltruth(node.plugin_enabled) && ltruth(node.plugin_opts))
			result.plugin_opts = node.plugin_opts;
		if (node.uot == "1")
			result.udp_over_tcp = uot_obj();
		set_if(result, "multiplex", mux);
	}
	if (node.protocol == "trojan") {
		set_if(result, "password", node.password);
		set_if(result, "tls", tls);
		set_if(result, "multiplex", mux);
		set_if(result, "transport", transport);
	}
	if (node.protocol == "vmess") {
		set_if(result, "uuid", node.uuid);
		set_if(result, "security", node.security);
		result.alter_id = (ltruth(node.alter_id) && tonumber(node.alter_id) != null) ? tonumber(node.alter_id) : 0;
		result.global_padding = node.global_padding == "1";
		result.authenticated_length = node.authenticated_length == "1";
		set_if(result, "tls", tls);
		result.packet_encoding = "";
		set_if(result, "multiplex", mux);
		set_if(result, "transport", transport);
	}
	if (node.protocol == "vless") {
		set_if(result, "uuid", node.uuid);
		if (node.tls == "1" && ltruth(node.flow))
			result.flow = node.flow;
		set_if(result, "tls", tls);
		result.packet_encoding = "xudp";
		set_if(result, "multiplex", mux);
		set_if(result, "transport", transport);
	}
	if (node.protocol == "wireguard") {
		if (ltruth(node.wireguard_reserved))
			node.wireguard_reserved = decode_reserved(node.wireguard_reserved);
		set_if(result, "local_address", node.wireguard_local_address);
		set_if(result, "private_key", node.wireguard_secret_key);
		set_if(result, "peer_public_key", node.wireguard_public_key);
		set_if(result, "pre_shared_key", node.wireguard_preSharedKey);
		set_if(result, "reserved", node.wireguard_reserved);
		set_if(result, "mtu", tonumber(node.wireguard_mtu));
	}
	if (node.protocol == "hysteria") {
		let server_ports = [];
		if (ltruth(node.hysteria_hop)) {
			let hop = collect_hop_ports(node.hysteria_hop);
			node.hysteria_hop = hop[0];
			server_ports = hop[1];
			result.server_port = null;
		}
		set_if(result, "server_ports", nonempty(server_ports));
		set_if(result, "hop_interval", hysteria_hop_interval(server_ports, node));
		set_if(result, "up_mbps", tonumber(node.hysteria_up_mbps));
		set_if(result, "down_mbps", tonumber(node.hysteria_down_mbps));
		set_if(result, "obfs", node.hysteria_obfs);
		if (node.hysteria_auth_type == "base64")
			set_if(result, "auth", node.hysteria_auth_password);
		if (node.hysteria_auth_type == "string")
			set_if(result, "auth_str", node.hysteria_auth_password);
		set_if(result, "stream_receive_window", tonumber(node.hysteria_recv_window_conn));
		set_if(result, "connection_receive_window", tonumber(node.hysteria_recv_window));
		result.disable_path_mtu_discovery = node.hysteria_disable_mtu_discovery == "1";
		set_if(result, "tls", tls);
	}
	if (node.protocol == "shadowtls") {
		set_if(result, "version", tonumber(node.shadowtls_version));
		if (node.shadowtls_version == "2" || node.shadowtls_version == "3")
			set_if(result, "password", node.password);
		set_if(result, "tls", tls);
	}
	if (node.protocol == "tuic") {
		set_if(result, "uuid", node.uuid);
		set_if(result, "password", node.password);
		result.congestion_control = lor(node.tuic_congestion_control, "cubic");
		result.udp_relay_mode = lor(node.tuic_udp_relay_mode, "native");
		result.udp_over_stream = false;
		result.zero_rtt_handshake = node.tuic_zero_rtt_handshake == "1";
		result.heartbeat = lor(tonumber(node.tuic_heartbeat), 3) + "s";
		set_if(result, "tls", tls);
		node.tuic_alpn = (ltruth(node.tuic_alpn) && node.tuic_alpn != "default") ? node.tuic_alpn : "h3";
		let alpn = gmatch(node.tuic_alpn, /[^,]+/g);
		if (length(alpn) > 0 && result.tls != null)
			result.tls.alpn = alpn;
	}
	if (node.protocol == "hysteria2") {
		let server_ports = [];
		if (ltruth(node.hysteria2_hop)) {
			let hop = collect_hop_ports(node.hysteria2_hop);
			node.hysteria2_hop = hop[0];
			server_ports = hop[1];
			result.server_port = null;
		}
		if (ltruth(node.hysteria2_realms))
			server_ports = [];
		let hop_t = hysteria2_hop_times(server_ports, node);
		set_if(result, "server_ports", nonempty(server_ports));
		set_if(result, "hop_interval", hop_t[0]);
		set_if(result, "hop_interval_max", hop_t[1]);
		set_if(result, "up_mbps", opt_num(node.hysteria2_up_mbps));
		set_if(result, "down_mbps", opt_num(node.hysteria2_down_mbps));
		set_if(result, "obfs", hysteria2_obfs(node, node.hysteria2_obfs_type));
		set_if(result, "password", or_nil(node.hysteria2_auth_password));
		set_if(result, "idle_timeout", hysteria2_idle(node.hysteria2_idle_timeout));
		set_if(result, "keep_alive_period", hysteria2_keepalive(node.hysteria2_keep_alive_period));
		set_if(result, "stream_receive_window", mb_window(node.hysteria2_stream_recv_win));
		set_if(result, "connection_receive_window", mb_window(node.hysteria2_conn_recv_win));
		if (version_ge_1_14_0 && node.hysteria2_disable_mtu_discovery == "1")
			result.disable_path_mtu_discovery = true;
		set_if(result, "tls", tls);
		if (ltruth(node.hysteria2_realms))
			set_if(result, "realm", client_realm(node, result));
	}
	if (node.protocol == "anytls") {
		result.password = (ltruth(node.password) && node.password != "") ? node.password : "";
		result.idle_session_check_interval = "30s";
		result.idle_session_timeout = "30s";
		result.min_idle_session = 5;
		if (api.compare_versions(local_version, ">=", "1.13.16"))
			result.client_metadata = "anytls/0.0.13";
		set_if(result, "tls", tls);
	}
	if (node.protocol == "ssh") {
		result.user = (ltruth(node.username) && node.username != "") ? node.username : "root";
		result.password = (ltruth(node.password) && node.password != "") ? node.password : "";
		set_if(result, "private_key", node.ssh_priv_key);
		set_if(result, "private_key_passphrase", node.ssh_priv_key_pp);
		set_if(result, "host_key", node.ssh_host_key);
		set_if(result, "host_key_algorithms", node.ssh_host_key_algo);
		set_if(result, "client_version", node.ssh_client_version);
	}
	if (node.protocol == "naive") {
		result.username = (ltruth(node.username) && node.username != "") ? node.username : "";
		result.password = (ltruth(node.password) && node.password != "") ? node.password : "";
		let ic = tonumber(lor(node.naive_insecure_concurrency, 0));
		result.insecure_concurrency = (ic != null && ic > 0) ? tonumber(node.naive_insecure_concurrency) : 0;
		result.udp_over_tcp = node.uot == "1" ? uot_obj() : false;
		set_if(result, "extra_headers", ua_headers(node.user_agent));
		result.quic = node.naive_quic == "1";
		if (node.naive_quic == "1" && ltruth(node.naive_congestion_control))
			result.quic_congestion_control = node.naive_congestion_control;
		set_if(result, "tls", tls);
	}
	if (node.protocol == "masque") {
		let headers = masque_header_map(node);
		result.type = "masque-client";
		if (!ltruth(headers.authorization)) {
			set_if(result, "username", node.username);
			set_if(result, "password", node.password);
		}
		if (ltruth(node.masque_path) && node.masque_path != "")
			result.path = node.masque_path;
		if (has_keys(headers))
			result.headers = headers;
		set_if(result, "tls", tls);
	}
	if (node.protocol == "snell") {
		set_if(result, "version", tonumber(node.snell_version));
		set_if(result, "psk", node.snell_psk);
		set_if(result, "userkey", node.password);
		result.reuse = node.snell_reuse == "1";
		set_if(result, "network", node.snell_network);
		if (node.snell_version == "4") {
			set_if(result, "obfs_mode", node.snell_obfs_mode);
			set_if(result, "obfs_host", node.snell_obfs_host);
		}
		if (node.snell_version == "6")
			set_if(result, "mode", node.snell_mode);
	}
}

export function gen_outbound(flag, node, tag, proxy_table) {
	ensure_version();
	if (!ltruth(node))
		return null;
	let node_id = node[".name"];
	if (tag == null)
		tag = node_id;
	let remarks = node.remarks;
	let proxy_tag = null;
	let fragment = null;
	let record_fragment = null;
	if (proxy_table != null && is_table(proxy_table)) {
		proxy_tag = or_nil(proxy_table.tag);
		let allow_frag = node.protocol != "naive" && node.protocol != "masque" && !ltruth(node.hysteria2_realms);
		if (ltruth(proxy_table.fragment) && allow_frag)
			fragment = true;
		if (ltruth(proxy_table.record_fragment) && allow_frag)
			record_fragment = true;
	}
	if (node.type != "sing-box") {
		if (node.type == "Socks") {
			node.protocol = "socks";
			proxy_tag = "socks <- " + node_id;
		} else {
			let new_port = null;
			let run_socks_instance = true;
			if (ltruth(NO_RUN)) {
				TMP_PORT = (TMP_PORT != null) ? (TMP_PORT + 1) : 3001;
				new_port = TMP_PORT;
				run_socks_instance = null;
			} else {
				let relay_port = (ltruth(proxy_tag) && ltruth(node.port)) ? ("" + node.port) : "";
				if (relay_port == "") {
					let cache = api.get_socks_port_by_cache(node_id);
					if (ltruth(cache)) {
						new_port = cache;
						run_socks_instance = null;
					}
				}
				if (ltruth(run_socks_instance)) {
					new_port = api.get_new_port();
					let config_file = sprintf("nodesocks_%s_%s.json", node_id, new_port);
					if (ltruth(tag) && ltruth(node_id) && index(tag, node_id) < 0)
						config_file = sprintf("nodesocks_%s_%s_%s.json", tag, node_id, new_port);
					let arg = sprintf("flag=%s node=%s bind=%s socks_port=%s config_file=%s relay_port=%s",
						new_port, node_id, "127.0.0.1", new_port, config_file, relay_port);
					api.sys.call(sprintf('/usr/share/passwall/app.sh run_socks "%s"> /dev/null', arg));
					if (relay_port == "")
						api.set_socks_port_to_cache(node_id, new_port);
				}
			}
			if (new_port != null) {
				node = {
					protocol: "socks",
					address: "127.0.0.1",
					port: new_port
				};
				proxy_tag = "socks <- " + node_id;
			}
		}
	} else if (ltruth(proxy_tag)) {
		node.detour = proxy_tag;
	}
	if (ltruth(remarks))
		tag = tag + ":" + remarks;
	node.address = lc(lor(node.address, ""));
	let resolver = { server: "direct" };
	set_if(resolver, "strategy", node.domain_strategy);
	let result = {
		tag: tag,
		type: node.protocol,
		server: node.address,
		domain_resolver: resolver
	};
	set_if(result, "_id", node_id);
	set_if(result, "_flag", flag);
	set_if(result, "_flag_proxy_tag", proxy_tag);
	set_if(result, "server_port", tonumber(node.port));
	set_if(result, "detour", node.detour);
	apply_node_dns(node, result);
	if (node.protocol == "masque") {
		node.alpn = null;
		node.utls = null;
		node.reality = null;
		node.transport = null;
		node.mux = null;
	}
	if (node.protocol == "hysteria" || node.protocol == "hysteria2" || node.protocol == "tuic" || node.protocol == "naive" || node.protocol == "masque")
		node.tls = "1";
	let tls = build_client_tls(node, fragment, record_fragment);
	let mux = build_client_mux(node);
	let transport = null;
	if (node.protocol != "masque")
		transport = build_client_transport(node);
	fill_client_protocol(node, result, tls, mux, transport);
	return result;
}

function server_users(node) {
	if (!(ltruth(node.users) && length(node.users) > 0))
		return null;
	let users = [];
	for (let v in node.users) {
		let user = api.uci_get_s(v);
		if (user == null || user === false)
			user = {};
		if (user[".type"] != "user")
			continue;
		let u = {};
		if (node.protocol == "mixed" || node.protocol == "socks" || node.protocol == "http" || node.protocol == "naive" || node.protocol == "masque") {
			u.username = user.username;
			u.password = user.password;
		}
		if (node.protocol == "shadowsocks" || node.protocol == "trojan" || node.protocol == "hysteria2" || node.protocol == "anytls") {
			u.name = user.username;
			u.password = user.password;
		}
		if (node.protocol == "vmess") {
			u.name = user.username;
			u.uuid = user.uuid;
			u.alterId = 0;
		}
		if (node.protocol == "vless") {
			u.name = user.username;
			u.uuid = user.uuid;
			u.flow = node.flow;
		}
		if (node.protocol == "hysteria") {
			u.name = user.username;
			u.auth_str = user.password;
		}
		if (node.protocol == "tuic") {
			u.name = user.username;
			u.password = user.password;
			u.uuid = user.uuid;
		}
		if (node.protocol == "wireguard") {
			u.public_key = user.wireguard_public_key;
			u.pre_shared_key = user.wireguard_pre_shared_key;
			u.allowed_ips = lor(user.allowed_ips, {});
			u.persistent_keepalive_interval = 0;
		}
		if (node.protocol == "snell") {
			u.name = user.username;
			u.userkey = user.password;
		}
		push(users, u);
	}
	if (length(users) == 0)
		return null;
	return users;
}

function build_server_tls(node) {
	let tls = { enabled: true };
	if (node.tls_use_pem != "1") {
		set_if(tls, "certificate_path", node.tls_certificateFile);
		set_if(tls, "key_path", node.tls_keyFile);
	}
	if (node.tls_use_pem == "1" && ltruth(node.tls_certificate))
		tls.certificate = pem_lines(node.tls_certificate);
	if (node.tls_use_pem == "1" && ltruth(node.tls_key))
		tls.key = pem_lines(node.tls_key);
	set_if(tls, "alpn", alpn_list(node.alpn));
	if (node.tls == "1" && node.reality == "1") {
		tls.certificate_path = null;
		tls.key_path = null;
		tls.certificate = null;
		tls.key = null;
		tls.server_name = node.reality_handshake_server;
		tls.reality = {
			enabled: true,
			private_key: node.reality_private_key,
			short_id: (node.reality_shortId != null) ? [node.reality_shortId] : [],
			handshake: {
				server: node.reality_handshake_server,
				server_port: tonumber(node.reality_handshake_server_port)
			}
		};
	}
	if (node.tls == "1" && node.ech == "1") {
		tls.ech = { enabled: true };
		if (ltruth(node.ech_key))
			tls.ech.key = pem_lines(node.ech_key);
	}
	return tls;
}

export function gen_config_server(node) {
	ensure_version();
	let endpoints = [];
	let inbounds = [];
	let outbounds = [
		{ type: "direct", tag: "direct" }
	];
	if (node.protocol == "masque") {
		node.tls = "1";
		node.reality = null;
	}
	let tls = build_server_tls(node);
	let mux = build_server_mux(node);
	let transport = build_server_transport(node);
	let inbound = {
		type: node.protocol,
		tag: "inbound",
		listen: "::",
		listen_port: tonumber(node.port)
	};
	let users = server_users(node);
	if (node.protocol == "masque") {
		tls.alpn = null;
		inbound.type = "masque-server";
		set_if(inbound, "users", users);
		if (ltruth(node.masque_path) && node.masque_path != "")
			inbound.path = node.masque_path;
		set_if(inbound, "address", node.masque_address);
		inbound.mtu = tonumber(lor(node.masque_mtu, 1280));
		inbound.tls = tls;
	}
	if (node.protocol == "mixed") {
		set_if(inbound, "users", users);
		inbound.set_system_proxy = false;
	}
	if (node.protocol == "socks")
		set_if(inbound, "users", users);
	if (node.protocol == "http") {
		set_if(inbound, "users", users);
		if (node.tls == "1")
			inbound.tls = tls;
	}
	if (node.protocol == "shadowsocks") {
		set_if(inbound, "method", node.method);
		set_if(inbound, "password", node.ss_password);
		set_if(inbound, "users", users);
		set_if(inbound, "multiplex", mux);
	}
	if (node.protocol == "vmess" && ltruth(users)) {
		inbound.users = users;
		if (node.tls == "1")
			inbound.tls = tls;
		set_if(inbound, "multiplex", mux);
		set_if(inbound, "transport", transport);
	}
	if (node.protocol == "vless" && ltruth(users)) {
		inbound.users = users;
		if (node.tls == "1")
			inbound.tls = tls;
		set_if(inbound, "multiplex", mux);
		set_if(inbound, "transport", transport);
	}
	if (node.protocol == "trojan" && ltruth(users)) {
		inbound.users = users;
		if (node.tls == "1")
			inbound.tls = tls;
		set_if(inbound, "multiplex", mux);
		set_if(inbound, "transport", transport);
	}
	if (node.protocol == "naive" && ltruth(users)) {
		inbound.users = users;
		inbound.tls = tls;
	}
	if (node.protocol == "hysteria") {
		inbound.up = node.hysteria_up_mbps + " Mbps";
		inbound.down = node.hysteria_down_mbps + " Mbps";
		set_if(inbound, "up_mbps", tonumber(node.hysteria_up_mbps));
		set_if(inbound, "down_mbps", tonumber(node.hysteria_down_mbps));
		set_if(inbound, "obfs", node.hysteria_obfs);
		set_if(inbound, "users", users);
		if (ltruth(node.hysteria_recv_window_conn))
			set_if(inbound, "stream_receive_window", tonumber(node.hysteria_recv_window_conn));
		if (ltruth(node.hysteria_recv_window_client))
			set_if(inbound, "connection_receive_window", tonumber(node.hysteria_recv_window_client));
		if (ltruth(node.hysteria_max_conn_client))
			set_if(inbound, "max_concurrent_streams", tonumber(node.hysteria_max_conn_client));
		inbound.disable_path_mtu_discovery = node.hysteria_disable_mtu_discovery == "1";
		inbound.tls = tls;
	}
	if (node.protocol == "tuic") {
		let alpn = alpn_list(node.tuic_alpn);
		if (alpn != null)
			tls.alpn = alpn;
		else
			delete tls.alpn;
		set_if(inbound, "users", users);
		inbound.congestion_control = lor(node.tuic_congestion_control, "cubic");
		inbound.zero_rtt_handshake = node.tuic_zero_rtt_handshake == "1";
		inbound.heartbeat = lor(tonumber(node.tuic_heartbeat), 3) + "s";
		inbound.tls = tls;
	}
	if (node.protocol == "hysteria2") {
		if (node.hysteria2_ignore_client_bandwidth != "1") {
			set_if(inbound, "up_mbps", opt_num(node.hysteria2_up_mbps));
			set_if(inbound, "down_mbps", opt_num(node.hysteria2_down_mbps));
		}
		set_if(inbound, "obfs", hysteria2_obfs(node, node.hysteria2_obfs_type));
		set_if(inbound, "users", users);
		inbound.ignore_client_bandwidth = node.hysteria2_ignore_client_bandwidth == "1";
		inbound.tls = tls;
		if (ltruth(node.hysteria2_realms))
			set_if(inbound, "realm", server_realm(node));
	}
	if (node.protocol == "anytls" && ltruth(users)) {
		inbound.users = users;
		inbound.tls = tls;
	}
	if (node.protocol == "wireguard") {
		inbound.listen = null;
		inbound.system = node.wireguard_system_interface == "1";
		inbound.name = "sbwg_" + node[".name"];
		inbound.mtu = tonumber(lor(node.wireguard_mtu, 1408));
		set_if(inbound, "address", node.wireguard_local_address);
		set_if(inbound, "private_key", node.wireguard_private_key);
		if (ltruth(users))
			inbound.peers = users;
	}
	if (node.protocol == "snell") {
		set_if(inbound, "users", users);
		set_if(inbound, "version", tonumber(node.snell_version));
		set_if(inbound, "psk", node.snell_psk);
		if (node.snell_version == "5")
			set_if(inbound, "obfs_mode", node.snell_obfs_mode);
		if (node.snell_version == "6")
			set_if(inbound, "mode", node.snell_mode);
	}
	if (node.protocol == "direct") {
		if (node.d_protocol != "TCP,UDP")
			set_if(inbound, "network", node.d_protocol);
		set_if(inbound, "override_address", node.d_address);
		set_if(inbound, "override_port", tonumber(node.d_port));
	}
	if (node.protocol == "wireguard" || node.protocol == "masque")
		push(endpoints, inbound);
	else
		push(inbounds, inbound);
	let route = {
		rules: [{
			ip_is_private: true,
			action: node.accept_lan == "1" ? "route" : "reject",
			outbound: node.accept_lan == "1" ? "direct" : null
		}]
	};
	if (ltruth(node.outbound_node)) {
		let outbound = null;
		if (node.outbound_node == "_iface" && ltruth(node.outbound_node_iface)) {
			outbound = {
				type: "direct",
				tag: "outbound",
				bind_interface: node.outbound_node_iface,
				routing_mark: 255
			};
			api.sys.call(sprintf("mkdir -p %s && touch %s/%s", api.TMP_IFACE_PATH, api.TMP_IFACE_PATH, node.outbound_node_iface));
		} else {
			let outbound_node_t = api.uci_get_c(node.outbound_node);
			if (node.outbound_node == "_socks" || node.outbound_node == "_http") {
				outbound_node_t = {
					type: node.type,
					protocol: replace(node.outbound_node, "_", ""),
					address: node.outbound_node_address,
					port: tonumber(node.outbound_node_port)
				};
				if (ltruth(node.outbound_node_username) && node.outbound_node_username != "")
					outbound_node_t.username = node.outbound_node_username;
				if (ltruth(node.outbound_node_password) && node.outbound_node_password != "")
					outbound_node_t.password = node.outbound_node_password;
			}
			outbound = gen_outbound(null, outbound_node_t, "outbound");
		}
		if (ltruth(outbound)) {
			route.final = outbound.tag;
			unshift(outbounds, outbound);
		}
	}
	let config = {
		log: {
			disabled: !ltruth(node) || node.log == "0",
			level: lor(get_log_level(node.loglevel), "info"),
			timestamp: true
		},
		dns: {
			servers: [{
				type: "local",
				tag: "direct"
			}]
		},
		endpoints: endpoints,
		inbounds: inbounds,
		outbounds: outbounds,
		route: route
	};
	for (let item in config.outbounds)
		drop_underscore(item);
	return finalize(config);
}

function get_node_by_id(id) {
	let section = null;
	let kind = type(id);
	if (kind == "object" || kind == "array")
		section = id;
	else if (kind == "string") {
		if (id == "" || id == "nil")
			return null;
		section = api.uci_get_c(id);
		if (section == null || section === false)
			section = {};
	} else {
		return null;
	}
	if (section[".type"] == "socks") {
		return {
			".name": section[".name"],
			remarks: "socks[" + lua_tostring(section.port) + "]",
			type: "sing-box",
			protocol: "socks",
			address: "127.0.0.1",
			port: section.port,
			uot: "1"
		};
	}
	if (section[".type"] == "nodes")
		return section;
	return null;
}

function parse_rule_set(w, rs) {
	ensure_version();
	if (!(type(w) == "string" && length(w) > 0))
		return null;
	if (!(index(w, "local:") == 0 || index(w, "remote:") == 0))
		return null;
	let colon = index(w, ":");
	let kind = substr(w, 0, colon);
	w = substr(w, colon + 1);
	let slash = rindex(w, "/");
	let filename = slash < 0 ? w : substr(w, slash + 1);
	let suffix = "";
	let dot = rindex(filename, ".");
	if (dot >= 0)
		suffix = substr(filename, dot + 1);
	let format = null;
	if (suffix == "srs")
		format = "binary";
	else if (suffix == "json")
		format = "source";
	if (format == null)
		return null;
	let first_dot = index(filename, ".");
	if (first_dot < 0)
		return null;
	let rule_set_tag = substr(filename, 0, first_dot);
	if (!(ltruth(rule_set_tag) && length(rule_set_tag) > 0))
		return null;
	if (rs)
		rule_set_tag = "rs_" + rule_set_tag;
	let result = {
		type: kind,
		tag: rule_set_tag,
		format: format
	};
	if (kind == "local")
		result.path = w;
	if (kind == "remote") {
		result.url = w;
		if (version_ge_1_14_0)
			result.http_client = "remote_http_client";
	}
	return result;
}

function geo_rule_set(prefix, rule_name) {
	let output_srs_file = "local:" + GEO_VAR.TO_SRS_PATH + prefix + "-" + rule_name + ".srs";
	return parse_rule_set(output_srs_file, false);
}

function strip_at(w, prefix) {
	return substr(w, length(prefix));
}

function split_ports(s) {
	let port = [];
	let port_range = [];
	for (let w in gmatch(s, /[^,]+/g)) {
		let n = tonumber(w);
		if (n != null && n >= 1 && n <= 65535)
			push(port, n);
		else
			push(port_range, w);
	}
	return [nonempty(port), nonempty(port_range)];
}

function read_proxy_list(path, enabled) {
	if (enabled != "1")
		return "";
	let text = null;
	if (ltruth(api.fs.access(path)))
		text = api.fs.readfile(path);
	if (type(text) != "string" || text == "")
		return "";
	let map = {};
	let list = [];
	if (substr(text, -1) == "\n")
		text = substr(text, 0, length(text) - 1);
	if (text == "")
		return "";
	for (let line in split(text, "\n")) {
		if (line != "" && index(line, "#") < 0 && !map[line]) {
			map[line] = 1;
			push(list, line);
		}
	}
	return join("\n", list);
}

export function gen_config(var) {
	ensure_version();
	let flag = var["flag"];
	let log = lor(var["log"], "0");
	let loglevel = lor(var["loglevel"], "warn");
	let logfile = lor(var["logfile"], "/dev/null");
	let node_id = var["node"];
	let server_host = var["server_host"];
	let server_port = var["server_port"];
	let tcp_proxy_way = var["tcp_proxy_way"];
	let redir_port = var["redir_port"];
	let local_socks_address = lor(var["local_socks_address"], "0.0.0.0");
	let local_socks_port = var["local_socks_port"];
	let local_socks_username = var["local_socks_username"];
	let local_socks_password = var["local_socks_password"];
	let local_http_address = lor(var["local_http_address"], "0.0.0.0");
	let local_http_port = var["local_http_port"];
	let local_http_username = var["local_http_username"];
	let local_http_password = var["local_http_password"];
	let dns_listen_port = var["dns_listen_port"];
	let direct_dns_port = var["direct_dns_port"];
	let direct_dns_udp_server = var["direct_dns_udp_server"];
	let direct_dns_tcp_server = var["direct_dns_tcp_server"];
	let direct_dns_query_strategy = var["direct_dns_query_strategy"];
	let remote_dns_udp_server = var["remote_dns_udp_server"];
	let remote_dns_udp_port = var["remote_dns_udp_port"];
	let remote_dns_quic = var["remote_dns_quic"];
	let remote_dns_tcp_server = var["remote_dns_tcp_server"];
	let remote_dns_tcp_port = var["remote_dns_tcp_port"];
	let remote_dns_tls = var["remote_dns_tls"];
	let remote_dns_doh = var["remote_dns_doh"];
	let remote_dns_http3 = var["remote_dns_http3"];
	let remote_dns_client_ip = var["remote_dns_client_ip"];
	let remote_dns_query_strategy = var["remote_dns_query_strategy"];
	let remote_dns_fake = var["remote_dns_fake"];
	let remote_rewrite_ttl = lor(var["remote_rewrite_ttl"], "30");
	let dns_cache = var["dns_cache"];
	let dns_socks_address = var["dns_socks_address"];
	let dns_socks_port = var["dns_socks_port"];
	let use_proxy_list = var["use_proxy_list"];
	let use_gfw_list = var["use_gfw_list"];
	let chn_list = var["chn_list"];
	let run_in_global = var["run_in_global"];
	NO_RUN = var["no_run"];

	let dns_domain_rules = [];
	let dns = null;
	let inbounds = [];
	let outbounds = [];
	let rule_set_table = {};
	let COMMON = {};
	let singbox_settings = lor(api.uci_get_c("@global_singbox[0]"), {});
	let route = { rules: [] };
	let experimental = null;
	let rules = [];

	function add_rule_set(tab) {
		if (ltruth(tab) && has_keys(tab) && ltruth(tab.tag) && !ltruth(rule_set_table[tab.tag]))
			rule_set_table[tab.tag] = tab;
	}

	function gen_urltest_outbound;
	function set_outbound_detour;
	function gen_outbound_get_tag;

	function gen_urltest_outbound(_node) {
		let urltest_id = _node[".name"];
		let urltest_tag = "urltest-" + urltest_id;
		for (let v in outbounds) {
			if (v.tag == urltest_tag)
				return [v, true];
		}
		let ut_nodes = null;
		if (ltruth(_node.node_add_mode) && _node.node_add_mode == "batch")
			ut_nodes = api.get_batch_nodes(_node);
		else
			ut_nodes = _node.urltest_node;
		if (!ltruth(NO_RUN) && ltruth(run_in_global))
			api.log("  - 加载 Sing-Box URLTest 节点【" + lor(_node.remarks, "") + "】，子节点数量：" + length(lor(ut_nodes, [])));
		let valid_nodes = [];
		let ut_list = lor(ut_nodes, []);
		for (let i = 0; i < length(ut_list); i++) {
			let ut_node_id = ut_list[i];
			let ut_node_tag = "ut-" + ut_node_id;
			let is_new_ut_node = true;
			for (let outbound in outbounds) {
				if (substr(lor(outbound.tag, ""), 0, length(ut_node_tag)) == ut_node_tag) {
					is_new_ut_node = false;
					push(valid_nodes, outbound.tag);
					break;
				}
			}
			if (is_new_ut_node) {
				let outbound_tag = gen_outbound_get_tag(flag, ut_node_id, ut_node_tag, {
					fragment: singbox_settings.fragment == "1" ? true : null,
					record_fragment: singbox_settings.record_fragment == "1" ? true : null
				});
				if (ltruth(outbound_tag))
					push(valid_nodes, outbound_tag);
			}
		}
		if (length(valid_nodes) == 0)
			return [null, null];
		let interval = api.format_go_time(_node.urltest_interval);
		let idle = api.format_go_time(_node.urltest_idle_timeout);
		let tol = tonumber(_node.urltest_tolerance);
		let outbound = {
			type: "urltest",
			tag: urltest_tag,
			outbounds: valid_nodes,
			url: lor(_node.urltest_url, "https://www.gstatic.com/generate_204"),
			interval: (interval != "0s") ? interval : "3m",
			tolerance: (ltruth(_node.urltest_tolerance) && tol != null && tol > 0) ? tol : 50,
			idle_timeout: (idle != "0s") ? idle : "30m",
			interrupt_exist_connections: (_node.urltest_interrupt_exist_connections == "true" || _node.urltest_interrupt_exist_connections == "1")
		};
		return [outbound, null];
	}

	function set_outbound_detour(node, outbound, outbounds_table) {
		if (!ltruth(node) || !ltruth(outbound) || !ltruth(outbounds_table))
			return [null, null];
		let default_out_tag = outbound.tag;
		let last_insert_outbound = null;
		if (node.shadowtls == "1") {
			let shadow_node = {
				type: "sing-box",
				protocol: "shadowtls",
				shadowtls_version: node.shadowtls_version,
				address: node.address,
				port: node.port,
				tls: "1",
				tls_serverName: node.shadowtls_serverName,
				utls: node.shadowtls_utls,
				fingerprint: node.shadowtls_fingerprint
			};
			if (node.shadowtls_version == "2" || node.shadowtls_version == "3")
				shadow_node.password = node.shadowtls_password;
			let shadowtls_outbound = gen_outbound(null, shadow_node, outbound.tag + "_shadowtls");
			if (ltruth(shadowtls_outbound)) {
				last_insert_outbound = shadowtls_outbound;
				outbound.detour = outbound.tag + "_shadowtls";
				outbound.server = null;
				outbound.server_port = null;
			}
		}
		if (node.chain_proxy == "1" && ltruth(node.preproxy_node)) {
			if (!ltruth(outbound["_flag_proxy_tag"])) {
				let preproxy_node = get_node_by_id(node.preproxy_node);
				if (ltruth(preproxy_node)) {
					let preproxy_outbound = null;
					let exist = null;
					if (preproxy_node.protocol == "_urltest") {
						let pair = gen_urltest_outbound(preproxy_node);
						preproxy_outbound = pair[0];
						exist = pair[1];
					} else {
						preproxy_outbound = gen_outbound(node[".name"], preproxy_node);
					}
					if (ltruth(preproxy_outbound)) {
						outbound.tag = preproxy_outbound.tag + " -> " + outbound.tag;
						outbound.detour = preproxy_outbound.tag;
						if (!exist)
							last_insert_outbound = preproxy_outbound;
						default_out_tag = outbound.tag;
					}
				}
			}
		}
		if (node.chain_proxy == "2" && ltruth(node.to_node)) {
			let to_node = get_node_by_id(node.to_node);
			if (ltruth(to_node) && type(to_node.protocol) == "string" && match(to_node.protocol, /^_/) != null)
				to_node = null;
			if (ltruth(to_node)) {
				let chained_tag = outbound.tag + " -> " + to_node[".name"] + (ltruth(to_node.remarks) ? (":" + to_node.remarks) : "");
				for (let o in outbounds_table) {
					if (o.tag == chained_tag)
						return [chained_tag, last_insert_outbound];
				}
				let to_outbound = null;
				if (to_node.type != "sing-box") {
					let to_tag = to_node[".name"];
					let new_port = api.get_new_port();
					push(inbounds, {
						type: "direct",
						tag: to_tag,
						listen: "127.0.0.1",
						listen_port: new_port,
						override_address: to_node.address,
						override_port: tonumber(to_node.port)
					});
					unshift(rules, {
						action: "route",
						inbound: [to_tag],
						outbound: outbound.tag
					});
					if (to_node.tls_serverName == null)
						to_node.tls_serverName = to_node.address;
					to_node.address = "127.0.0.1";
					to_node.port = new_port;
					to_outbound = gen_outbound(node[".name"], to_node, to_tag, { tag: to_tag });
				} else {
					to_outbound = gen_outbound(node[".name"], to_node);
				}
				if (ltruth(to_outbound)) {
					to_outbound.tag = outbound.tag + " -> " + to_outbound.tag;
					if (to_node.type == "sing-box")
						to_outbound.detour = outbound.tag;
					push(outbounds_table, to_outbound);
					default_out_tag = to_outbound.tag;
				}
			}
		}
		if (node.chain_proxy == "3" && ltruth(node.outbound_iface)) {
			outbound.detour = null;
			outbound.bind_interface = node.outbound_iface;
		}
		return [default_out_tag, last_insert_outbound];
	}

	function gen_outbound_get_tag(flag_in, id, tag, proxy_table) {
		if (!ltruth(id) || id == "nil")
			return null;
		let node = get_node_by_id(id);
		if (!ltruth(tag))
			tag = node[".name"];
		if (!ltruth(node))
			return null;
		if (proxy_table.chain_proxy == "1" || proxy_table.chain_proxy == "2") {
			node.chain_proxy = proxy_table.chain_proxy;
			node.preproxy_node = proxy_table.chain_proxy == "1" ? proxy_table.preproxy_node : false;
			node.to_node = proxy_table.chain_proxy == "2" ? proxy_table.to_node : false;
			proxy_table.chain_proxy = null;
			proxy_table.preproxy_node = null;
			proxy_table.to_node = null;
		}
		let outbound = null;
		let exist = null;
		if (node.protocol == "_urltest") {
			let pair = gen_urltest_outbound(node);
			outbound = pair[0];
			exist = pair[1];
			if (exist && !ltruth(node.chain_proxy))
				return outbound.tag;
		} else if (node.protocol == "_iface") {
			if (ltruth(node.iface)) {
				outbound = {
					tag: tag,
					type: "direct",
					bind_interface: node.iface,
					routing_mark: 255
				};
				api.sys.call(sprintf("mkdir -p %s && touch %s/%s", api.TMP_IFACE_PATH, api.TMP_IFACE_PATH, node.iface));
			}
		} else {
			for (let item in outbounds) {
				if (ltruth(item["_flag_proxy_tag"]) && index(item["_flag_proxy_tag"], "socks <- " + node[".name"]) >= 0) {
					outbound = api.clone(item);
					outbound.tag = tag;
					break;
				}
			}
			if (outbound == null)
				outbound = gen_outbound(flag_in, node, tag, proxy_table);
		}
		if (!ltruth(outbound))
			return null;
		let det = set_outbound_detour(node, outbound, outbounds);
		if (!exist)
			push(outbounds, outbound);
		if (ltruth(det[1]))
			push(outbounds, det[1]);
		return det[0];
	}

	if (ltruth(node_id)) {
		let node = api.uci_get_c(node_id);
		if (ltruth(node) && ltruth(server_host) && ltruth(server_port)) {
			node.address = server_host;
			node.port = server_port;
		}
		if (ltruth(local_socks_port)) {
			let inbound = {
				type: "socks",
				tag: "socks-in",
				listen: local_socks_address,
				listen_port: tonumber(local_socks_port)
			};
			if (ltruth(local_socks_username) && ltruth(local_socks_password) && local_socks_username != "" && local_socks_password != "") {
				inbound.users = [{
					username: local_socks_username,
					password: local_socks_password
				}];
			}
			push(inbounds, inbound);
			push(route.rules, { action: "sniff", inbound: inbound.tag });
		}
		if (ltruth(local_http_port)) {
			let inbound = {
				type: "http",
				tag: "http-in",
				listen: local_http_address,
				listen_port: tonumber(local_http_port)
			};
			if (ltruth(local_http_username) && ltruth(local_http_password) && local_http_username != "" && local_http_password != "") {
				inbound.users = [{
					username: local_http_username,
					password: local_http_password
				}];
			}
			push(inbounds, inbound);
		}
		if (ltruth(redir_port)) {
			let inbound_tproxy = {
				type: "tproxy",
				tag: "tproxy",
				listen: "::",
				listen_port: tonumber(redir_port)
			};
			if (tcp_proxy_way != "tproxy") {
				let inbound = {
					type: "redirect",
					tag: "redirect_tcp",
					listen: "::",
					listen_port: tonumber(redir_port)
				};
				push(inbounds, inbound);
				push(route.rules, { action: "sniff", inbound: inbound.tag });
				inbound_tproxy.tag = "tproxy_udp";
				inbound_tproxy.network = "udp";
			}
			push(inbounds, inbound_tproxy);
			push(route.rules, { action: "sniff", inbound: inbound_tproxy.tag });
		}

		function gen_shunt_node(rule_name, shunt_id) {
			if (!ltruth(rule_name))
				return null;
			if (shunt_id == null)
				shunt_id = node[rule_name];
			if (shunt_id == "_direct")
				return "direct";
			if (shunt_id == "_blackhole")
				return "block";
			if (shunt_id == "_default" && rule_name != "default")
				return "default";
			if (ltruth(shunt_id)) {
				let proxy_table = {
					fragment: singbox_settings.fragment == "1",
					record_fragment: singbox_settings.record_fragment == "1"
				};
				let preproxy_node_id = node[rule_name + "_proxy_tag"];
				if (preproxy_node_id == shunt_id)
					preproxy_node_id = null;
				if (ltruth(preproxy_node_id)) {
					proxy_table.chain_proxy = "2";
					proxy_table.to_node = shunt_id;
					return gen_outbound_get_tag(flag, preproxy_node_id, rule_name, proxy_table);
				}
				return gen_outbound_get_tag(flag, shunt_id, rule_name, proxy_table);
			}
			return null;
		}

		if (ltruth(node) && node.protocol == "_shunt") {
			inner_fakedns = lor(node.fakedns, "0");
			let default_node_id = lor(node.default_node, "_direct");
			COMMON.default_outbound_tag = gen_shunt_node("default", default_node_id);
			if (inner_fakedns == "1" && node["default_fakedns"] == "1")
				remote_dns_fake = true;

			function foreach_shunt_rule(callback) {
				api.uci_foreach_c("shunt_rules", callback);
				if (use_gfw_list != "1" || chn_list != "0")
					return;
				let domain_list = read_proxy_list("/etc/passwall/rules/proxy_host", use_proxy_list);
				let ip_list = read_proxy_list("/etc/passwall/rules/proxy_ip", use_proxy_list);
				let bin = api.finded_com("geoview");
				if (ltruth(bin)) {
					let geo_file = asset_dir(lor(api.uci_get_c("@global_rules[0]", "v2ray_location_asset"), "/usr/share/v2ray/")) + "/geosite.dat";
					let cmd = "\"" + bin + "\" -type geosite -input \"" + geo_file + "\" | grep -q \"^GFW$\"";
					if (api.sys.call(cmd) == 0)
						domain_list = (domain_list == "") ? "geosite:gfw" : (domain_list + "\ngeosite:gfw");
				}
				if (domain_list != "" || ip_list != "") {
					node["GFW_Mode_List"] = "_default";
					callback({
						".name": "GFW_Mode_List",
						remarks: "GFW_Mode_List",
						domain_list: domain_list != "" ? domain_list : null,
						ip_list: ip_list != "" ? ip_list : null,
						group: node["shunt_group"]
					});
				}
			}

			foreach_shunt_rule(function (e) {
				if (node["shunt_group"] != e.group)
					return;
				let outbound_tag = gen_shunt_node(e[".name"], null);
				if (!(ltruth(outbound_tag) && ltruth(e.remarks)))
					return;
				if (outbound_tag == "default")
					outbound_tag = COMMON.default_outbound_tag;
				let protocols = null;
				if (ltruth(e["protocol"]) && e["protocol"] != "")
					protocols = gmatch(e["protocol"], /[^ ]+/g);
				let inbound_tag = null;
				if (ltruth(e["inbound"]) && e["inbound"] != "") {
					inbound_tag = [];
					if (index(e["inbound"], "tproxy") >= 0 && ltruth(redir_port)) {
						if (tcp_proxy_way == "tproxy")
							push(inbound_tag, "tproxy");
						else {
							push(inbound_tag, "redirect_tcp");
							push(inbound_tag, "tproxy_udp");
						}
					}
					if (index(e["inbound"], "socks") >= 0 && ltruth(local_socks_port))
						push(inbound_tag, "socks-in");
				}
				let rule = {
					action: "route",
					outbound: outbound_tag
				};
				set_if(rule, "inbound", inbound_tag);
				set_if(rule, "protocol", protocols);
				if (outbound_tag == "block") {
					rule.action = "reject";
					rule.outbound = null;
				}
				if (ltruth(e.network))
					rule.network = gmatch(e.network, /[^,]+/g);
				if (ltruth(e.source)) {
					let source_ip_cidr = [];
					let is_private = false;
					for (let w in gmatch(e.source, /[^ ]+/g)) {
						if (index(w, "geoip") == 0) {
							if (strip_at(w, "geoip:") == "private")
								is_private = true;
						} else {
							push(source_ip_cidr, w);
						}
					}
					if (is_private)
						rule.source_ip_is_private = true;
					set_if(rule, "source_ip_cidr", nonempty(source_ip_cidr));
					if (is_private || length(source_ip_cidr) > 0)
						rule.rule_set_ip_cidr_match_source = true;
				}
				if (ltruth(e.port)) {
					let ports = split_ports(e.port);
					set_if(rule, "port", ports[0]);
					set_if(rule, "port_range", ports[1]);
				}
				let rule_set = [];
				if (ltruth(e.domain_list)) {
					let domain_table = {
						shunt_tag: e[".name"],
						outboundTag: outbound_tag,
						domain: [],
						domain_suffix: [],
						domain_keyword: [],
						domain_regex: [],
						rule_set: []
					};
					if (e.invert == "1")
						domain_table.invert = true;
					for (let raw in gmatch(e.domain_list, /[^\r\n]+/g)) {
						let w = api.trim(raw);
						if (w == "" || index(w, "#") == 0)
							continue;
						if (index(w, "geosite:") == 0) {
							let geosite = strip_at(w, "geosite:");
							let t = geo_rule_set("geosite", geosite);
							if (ltruth(t)) {
								GEO_VAR.SITE_TAGS[geosite] = true;
								add_rule_set(t);
								push(rule_set, t.tag);
								push(domain_table.rule_set, t.tag);
							}
						} else if (index(w, "regexp:") == 0) {
							push(domain_table.domain_regex, strip_at(w, "regexp:"));
						} else if (index(w, "full:") == 0) {
							push(domain_table.domain, strip_at(w, "full:"));
						} else if (index(w, "domain:") == 0) {
							push(domain_table.domain_suffix, strip_at(w, "domain:"));
						} else if (index(w, "rule-set:") == 0 || index(w, "rs:") == 0) {
							let t = parse_rule_set(substr(w, index(w, ":") + 1), true);
							if (ltruth(t)) {
								add_rule_set(t);
								push(rule_set, t.tag);
								push(domain_table.rule_set, t.tag);
							}
						} else {
							push(domain_table.domain_keyword, w);
						}
					}
					set_if(rule, "domain", nonempty(domain_table.domain));
					set_if(rule, "domain_suffix", nonempty(domain_table.domain_suffix));
					set_if(rule, "domain_keyword", nonempty(domain_table.domain_keyword));
					set_if(rule, "domain_regex", nonempty(domain_table.domain_regex));
					set_if(rule, "rule_set", nonempty(domain_table.rule_set));
					if (inner_fakedns == "1" && node[e[".name"] + "_fakedns"] == "1")
						domain_table.fakedns = true;
					if (ltruth(outbound_tag) && (ltruth(rule.domain) || ltruth(rule.domain_suffix) || ltruth(rule.domain_keyword) || ltruth(rule.domain_regex) || ltruth(rule.rule_set)))
						push(dns_domain_rules, api.clone(domain_table));
				}
				if (ltruth(e.ip_list)) {
					let ip_cidr = [];
					let is_private = false;
					for (let raw in gmatch(e.ip_list, /[^\r\n]+/g)) {
						let w = api.trim(raw);
						if (w == "" || index(w, "#") == 0)
							continue;
						if (index(w, "geoip:") == 0) {
							let geoip = strip_at(w, "geoip:");
							if (geoip == "private") {
								is_private = true;
							} else {
								let t = geo_rule_set("geoip", geoip);
								if (ltruth(t)) {
									GEO_VAR.IP_TAGS[geoip] = true;
									add_rule_set(t);
									push(rule_set, t.tag);
								}
							}
						} else if (index(w, "rule-set:") == 0 || index(w, "rs:") == 0) {
							let t = parse_rule_set(substr(w, index(w, ":") + 1), true);
							if (ltruth(t)) {
								add_rule_set(t);
								push(rule_set, t.tag);
							}
						} else {
							push(ip_cidr, w);
						}
					}
					if (is_private)
						rule.ip_is_private = true;
					set_if(rule, "ip_cidr", nonempty(ip_cidr));
				}
				set_if(rule, "rule_set", nonempty(rule_set));
				if (e.invert == "1")
					rule.invert = true;
				push(rules, rule);
			});
			if (use_gfw_list == "1" && chn_list == "0") {
				push(rules, {
					action: "route",
					port_range: ["0:65535"],
					outbound: "direct"
				});
			}
		} else {
			COMMON.default_outbound_tag = gen_outbound_get_tag(flag, lor(node, node_id), null, {
				fragment: singbox_settings.fragment == "1" ? true : null,
				record_fragment: singbox_settings.record_fragment == "1" ? true : null
			});
		}
		for (let item in rules)
			push(route.rules, item);
	}

	if (ltruth(COMMON.default_outbound_tag))
		route.final = COMMON.default_outbound_tag;

	if (ltruth(dns_listen_port)) {
		dns = {
			servers: [],
			rules: [],
			disable_cache: ltruth(dns_cache) && dns_cache == "0",
			disable_expire: false,
			independent_cache: false,
			reverse_mapping: true
		};
		let default_out_tag = COMMON.default_outbound_tag;
		if (ltruth(dns_socks_address) && ltruth(dns_socks_port)) {
			default_out_tag = "dns_socks_out";
			unshift(outbounds, {
				type: "socks",
				tag: default_out_tag,
				server: dns_socks_address,
				server_port: tonumber(dns_socks_port)
			});
		}
		remote_strategy = "prefer_ipv6";
		if (remote_dns_query_strategy == "UseIPv4")
			remote_strategy = "ipv4_only";
		else if (remote_dns_query_strategy == "UseIPv6")
			remote_strategy = "ipv6_only";
		let remote_server = {
			tag: "remote",
			domain_resolver: "direct",
			detour: default_out_tag
		};
		if (ltruth(remote_dns_udp_server)) {
			remote_server.type = "udp";
			remote_server.server = remote_dns_udp_server;
			remote_server.server_port = lor(tonumber(remote_dns_udp_port), 53);
			if (ltruth(remote_dns_quic)) {
				remote_server.type = "quic";
				remote_server.server_port = lor(tonumber(remote_dns_udp_port), 853);
			}
		} else if (ltruth(remote_dns_tcp_server)) {
			remote_server.type = "tcp";
			remote_server.server = remote_dns_tcp_server;
			remote_server.server_port = lor(tonumber(remote_dns_tcp_port), 53);
			if (ltruth(remote_dns_tls)) {
				remote_server.type = "tls";
				remote_server.server_port = lor(tonumber(remote_dns_tcp_port), 853);
			}
		} else if (ltruth(remote_dns_doh)) {
			let parsed = api.parseDoH(remote_dns_doh);
			if (parsed != null) {
				remote_server.type = ltruth(remote_dns_http3) ? "h3" : "https";
				remote_server.server = parsed.hostname;
				remote_server.server_port = lor(parsed.port, 443);
				remote_server.path = lor(parsed.pathname, "");
				if (api.datatypes.hostname(parsed.hostname)) {
					if (ltruth(parsed.hostip)) {
						if (hosts_predefined == null)
							hosts_predefined = {};
						hosts_predefined[parsed.hostname] = parsed.hostip;
						remote_server_domain_resolver = "hosts";
					} else {
						GLOBAL.DNS_HOSTNAME[parsed.hostname] = true;
						remote_server_domain_resolver = "direct";
					}
				}
			}
		}
		if (api.is_local_ip(remote_server.server))
			remote_server.detour = "direct";
		if (ltruth(remote_server_domain_resolver))
			remote_server.domain_resolver = remote_server_domain_resolver;
		push(dns.servers, remote_server);
		fakedns_tag = "remote_fakeip";
		if (ltruth(remote_dns_fake) || inner_fakedns == "1") {
			push(dns.servers, {
				tag: fakedns_tag,
				type: "fakeip",
				inet4_range: "198.18.0.0/16",
				inet6_range: "2001:2::/48"
			});
			if (experimental == null)
				experimental = {};
			experimental.cache_file = {
				enabled: true,
				store_fakeip: true,
				path: api.CACHE_PATH + "/singbox_" + flag + ".db"
			};
		}
		if (ltruth(direct_dns_udp_server) || ltruth(direct_dns_tcp_server)) {
			let domain = [];
			let nodes_domain_text = api.sys.exec('uci show passwall | sed -n "s/.*\\.address=\'\\([^\'\']*\\)\'/\\1/p" | sort -u');
			for (let raw in gmatch(nodes_domain_text, /[^\r\n]+/g)) {
				let w = lc(lor(raw, ""));
				if (!api.vps_domain_exclude(w) && api.datatypes.hostname(w) && !ltruth(GLOBAL.VPS_EXCLUDE[w]))
					push(domain, w);
			}
			if (length(domain) > 0)
				unshift(dns_domain_rules, { outboundTag: "direct", domain: domain });
			direct_strategy = "prefer_ipv6";
			if (direct_dns_query_strategy == "UseIPv4")
				direct_strategy = "ipv4_only";
			else if (direct_dns_query_strategy == "UseIPv6")
				direct_strategy = "ipv6_only";
			let direct_dns_server = null;
			let port = null;
			let dns_type = null;
			if (ltruth(direct_dns_udp_server)) {
				port = lor(tonumber(direct_dns_port), 53);
				direct_dns_server = direct_dns_udp_server;
				dns_type = "udp";
			} else if (ltruth(direct_dns_tcp_server)) {
				port = lor(tonumber(direct_dns_port), 53);
				direct_dns_server = direct_dns_tcp_server;
				dns_type = "tcp";
			}
			push(dns.servers, {
				tag: "direct",
				type: dns_type,
				server: direct_dns_server,
				server_port: port,
				detour: "direct"
			});
		}
		let default_dns_flag = "remote";
		if (ltruth(dns_socks_address) && ltruth(dns_socks_port)) {
			/* remote */
		} else if (ltruth(node_id) && ltruth(redir_port)) {
			let shunt_node = get_node_by_id(node_id);
			if (shunt_node.protocol == "_shunt" && shunt_node.default_node == "_direct")
				default_dns_flag = "direct";
		} else {
			default_dns_flag = "direct";
		}
		dns.final = default_dns_flag;
		dns.strategy = "prefer_ipv6";
		if (length(dns_domain_rules) > 0) {
			for (let value in dns_domain_rules) {
				if (!(ltruth(value.outboundTag) && (ltruth(value.domain) || ltruth(value.domain_suffix) || ltruth(value.domain_keyword) || ltruth(value.domain_regex) || ltruth(value.rule_set))))
					continue;
				let dns_rule = {
					action: "route",
					server: value.outboundTag,
					disable_cache: false
				};
				set_if(dns_rule, "domain", (ltruth(value.domain) && length(value.domain) > 0) ? value.domain : null);
				set_if(dns_rule, "domain_suffix", (ltruth(value.domain_suffix) && length(value.domain_suffix) > 0) ? value.domain_suffix : null);
				set_if(dns_rule, "domain_keyword", (ltruth(value.domain_keyword) && length(value.domain_keyword) > 0) ? value.domain_keyword : null);
				set_if(dns_rule, "domain_regex", (ltruth(value.domain_regex) && length(value.domain_regex) > 0) ? value.domain_regex : null);
				set_if(dns_rule, "rule_set", (ltruth(value.rule_set) && length(value.rule_set) > 0) ? value.rule_set : null);
				set_if(dns_rule, "invert", value.invert);
				if (value.outboundTag == "block") {
					dns_rule.action = "predefined";
					dns_rule.rcode = "NOERROR";
					dns_rule.server = null;
					dns_rule.disable_cache = null;
				}
				if (value.outboundTag == "direct") {
					let block_rule = null;
					if (direct_strategy == "ipv4_only") {
						block_rule = api.clone(dns_rule);
						block_rule.query_type = ["AAAA"];
					} else if (direct_strategy == "ipv6_only") {
						block_rule = api.clone(dns_rule);
						block_rule.query_type = ["A"];
					}
					if (block_rule != null) {
						block_rule.action = "predefined";
						block_rule.rcode = "NOERROR";
						block_rule.disable_cache = null;
						block_rule.server = null;
						push(dns.rules, block_rule);
					}
				}
				if (value.outboundTag != "block" && value.outboundTag != "direct") {
					dns_rule.server = "remote";
					dns_rule.rewrite_ttl = tonumber(remote_rewrite_ttl);
					let block_rule = null;
					if (remote_strategy == "ipv4_only") {
						block_rule = api.clone(dns_rule);
						block_rule.query_type = ["AAAA"];
					} else if (remote_strategy == "ipv6_only") {
						block_rule = api.clone(dns_rule);
						block_rule.query_type = ["A"];
					}
					if (block_rule != null) {
						block_rule.action = "predefined";
						block_rule.rcode = "NOERROR";
						block_rule.disable_cache = null;
						block_rule.server = null;
						block_rule.rewrite_ttl = null;
						push(dns.rules, block_rule);
					}
					dns_rule.client_subnet = remote_dns_client_ip;
					if (value.outboundTag != COMMON.default_outbound_tag && (ltruth(remote_server.address) || ltruth(remote_server.server))) {
						let remote_dns_server = api.clone(remote_server);
						remote_dns_server.tag = value.shunt_tag;
						let is_local = (ltruth(remote_server.address) && api.is_local_ip(remote_server.address)) || (ltruth(remote_server.server) && api.is_local_ip(remote_server.server));
						remote_dns_server.detour = is_local ? "direct" : value.outboundTag;
						push(dns.servers, remote_dns_server);
						dns_rule.server = remote_dns_server.tag;
					}
					if (value.fakedns) {
						let fakedns_dns_rule = api.clone(dns_rule);
						if (remote_strategy == "ipv4_only")
							fakedns_dns_rule.query_type = ["A"];
						else if (remote_strategy == "ipv6_only")
							fakedns_dns_rule.query_type = ["AAAA"];
						else
							fakedns_dns_rule.query_type = ["A", "AAAA"];
						fakedns_dns_rule.server = fakedns_tag;
						fakedns_dns_rule.rewrite_ttl = 1;
						fakedns_dns_rule.disable_cache = true;
						fakedns_dns_rule.client_subnet = null;
						push(dns.rules, fakedns_dns_rule);
					}
				}
				push(dns.rules, dns_rule);
			}
		}
		if (default_dns_flag == "remote") {
			let block_rule = null;
			let dns_rule_query_type = ["A", "AAAA"];
			if (remote_strategy == "ipv4_only") {
				block_rule = { query_type: ["AAAA"], action: "predefined", rcode: "NOERROR" };
				dns_rule_query_type = ["A"];
			} else if (remote_strategy == "ipv6_only") {
				block_rule = { query_type: ["A"], action: "predefined", rcode: "NOERROR" };
				dns_rule_query_type = ["AAAA"];
			}
			if (block_rule != null)
				push(dns.rules, block_rule);
			if (ltruth(remote_dns_fake)) {
				push(dns.rules, {
					query_type: dns_rule_query_type,
					server: fakedns_tag,
					disable_cache: true,
					rewrite_ttl: 1
				});
			}
			push(dns.rules, {
				server: "remote",
				disable_cache: true,
				rewrite_ttl: tonumber(remote_rewrite_ttl)
			});
		}
		let dns_in = {
			type: "direct",
			tag: "dns-in",
			listen: "127.0.0.1",
			listen_port: tonumber(dns_listen_port)
		};
		push(inbounds, dns_in);
		push(route.rules, { action: "sniff", inbound: dns_in.tag });
		unshift(route.rules, { action: "hijack-dns", inbound: dns_in.tag });
	}

	if (dns == null) {
		dns = {
			servers: [{
				type: "local",
				tag: "direct"
			}]
		};
	}
	route.default_domain_resolver = { server: "direct" };
	if (dns.rules == null)
		dns.rules = [];
	for (let k, v in GLOBAL.DNS_SERVER) {
		push(dns.servers, v.server);
		unshift(dns.rules, {
			action: "route",
			server: v.server.tag,
			disable_cache: false,
			domain: v.domain
		});
	}
	if (has_keys(GLOBAL.DNS_HOSTNAME)) {
		let hostname = [];
		for (let line in GLOBAL.DNS_HOSTNAME)
			push(hostname, line);
		unshift(dns.rules, {
			query_type: ["A", "AAAA"],
			domain: hostname,
			server: "direct"
		});
	}
	if (has_keys(ech_domain)) {
		push(dns.servers, {
			tag: "ech-dns",
			type: "https",
			server: "223.5.5.5"
		});
		let domain = [];
		for (let line in ech_domain)
			push(domain, line);
		unshift(dns.rules, { domain: domain, server: "ech-dns" });
	}
	let hosts_server = { tag: "hosts", type: "hosts" };
	if (hosts_predefined != null && has_keys(hosts_predefined))
		hosts_server.predefined = hosts_predefined;
	push(dns.servers, hosts_server);
	if (!version_ge_1_14_0)
		unshift(dns.rules, { ip_accept_any: true, server: "hosts" });
	else
		unshift(dns.rules, { preferred_by: "hosts", action: "route", server: "hosts" });
	if (COMMON.default_outbound_tag == "block") {
		route.final = null;
		push(route.rules, { action: "reject" });
	}
	if (has_keys(rule_set_table)) {
		route.rule_set = [];
		for (let k, v in rule_set_table)
			push(route.rule_set, v);
	}
	let http_clients = null;
	let proxy_tag = COMMON.default_outbound_tag;
	if (proxy_tag == "block" || proxy_tag == "direct") {
		let first_node = null;
		for (let v in outbounds) {
			if (!ltruth(v["_flag_proxy_tag"]) && !ltruth(v.detour) && ltruth(v["_id"]) && ((ltruth(v.server) && (ltruth(v.server_port) || ltruth(v.server_ports))) || v.type == "urltest")) {
				first_node = lor(first_node, v.tag);
				if (v.type == "urltest") {
					proxy_tag = v.tag;
					break;
				}
			}
		}
		if (proxy_tag == COMMON.default_outbound_tag)
			proxy_tag = first_node;
	}
	http_clients = [
		{ tag: "remote_http_client", detour: proxy_tag },
		{ tag: "direct_http_client", detour: "direct" }
	];
	let config = {
		log: {
			disabled: log == "0",
			level: get_log_level(loglevel),
			timestamp: true,
			output: logfile
		},
		dns: dns,
		inbounds: inbounds,
		outbounds: outbounds,
		route: route
	};
	set_if(config, "experimental", experimental);
	if (version_ge_1_14_0)
		config.http_clients = http_clients;
	push(outbounds, {
		type: "direct",
		tag: "direct",
		routing_mark: 255
	});
	for (let value in config.outbounds) {
		if (!ltruth(value["_flag_proxy_tag"]) && !ltruth(value.detour) && ltruth(value["_id"]) && ltruth(value.server) && (ltruth(value.server_port) || ltruth(value.server_ports)) && !ltruth(NO_RUN))
			api.sys.call(sprintf("echo '%s' >> %s", value["_id"], api.TMP_PATH + "/direct_node_list"));
		if (!ltruth(value.detour) && !ltruth(value.bind_interface) && ltruth(value.server))
			value.detour = "direct";
		if (ltruth(value.server) && !api.datatypes.hostname(value.server) && !ltruth(value.realm))
			value.domain_resolver = null;
		drop_underscore(value);
	}
	let endpoints = [];
	for (let i = length(config.outbounds) - 1; i >= 0; i--) {
		let value = config.outbounds[i];
		if (value.type == "wireguard") {
			let endpoint = {
				type: "wireguard",
				tag: value.tag,
				peers: [{
					address: value.server,
					port: value.server_port,
					public_key: value.peer_public_key,
					pre_shared_key: value.pre_shared_key,
					allowed_ips: ["0.0.0.0/0"],
					reserved: value.reserved
				}],
				domain_resolver: {
					server: "direct",
					strategy: value.domain_strategy
				},
				detour: value.detour
			};
			set_if(endpoint, "system", value.system_interface);
			set_if(endpoint, "name", value.interface_name);
			set_if(endpoint, "mtu", value.mtu);
			set_if(endpoint, "address", value.local_address);
			set_if(endpoint, "private_key", value.private_key);
			push(endpoints, endpoint);
			splice(config.outbounds, i, 1);
		} else if (value.type == "masque-client") {
			push(endpoints, value);
			splice(config.outbounds, i, 1);
		}
	}
	if (length(endpoints) > 0)
		config.endpoints = endpoints;
	return api.jsonc.stringify(finalize(config), 1);
}

export function gen_proto_config(var) {
	let local_socks_address = lor(var["local_socks_address"], "0.0.0.0");
	let local_socks_port = var["local_socks_port"];
	let local_socks_username = var["local_socks_username"];
	let local_socks_password = var["local_socks_password"];
	let local_http_address = lor(var["local_http_address"], "0.0.0.0");
	let local_http_port = var["local_http_port"];
	let local_http_username = var["local_http_username"];
	let local_http_password = var["local_http_password"];
	let server_proto = var["server_proto"];
	let server_address = var["server_address"];
	let server_port = var["server_port"];
	let server_username = var["server_username"];
	let server_password = var["server_password"];
	let inbounds = [];
	let outbounds = [];
	if (ltruth(local_socks_address) && ltruth(local_socks_port)) {
		let inbound = {
			type: "socks",
			tag: "socks-in",
			listen: local_socks_address,
			listen_port: tonumber(local_socks_port)
		};
		if (ltruth(local_socks_username) && ltruth(local_socks_password) && local_socks_username != "" && local_socks_password != "") {
			inbound.users = {
				username: local_socks_username,
				password: local_socks_password
			};
		}
		push(inbounds, inbound);
	}
	if (ltruth(local_http_address) && ltruth(local_http_port)) {
		let inbound = {
			type: "http",
			tag: "http-in",
			listen: local_http_address,
			listen_port: tonumber(local_http_port)
		};
		if (ltruth(local_http_username) && ltruth(local_http_password) && local_http_username != "" && local_http_password != "") {
			inbound.users = [{
				username: local_http_username,
				password: local_http_password
			}];
		}
		push(inbounds, inbound);
	}
	if (server_proto != "nil" && server_address != "nil" && server_port != "nil") {
		let outbound = {
			type: server_proto,
			tag: "out",
			server: server_address,
			server_port: tonumber(server_port)
		};
		if (ltruth(server_username) && ltruth(server_password)) {
			outbound.username = server_username;
			outbound.password = server_password;
		}
		push(outbounds, outbound);
	}
	let config = {
		log: {
			disabled: true,
			level: "warn",
			timestamp: true
		},
		inbounds: inbounds,
		outbounds: outbounds
	};
	return api.jsonc.stringify(finalize(config), 1);
}

function print_result(result) {
	if (result == null)
		print("nil\n");
	else if (type(result) == "string")
		print(result, "\n");
	else
		print(api.jsonc.stringify(result, 1), "\n");
}

function dispatch(name) {
	if (name == "gen_config")
		return gen_config;
	if (name == "gen_proto_config")
		return gen_proto_config;
	if (name == "gen_config_server")
		return gen_config_server;
	if (name == "geo_convert_srs")
		return geo_convert_srs;
	if (name == "gen_outbound")
		return gen_outbound;
	if (name == "check_geoview")
		return check_geoview;
	return null;
}

// argv[0] = exported function name; argv[1] = JSON object string.
// Not invoked on import.
export function main(argv) {
	if (argv == null || length(argv) < 1 || argv[0] == null || argv[0] === false)
		return;
	let func = dispatch(argv[0]);
	if (func == null)
		return;
	let parsed = null;
	if (length(argv) > 1 && argv[1] != null)
		parsed = api.jsonc.parse(argv[1]);
	print_result(func(parsed));
	if ((has_keys(GEO_VAR.SITE_TAGS) || has_keys(GEO_VAR.IP_TAGS)) && !ltruth(NO_RUN))
		convert_geofile();
}
