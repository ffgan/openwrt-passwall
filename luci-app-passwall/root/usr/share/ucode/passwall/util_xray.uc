'use strict';

import * as api from 'passwall.api';

const xray_min_version = "26.7.11";

const FRAGMENT_TRANSPORTS = {
	raw: 1,
	ws: 1,
	httpupgrade: 1,
	grpc: 1,
	xhttp: 1
};

const MKCP_HEADER = {
	none: "none",
	srtp: "srtp",
	utp: "utp",
	"wechat-video": "wechat",
	dtls: "dtls",
	wireguard: "wireguard",
	dns: "dns"
};

const OUTBOUND_EXCLUDE = {
	blackhole: 1,
	dns: 1,
	freedom: 1,
	loopback: 1
};

/* Module state. Lua kept these on the module table across calls. */
let GLOBAL = {
	DNS_SERVER: {},
	DNS_HOSTNAME: {},
	VPS_EXCLUDE: {}
};

let NO_RUN = null;
let TMP_PORT = null;
let fragment_table = null;
let noise_table = null;
let inner_fakedns = null;

/* Lua truthiness: only null and false are falsy. 0 and "" are truthy.
   ucode == treats 0 and "" as false, so comparisons here stay strict. */
function truthy(v) {
	return v != null && v !== false;
}

function lua_or(val, fallback) {
	return truthy(val) ? val : fallback;
}

function nonempty(v) {
	return truthy(v) && v !== "";
}

function lua_tostring(v) {
	if (v == null)
		return "nil";
	if (v === true)
		return "true";
	if (v === false)
		return "false";
	return "" + v;
}

function is_table(v) {
	let t = type(v);
	return t == "object" || t == "array";
}

function to_number(v) {
	if (v == null || type(v) == "bool")
		return null;
	let t = type(v);
	if (t == "int")
		return v;
	if (t == "double")
		return (v == v) ? v : null;
	if (t != "string")
		return null;
	if (!match(v, /^[[:space:]]*[+-]?([[:digit:]]+(\.[[:digit:]]*)?|\.[[:digit:]]+)([eE][+-]?[[:digit:]]+)?[[:space:]]*$/))
		return null;
	return +v;
}

function tonumber_or(v, fallback) {
	if (!truthy(v))
		return fallback;
	let n = to_number(v);
	return n != null ? n : fallback;
}

function trim_s(s) {
	if (type(s) != "string")
		return "";
	return api.trim(s);
}

function nl_to_real(s) {
	return replace(s, "\\n", "\n");
}

function contains(s, needle) {
	return type(s) == "string" && type(needle) == "string" && index(s, needle) >= 0;
}

function has_prefix(s, prefix) {
	return type(s) == "string" && substr(s, 0, length(prefix)) == prefix;
}

function split_matches(s, re) {
	let out = [];
	if (type(s) != "string")
		return out;
	let ms = match(s, re);
	if (!ms)
		return out;
	for (let m in ms)
		push(out, m[0]);
	return out;
}

function linsert(arr, lua_pos, value) {
	splice(arr, lua_pos - 1, 0, value);
}

function file_lines(content) {
	if (content == null)
		return null;
	if (content == "")
		return [];
	let parts = split(content, "\n");
	if (length(parts) > 0 && parts[length(parts) - 1] == "" && substr(content, -1) == "\n")
		pop(parts);
	return parts;
}

function try_parse_b64_json(s) {
	try {
		let parsed = api.jsonc.parse(api.base64Decode(s));
		return is_table(parsed) ? parsed : null;
	}
	catch (e) {
		return null;
	}
}

function strip_nulls(v) {
	let t = type(v);
	if (t == "array") {
		let out = [];
		for (let item in v)
			push(out, strip_nulls(item));
		return out;
	}
	if (t == "object") {
		let out = {};
		for (let k, val in v) {
			if (val != null)
				out[k] = strip_nulls(val);
		}
		return out;
	}
	return v;
}

function drop_private_keys(list) {
	for (let value in list) {
		if (type(value) != "object")
			continue;
		let ks = keys(value);
		for (let k in ks) {
			if (type(k) == "string" && substr(k, 0, 1) == "_")
				delete value[k];
		}
	}
}

function http_paths(t) {
	let r = [];
	if (type(t) != "array")
		return r;
	for (let v in t)
		push(r, v === "" ? "/" : v);
	return r;
}

function gecko_packet_size(node) {
	let min = to_number(node.hysteria2_obfs_MinPacketSize);
	let max = to_number(node.hysteria2_obfs_MaxPacketSize);
	if (min == null)
		min = 512;
	if (max == null)
		max = 1200;
	if (min <= 0 || min > max || max > 2048) {
		min = 512;
		max = 1200;
	}
	return min + "-" + max;
}

function hop_interval(v) {
	if (!truthy(v))
		return 30;
	if (type(v) == "string" && index(v, "-") >= 0) {
		let m = match(v, /^(\d+)-(\d+)$/);
		if (m) {
			let min = to_number(m[1]);
			let max = to_number(m[2]);
			if (min != null && max != null) {
				if (!(min >= 5))
					min = 5;
				if (!(max >= min))
					max = min;
				return min + "-" + max;
			}
		}
		return 30;
	}
	let src = type(v) == "string" ? v : ("" + v);
	let md = match(src, /^\d+/);
	let num = md ? to_number(md[0]) : null;
	return (num != null && num >= 5) ? num : 30;
}

function hysteria_idle(t) {
	let s = "" + lua_or(t, "30");
	let md = match(s, /^\d+/);
	let n = md ? to_number(md[0]) : null;
	return (n != null && n >= 4 && n <= 120) ? n : 30;
}

function hysteria_keepalive(t) {
	let s = "" + lua_or(t, "0");
	let md = match(s, /^\d+/);
	let n = md ? to_number(md[0]) : null;
	return (n != null && n >= 2 && n <= 60) ? n : null;
}

function mb_window(raw) {
	let n = to_number(raw);
	return n != null ? n * 1048576 : null;
}

function tolerance_ratio(raw) {
	let t = to_number(raw);
	if (t == null)
		t = 0;
	if (t < 1)
		return null;
	if (t > 100)
		t = 100;
	return t / 100.0;
}

function expected_count(raw) {
	if (!truthy(raw))
		return 2;
	let n = to_number(raw);
	return n != null ? n : 2;
}

function probe_every(raw) {
	let t = api.format_go_time(raw);
	if (t == "0s")
		return "60s";
	if (type(t) == "string" && !match(t, /[hm]/)) {
		let md = match(t, /\d+/);
		let n = md ? to_number(md[0]) : null;
		if (n != null && n < 10)
			return "10s";
	}
	return t;
}

function kcp_settings(node) {
	return {
		mtu: (nonempty(node.mkcp_mtu)) ? tonumber_or(node.mkcp_mtu, 1350) : 1350,
		tti: 50,
		uplinkCapacity: 12,
		downlinkCapacity: 100,
		cwndMultiplier: 1,
		maxSendingWindow: 2 * 1024 * 1024
	};
}

function mkcp_udp(node) {
	let udp = [];
	if (truthy(node.mkcp_guise) && node.mkcp_guise !== "none") {
		let g = { type: "mkcp-legacy" };
		g.settings = { header: MKCP_HEADER[node.mkcp_guise] };
		if (node.mkcp_guise == "dns" && nonempty(node.mkcp_domain))
			g.settings.value = node.mkcp_domain;
		push(udp, g);
	}
	let s = { type: "mkcp-legacy" };
	if (nonempty(node.mkcp_seed))
		s.settings = { value: node.mkcp_seed };
	push(udp, s);
	return udp;
}

function hysteria_obfs(node, udp) {
	if (!(nonempty(node.hysteria2_obfs_type)))
		return;
	let o = {
		type: "salamander",
		settings: truthy(node.hysteria2_obfs_password) ? { password: node.hysteria2_obfs_password } : null
	};
	if (node.hysteria2_obfs_type == "gecko")
		o.settings.packetSize = gecko_packet_size(node);
	push(udp, o);
}

function hysteria_realm(node, udp) {
	if (!truthy(node.hysteria2_realms))
		return;
	let realm = api.parse_realm_uri(node.hysteria2_realm_url);
	let url = null;
	let stun = null;
	if (realm) {
		url = realm.scheme + "://" + realm.token + "@" + realm.server_url + "/" + realm.realm_id;
		stun = lua_or(realm.stun_servers, node.hysteria2_realm_stun);
	}
	push(udp, {
		type: "realm",
		settings: {
			url: url,
			stunServers: stun,
			portMapping: node.hysteria2_realm_upnp == "1" ? { enabled: true } : null
		}
	});
}

function client_quic(node) {
	let up = to_number(node.hysteria2_up_mbps);
	let down = to_number(node.hysteria2_down_mbps);
	if (up == null)
		up = 0;
	if (down == null)
		down = 0;
	return {
		congestion: (up <= 0 && down <= 0) ? "bbr" : "brutal",
		brutalUp: up > 0 ? (up + "mbps") : null,
		brutalDown: down > 0 ? (down + "mbps") : null,
		udpHop: truthy(node.hysteria2_hop) ? {
			ports: replace(node.hysteria2_hop, ":", "-"),
			interval: hop_interval(node.hysteria2_hop_interval)
		} : null,
		maxIdleTimeout: hysteria_idle(node.hysteria2_idle_timeout),
		keepAlivePeriod: hysteria_keepalive(node.hysteria2_keep_alive_period),
		disablePathMTUDiscovery: node.hysteria2_disable_mtu_discovery == "1",
		initStreamReceiveWindow: mb_window(node.hysteria2_stream_recv_win),
		initConnectionReceiveWindow: mb_window(node.hysteria2_conn_recv_win)
	};
}

function server_quic(node) {
	let ignore = to_number(node.hysteria2_ignore_client_bandwidth) == 1;
	let up = !ignore ? to_number(node.hysteria2_up_mbps) : 0;
	let down = !ignore ? to_number(node.hysteria2_down_mbps) : 0;
	if (up == null)
		up = 0;
	if (down == null)
		down = 0;
	return {
		congestion: (up <= 0 && down <= 0) ? "bbr" : "brutal",
		brutalUp: up > 0 ? (up + "mbps") : null,
		brutalDown: down > 0 ? (down + "mbps") : null
	};
}

function client_finalmask(node, fragment, noise) {
	let finalmask = {};
	let TP = node.transport;
	if (TP == "mkcp") {
		finalmask.udp = mkcp_udp(node);
	}
	else if (TP == "hysteria") {
		let udp = [];
		hysteria_obfs(node, udp);
		hysteria_realm(node, udp);
		finalmask.udp = udp;
		finalmask.quicParams = client_quic(node);
	}
	if (truthy(fragment) && truthy(fragment_table) && truthy(FRAGMENT_TRANSPORTS[TP])) {
		if (finalmask.tcp == null)
			finalmask.tcp = [];
		unshift(finalmask.tcp, api.clone(fragment_table));
	}
	if (truthy(noise) && truthy(noise_table) && (TP == "mkcp" || (TP == "xhttp" && node.alpn == "h3"))) {
		if (finalmask.udp == null)
			finalmask.udp = [];
		unshift(finalmask.udp, api.clone(noise_table));
	}
	if (nonempty(node.finalmask)) {
		let fm = try_parse_b64_json(node.finalmask);
		if (fm)
			finalmask = fm;
	}
	return api.cleanEmptyTables(finalmask);
}

function server_finalmask(node) {
	let finalmask = {};
	if (node.transport == "mkcp") {
		finalmask.udp = mkcp_udp(node);
	}
	else if (node.transport == "hysteria") {
		let udp = [];
		hysteria_obfs(node, udp);
		hysteria_realm(node, udp);
		finalmask.udp = udp;
		finalmask.quicParams = server_quic(node);
	}
	if (nonempty(node.finalmask)) {
		let fm = try_parse_b64_json(node.finalmask);
		if (fm)
			finalmask = fm;
	}
	return api.cleanEmptyTables(finalmask);
}

function xhttp_extra(node) {
	let extra = {};
	if (truthy(node.xhttp_extra)) {
		let parsed = null;
		try {
			parsed = api.jsonc.parse(api.base64Decode(node.xhttp_extra));
		}
		catch (e) {
			parsed = null;
		}
		if (is_table(parsed))
			extra = truthy(parsed.extra) ? parsed.extra : parsed;
	}
	if (truthy(node.user_agent)) {
		if (!truthy(extra.headers))
			extra.headers = {};
		if (!truthy(extra.headers["User-Agent"]) && !truthy(extra.headers["user-agent"]))
			extra.headers["User-Agent"] = node.user_agent;
	}
	return api.cleanEmptyTables(extra);
}

function masque_headers(node) {
	let headers = {};
	if (node.masque_warp != "1" && (nonempty(node.username) || nonempty(node.password))) {
		headers["authorization"] = "Basic " + api.base64Encode(lua_or(node.username, "") + ":" + lua_or(node.password, ""));
	}
	if (nonempty(node.user_agent))
		headers["user-agent"] = node.user_agent;
	let text = nl_to_real(lua_or(node.masque_headers, ""));
	let lines = split_matches(text, /[^\r\n]+/g);
	for (let line in lines) {
		let m = match(line, /^\s*([^:]+):\s*(.*)$/);
		if (m) {
			let key = lc(api.trim(m[1]));
			let value = replace(m[2], /\s+$/, "");
			headers[key] = value;
		}
	}
	return length(headers) > 0 ? headers : null;
}

function shadowsocks_method(method) {
	if (method == "chacha20-ietf-poly1305")
		return "chacha20-poly1305";
	if (method == "xchacha20-ietf-poly1305")
		return "xchacha20-poly1305";
	if (truthy(method) && method !== "")
		return method;
	return null;
}

function vless_flow(node) {
	let enc_active = nonempty(node.encryption) && node.encryption != "none";
	if (node.protocol == "vless" && (node.tls == "1" || enc_active) && nonempty(node.flow))
		return node.flow;
	return null;
}

function csv_tokens(s) {
	let out = [];
	let parts = split_matches(trim_s(s), /[^,]+/g);
	for (let w in parts) {
		w = replace(w, /\s+/g, "");
		if (w != "")
			push(out, w);
	}
	return out;
}

function noise_rand(n) {
	if (!(n.type == "rand" && truthy(n.packet)))
		return null;
	if (type(n.packet) == "string" && index(n.packet, "-") >= 0)
		return n.packet;
	return to_number(n.packet);
}

function noise_delay(v) {
	if (!truthy(v))
		return null;
	if (type(v) == "string" && index(v, "-") >= 0)
		return v;
	return to_number(v);
}

function get_domain_excluded() {
	let path = sprintf("/etc/%s/rules/domains_excluded", api.c_config);
	let content = api.fs.readfile(path);
	if (content == null)
		return null;
	let hosts = [];
	for (let w in split_matches(content, /[^\n]+/g)) {
		let s = api.trim(w);
		if (s == "")
			continue;
		if (type(s) == "string" && index(s, "#") == 0)
			continue;
		push(hosts, s);
	}
	if (length(hosts) == 0)
		return null;
	return hosts;
}

function get_log_level(s) {
	if (s == "warn")
		return "warning";
	return s;
}

function need_stream_settings(node, dialer_proxy_tag) {
	if (truthy(node.streamSettings) || truthy(dialer_proxy_tag))
		return true;
	let p = node.protocol;
	return p == "vmess" || p == "vless" || p == "socks" || p == "shadowsocks" || p == "trojan" || p == "hysteria" || p == "http" || p == "masque";
}

function client_stream_settings(node, dialer_proxy_tag, fragment, noise) {
	let raw_ok = (node.transport == "raw" || node.transport == "tcp") && node.protocol != "socks" && truthy(node.tcp_guise) && node.tcp_guise !== "none";
	return {
		sockopt: {
			mark: 255,
			domainStrategy: lua_or(node.domain_strategy, "UseIP"),
			tcpFastOpen: node.tcp_fast_open == "1" ? true : null,
			tcpMptcp: node.tcpMptcp == "1" ? true : null,
			happyEyeballs: node.happy_eyeballs == "1" ? {
				TryDelayMs: 250,
				PrioritizeIPv6: false,
				Interleave: 1,
				MaxConcurrentTry: 4
			} : null,
			dialerProxy: dialer_proxy_tag
		},
		method: node.transport,
		security: node.stream_security,
		tlsSettings: node.stream_security == "tls" ? {
			serverName: node.tls_serverName,
			fingerprint: (node.type == "Xray" && node.utls == "1" && nonempty(node.fingerprint)) ? node.fingerprint : null,
			pinnedPeerCertSha256: nonempty(node.tls_pinSHA256) ? lua_or(api.sha256_sb_xray(node.tls_pinSHA256), "") : "",
			verifyPeerCertByName: lua_or(node.tls_CertByName, ""),
			echConfigList: node.ech == "1" ? node.ech_config : null,
			certificates: (node.tls_certificate == "1" && node.tls_certificate_pem !== "") ? {
				certificate: api.split(nl_to_real(node.tls_certificate_pem), "\n"),
				usage: "verify"
			} : null,
			cipherSuites: node.cipherSuites
		} : null,
		realitySettings: node.stream_security == "reality" ? {
			serverName: node.tls_serverName,
			publicKey: node.reality_publicKey,
			shortId: lua_or(node.reality_shortId, ""),
			spiderX: lua_or(node.reality_spiderX, "/"),
			fingerprint: (node.type == "Xray" && nonempty(node.fingerprint)) ? node.fingerprint : "chrome",
			mldsa65Verify: node.use_mldsa65Verify == "1" ? node.reality_mldsa65Verify : null
		} : null,
		rawSettings: raw_ok ? {
			header: {
				type: node.tcp_guise,
				request: node.tcp_guise == "http" ? {
					path: truthy(node.tcp_guise_http_path) ? http_paths(node.tcp_guise_http_path) : ["/"],
					headers: (truthy(node.tcp_guise_http_host) || truthy(node.user_agent)) ? {
						Host: node.tcp_guise_http_host,
						"User-Agent": truthy(node.user_agent) ? [node.user_agent] : null
					} : null
				} : null
			}
		} : null,
		kcpSettings: node.transport == "mkcp" ? kcp_settings(node) : null,
		wsSettings: node.transport == "ws" ? {
			path: lua_or(node.ws_path, "/"),
			host: node.ws_host,
			headers: truthy(node.user_agent) ? { "User-Agent": node.user_agent } : null,
			maxEarlyData: to_number(node.ws_maxEarlyData),
			earlyDataHeaderName: truthy(node.ws_earlyDataHeaderName) ? node.ws_earlyDataHeaderName : null,
			heartbeatPeriod: to_number(node.ws_heartbeatPeriod)
		} : null,
		grpcSettings: node.transport == "grpc" ? {
			serviceName: node.grpc_serviceName,
			multiMode: node.grpc_mode == "multi",
			idle_timeout: truthy(node.grpc_idle_timeout) ? (function() {
				let n = to_number(node.grpc_idle_timeout);
				if (n == null)
					return null;
				return n < 10 ? 10 : n;
			})() : null,
			health_check_timeout: to_number(node.grpc_health_check_timeout),
			permit_without_stream: node.grpc_permit_without_stream == "1",
			initial_windows_size: tonumber_or(node.grpc_initial_windows_size, 0),
			user_agent: node.user_agent
		} : null,
		httpupgradeSettings: node.transport == "httpupgrade" ? {
			path: lua_or(node.httpupgrade_path, "/"),
			host: node.httpupgrade_host,
			headers: truthy(node.user_agent) ? { "User-Agent": node.user_agent } : null
		} : null,
		xhttpSettings: node.transport == "xhttp" ? {
			mode: lua_or(node.xhttp_mode, "auto"),
			path: lua_or(node.xhttp_path, "/"),
			host: node.xhttp_host,
			extra: xhttp_extra(node)
		} : null,
		masqueSettings: node.protocol == "masque" ? {
			path: nonempty(node.masque_path) ? node.masque_path : null,
			warp: node.masque_warp == "1" ? {
				privateKey: nl_to_real(lua_or(node.masque_warp_private_key, "")),
				publicKey: nl_to_real(lua_or(node.masque_warp_public_key, "")),
				address: node.masque_warp_address
			} : null,
			headers: masque_headers(node)
		} : null,
		hysteriaSettings: node.transport == "hysteria" ? {
			version: 2,
			auth: node.hysteria2_auth_password
		} : null,
		finalmask: client_finalmask(node, fragment, noise)
	};
}

function apply_alpn(node, streamSettings) {
	let alpn = [];
	if (truthy(node.alpn) && node.alpn != "default") {
		for (let w in split_matches(node.alpn, /[^,]+/g))
			push(alpn, w);
	}
	if (length(alpn) > 0 && streamSettings != null && streamSettings.tlsSettings != null)
		streamSettings.tlsSettings.alpn = alpn;
}

function register_domain_resolver(node) {
	if (!(api.datatypes.hostname(node.address) && truthy(node.domain_resolver) && (truthy(node.domain_resolver_dns) || truthy(node.domain_resolver_dns_https))))
		return;
	let dns_proto = node.domain_resolver;
	let config_address = null;
	let config_port = null;
	if (dns_proto == "https") {
		let _a = api.parseDoH(node.domain_resolver_dns_https);
		if (_a) {
			config_address = _a.url;
			config_port = lua_or(_a.port, 443);
			if (truthy(_a.hostname) && api.datatypes.hostname(_a.hostname))
				GLOBAL.DNS_HOSTNAME[_a.hostname] = true;
		}
	}
	else {
		let server_address = node.domain_resolver_dns;
		config_port = 53;
		let parts = api.split(server_address, ":");
		if (length(parts) > 1) {
			server_address = parts[0];
			config_port = to_number(parts[length(parts) - 1]);
		}
		config_address = server_address;
		if (dns_proto == "tcp") {
			if (server_address == null || config_port == null)
				die("attempt to concatenate a nil value");
			config_address = dns_proto + "://" + server_address + ":" + config_port;
		}
	}
	if (config_address == null)
		die("attempt to concatenate a nil value");
	let dns_key = dns_proto + "|" + config_address + "|" + lua_tostring(config_port);
	if (GLOBAL.DNS_SERVER[dns_key] == null) {
		GLOBAL.DNS_SERVER[dns_key] = {
			tag: "dns-node-" + api.gen_random_char(),
			address: config_address,
			port: config_port,
			finalQuery: true,
			disableCache: false,
			serveStale: true,
			domains: []
		};
	}
	let exists = false;
	let domain = "full:" + node.address;
	for (let d in GLOBAL.DNS_SERVER[dns_key].domains) {
		if (d == domain) {
			exists = true;
			break;
		}
	}
	if (!exists)
		push(GLOBAL.DNS_SERVER[dns_key].domains, domain);
	GLOBAL.VPS_EXCLUDE[node.address] = true;
}

function decode_wireguard_reserved(node) {
	if (!(node.protocol == "wireguard" && truthy(node.wireguard_reserved)))
		return;
	let bytes = [];
	if (type(node.wireguard_reserved) == "string" && !match(node.wireguard_reserved, /[^0-9,]+/)) {
		let ms = match(node.wireguard_reserved, /\d+/g);
		if (ms) {
			for (let m in ms)
				push(bytes, to_number(m[0]));
		}
	}
	else {
		let result = api.base64Decode(node.wireguard_reserved);
		if (type(result) == "string") {
			for (let i = 0; i < length(result); i++)
				push(bytes, ord(result, i));
		}
	}
	node.wireguard_reserved = length(bytes) > 0 ? bytes : null;
}

function gen_outbound(flag, node, tag, proxy_table) {
	let result = null;
	if (truthy(node)) {
		let node_id = node[".name"];
		if (tag == null)
			tag = node_id;
		let remarks = node.remarks;
		let proxy_tag = null;
		let dialer_proxy_tag = null;
		let fragment = null;
		let noise = null;

		if (proxy_table != null && is_table(proxy_table)) {
			proxy_tag = lua_or(proxy_table.tag, null);
			fragment = (truthy(proxy_table.fragment) && !truthy(node.hysteria2_realms)) ? true : null;
			noise = (truthy(proxy_table.noise) && !truthy(node.hysteria2_realms)) ? true : null;
		}

		if (node.type != "Xray") {
			if (node.type == "Socks") {
				node.protocol = "socks";
				node.transport = "raw";
			}
			else {
				let new_port = null;
				let run_socks_instance = true;
				if (truthy(NO_RUN)) {
					TMP_PORT = truthy(TMP_PORT) ? TMP_PORT + 1 : 3001;
					new_port = TMP_PORT;
					run_socks_instance = null;
				}
				else {
					let relay_port = (truthy(proxy_tag) && truthy(node.port)) ? ("" + node.port) : "";
					if (relay_port == "") {
						let cache = api.get_socks_port_by_cache(node_id);
						if (truthy(cache)) {
							new_port = cache;
							run_socks_instance = null;
						}
					}
					if (truthy(run_socks_instance)) {
						new_port = api.get_new_port();
						let config_file = sprintf("nodesocks_%s_%s.json", node_id, new_port);
						if (truthy(tag) && truthy(node_id) && !(type(tag) == "string" && index(tag, node_id) >= 0))
							config_file = sprintf("nodesocks_%s_%s_%s.json", tag, node_id, new_port);
						let arg = sprintf("flag=%s node=%s bind=%s socks_port=%s config_file=%s relay_port=%s",
							new_port, node_id, "127.0.0.1", new_port, config_file, relay_port);
						api.sys.call(sprintf('/usr/share/passwall/app.sh run_socks "%s"> /dev/null', arg));
						if (relay_port == "")
							api.set_socks_port_to_cache(node_id, new_port);
					}
				}
				if (truthy(new_port)) {
					node = {
						protocol: "socks",
						transport: "raw",
						address: "127.0.0.1",
						port: new_port
					};
				}
			}
			node.stream_security = "none";
			proxy_tag = "socks <- " + node_id;
		}
		else {
			dialer_proxy_tag = proxy_tag;
		}

		if (node.type == "Xray") {
			if (truthy(node.tls) && node.tls == "1") {
				node.stream_security = "tls";
				if (node.type == "Xray" && truthy(node.reality) && node.reality == "1")
					node.stream_security = "reality";
			}
		}

		decode_wireguard_reserved(node);

		if (node.protocol == "hysteria2") {
			node.protocol = "hysteria";
			node.transport = "hysteria";
			node.stream_security = "tls";
		}
		if (node.protocol == "masque") {
			node.transport = "masque";
			node.stream_security = "tls";
			node.utls = null;
		}
		if (node.protocol == "http" && node.stream_security == "tls")
			node.transport = "raw";

		if (truthy(remarks))
			tag = tag + ":" + remarks;

		node.address = lc(lua_or(node.address, ""));

		result = {
			_id: node_id,
			_flag: flag,
			_flag_proxy_tag: proxy_tag,
			tag: tag,
			protocol: node.protocol,
			mux: node.protocol != "masque" ? {
				enabled: node.mux == "1",
				concurrency: node.mux == "1" ? tonumber_or(node.mux_concurrency, -1) : null,
				xudpConcurrency: node.mux == "1" ? tonumber_or(node.xudp_concurrency, 8) : null
			} : null,
			streamSettings: need_stream_settings(node, dialer_proxy_tag) ? client_stream_settings(node, dialer_proxy_tag, fragment, noise) : null,
			settings: {
				address: node.protocol == "wireguard" ? lua_or(node.wireguard_local_address, node.address) : node.address,
				port: to_number(node.port),
				id: (node.protocol == "vmess" || node.protocol == "vless") ? node.uuid : null,
				encryption: node.protocol == "vless" ? (nonempty(node.encryption) ? node.encryption : "none") : null,
				flow: vless_flow(node),
				security: node.protocol == "vmess" ? node.security : null,
				user: (node.protocol == "socks" || node.protocol == "http") ? node.username : null,
				pass: (node.protocol == "socks" || node.protocol == "http") ? node.password : null,
				password: (node.protocol == "shadowsocks" || node.protocol == "trojan") ? node.password : null,
				method: node.protocol == "shadowsocks" ? shadowsocks_method(node.method) : null,
				secretKey: node.protocol == "wireguard" ? node.wireguard_secret_key : null,
				peers: node.protocol == "wireguard" ? [{
					publicKey: node.wireguard_public_key,
					endpoint: node.address + ":" + node.port,
					preSharedKey: node.wireguard_preSharedKey,
					keepAlive: truthy(node.wireguard_keepAlive) ? to_number(node.wireguard_keepAlive) : null
				}] : null,
				mtu: (node.protocol == "wireguard" && truthy(node.wireguard_mtu)) ? to_number(node.wireguard_mtu) : null,
				reserved: (node.protocol == "wireguard" && truthy(node.wireguard_reserved)) ? node.wireguard_reserved : null,
				version: node.protocol == "hysteria" ? 2 : null,
				level: 0
			}
		};

		if (node.protocol == "hysteria" && truthy(node.hysteria2_realms)) {
			let realm = api.parse_realm_uri(node.hysteria2_realm_url);
			if (realm) {
				result.settings.address = realm.address;
				result.settings.port = realm.port;
			}
		}

		if (node.protocol == "wireguard") {
			result.settings.noKernelTun = true;
			if (nonempty(node.finalmask)) {
				let fm = try_parse_b64_json(node.finalmask);
				if (fm) {
					if (result.streamSettings == null)
						result.streamSettings = {};
					result.streamSettings.finalmask = fm;
				}
			}
		}

		apply_alpn(node, result.streamSettings);
		register_domain_resolver(node);
	}
	return result;
}

function server_users(node) {
	if (!(truthy(node.users) && type(node.users) == "array" && length(node.users) > 0))
		return null;
	let users = [];
	for (let v in node.users) {
		let user = lua_or(api.uci_get_s(v), {});
		if (user[".type"] == "user") {
			let u = {};
			if (node.protocol == "socks" || node.protocol == "http") {
				u.user = user.username;
				u.pass = user.password;
			}
			if (node.protocol == "masque") {
				u.email = user.username;
				u.pass = user.password;
			}
			if (node.protocol == "shadowsocks" || node.protocol == "trojan") {
				u.email = user.username;
				u.password = user.password;
			}
			if (node.protocol == "vmess") {
				u.email = user.username;
				u.id = user.uuid;
				u.alterId = 0;
			}
			if (node.protocol == "vless") {
				u.email = user.username;
				u.id = user.uuid;
				u.flow = node.flow;
			}
			if (node.protocol == "hysteria2") {
				u.email = user.username;
				u.auth = user.password;
			}
			if (node.protocol == "wireguard") {
				u.publicKey = user.wireguard_public_key;
				u.preSharedKey = user.wireguard_pre_shared_key;
				u.keepAlive = 0;
				u.allowedIPs = user.allowed_ips;
			}
			push(users, u);
		}
	}
	if (length(users) == 0)
		return null;
	return users;
}

function server_stream_settings(node) {
	return {
		method: node.transport,
		security: "none",
		masqueSettings: node.protocol == "masque" ? {
			path: nonempty(node.masque_path) ? node.masque_path : null
		} : null,
		tlsSettings: node.tls == "1" ? {
			disableSystemRoot: false,
			certificates: [{
				certificateFile: node.tls_use_pem != "1" ? node.tls_certificateFile : null,
				keyFile: node.tls_use_pem != "1" ? node.tls_keyFile : null,
				certificate: (node.tls_use_pem == "1" && truthy(node.tls_certificate)) ? api.split(nl_to_real(node.tls_certificate), "\n") : null,
				key: (node.tls_use_pem == "1" && truthy(node.tls_key)) ? api.split(nl_to_real(node.tls_key), "\n") : null
			}],
			echServerKeys: node.ech == "1" ? node.ech_key : null
		} : null,
		rawSettings: (node.transport == "raw" || node.transport == "tcp") ? {
			header: {
				type: node.tcp_guise,
				request: node.tcp_guise == "http" ? {
					path: truthy(node.tcp_guise_http_path) ? http_paths(node.tcp_guise_http_path) : ["/"],
					headers: {
						Host: lua_or(node.tcp_guise_http_host, {})
					}
				} : null
			}
		} : null,
		kcpSettings: node.transport == "mkcp" ? kcp_settings(node) : null,
		wsSettings: node.transport == "ws" ? {
			host: node.ws_host,
			path: node.ws_path
		} : null,
		grpcSettings: (node.transport == "grpc" && truthy(node.grpc_serviceName)) ? {
			serviceName: node.grpc_serviceName
		} : null,
		httpupgradeSettings: node.transport == "httpupgrade" ? {
			path: lua_or(node.httpupgrade_path, "/"),
			host: node.httpupgrade_host
		} : null,
		xhttpSettings: node.transport == "xhttp" ? {
			path: lua_or(node.xhttp_path, "/"),
			host: node.xhttp_host,
			maxUploadSize: node.xhttp_maxuploadsize,
			maxConcurrentUploads: node.xhttp_maxconcurrentuploads
		} : null,
		hysteriaSettings: node.transport == "hysteria" ? {
			version: 2
		} : null,
		finalmask: server_finalmask(node),
		sockopt: {
			tcpFastOpen: node.tcp_fast_open == "1" ? true : null,
			acceptProxyProtocol: (truthy(node.acceptProxyProtocol) && node.acceptProxyProtocol == "1")
		}
	};
}

export function gen_config_server(node) {
	let settings = null;
	let routing = null;
	let outbounds = [
		{ protocol: "freedom", tag: "direct", settings: { finalRules: [{ action: "allow" }] } },
		{ protocol: "blackhole", tag: "blocked" }
	];

	let users = server_users(node);

	if (node.protocol == "vmess" || node.protocol == "vless") {
		if (users) {
			settings = {
				users: users,
				decryption: node.protocol == "vless" ? (nonempty(node.decryption) ? node.decryption : "none") : null
			};
		}
	}
	else if (node.protocol == "socks") {
		settings = {
			udp: node.udp_forward == "1",
			auth: truthy(users) ? "password" : "noauth",
			users: users
		};
	}
	else if (node.protocol == "http") {
		settings = {
			allowTransparent: false,
			users: users
		};
		node.transport = "raw";
		node.tcp_guise = "none";
	}
	else if (node.protocol == "shadowsocks") {
		settings = {
			method: node.method,
			password: node.ss_password,
			users: users,
			network: lua_or(node.ss_network, "tcp,udp")
		};
	}
	else if (node.protocol == "trojan") {
		if (users)
			settings = { users: users };
	}
	else if (node.protocol == "hysteria2") {
		settings = {
			version: 2,
			users: users
		};
	}
	else if (node.protocol == "masque") {
		node.transport = "masque";
		node.tls = "1";
		node.reality = null;
		node.alpn = null;
		node.fallback = null;
		node.finalmask = null;
		settings = {
			users: users,
			address: node.masque_address,
			mtu: to_number(lua_or(node.masque_mtu, 1280))
		};
	}
	else if (node.protocol == "tunnel") {
		settings = {
			allowedNetwork: node.d_protocol,
			rewriteAddress: node.d_address,
			rewritePort: to_number(node.d_port)
		};
	}
	else if (node.protocol == "wireguard") {
		settings = {
			secretKey: node.wireguard_private_key,
			mtu: to_number(lua_or(node.wireguard_mtu, 1420)),
			peers: users
		};
	}

	if (node.fallback == "1") {
		let fallbacks = [];
		if (type(node.fallback_list) == "array") {
			for (let i = 0; i < length(node.fallback_list); i++) {
				let fallbackStr = node.fallback_list[i];
				if (truthy(fallbackStr)) {
					let tmp = split_matches(fallbackStr, /[^,]+/g);
					let dest = length(tmp) > 0 ? tmp[0] : "";
					let path = length(tmp) > 1 ? tmp[1] : null;
					let xver = length(tmp) > 2 ? to_number(tmp[2]) : null;
					if (!contains(dest, "."))
						dest = to_number(dest);
					while (length(fallbacks) < i)
						push(fallbacks, null);
					fallbacks[i] = {
						path: path,
						dest: dest,
						xver: xver
					};
				}
			}
		}
		settings.fallbacks = fallbacks;
	}

	routing = {
		domainStrategy: "IPOnDemand",
		rules: [{
			ip: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
			outboundTag: (node.accept_lan == null || node.accept_lan == "0") ? "blocked" : "direct"
		}]
	};

	if (truthy(node.outbound_node)) {
		let outbound = null;
		if (node.outbound_node == "_iface" && truthy(node.outbound_node_iface)) {
			outbound = {
				protocol: "freedom",
				tag: "outbound",
				streamSettings: {
					sockopt: {
						mark: 255,
						interface: node.outbound_node_iface
					}
				},
				settings: {
					finalRules: [{ action: "allow" }]
				}
			};
			api.sys.call(sprintf("mkdir -p %s && touch %s/%s", api.TMP_IFACE_PATH, api.TMP_IFACE_PATH, node.outbound_node_iface));
		}
		else {
			let outbound_node_t = api.uci_get_c(node.outbound_node);
			if (node.outbound_node == "_socks" || node.outbound_node == "_http") {
				outbound_node_t = {
					type: node.type,
					protocol: replace(node.outbound_node, "_", ""),
					transport: "tcp",
					address: node.outbound_node_address,
					port: node.outbound_node_port,
					username: nonempty(node.outbound_node_username) ? node.outbound_node_username : null,
					password: nonempty(node.outbound_node_password) ? node.outbound_node_password : null
				};
			}
			outbound = gen_outbound(null, outbound_node_t, "outbound");
		}
		if (outbound)
			unshift(outbounds, outbound);
	}

	if (node.protocol == "hysteria2") {
		node.protocol = "hysteria";
		node.transport = "hysteria";
		node.tls = "1";
	}

	let config = {
		log: {
			loglevel: node.log == "1" ? lua_or(get_log_level(node.loglevel), "none") : "none"
		},
		inbounds: [{
			listen: "::",
			port: to_number(node.port),
			protocol: node.protocol,
			settings: settings,
			streamSettings: server_stream_settings(node)
		}],
		outbounds: outbounds,
		routing: routing,
		version: {
			min: xray_min_version
		}
	};

	let alpn = [];
	if (truthy(node.alpn) && node.alpn != "default") {
		for (let w in split_matches(node.alpn, /[^,]+/g))
			push(alpn, w);
	}
	if (length(alpn) > 0 && config.inbounds[0].streamSettings.tlsSettings)
		config.inbounds[0].streamSettings.tlsSettings.alpn = alpn;

	if (node.tls == "1") {
		config.inbounds[0].streamSettings.security = "tls";
		if (node.reality == "1") {
			config.inbounds[0].streamSettings.tlsSettings = null;
			config.inbounds[0].streamSettings.security = "reality";
			config.inbounds[0].streamSettings.realitySettings = {
				show: false,
				dest: node.reality_dest,
				serverNames: lua_or(node.reality_serverNames, []),
				privateKey: node.reality_private_key,
				shortIds: lua_or(node.reality_shortId, ""),
				mldsa65Seed: node.use_mldsa65Seed == "1" ? node.reality_mldsa65Seed : null,
				minClientVer: "1.0.0"
			};
		}
	}

	drop_private_keys(config.outbounds);
	return strip_nulls(config);
}

function collect_rule_items(text) {
	let sink = [];
	for (let w in split_matches(text, /[^\r\n]+/g)) {
		w = api.trim(w);
		if (w == "" || (type(w) == "string" && index(w, "#") == 0))
			continue;
		if (has_prefix(w, "rule-set:") || has_prefix(w, "rs:") || has_prefix(w, "ext:"))
			continue;
		push(sink, w);
	}
	return sink;
}

function geosite_dat_path() {
	let asset = lua_or(api.uci_get_c("@global_rules[0]", "v2ray_location_asset"), "/usr/share/v2ray/");
	let m = match(asset, /^(.*)\//);
	if (!m)
		die("attempt to concatenate a nil value");
	return m[1] + "/geosite.dat";
}

export function gen_config(vars) {
	let flag = vars["flag"];
	let node_id = vars["node"];
	let server_host = vars["server_host"];
	let server_port = vars["server_port"];
	let tcp_proxy_way = lua_or(vars["tcp_proxy_way"], "redirect");
	let redir_port = vars["redir_port"];
	let local_socks_address = lua_or(vars["local_socks_address"], "0.0.0.0");
	let local_socks_port = vars["local_socks_port"];
	let local_socks_username = vars["local_socks_username"];
	let local_socks_password = vars["local_socks_password"];
	let local_http_address = lua_or(vars["local_http_address"], "0.0.0.0");
	let local_http_port = vars["local_http_port"];
	let local_http_username = vars["local_http_username"];
	let local_http_password = vars["local_http_password"];
	let dns_listen_port = vars["dns_listen_port"];
	let dns_cache = vars["dns_cache"];
	let direct_dns_port = vars["direct_dns_port"];
	let direct_dns_udp_server = vars["direct_dns_udp_server"];
	let direct_dns_tcp_server = vars["direct_dns_tcp_server"];
	let direct_dns_query_strategy = vars["direct_dns_query_strategy"];
	let remote_dns_udp_server = vars["remote_dns_udp_server"];
	let remote_dns_udp_port = vars["remote_dns_udp_port"];
	let remote_dns_tcp_server = vars["remote_dns_tcp_server"];
	let remote_dns_tcp_port = vars["remote_dns_tcp_port"];
	let remote_dns_doh = vars["remote_dns_doh"];
	let remote_dns_client_ip = vars["remote_dns_client_ip"];
	let remote_dns_fake = vars["remote_dns_fake"];
	let remote_dns_query_strategy = vars["remote_dns_query_strategy"];
	let dns_socks_address = vars["dns_socks_address"];
	let dns_socks_port = vars["dns_socks_port"];
	let loglevel = lua_or(vars["loglevel"], "warning");
	let use_proxy_list = vars["use_proxy_list"];
	let use_gfw_list = vars["use_gfw_list"];
	let chn_list = vars["chn_list"];
	let run_in_global = vars["run_in_global"];
	NO_RUN = vars["no_run"];

	let dns_domain_rules = [];
	let dns = null;
	let fakedns = null;
	let routing = null;
	let observatory = null;
	let burstObservatory = null;
	let strategy = null;
	let inbounds = [];
	let outbounds = [];
	let COMMON = {};

	let xray_settings = lua_or(api.uci_get_c("@global_xray[0]"), {});

	if (xray_settings.fragment == "1") {
		let lengths = csv_tokens(xray_settings.fragment_lengths);
		let delays = csv_tokens(xray_settings.fragment_delays);
		fragment_table = {
			type: "fragment",
			settings: {
				packets: lua_or(xray_settings.fragment_packets, "tlshello"),
				lengths: length(lengths) > 0 ? lengths : ["3-5", "6-8", "10-20"],
				delays: length(delays) > 0 ? delays : ["10-20"],
				maxSplit: lua_or(xray_settings.fragment_maxSplit, "3-6")
			}
		};
	}

	if (xray_settings.noise == "1") {
		let noises = [];
		api.uci_foreach_c("xray_noise_packets", function(n) {
			if (n.enabled == "1") {
				push(noises, {
					rand: noise_rand(n),
					type: n.type != "rand" ? n.type : null,
					packet: n.type != "rand" ? n.packet : null,
					delay: noise_delay(n.delay)
				});
			}
		});
		noise_table = length(noises) > 0 ? {
			type: "noise",
			settings: { reset: 0, noise: noises }
		} : null;
	}

	if (truthy(node_id)) {
		let node = api.uci_get_c(node_id);
		let balancers = [];
		let rules = [];
		if (node) {
			if (truthy(server_host) && truthy(server_port)) {
				node.address = server_host;
				node.port = server_port;
			}
		}
		if (truthy(local_socks_port)) {
			let inbound = {
				tag: "socks-in",
				listen: local_socks_address,
				port: to_number(local_socks_port),
				protocol: "socks",
				settings: { auth: "noauth", udp: true },
				sniffing: {
					enabled: xray_settings.sniffing_override_dest == "1" || (truthy(node) && node.protocol == "_shunt")
				}
			};
			if (inbound.sniffing.enabled == true) {
				inbound.sniffing.destOverride = ["http", "tls", "quic"];
				inbound.sniffing.routeOnly = xray_settings.sniffing_override_dest != "1" ? true : null;
				inbound.sniffing.domainsExcluded = xray_settings.sniffing_override_dest == "1" ? get_domain_excluded() : null;
			}
			if (truthy(local_socks_username) && truthy(local_socks_password) && local_socks_username !== "" && local_socks_password !== "") {
				inbound.settings.auth = "password";
				inbound.settings.users = [{
					user: local_socks_username,
					pass: local_socks_password
				}];
			}
			push(inbounds, inbound);
		}
		if (truthy(local_http_port)) {
			let inbound = {
				listen: local_http_address,
				port: to_number(local_http_port),
				protocol: "http",
				settings: { allowTransparent: false }
			};
			if (truthy(local_http_username) && truthy(local_http_password) && local_http_username !== "" && local_http_password !== "") {
				inbound.settings.users = [{
					user: local_http_username,
					pass: local_http_password
				}];
			}
			push(inbounds, inbound);
		}

		function get_node_by_id;
		function gen_loopback;
		function gen_balancer;
		function set_outbound_detour;
		function gen_outbound_get_tag;

		function get_node_by_id(id) {
			let section;
			let id_type = type(id);
			if (id_type == "object" || id_type == "array") {
				section = id;
			}
			else if (id_type == "string") {
				if (id == "" || id == "nil")
					return null;
				section = lua_or(api.uci_get_c(id), {});
			}
			else {
				return null;
			}
			if (section[".type"] == "socks") {
				return {
					".name": section[".name"],
					remarks: sprintf("socks[%s]", section.port),
					type: "Xray",
					protocol: "socks",
					address: "127.0.0.1",
					port: section.port,
					transport: "tcp",
					stream_security: "none"
				};
			}
			if (section[".type"] == "nodes")
				return section;
			return null;
		}

		function gen_loopback(outbound_tag, loopback_dst) {
			if (!truthy(outbound_tag) || outbound_tag === "")
				return null;
			let inbound_tag = truthy(loopback_dst) ? ("lo-to-" + loopback_dst) : (outbound_tag + "-lo");
			for (let o in outbounds) {
				if (o.tag == outbound_tag && o.protocol == "loopback" && o.settings.inboundTag == inbound_tag)
					return o;
			}
			let loopback_outbound = {
				protocol: "loopback",
				tag: outbound_tag,
				settings: { inboundTag: inbound_tag }
			};
			if (outbound_tag == "default")
				unshift(outbounds, loopback_outbound);
			else
				push(outbounds, loopback_outbound);
			return loopback_outbound;
		}

		function gen_balancer(_node, loopback_tag) {
			let balancer_id = _node[".name"];
			let balancer_tag = "balancer-" + balancer_id;
			let loopback_dst = balancer_id;
			if (!truthy(loopback_tag) || loopback_tag === "")
				loopback_tag = balancer_id;
			for (let v in balancers) {
				if (v.tag == balancer_tag) {
					let loopback_outbound = gen_loopback(loopback_tag, loopback_dst);
					return [balancer_tag, loopback_outbound];
				}
			}
			let blc_nodes;
			if (truthy(_node.node_add_mode) && _node.node_add_mode == "batch")
				blc_nodes = api.get_batch_nodes(_node);
			else
				blc_nodes = _node.balancing_node;

			if (!truthy(NO_RUN) && truthy(run_in_global)) {
				let listed = lua_or(blc_nodes, []);
				let count = type(listed) == "array" ? length(listed) : 0;
				api.log("  - 加载 Xray 负载均衡 节点【" + lua_or(_node.remarks, "") + "】，子节点数量：" + count);
			}

			let valid_nodes = [];
			let listed_nodes = lua_or(blc_nodes, []);
			if (type(listed_nodes) != "array")
				listed_nodes = [];
			for (let i = 0; i < length(listed_nodes); i++) {
				let blc_node_id = listed_nodes[i];
				let blc_node_tag = "blc-" + blc_node_id;
				let is_new_blc_node = true;
				for (let outbound in outbounds) {
					if (has_prefix(outbound.tag, blc_node_tag)) {
						is_new_blc_node = false;
						push(valid_nodes, outbound.tag);
						break;
					}
				}
				if (is_new_blc_node) {
					let outboundTag = gen_outbound_get_tag(flag, blc_node_id, blc_node_tag, {
						fragment: xray_settings.fragment == "1" ? true : null,
						noise: xray_settings.noise == "1" ? true : null
					});
					if (outboundTag)
						push(valid_nodes, outboundTag);
				}
				if (_node.fallback_node == blc_node_id)
					_node.fallback_node = null;
			}
			if (length(valid_nodes) == 0)
				return null;

			let fallback_node_id = _node.fallback_node;
			fallback_node_id = (truthy(fallback_node_id) && fallback_node_id !== "") ? fallback_node_id : null;
			let fallback_node_tag = (fallback_node_id == "_direct") ? "direct" : "blackhole";
			if (truthy(fallback_node_id) && fallback_node_id != "_direct") {
				let is_new_node = true;
				for (let outbound in outbounds) {
					if (has_prefix(outbound.tag, fallback_node_id)) {
						is_new_node = false;
						fallback_node_tag = outbound.tag;
						break;
					}
				}
				if (is_new_node) {
					let fallback_node = get_node_by_id(fallback_node_id);
					if (fallback_node) {
						if (fallback_node.protocol != "_balancing") {
							let outboundTag = gen_outbound_get_tag(flag, fallback_node, fallback_node_id, {
								fragment: xray_settings.fragment == "1" ? true : null,
								noise: xray_settings.noise == "1" ? true : null
							});
							if (outboundTag)
								fallback_node_tag = outboundTag;
						}
						else if (gen_balancer(fallback_node)) {
							fallback_node_tag = fallback_node_id;
						}
					}
				}
			}
			if (_node.balancingStrategy == "leastLoad") {
				strategy = {
					type: _node.balancingStrategy,
					settings: {
						expected: expected_count(_node.expected),
						maxRTT: "1s",
						tolerance: tolerance_ratio(_node.tolerance)
					}
				};
			}
			else {
				strategy = { type: lua_or(_node.balancingStrategy, "random") };
			}
			push(balancers, {
				tag: balancer_tag,
				selector: api.clone(valid_nodes),
				fallbackTag: fallback_node_tag,
				strategy: strategy
			});
			if (_node.balancingStrategy == "leastPing" || _node.balancingStrategy == "leastLoad" || truthy(fallback_node_tag)) {
				let t = probe_every(_node.probeInterval);
				if (_node.balancingStrategy == "leastLoad") {
					burstObservatory = lua_or(burstObservatory, {
						subjectSelector: ["blc-"],
						pingConfig: {
							destination: truthy(_node.useCustomProbeUrl) ? _node.probeUrl : null,
							interval: t,
							sampling: 3,
							timeout: "5s"
						}
					});
				}
				else {
					observatory = lua_or(observatory, {
						subjectSelector: ["blc-"],
						probeUrl: truthy(_node.useCustomProbeUrl) ? _node.probeUrl : null,
						probeInterval: t,
						enableConcurrency: true
					});
				}
			}
			let loopback_outbound = gen_loopback(loopback_tag, loopback_dst);
			let inbound_tag = loopback_outbound.settings.inboundTag;
			push(rules, { inboundTag: [inbound_tag], balancerTag: balancer_tag });
			return [balancer_tag, loopback_outbound];
		}

		function set_outbound_detour(detour_node, outbound, outbounds_table) {
			if (!truthy(detour_node) || !truthy(outbound) || !truthy(outbounds_table))
				return [null, null];
			let default_outTag = outbound.tag;
			let last_insert_outbound = null;

			if (detour_node.chain_proxy == "1" && truthy(detour_node.preproxy_node)) {
				if (!truthy(outbound["_flag_proxy_tag"])) {
					let preproxy_node = get_node_by_id(detour_node.preproxy_node);
					if (preproxy_node) {
						let preproxy_outbound = null;
						let exist = null;
						if (preproxy_node.protocol == "_balancing") {
							let bal = gen_balancer(preproxy_node);
							if (bal && bal[1]) {
								preproxy_outbound = bal[1];
								exist = true;
							}
						}
						else {
							preproxy_outbound = gen_outbound(detour_node[".name"], preproxy_node);
						}
						if (preproxy_outbound) {
							outbound.tag = preproxy_outbound.tag + " -> " + outbound.tag;
							if (outbound.streamSettings == null)
								outbound.streamSettings = {};
							if (outbound.streamSettings.sockopt == null)
								outbound.streamSettings.sockopt = {};
							outbound.streamSettings.sockopt.dialerProxy = preproxy_outbound.tag;
							if (!exist)
								last_insert_outbound = preproxy_outbound;
							default_outTag = outbound.tag;
						}
					}
				}
			}
			if (detour_node.chain_proxy == "2" && truthy(detour_node.to_node)) {
				let to_node = get_node_by_id(detour_node.to_node);
				if (to_node) {
					if (truthy(to_node.protocol) && match(to_node.protocol, /^_/))
						to_node = null;
				}
				if (to_node) {
					let to_outbound = null;
					if (to_node.type != "Xray") {
						if (to_node[".name"] == null)
							die("attempt to concatenate a nil value");
						let in_tag = "inbound_" + to_node[".name"] + "_" + lua_tostring(outbound.tag);
						let new_port = api.get_new_port();
						push(inbounds, {
							tag: in_tag,
							listen: "127.0.0.1",
							port: new_port,
							protocol: "tunnel",
							settings: {
								allowedNetwork: "tcp,udp",
								rewriteAddress: to_node.address,
								rewritePort: to_number(to_node.port)
							}
						});
						if (to_node.tls_serverName == null)
							to_node.tls_serverName = to_node.address;
						to_node.address = "127.0.0.1";
						to_node.port = new_port;
						linsert(rules, 1, {
							inboundTag: [in_tag],
							outboundTag: outbound.tag
						});
						to_outbound = gen_outbound(detour_node[".name"], to_node, to_node[".name"], {
							tag: to_node[".name"]
						});
					}
					else {
						to_outbound = gen_outbound(detour_node[".name"], to_node);
					}
					if (to_outbound) {
						to_outbound.tag = outbound.tag + " -> " + to_outbound.tag;
						if (to_node.type == "Xray") {
							if (to_outbound.streamSettings == null)
								to_outbound.streamSettings = {};
							if (to_outbound.streamSettings.sockopt == null)
								to_outbound.streamSettings.sockopt = {};
							to_outbound.streamSettings.sockopt.dialerProxy = outbound.tag;
						}
						push(outbounds_table, to_outbound);
						default_outTag = to_outbound.tag;
					}
				}
			}
			if (detour_node.chain_proxy == "3" && truthy(detour_node.outbound_iface)) {
				if (outbound.streamSettings && outbound.streamSettings.sockopt)
					outbound.streamSettings.sockopt.interface = detour_node.outbound_iface;
			}
			return [default_outTag, last_insert_outbound];
		}

		function gen_outbound_get_tag(ob_flag, id, tag, proxy_table) {
			if (!truthy(id) || id === "" || id === "nil")
				return null;
			let ob_node = get_node_by_id(id);
			if (!truthy(tag))
				tag = ob_node[".name"];
			if (ob_node) {
				if (proxy_table.chain_proxy == "1" || proxy_table.chain_proxy == "2") {
					ob_node.chain_proxy = proxy_table.chain_proxy;
					ob_node.preproxy_node = proxy_table.chain_proxy == "1" ? proxy_table.preproxy_node : false;
					ob_node.to_node = proxy_table.chain_proxy == "2" ? proxy_table.to_node : false;
					delete proxy_table.chain_proxy;
					delete proxy_table.preproxy_node;
					delete proxy_table.to_node;
				}
				let outbound = null;
				let has_add_outbound = null;
				for (let _outbound in outbounds) {
					let marker = "socks <- " + ob_node[".name"];
					if (truthy(_outbound["_flag_proxy_tag"]) && contains(_outbound["_flag_proxy_tag"], marker)) {
						outbound = api.clone(_outbound);
						outbound.tag = tag;
						break;
					}
				}
				if (ob_node.protocol == "_balancing") {
					let bal = gen_balancer(ob_node, tag);
					if (bal && bal[1]) {
						outbound = bal[1];
						ob_node[".name"] = outbound.tag;
						has_add_outbound = true;
					}
				}
				else if (ob_node.protocol == "_iface") {
					if (truthy(ob_node.iface)) {
						outbound = {
							tag: tag,
							protocol: "freedom",
							streamSettings: {
								sockopt: {
									mark: 255,
									interface: ob_node.iface
								}
							},
							settings: {
								finalRules: [{ action: "allow" }]
							}
						};
						api.sys.call(sprintf("mkdir -p %s && touch %s/%s", api.TMP_IFACE_PATH, api.TMP_IFACE_PATH, ob_node.iface));
					}
				}
				if (!outbound)
					outbound = gen_outbound(ob_flag, ob_node, tag, proxy_table);
				if (outbound) {
					let det = set_outbound_detour(ob_node, outbound, outbounds);
					let default_outbound_tag = det[0];
					let last_insert_outbound = det[1];
					if (!has_add_outbound) {
						if (tag == "default")
							unshift(outbounds, outbound);
						else
							push(outbounds, outbound);
					}
					if (last_insert_outbound)
						push(outbounds, last_insert_outbound);
					return default_outbound_tag;
				}
			}
			return null;
		}

		if (node && node.protocol == "_shunt") {
			inner_fakedns = lua_or(node.fakedns, "0");

			function gen_shunt_node(rule_name, _node_id) {
				if (!truthy(rule_name))
					return null;
				if (!truthy(_node_id))
					_node_id = node[rule_name];
				if (_node_id == "_direct")
					return "direct";
				if (_node_id == "_blackhole")
					return "blackhole";
				if (_node_id == "_default" && rule_name != "default")
					return "default";
				if (truthy(_node_id)) {
					let proxy_table = {
						fragment: xray_settings.fragment == "1",
						noise: xray_settings.noise == "1"
					};
					let preproxy_node_id = node[rule_name + "_proxy_tag"];
					if (preproxy_node_id == _node_id)
						preproxy_node_id = null;
					if (truthy(preproxy_node_id)) {
						proxy_table.chain_proxy = "2";
						proxy_table.to_node = _node_id;
						return gen_outbound_get_tag(flag, preproxy_node_id, rule_name, proxy_table);
					}
					return gen_outbound_get_tag(flag, _node_id, rule_name, proxy_table);
				}
				return null;
			}

			let default_node_id = lua_or(node.default_node, "_direct");
			let default_outboundTag = gen_shunt_node("default", default_node_id);
			COMMON.default_outbound_tag = default_outboundTag;

			if (inner_fakedns == "1" && node["default_fakedns"] == "1")
				remote_dns_fake = true;

			function read_proxy_list(path) {
				if (use_proxy_list != "1")
					return "";
				let content = api.fs.readfile(path);
				let lines = file_lines(content);
				if (lines == null)
					return "";
				let seen = {};
				let list = [];
				for (let line in lines) {
					if (line != "" && !contains(line, "#") && seen[line] == null) {
						seen[line] = 1;
						push(list, line);
					}
				}
				return join("\n", list);
			}

			function foreach_shunt_rule(callback) {
				api.uci_foreach_c("shunt_rules", callback);
				if (use_gfw_list != "1" || chn_list != "0")
					return;
				let domain_list = read_proxy_list("/etc/passwall/rules/proxy_host");
				let ip_list = read_proxy_list("/etc/passwall/rules/proxy_ip");
				let bin = api.finded_com("geoview");
				if (truthy(bin)) {
					let geo_file = geosite_dat_path();
					if (api.sys.call('"' + bin + '" -type geosite -input "' + geo_file + '" | grep -q "^GFW$"') == 0)
						domain_list = domain_list == "" ? "geosite:gfw" : domain_list + "\ngeosite:gfw";
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

			foreach_shunt_rule(function(e) {
				if (node["shunt_group"] != e.group)
					return;
				let outbound_tag = gen_shunt_node(e[".name"]);
				if (truthy(outbound_tag) && truthy(e.remarks)) {
					if (outbound_tag == "default")
						outbound_tag = default_outboundTag;
					let protocols = null;
					if (nonempty(e["protocol"]))
						protocols = split_matches(e["protocol"], /[^ ]+/g);
					let inbound_tag = null;
					if (nonempty(e["inbound"])) {
						inbound_tag = [];
						if (contains(e["inbound"], "tproxy")) {
							if (truthy(redir_port)) {
								push(inbound_tag, "tcp_redir");
								push(inbound_tag, "udp_redir");
							}
						}
						if (contains(e["inbound"], "socks")) {
							if (truthy(local_socks_port))
								push(inbound_tag, "socks-in");
						}
					}
					let domains = null;
					if (truthy(e.domain_list)) {
						let domain_table = {
							shunt_rule_name: e[".name"],
							outboundTag: outbound_tag,
							domain: [],
							fakedns: null
						};
						domains = collect_rule_items(e.domain_list);
						for (let w in domains)
							push(domain_table.domain, w);
						if (inner_fakedns == "1" && node[e[".name"] + "_fakedns"] == "1" && length(domains) > 0)
							domain_table.fakedns = true;
						if (length(domains) == 0)
							domains = null;
						if (truthy(outbound_tag) && domains)
							push(dns_domain_rules, api.clone(domain_table));
					}
					let ip = null;
					if (truthy(e.ip_list)) {
						ip = collect_rule_items(e.ip_list);
						if (length(ip) == 0)
							ip = null;
					}
					let source = null;
					if (truthy(e.source))
						source = split_matches(e.source, /[^ ]+/g);
					let rule = {
						ruleTag: e.remarks,
						inboundTag: inbound_tag,
						outboundTag: outbound_tag,
						network: lua_or(e["network"], "tcp,udp"),
						source: source,
						port: (truthy(e["port"]) && e["port"] !== "") ? e["port"] : null,
						protocol: protocols
					};
					if (domains) {
						let _rule = api.clone(rule);
						_rule.ruleTag = _rule.ruleTag + " Domains";
						_rule.domains = domains;
						push(rules, _rule);
					}
					if (ip) {
						let _rule = api.clone(rule);
						_rule.ruleTag = _rule.ruleTag + " IP";
						_rule.ip = ip;
						push(rules, _rule);
					}
					if (!domains && !ip && protocols)
						push(rules, rule);
				}
			});

			if (use_gfw_list == "1" && chn_list == "0") {
				push(rules, {
					ruleTag: "GFW_Mode_Default",
					outboundTag: "direct",
					port: node.domainStrategy == "IPIfNonMatch" ? "1-65535" : null,
					network: node.domainStrategy != "IPIfNonMatch" ? "tcp,udp" : null
				});
			}

			if (truthy(default_outboundTag)) {
				let rule = {
					_flag: "default",
					outboundTag: default_outboundTag
				};
				if (node.domainStrategy == "IPIfNonMatch")
					rule.port = "1-65535";
				else
					rule.network = "tcp,udp";
				push(rules, rule);
			}

			routing = {
				domainStrategy: lua_or(node.domainStrategy, "AsIs"),
				domainMatcher: lua_or(node.domainMatcher, "hybrid"),
				balancers: length(balancers) > 0 ? balancers : null,
				rules: rules
			};
		}
		else {
			COMMON.default_outbound_tag = gen_outbound_get_tag(flag, truthy(node) ? node : node_id, null, {
				fragment: xray_settings.fragment == "1" ? true : null,
				noise: xray_settings.noise == "1" ? true : null
			});
			if (truthy(COMMON.default_outbound_tag)) {
				routing = {
					domainStrategy: "AsIs",
					domainMatcher: "hybrid",
					balancers: length(balancers) > 0 ? balancers : null,
					rules: rules
				};
				push(routing.rules, {
					ruleTag: "default",
					network: "tcp,udp",
					outboundTag: COMMON.default_outbound_tag
				});
			}
		}

		if (truthy(redir_port)) {
			let inbound = {
				port: to_number(redir_port),
				protocol: "tunnel",
				settings: { allowedNetwork: "tcp,udp", followRedirect: true },
				streamSettings: { sockopt: { tproxy: "tproxy" } },
				sniffing: {
					enabled: xray_settings.sniffing_override_dest == "1" || node.protocol == "_shunt"
				}
			};
			if (inbound.sniffing.enabled == true) {
				inbound.sniffing.destOverride = ["http", "tls", "quic"];
				inbound.sniffing.metadataOnly = false;
				inbound.sniffing.routeOnly = xray_settings.sniffing_override_dest != "1" ? true : null;
				inbound.sniffing.domainsExcluded = xray_settings.sniffing_override_dest == "1" ? get_domain_excluded() : null;
			}
			if (truthy(remote_dns_fake) || inner_fakedns == "1") {
				inbound.sniffing.enabled = true;
				if (!truthy(inbound.sniffing.destOverride)) {
					inbound.sniffing.destOverride = ["fakedns"];
					inbound.sniffing.metadataOnly = true;
				}
				else {
					push(inbound.sniffing.destOverride, "fakedns");
					inbound.sniffing.metadataOnly = false;
				}
			}

			let tcp_inbound = api.clone(inbound);
			tcp_inbound.tag = "tcp_redir";
			tcp_inbound.settings.allowedNetwork = "tcp";
			tcp_inbound.streamSettings.sockopt.tproxy = tcp_proxy_way;
			push(inbounds, tcp_inbound);

			let udp_inbound = api.clone(inbound);
			udp_inbound.tag = "udp_redir";
			udp_inbound.settings.allowedNetwork = "udp";
			push(inbounds, udp_inbound);
		}
	}

	let node_dns = [];
	for (let key, server in GLOBAL.DNS_SERVER) {
		push(node_dns, {
			server: server,
			outboundTag: "direct"
		});
	}

	if ((truthy(remote_dns_udp_server) && truthy(remote_dns_udp_port)) || (truthy(remote_dns_tcp_server) && truthy(remote_dns_tcp_port)) || truthy(remote_dns_doh) || length(node_dns) > 0) {
		if (!routing) {
			routing = {
				domainStrategy: "IPOnDemand",
				rules: []
			};
		}

		dns = {
			tag: "dns-global",
			hosts: {},
			disableCache: (truthy(dns_cache) && dns_cache == "0"),
			disableFallback: true,
			disableFallbackIfMatch: true,
			servers: [],
			clientIp: nonempty(remote_dns_client_ip) ? remote_dns_client_ip : null,
			queryStrategy: "UseIP",
			useSystemHosts: true
		};

		let _direct_dns = {};
		direct_dns_udp_server = nonempty(direct_dns_udp_server) ? direct_dns_udp_server : null;

		if (truthy(direct_dns_udp_server) || truthy(direct_dns_tcp_server)) {
			_direct_dns.tag = "dns-global-direct";
			_direct_dns.queryStrategy = nonempty(direct_dns_query_strategy) ? direct_dns_query_strategy : "UseIP";
			if (truthy(direct_dns_udp_server)) {
				let port = to_number(direct_dns_port);
				if (port == null)
					port = 53;
				_direct_dns.port = port;
				_direct_dns.address = direct_dns_udp_server;
			}
			else if (truthy(direct_dns_tcp_server)) {
				if (api.is_ipv6(direct_dns_tcp_server))
					direct_dns_tcp_server = api.get_ipv6_full(direct_dns_tcp_server);
				let port = to_number(direct_dns_port);
				if (port == null)
					port = 53;
				_direct_dns.address = "tcp://" + direct_dns_tcp_server + ":" + port;
				_direct_dns.port = port;
			}
			if (COMMON.default_outbound_tag == "direct")
				push(dns.servers, _direct_dns);
		}

		if (truthy(dns_listen_port) && length(_direct_dns) > 0) {
			let domain = [];
			let nodes_domain_text = api.sys.exec("uci show passwall | sed -n \"s/.*\\.\\(address\\|download_address\\)='\\([^']*\\)'/\\2/p\" | sort -u");
			for (let w in split_matches(nodes_domain_text, /[^\r\n]+/g)) {
				w = lc(w != null ? w : "");
				if (!api.vps_domain_exclude(w) && api.datatypes.hostname(w) && !truthy(GLOBAL.VPS_EXCLUDE[w]))
					push(domain, "full:" + w);
			}
			if (length(domain) > 0) {
				unshift(dns_domain_rules, {
					shunt_rule_name: "logic-vpslist",
					outboundTag: "direct",
					domain: domain
				});
			}
		}

		let _remote_dns = {};
		if (truthy(remote_dns_udp_server)) {
			_remote_dns.address = remote_dns_udp_server;
			let p = to_number(remote_dns_udp_port);
			_remote_dns.port = p != null ? p : 53;
		}
		else if (truthy(remote_dns_tcp_server)) {
			if (api.is_ipv6(remote_dns_tcp_server))
				remote_dns_tcp_server = api.get_ipv6_full(remote_dns_tcp_server);
			let rport = to_number(remote_dns_tcp_port);
			if (rport == null)
				die("attempt to concatenate a null value");
			_remote_dns.address = "tcp://" + remote_dns_tcp_server + ":" + rport;
			_remote_dns.port = rport != null ? rport : 53;
		}
		else if (truthy(remote_dns_doh)) {
			let _a = api.parseDoH(remote_dns_doh);
			if (_a) {
				_remote_dns.address = _a.url;
				_remote_dns.port = lua_or(_a.port, 443);
				if (api.datatypes.hostname(_a.hostname)) {
					if (truthy(_a.hostip))
						dns.hosts[_a.hostname] = _a.hostip;
					else
						GLOBAL.DNS_HOSTNAME[_a.hostname] = true;
				}
			}
		}

		if (length(_remote_dns) > 0) {
			_remote_dns.queryStrategy = nonempty(remote_dns_query_strategy) ? remote_dns_query_strategy : "UseIPv4";
			push(dns.servers, _remote_dns);
		}

		let _remote_fakedns = {
			address: "fakedns"
		};

		if (truthy(remote_dns_fake) || inner_fakedns == "1") {
			fakedns = [];
			let fakedns4 = {
				ipPool: "198.18.0.0/16",
				poolSize: 65535
			};
			let fakedns6 = {
				ipPool: "2001:2::/48",
				poolSize: 65535
			};
			if (remote_dns_query_strategy == "UseIP") {
				push(fakedns, fakedns4);
				push(fakedns, fakedns6);
			}
			else if (remote_dns_query_strategy == "UseIPv4") {
				push(fakedns, fakedns4);
			}
			else if (remote_dns_query_strategy == "UseIPv6") {
				push(fakedns, fakedns6);
			}
			if (truthy(remote_dns_fake))
				unshift(dns.servers, _remote_fakedns);
		}

		let dns_outbound_tag = "direct";
		if (truthy(dns_socks_address) && truthy(dns_socks_port)) {
			dns_outbound_tag = "out";
			unshift(outbounds, {
				tag: dns_outbound_tag,
				protocol: "socks",
				streamSettings: {
					network: "tcp",
					security: "none",
					sockopt: {
						mark: 255
					}
				},
				settings: {
					servers: [{
						address: dns_socks_address,
						port: to_number(dns_socks_port)
					}]
				}
			});
		}
		else if (truthy(COMMON.default_outbound_tag)) {
			dns_outbound_tag = COMMON.default_outbound_tag;
		}

		let dns_rule_position = 1;
		let remote_dns_outbound = null;
		if (truthy(dns_listen_port)) {
			push(inbounds, {
				listen: "127.0.0.1",
				port: to_number(dns_listen_port),
				protocol: "tunnel",
				tag: "dns-in",
				settings: {
					allowedNetwork: "tcp,udp"
				}
			});

			let chn_list_global = lua_or(api.uci_get_c("@global[0]", "chn_list"), "direct");
			remote_dns_outbound = {
				tag: "dns-out",
				protocol: "dns",
				streamSettings: truthy(dns_outbound_tag) ? {
					sockopt: {
						dialerProxy: dns_outbound_tag != "blackhole" ? dns_outbound_tag : "direct"
					}
				} : null,
				settings: {
					rewriteAddress: chn_list_global != "proxy" ? "8.8.8.8" : "223.5.5.5",
					rewritePort: 53,
					rewriteNetwork: "tcp",
					rules: []
				}
			};

			linsert(routing.rules, 1, {
				inboundTag: ["dns-in"],
				outboundTag: "dns-out"
			});
			dns_rule_position = dns_rule_position + 1;
		}

		if (!truthy(COMMON.default_outbound_tag) || COMMON.default_outbound_tag == "direct") {
			if (truthy(direct_dns_udp_server) || truthy(direct_dns_tcp_server)) {
				linsert(routing.rules, dns_rule_position, {
					inboundTag: ["dns-global-direct"],
					outboundTag: "direct"
				});
				dns_rule_position = dns_rule_position + 1;
			}
		}

		let remote_dns_out_rules = [];
		if (length(dns_domain_rules) > 0) {
			for (let value in dns_domain_rules) {
				if (truthy(value.domain) && truthy(value.outboundTag)) {
					let dns_server = null;
					if (value.outboundTag == "direct" && truthy(_direct_dns.address))
						dns_server = api.clone(_direct_dns);
					else if (value.fakedns)
						dns_server = api.clone(_remote_fakedns);
					else
						dns_server = api.clone(_remote_dns);
					let outboundTag = null;
					if (dns_server) {
						if (!api.is_local_ip(dns_server.address) || value.outboundTag == "blackhole")
							outboundTag = value.outboundTag;
						else
							outboundTag = "direct";
					}
					if (value.outboundTag == "blackhole") {
						push(remote_dns_out_rules, {
							action: "return",
							rCode: 0,
							domain: api.clone(value.domain)
						});
					}
					else {
						push(remote_dns_out_rules, {
							action: "hijack",
							qType: "1,28",
							domain: api.clone(value.domain)
						});
					}
					if (dns_server) {
						dns_server.domains = value.domain;
						if (truthy(value.shunt_rule_name)) {
							dns_server.tag = "dns-in-" + value.shunt_rule_name;
							if (value.shunt_rule_name == "logic-vpslist") {
								dns_server.finalQuery = true;
								dns_server.disableCache = false;
								dns_server.serveStale = true;
								dns_server.serveExpiredTTL = 30;
							}
						}
						push(dns.servers, dns_server);
						linsert(routing.rules, dns_rule_position, {
							inboundTag: [dns_server.tag],
							outboundTag: outboundTag
						});
						dns_rule_position = dns_rule_position + 1;
					}
				}
			}
		}

		let _outboundTag;
		if ((truthy(_remote_dns.address) && !api.is_local_ip(_remote_dns.address)) || dns_outbound_tag == "blackhole")
			_outboundTag = dns_outbound_tag;
		else
			_outboundTag = "direct";
		linsert(routing.rules, dns_rule_position, {
			inboundTag: ["dns-global"],
			outboundTag: _outboundTag
		});
		dns_rule_position = dns_rule_position + 1;

		let default_rule_index = null;
		for (let index, value in routing.rules) {
			if (value != null && value.ruleTag == "default") {
				default_rule_index = index;
				break;
			}
		}
		if (default_rule_index != null) {
			let default_rule = api.clone(routing.rules[default_rule_index]);
			splice(routing.rules, default_rule_index, 1);
			push(routing.rules, default_rule);
		}

		if (length(dns.hosts) == 0)
			dns.hosts = null;

		if (remote_dns_outbound) {
			if (remote_dns_outbound.settings.rules) {
				push(remote_dns_out_rules, {
					action: "hijack",
					qType: "1,28"
				});
				push(remote_dns_out_rules, {
					action: "direct"
				});
				remote_dns_outbound.settings.rules = remote_dns_out_rules;
			}
			push(outbounds, remote_dns_outbound);
		}

		if (length(node_dns) > 0 && length(dns.servers) < 1)
			dns.servers = ["localhost"];
		let idx = truthy(dns_listen_port) ? 2 : 1;
		for (let i = length(node_dns) - 1; i >= 0; i--) {
			let value = node_dns[i];
			linsert(routing.rules, idx, {
				inboundTag: [value.server.tag],
				outboundTag: value.outboundTag
			});
			linsert(dns.servers, 2, value.server);
		}
		if (length(GLOBAL.DNS_HOSTNAME) > 0) {
			let hostname = [];
			for (let line in GLOBAL.DNS_HOSTNAME)
				push(hostname, line);
			let new_dns_server = length(_direct_dns) > 0 ? api.clone(_direct_dns) : { address: "localhost" };
			new_dns_server.tag = "dns-in-bootstrap";
			new_dns_server.domains = hostname;
			linsert(dns.servers, 2, new_dns_server);
			linsert(routing.rules, idx, {
				inboundTag: ["dns-in-bootstrap"],
				outboundTag: "direct"
			});
		}
	}

	if (inbounds || outbounds) {
		let config = {
			env: {
				XRAY_LOCATION_ASSET: lua_or(api.uci_get_c("@global_rules[0]", "v2ray_location_asset"), "/usr/share/v2ray/")
			},
			log: {
				loglevel: get_log_level(loglevel)
			},
			dns: dns,
			fakedns: fakedns,
			inbounds: inbounds,
			outbounds: outbounds,
			observatory: !truthy(burstObservatory) ? observatory : null,
			burstObservatory: burstObservatory,
			routing: routing,
			policy: {
				levels: {
					"0": {
						bufferSize: truthy(xray_settings.buffer_size) ? to_number(xray_settings.buffer_size) : null,
						statsUserUplink: false,
						statsUserDownlink: false
					}
				}
			},
			version: {
				min: xray_min_version
			}
		};

		let direct_outbound = {
			protocol: "freedom",
			tag: "direct",
			settings: {
				finalRules: [{ action: "allow" }]
			},
			streamSettings: {
				sockopt: {
					mark: 255,
					domainStrategy: nonempty(direct_dns_query_strategy) ? direct_dns_query_strategy : "UseIP"
				}
			}
		};
		if (COMMON.default_outbound_tag == "direct")
			unshift(outbounds, direct_outbound);
		else
			push(outbounds, direct_outbound);

		let blackhole_outbound = {
			protocol: "blackhole",
			tag: "blackhole"
		};
		if (COMMON.default_outbound_tag == "blackhole")
			unshift(outbounds, blackhole_outbound);
		else
			push(outbounds, blackhole_outbound);

		for (let value in config.outbounds) {
			let pt = value.protocol;
			if (!truthy(value["_flag_proxy_tag"]) && truthy(value["_id"]) && pt && !truthy(OUTBOUND_EXCLUDE[pt]) && !truthy(NO_RUN))
				api.sys.call(sprintf("echo '%s' >> %s", value["_id"], api.TMP_PATH + "/direct_node_list"));
		}
		drop_private_keys(config.outbounds);
		return api.jsonc.stringify(strip_nulls(config), 1);
	}
	return null;
}

export function gen_proto_config(vars) {
	let local_socks_address = lua_or(vars["local_socks_address"], "0.0.0.0");
	let local_socks_port = vars["local_socks_port"];
	let local_socks_username = vars["local_socks_username"];
	let local_socks_password = vars["local_socks_password"];
	let local_http_address = lua_or(vars["local_http_address"], "0.0.0.0");
	let local_http_port = vars["local_http_port"];
	let local_http_username = vars["local_http_username"];
	let local_http_password = vars["local_http_password"];
	let server_proto = vars["server_proto"];
	let server_address = vars["server_address"];
	let server_port = vars["server_port"];
	let server_username = vars["server_username"];
	let server_password = vars["server_password"];

	let inbounds = [];
	let outbounds = [];
	let routing = null;

	if (truthy(local_socks_address) && truthy(local_socks_port)) {
		let inbound = {
			listen: local_socks_address,
			port: to_number(local_socks_port),
			protocol: "socks",
			settings: {
				udp: true,
				auth: "noauth"
			}
		};
		if (truthy(local_socks_username) && truthy(local_socks_password) && local_socks_username !== "" && local_socks_password !== "") {
			inbound.settings.auth = "password";
			inbound.settings.users = [{
				user: local_socks_username,
				pass: local_socks_password
			}];
		}
		push(inbounds, inbound);
	}

	if (truthy(local_http_address) && truthy(local_http_port)) {
		let inbound = {
			listen: local_http_address,
			port: to_number(local_http_port),
			protocol: "http",
			settings: {
				allowTransparent: false
			}
		};
		if (truthy(local_http_username) && truthy(local_http_password) && local_http_username !== "" && local_http_password !== "") {
			inbound.settings.users = [{
				user: local_http_username,
				pass: local_http_password
			}];
		}
		push(inbounds, inbound);
	}

	if (server_proto != "nil" && server_address != "nil" && server_port != "nil") {
		let outbound = {
			protocol: server_proto,
			streamSettings: {
				method: "raw",
				security: "none"
			},
			settings: {
				servers: [{
					address: server_address,
					port: to_number(server_port),
					users: (truthy(server_username) && truthy(server_password)) ? [{
						user: server_username,
						pass: server_password
					}] : null
				}]
			}
		};
		if (outbound)
			push(outbounds, outbound);
	}

	push(outbounds, {
		protocol: "freedom",
		tag: "direct",
		settings: {
			finalRules: [{ action: "allow" }]
		},
		streamSettings: {
			sockopt: { mark: 255 }
		}
	});

	let config = {
		log: {
			loglevel: "warning"
		},
		inbounds: inbounds,
		outbounds: outbounds,
		routing: routing,
		version: {
			min: xray_min_version
		}
	};
	return api.jsonc.stringify(strip_nulls(config), 1);
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
	return null;
}

// argv[0] = gen_config | gen_proto_config | gen_config_server
// argv[1] = JSON object string. Not invoked on import.
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
}
