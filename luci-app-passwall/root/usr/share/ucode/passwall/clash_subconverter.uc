'use strict';

// Clash subscription converter.
// Replaces lyaml with a YAML subset parser sufficient for Clash `proxies:` documents.

import * as api from 'passwall.api';
import { lua_or as luaOr } from 'passwall.text';
let enc, b64, jsonStringify, host_format, build_alpn, get_first, nonemptyObj, build_common, toNumber, pushParam, finishLink, encode_vless, encode_trojan, omitNulls, encode_vmess, encode_ss, encode_hysteria, encode_hysteria2, encode_tuic, encode_anytls, encode_ssr, encode_snell, encode_node, chAt, stripInlineComment, parsePlain, utf8chr, parseQuotedText, flowDepth, parseFlow, unquoteKey, splitKey, parseYaml, parseClashNode, format_size, parse_clash_sub_info;

let domain_redir = {};

enc = function(v) {
	if (v === null || v === false)
		return api.UrlEncode("");
	if (type(v) != "string")
		v = "" + v;
	return api.UrlEncode(v);
};

b64 = function(v) {
	if (v === null || v === false)
		return "";
	if (type(v) != "string")
		v = "" + v;
	let out = api.base64Encode(v);
	return out === null ? "" : out;
};

jsonStringify = function(v) {
	let out = api.jsonc.stringify(v);
	return out === null ? "" : out;
};

host_format = function(host) {
	if (host === null || host === false)
		return "";
	let str = host;
	let m = match("" + host, /\[(.+)\]/);
	if (m)
		str = m[1];
	if (api.datatypes.ip6addr(str))
		return "[" + str + "]";
	return "" + host;
};

build_alpn = function(alpn) {
	if (alpn === null || alpn === false)
		return null;

	let seen = {};
	let order = ["h3", "h2", "http/1.1"];

	if (type(alpn) == "array") {
		for (let v in alpn) {
			if (v !== null && v !== false)
				seen["" + v] = true;
		}
	} else {
		seen["" + alpn] = true;
	}

	let t = [];
	for (let v in order) {
		if (seen[v] === true)
			push(t, v);
	}
	if (length(t) == 0)
		return null;
	return join(",", t);
};

get_first = function(v) {
	if (type(v) == "array")
		return length(v) > 0 ? v[0] : null;
	return v;
};

nonemptyObj = function(o) {
	return type(o) == "object" && length(o) > 0;
};

build_common = function(node) {
	let o = {};

	o.server = host_format(node.server);
	o.port = node.port;
	o.name = node.name;

	o.tls = {};

	if (node["reality-opts"]) {
		o.tls.security = "reality";
		o.tls.pbk = node["reality-opts"]["public-key"];
		o.tls.sid = node["reality-opts"]["short-id"];
	} else if (node.tls) {
		o.tls.security = "tls";
	}

	o.tls.sni = luaOr(node.servername, node.sni);
	o.tls.fp = node["client-fingerprint"];
	o.tls.pcs = node.fingerprint;
	o.tls.insecure = node["skip-cert-verify"] === true;
	o.tls.alpn = build_alpn(node.alpn);

	let ech_opts = node["ech-opts"];
	if (ech_opts && ech_opts.enable === true) {
		if (ech_opts["query-server-name"])
			o.tls.ech = ech_opts["query-server-name"] + "+https://223.5.5.5/dns-query";
		else if (ech_opts.config)
			o.tls.ech = ech_opts.config;
	}

	o.transport = {};
	let net = (node.network === null || node.network === false) ? "tcp" : node.network;
	o.transport.type = net;

	if (net == "ws") {
		let opts = node["ws-opts"];
		if (opts) {
			let path = (opts.path === null || opts.path === false) ? "/" : opts.path;
			let ed = opts["max-early-data"];
			let eh = opts["early-data-header-name"];
			if (ed !== null && ed !== false)
				path = path + "?ed=" + ed;
			if (eh !== null && eh !== false)
				path = path + (index(path, "?") >= 0 ? "&eh=" : "?eh=") + eh;
			o.transport.path = path;
			o.transport.host = opts.headers ? opts.headers.Host : null;
		}
	} else if (net == "grpc") {
		let opts = node["grpc-opts"];
		if (opts)
			o.transport.serviceName = opts["grpc-service-name"];
	} else if (net == "http") {
		let opts = node["http-opts"];
		if (opts) {
			o.transport.host = luaOr(get_first(opts.host), opts.headers ? get_first(opts.headers.Host) : null);
			o.transport.path = get_first(opts.path);
		}
	} else if (net == "h2") {
		let opts = node["h2-opts"];
		if (opts) {
			o.transport.host = get_first(opts.host);
			o.transport.path = opts.path;
		}
	} else if (net == "xhttp") {
		let opts = node["xhttp-opts"];
		if (opts) {
			o.transport.host = opts.host;
			o.transport.path = opts.path;
			o.transport.mode = opts.mode;

			let extra = {};

			if (opts.headers)
				extra.headers = opts.headers;
			if (opts["x-padding-bytes"])
				extra.xPaddingBytes = opts["x-padding-bytes"];
			if (opts["no-grpc-header"] !== null)
				extra.noGRPCHeader = opts["no-grpc-header"];
			if (opts["sc-max-each-post-bytes"])
				extra.scMaxEachPostBytes = opts["sc-max-each-post-bytes"];
			if (opts["sc-min-posts-interval-ms"])
				extra.scMinPostsIntervalMs = opts["sc-min-posts-interval-ms"];

			if (opts["reuse-settings"]) {
				let r = opts["reuse-settings"];
				let xmux = {};
				if (r["max-concurrency"])
					xmux.maxConcurrency = r["max-concurrency"];
				if (r["max-connections"]) {
					let n = toNumber(r["max-connections"]);
					if (n !== null)
						xmux.maxConnections = n;
				}
				if (r["c-max-reuse-times"]) {
					let n = toNumber(r["c-max-reuse-times"]);
					if (n !== null)
						xmux.cMaxReuseTimes = n;
				}
				if (r["h-max-request-times"])
					xmux.hMaxRequestTimes = r["h-max-request-times"];
				if (r["h-max-reusable-secs"])
					xmux.hMaxReusableSecs = r["h-max-reusable-secs"];
				if (r["h-keep-alive-period"]) {
					let n = toNumber(r["h-keep-alive-period"]);
					if (n !== null)
						xmux.hKeepAlivePeriod = n;
				}
				if (nonemptyObj(xmux))
					extra.xmux = xmux;
			}

			if (opts["download-settings"]) {
				let d = opts["download-settings"];
				let ds = {};
				if (d.server)
					ds.address = luaOr(domain_redir[d.server], d.server);
				if (d.port)
					ds.port = d.port;
				ds.network = "xhttp";
				if (d.tls) {
					ds.security = "tls";
					ds.tlsSettings = {};
					if (d.servername)
						ds.tlsSettings.serverName = d.servername;
					if (d["skip-cert-verify"] === true)
						ds.tlsSettings.allowInsecure = true;
					if (d["client-fingerprint"])
						ds.tlsSettings.fingerprint = d["client-fingerprint"];
					if (d.fingerprint)
						ds.tlsSettings.pinnedPeerCertSha256 = d.fingerprint;
					if (d.alpn)
						ds.tlsSettings.alpn = d.alpn;
				}
				let xs = {};
				if (d.path)
					xs.path = d.path;
				if (d.host)
					xs.host = d.host;
				if (nonemptyObj(xs))
					ds.xhttpSettings = xs;
				extra.downloadSettings = ds;
			}

			if (nonemptyObj(extra))
				o.transport.extra = jsonStringify(extra);
		}
	}

	return o;
};

toNumber = function(v) {
	if (type(v) == "int" || type(v) == "double")
		return v == v ? v : null;
	if (type(v) != "string" || v == "")
		return null;
	if (match(v, /^[+-]?[0-9]+$/) === null && match(v, /^[+-]?([0-9]+\.[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$/) === null && match(v, /^[+-]?[0-9]+[eE][+-]?[0-9]+$/) === null)
		return null;
	let n = +v;
	return n == n ? n : null;
};

pushParam = function(p, key, value, encode) {
	if (value === null || value === false)
		return;
	if (encode)
		push(p, key + "=" + enc(value));
	else
		push(p, key + "=" + value);
};

finishLink = function(link, p, name) {
	if (length(p) > 0)
		link = link + "?" + join("&", p);
	return link + "#" + enc(luaOr(name, ""));
};

encode_vless = function(node) {
	let o = build_common(node);
	let link = "vless://" + node.uuid + "@" + o.server + ":" + o.port;
	let p = [];

	if (type(node.flow) == "string" && substr(node.flow, 0, 5) == "xtls-")
		push(p, "flow=" + enc(node.flow));
	if (node.encryption)
		push(p, "encryption=" + enc(node.encryption));

	if (o.tls.security)
		push(p, "security=" + o.tls.security);
	pushParam(p, "pbk", o.tls.pbk, true);
	pushParam(p, "sid", o.tls.sid, true);
	pushParam(p, "sni", o.tls.sni, true);
	pushParam(p, "fp", o.tls.fp, true);
	pushParam(p, "alpn", o.tls.alpn, true);
	pushParam(p, "ech", o.tls.ech, true);
	pushParam(p, "pcs", o.tls.pcs, true);
	push(p, "allowInsecure=" + (o.tls.insecure ? "1" : "0"));

	push(p, "type=" + o.transport.type);
	pushParam(p, "host", o.transport.host, true);
	pushParam(p, "path", o.transport.path, true);
	pushParam(p, "serviceName", o.transport.serviceName, true);
	pushParam(p, "mode", o.transport.mode, true);
	pushParam(p, "extra", o.transport.extra, true);

	return [0, finishLink(link, p, o.name)];
};

encode_trojan = function(node) {
	let o = build_common(node);
	let link = "trojan://" + node.password + "@" + o.server + ":" + o.port;
	let p = [];

	if (o.tls.security)
		push(p, "security=" + o.tls.security);
	pushParam(p, "pbk", o.tls.pbk, true);
	pushParam(p, "sid", o.tls.sid, true);
	pushParam(p, "sni", o.tls.sni, true);
	pushParam(p, "fp", o.tls.fp, true);
	pushParam(p, "alpn", o.tls.alpn, true);
	pushParam(p, "ech", o.tls.ech, true);
	pushParam(p, "pcs", o.tls.pcs, true);
	push(p, "allowInsecure=" + (o.tls.insecure ? "1" : "0"));

	push(p, "type=" + o.transport.type);
	pushParam(p, "host", o.transport.host, true);
	pushParam(p, "path", o.transport.path, true);
	pushParam(p, "serviceName", o.transport.serviceName, true);

	return [0, finishLink(link, p, o.name)];
};

omitNulls = function(obj) {
	let ks = keys(obj);
	if (ks === null)
		return obj;
	for (let k in ks) {
		if (obj[k] === null)
			delete obj[k];
	}
	return obj;
};

encode_vmess = function(node) {
	let o = build_common(node);
	let obj = {
		v: "2",
		ps: o.name,
		add: node.server,
		port: "" + node.port,
		id: node.uuid,
		aid: "" + (node.alterId ?? 0),
		net: o.transport.type,
		security: node.cipher,
		scy: node.cipher,
		type: "none",
		host: luaOr(o.transport.host, ""),
		path: luaOr(o.transport.path, ""),
		tls: o.tls.security == "tls" ? "tls" : "",
		sni: o.tls.sni,
		alpn: o.tls.alpn,
		fp: o.tls.fp,
		ech: o.tls.ech,
		pcs: o.tls.pcs,
		insecure: o.tls.insecure ? "1" : "0",
		tfo: (node.tfo !== null && node.tfo !== false) ? "1" : "0"
	};

	if (o.transport.type == "grpc")
		obj.path = luaOr(o.transport.serviceName, "");

	return [0, "vmess://" + b64(jsonStringify(omitNulls(obj)))];
};

encode_ss = function(node) {
	let ss_method = {
		"none": 1, "aes-128-gcm": 1, "aes-192-gcm": 1, "aes-256-gcm": 1,
		"chacha20-ietf-poly1305": 1, "xchacha20-ietf-poly1305": 1,
		"2022-blake3-aes-128-gcm": 1, "2022-blake3-aes-256-gcm": 1,
		"2022-blake3-chacha20-poly1305": 1,
		"aes-128-ctr": 1, "aes-192-ctr": 1, "aes-256-ctr": 1,
		"aes-128-cfb": 1, "aes-192-cfb": 1, "aes-256-cfb": 1,
		"rc4-md5": 1, "chacha20-ietf": 1, "xchacha20": 1
	};
	let cipher = luaOr(node.cipher, "");
	if (!ss_method[cipher])
		return [1, "订阅转换 → 丢弃 SS 节点：" + luaOr(node.name, "") + "，因 Core 不支持 " + cipher + " 加密方式"];

	let userinfo = node.cipher + ":" + node.password;
	let base = userinfo + "@" + host_format(node.server) + ":" + node.port;
	let link = "ss://" + b64(base);
	let p = [];

	if (node.udp)
		push(p, "udp=1");
	if (node["udp-over-tcp"])
		push(p, "uot=1");

	if (node.plugin) {
		let plugin = node.plugin == "obfs" ? "obfs-local" : node.plugin;
		if (plugin == "shadow-tls") {
			let shadow_tls = b64(jsonStringify(luaOr(node["plugin-opts"], {})));
			push(p, "shadow-tls=" + enc(shadow_tls));
		} else if (plugin == "obfs-local" || plugin == "v2ray-plugin") {
			let opts = [];
			let popts = node["plugin-opts"];
			if (type(popts) != "object" || popts === null)
				popts = {};
			for (let k, v in popts) {
				let key = k;
				let val = v;
				if (plugin == "obfs-local") {
					if (key == "mode")
						key = "obfs";
					if (key == "host")
						key = "obfs-host";
				} else if (plugin == "v2ray-plugin") {
					if (key == "mode" && val == "websocket") {
						val = null;
					} else if (type(val) == "bool") {
						if (val === true)
							push(opts, key);
						val = null;
					}
				}
				if (val !== null) {
					if (type(val) == "bool")
						val = val ? "1" : "0";
					push(opts, key + "=" + val);
				}
			}
			if (length(opts) > 0)
				plugin = plugin + ";" + join(";", opts);
			push(p, "plugin=" + enc(plugin));
		} else {
			return [1, "订阅转换 → 丢弃 SS 节点：" + luaOr(node.name, "") + "，因 Core 不支持 " + plugin + " 插件"];
		}
	}

	return [0, finishLink(link, p, node.name)];
};

// The Lua source defined this encoder twice; the first body is Hysteria v1
// and is what encode_node calls as encode_hysteria.
encode_hysteria = function(node) {
	let link = "hysteria://" + host_format(node.server) + ":" + luaOr(node.port, "");
	let p = [];

	pushParam(p, "auth", node["auth-str"], false);
	pushParam(p, "mport", node["ports"], false);
	pushParam(p, "obfsParam", node.obfs, false);
	pushParam(p, "sni", node.sni, false);
	pushParam(p, "upmbps", node.up, false);
	pushParam(p, "downmbps", node.down, false);
	if (node["skip-cert-verify"])
		push(p, "insecure=1");
	pushParam(p, "pinSHA256", node["fingerprint"], true);
	if (node.alpn)
		push(p, "alpn=" + enc(build_alpn(node.alpn)));

	return [0, finishLink(link, p, node.name)];
};

encode_hysteria2 = function(node) {
	let link = "hysteria2://" + luaOr(node.password, "") + "@" + host_format(node.server) + ":" + luaOr(node.port, "");
	let p = [];

	pushParam(p, "mport", node["ports"], true);
	pushParam(p, "obfs", node.obfs, false);
	pushParam(p, "obfs-password", node["obfs-password"], false);
	pushParam(p, "minPacketSize", node["obfs-min-packet-size"], false);
	pushParam(p, "maxPacketSize", node["obfs-max-packet-size"], false);
	pushParam(p, "upmbps", node.up, false);
	pushParam(p, "downmbps", node.down, false);
	pushParam(p, "sni", node.sni, true);
	if (node["skip-cert-verify"])
		push(p, "insecure=1");
	pushParam(p, "pinSHA256", node["fingerprint"], true);

	return [0, finishLink(link, p, node.name)];
};

encode_tuic = function(node) {
	let link = "tuic://" + node.uuid + ":" + node.password + "@" + host_format(node.server) + ":" + node.port;
	let p = [];

	if (node["congestion-controller"])
		push(p, "congestion_control=" + node["congestion-controller"]);
	if (node.alpn)
		push(p, "alpn=" + enc(build_alpn(node.alpn)));
	pushParam(p, "sni", node.sni, true);
	if (node["disable-sni"])
		push(p, "disable_sni=1");
	if (node["skip-cert-verify"])
		push(p, "allowInsecure=1");
	if (node["udp-relay-mode"])
		push(p, "udp_relay_mode=" + node["udp-relay-mode"]);
	pushParam(p, "pcs", node["fingerprint"], true);

	return [0, finishLink(link, p, node.name)];
};

encode_anytls = function(node) {
	let err_msg = null;
	if (node["shadow-tls-opts"])
		err_msg = "ShadowTLS";
	else if (node["restls-opts"])
		err_msg = "ResTLS";
	else if (node["jls-opts"])
		err_msg = "JLS";
	if (err_msg)
		return [1, "订阅转换 → 丢弃 AnyTLS 节点：" + luaOr(node.name, "") + "，因 Sing-Box 不支持 AnyTLS + " + err_msg];

	let o = build_common(node);
	let link = "anytls://" + luaOr(node.password, "") + "@" + host_format(node.server) + ":" + node.port;
	let p = [];

	if (o.tls.security)
		push(p, "security=" + o.tls.security);
	pushParam(p, "pbk", o.tls.pbk, true);
	pushParam(p, "sid", o.tls.sid, true);
	pushParam(p, "sni", o.tls.sni, true);
	pushParam(p, "alpn", o.tls.alpn, true);
	pushParam(p, "fp", o.tls.fp, true);
	pushParam(p, "ech", o.tls.ech, true);
	pushParam(p, "pcs", o.tls.pcs, true);
	push(p, "insecure=" + (o.tls.insecure ? "1" : "0"));

	return [0, finishLink(link, p, node.name)];
};

encode_ssr = function(node) {
	let link = host_format(node.server) + ":" + node.port + ":" + luaOr(node.protocol, "") + ":" +
		luaOr(node.cipher, "") + ":" + luaOr(node.obfs, "") + ":" + b64(node.password);
	let p = [];

	if (node["obfs-param"])
		push(p, "obfsparam=" + b64(node["obfs-param"]));
	if (node["protocol-param"])
		push(p, "protoparam=" + b64(node["protocol-param"]));
	push(p, "remarks=" + b64(node.name));

	if (length(p) > 0)
		link = link + "?" + join("&", p);
	return [0, "ssr://" + b64(link)];
};

encode_snell = function(node) {
	let err_msg = null;
	let obfs = node["obfs-opts"];
	if (obfs && obfs.mode != "http" && obfs.mode != "none")
		err_msg = obfs.mode;
	if (err_msg)
		return [1, "订阅转换 → 丢弃 Snell 节点：" + luaOr(node.name, "") + "，因 Sing-Box 不支持 Snell + " + err_msg];

	let version = 4;
	if (node.version !== null && node.version !== false) {
		let n = toNumber(node.version);
		version = n === null ? 4 : n;
	}
	version = version == 5 ? 4 : version;
	if (version < 4)
		return [1, "订阅转换 → 丢弃 Snell 节点：" + luaOr(node.name, "") + "，因 Sing-Box 不支持 Snell 版本小于 4"];

	let link = "snell://" + host_format(node.server) + ":" + node.port;
	let p = [];
	if (node.psk)
		push(p, "psk=" + enc(node.psk));
	push(p, "version=" + version);
	if (obfs && obfs.mode == "http") {
		push(p, "obfs=http");
		if (obfs.host)
			push(p, "obfs-host=" + enc(obfs.host));
	}
	push(p, "reuse=" + (node.reuse ? "1" : "0"));

	return [0, finishLink(link, p, node.name)];
};

encode_node = function(node) {
	if (type(node) != "object" || node === null)
		return null;
	if ((node.type === null || node.type === false) || (node.name === null || node.name === false))
		return null;

	let t = node.type;
	node.server = luaOr(domain_redir[node.server], node.server);

	if (t == "vless")
		return encode_vless(node);
	if (t == "trojan")
		return encode_trojan(node);
	if (t == "vmess")
		return encode_vmess(node);
	if (t == "ss")
		return encode_ss(node);
	if (t == "hysteria")
		return encode_hysteria(node);
	if (t == "hysteria2")
		return encode_hysteria2(node);
	if (t == "tuic")
		return encode_tuic(node);
	if (t == "anytls")
		return encode_anytls(node);
	if (t == "ssr")
		return encode_ssr(node);
	if (t == "snell")
		return encode_snell(node);
	api.log("订阅转换 → 丢弃不支持的节点：" + node.name + "，节点类型：" + t);
	return null;
};

// --- YAML subset -----------------------------------------------------------

chAt = function(s, i) {
	return substr(s, i, 1);
};

stripInlineComment = function(s) {
	let q = null;
	let esc = false;
	let out = "";
	for (let i = 0; i < length(s); i++) {
		let c = chAt(s, i);
		if (esc) {
			out = out + c;
			esc = false;
			continue;
		}
		if (q !== null) {
			out = out + c;
			if (c == "\\" && q == "\"")
				esc = true;
			else if (c == q) {
				if (q == "'" && chAt(s, i + 1) == "'") {
					out = out + "'";
					i++;
				} else {
					q = null;
				}
			}
			continue;
		}
		if (c == "'" || c == "\"") {
			q = c;
			out = out + c;
			continue;
		}
		if (c == "#" && (i == 0 || chAt(s, i - 1) == " " || chAt(s, i - 1) == "\t"))
			break;
		out = out + c;
	}
	return trim(out);
};

parsePlain = function(s) {
	if (s === null)
		return null;
	s = trim(s);
	if (s == "" || s == "~" || s == "null" || s == "Null" || s == "NULL")
		return null;
	if (s == "true" || s == "True" || s == "TRUE" || s == "yes" || s == "Yes" || s == "YES" || s == "on" || s == "On" || s == "ON")
		return true;
	if (s == "false" || s == "False" || s == "FALSE" || s == "no" || s == "No" || s == "NO" || s == "off" || s == "Off" || s == "OFF")
		return false;
	if (match(s, /^[+-]?[0-9]+$/))
		return int(s);
	if (match(s, /^[+-]?([0-9]+\.[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$/) || match(s, /^[+-]?[0-9]+[eE][+-]?[0-9]+$/)) {
		let n = +s;
		return n == n ? n : s;
	}
	if (match(s, /^0x[0-9A-Fa-f]+$/)) {
		let n = hex(substr(s, 2));
		return n == n ? n : s;
	}
	return s;
};

utf8chr = function(cp) {
	return chr(cp);
};

parseQuotedText = function(s, allowTail) {
	if (length(s) == 0)
		die("yaml quote");
	let q = chAt(s, 0);
	if (q != "\"" && q != "'")
		die("yaml quote");
	let out = "";
	let i = 1;
	if (q == "'") {
		while (i < length(s)) {
			let c = chAt(s, i);
			if (c == "'") {
				if (chAt(s, i + 1) == "'") {
					out = out + "'";
					i += 2;
					continue;
				}
				i++;
				break;
			}
			out = out + c;
			i++;
		}
	} else {
		while (i < length(s)) {
			let c = chAt(s, i);
			if (c == "\\") {
				let n = chAt(s, i + 1);
				if (n == "n") out = out + "\n";
				else if (n == "t") out = out + "\t";
				else if (n == "r") out = out + "\r";
				else if (n == "\\") out = out + "\\";
				else if (n == "\"") out = out + "\"";
				else if (n == "/") out = out + "/";
				else if (n == "0") out = out + chr(0);
				else if (n == "b") out = out + chr(8);
				else if (n == "f") out = out + chr(12);
				else if (n == "x") {
					let h = substr(s, i + 2, 2);
					let cp = int(h, 16);
					if (cp != cp)
						die("yaml hex");
					out = out + chr(cp);
					i += 4;
					continue;
				} else if (n == "u") {
					let h = substr(s, i + 2, 4);
					let cp = int(h, 16);
					if (cp != cp)
						die("yaml unicode");
					out = out + utf8chr(cp);
					i += 6;
					continue;
				} else if (n == "\n" || n == "") {
					// escaped line break, drop the break and surrounding space
					i += 2;
					while (i < length(s) && (chAt(s, i) == " " || chAt(s, i) == "\t"))
						i++;
					continue;
				} else {
					out = out + n;
				}
				i += 2;
				continue;
			}
			if (c == "\"") {
				i++;
				break;
			}
			out = out + c;
			i++;
		}
	}
	if (!allowTail) {
		let rest = trim(substr(s, i));
		if (length(rest) > 0 && chAt(rest, 0) != "#")
			die("yaml quote tail");
	}
	return out;
};

flowDepth = function(s) {
	let d = 0;
	let q = null;
	let esc = false;
	for (let i = 0; i < length(s); i++) {
		let c = chAt(s, i);
		if (esc) {
			esc = false;
			continue;
		}
		if (q !== null) {
			if (c == "\\" && q == "\"")
				esc = true;
			else if (c == q) {
				if (q == "'" && chAt(s, i + 1) == "'")
					i++;
				else
					q = null;
			}
			continue;
		}
		if (c == "'" || c == "\"") {
			q = c;
			continue;
		}
		if (c == "{" || c == "[")
			d++;
		else if (c == "}" || c == "]")
			d--;
	}
	return d;
};

parseFlow = function(s) {
	let p = 0;

	let parseFlowVal, parseFlowSeq, parseFlowMap;

	function skipWs() {
		while (p < length(s)) {
			let c = chAt(s, p);
			if (c != " " && c != "\t" && c != "\n" && c != "\r")
				break;
			p++;
		}
	}

	parseFlowVal = function() {
		skipWs();
		let c = chAt(s, p);
		if (c == "[")
			return parseFlowSeq();
		if (c == "{")
			return parseFlowMap();
		if (c == "\"" || c == "'") {
			let rest = substr(s, p);
			let val = parseQuotedText(rest, true);
			// advance p by the consumed quoted span
			let q = c;
			p++;
			if (q == "'") {
				while (p < length(s)) {
					if (chAt(s, p) == "'") {
						if (chAt(s, p + 1) == "'") {
							p += 2;
							continue;
						}
						p++;
						break;
					}
					p++;
				}
			} else {
				while (p < length(s)) {
					if (chAt(s, p) == "\\") {
						p += 2;
						continue;
					}
					if (chAt(s, p) == "\"") {
						p++;
						break;
					}
					p++;
				}
			}
			return val;
		}
		let start = p;
		while (p < length(s)) {
			let ch = chAt(s, p);
			if (ch == "," || ch == "]" || ch == "}" || ch == "\n" || ch == "\r")
				break;
			if (ch == "#" && (p == start || chAt(s, p - 1) == " " || chAt(s, p - 1) == "\t"))
				break;
			p++;
		}
		return parsePlain(substr(s, start, p - start));
	};

	parseFlowSeq = function() {
		p++;
		let arr = [];
		skipWs();
		if (chAt(s, p) == "]") {
			p++;
			return arr;
		}
		while (p < length(s)) {
			push(arr, parseFlowVal());
			skipWs();
			if (chAt(s, p) == ",") {
				p++;
				skipWs();
				if (chAt(s, p) == "]") {
					p++;
					break;
				}
				continue;
			}
			if (chAt(s, p) == "]") {
				p++;
				break;
			}
			die("yaml flow seq");
		}
		return arr;
	};

	parseFlowMap = function() {
		p++;
		let obj = {};
		skipWs();
		if (chAt(s, p) == "}") {
			p++;
			return obj;
		}
		while (p < length(s)) {
			skipWs();
			let key;
			let c = chAt(s, p);
			if (c == "\"" || c == "'") {
				key = parseQuotedText(substr(s, p), true);
				p++;
				if (c == "'") {
					while (p < length(s)) {
						if (chAt(s, p) == "'") {
							if (chAt(s, p + 1) == "'") {
								p += 2;
								continue;
							}
							p++;
							break;
						}
						p++;
					}
				} else {
					while (p < length(s)) {
						if (chAt(s, p) == "\\") {
							p += 2;
							continue;
						}
						if (chAt(s, p) == "\"") {
							p++;
							break;
						}
						p++;
					}
				}
			} else {
				let start = p;
				while (p < length(s) && chAt(s, p) != ":" && chAt(s, p) != "}" && chAt(s, p) != "," && chAt(s, p) != "\n")
					p++;
				key = trim(substr(s, start, p - start));
			}
			skipWs();
			if (chAt(s, p) == ":")
				p++;
			else
				die("yaml flow map");
			let val = parseFlowVal();
			obj[key] = val;
			skipWs();
			if (chAt(s, p) == ",") {
				p++;
				skipWs();
				if (chAt(s, p) == "}") {
					p++;
					break;
				}
				continue;
			}
			if (chAt(s, p) == "}") {
				p++;
				break;
			}
			die("yaml flow map");
		}
		return obj;
	};

	return parseFlowVal();
};

unquoteKey = function(key) {
	key = trim(key);
	if (length(key) >= 2 && (chAt(key, 0) == "\"" || chAt(key, 0) == "'"))
		return parseQuotedText(key, false);
	return key;
};

splitKey = function(text) {
	let q = null;
	let esc = false;
	for (let k = 0; k < length(text); k++) {
		let c = chAt(text, k);
		if (esc) {
			esc = false;
			continue;
		}
		if (q !== null) {
			if (c == "\\" && q == "\"")
				esc = true;
			else if (c == q) {
				if (q == "'" && chAt(text, k + 1) == "'")
					k++;
				else
					q = null;
			}
			continue;
		}
		if (c == "'" || c == "\"") {
			q = c;
			continue;
		}
		if (c == "#")
			break;
		if (c == ":") {
			let next = chAt(text, k + 1);
			if (next == "" || next == " " || next == "\t") {
				let key = unquoteKey(substr(text, 0, k));
				let rest = trim(substr(text, k + 1));
				if (key == "")
					return null;
				return [key, rest];
			}
		}
	}
	return null;
};

parseYaml = function(src) {
	if (type(src) != "string")
		die("yaml type");
	if (substr(src, 0, 3) == "\xEF\xBB\xBF")
		src = substr(src, 3);
	src = replace(src, /\r\n/g, "\n");
	src = replace(src, /\r/g, "\n");
	let lines = split(src, "\n");
	let n = length(lines);
	let i = 0;
	let anchors = {};

	let parseBlock, parseMap, parseSeq, parseRest, parseBlockScalar, collectFlow, literalParts, foldParts;

	function indentOf(line) {
		let k = 0;
		while (k < length(line) && chAt(line, k) == " ")
			k++;
		return k;
	}

	function blankOrComment(line) {
		let t = trim(line);
		return t == "" || chAt(t, 0) == "#";
	}

	function peek() {
		let j = i;
		while (j < n) {
			let line = lines[j];
			if (blankOrComment(line)) {
				j++;
				continue;
			}
			let ind = indentOf(line);
			let text = trim(substr(line, ind));
			if (text == "---" || text == "..." || chAt(text, 0) == "%") {
				j++;
				continue;
			}
			return { index: j, indent: ind, text: text };
		}
		return null;
	}

	function takeAnchor(rest) {
		let m = match(rest, /^&([A-Za-z0-9_-]+)[ \t]+([\s\S]*)$/);
		if (m)
			return [m[1], m[2]];
		m = match(rest, /^&([A-Za-z0-9_-]+)$/);
		if (m)
			return [m[1], ""];
		return [null, rest];
	}

	function stripTag(rest) {
		let m = match(rest, /^![^ \t]+[ \t]+([\s\S]*)$/);
		if (m)
			return m[1];
		m = match(rest, /^![^ \t]+$/);
		if (m)
			return "";
		return rest;
	}

	function remember(anchor, val) {
		if (anchor !== null)
			anchors[anchor] = val;
		return val;
	}

	collectFlow = function(first) {
		let chunk = first;
		while (flowDepth(chunk) > 0) {
			if (i >= n)
				die("yaml flow eof");
			chunk = chunk + "\n" + lines[i];
			i++;
		}
		return chunk;
	};

	parseBlockScalar = function(header, parentIndent) {
		let spec = trim(header);
		let style = chAt(spec, 0);
		spec = stripInlineComment(substr(spec, 1));
		let chomp = "clip";
		if (index(spec, "-") >= 0)
			chomp = "strip";
		if (index(spec, "+") >= 0)
			chomp = "keep";
		let forced = null;
		let nm = match(spec, /([0-9]+)/);
		if (nm)
			forced = int(nm[1]);

		let start = i;
		let end = i;
		let minInd = null;
		while (end < n) {
			let line = lines[end];
			if (blankOrComment(line) && trim(line) == "") {
				end++;
				continue;
			}
			// A comment-only line inside a block scalar is content, not a skip,
			// once the block has started. Blank lines were handled above.
			if (trim(line) != "" && chAt(trim(line), 0) == "#" && minInd === null) {
				break;
			}
			let ind = indentOf(line);
			if (trim(line) != "" && ind <= parentIndent)
				break;
			if (trim(line) != "") {
				if (minInd === null || ind < minInd)
					minInd = ind;
			}
			end++;
		}
		i = end;
		if (minInd === null)
			return chomp == "keep" ? "\n" : "";
		let useInd = forced === null ? minInd : parentIndent + forced;
		let parts = [];
		for (let li = start; li < end; li++) {
			let line = lines[li];
			if (trim(line) == "")
				push(parts, "");
			else if (length(line) >= useInd)
				push(parts, substr(line, useInd));
			else
				push(parts, trim(line));
		}
		if (style == ">")
			return foldParts(parts, chomp);
		return literalParts(parts, chomp);
	};

	literalParts = function(parts, chomp) {
		let s = join("\n", parts);
		if (chomp == "strip")
			return replace(s, /\n+$/, "");
		if (chomp == "keep") {
			if (substr(s, -1) != "\n")
				s = s + "\n";
			return s;
		}
		s = replace(s, /\n+$/, "");
		return s == "" ? "" : s + "\n";
	};

	foldParts = function(parts, chomp) {
		let out = "";
		let buf = [];
		function flushBuf() {
			if (length(buf) == 0)
				return;
			if (out != "" && substr(out, -1) != "\n")
				out = out + "\n";
			out = out + join(" ", buf);
			buf = [];
		}
		for (let line in parts) {
			if (line == "") {
				flushBuf();
				if (out == "" || substr(out, -1) != "\n")
					out = out + "\n";
				else
					out = out + "\n";
			} else {
				push(buf, line);
			}
		}
		flushBuf();
		if (chomp == "strip")
			return replace(out, /\n+$/, "");
		if (chomp == "keep") {
			if (out == "" || substr(out, -1) != "\n")
				out = out + "\n";
			return out;
		}
		out = replace(out, /\n+$/, "");
		return out == "" ? "" : out + "\n";
	};

	parseRest = function(rest, parentIndent) {
		rest = stripTag(rest);
		rest = stripInlineComment(rest);
		let anchorPair = takeAnchor(rest);
		let anchor = anchorPair[0];
		rest = anchorPair[1];
		if (rest == "" || rest === null) {
			let nx = peek();
			// `key:\n- item` is valid YAML: the sequence may sit at the key's column.
			if (nx !== null && nx.indent >= parentIndent && chAt(nx.text, 0) == "-" && (length(nx.text) == 1 || chAt(nx.text, 1) == " "))
				return remember(anchor, parseSeq(nx.indent));
			if (nx !== null && nx.indent > parentIndent)
				return remember(anchor, parseBlock(nx.indent));
			return remember(anchor, null);
		}
		let head = chAt(rest, 0);
		if (head == "|" || head == ">")
			return remember(anchor, parseBlockScalar(rest, parentIndent));
		if (head == "[" || head == "{") {
			let chunk = collectFlow(rest);
			return remember(anchor, parseFlow(chunk));
		}
		if (head == "*") {
			let name = trim(substr(rest, 1));
			let sp = index(name, " ");
			if (sp >= 0)
				name = substr(name, 0, sp);
			return remember(anchor, anchors[name] ?? null);
		}
		if (head == "\"" || head == "'")
			return remember(anchor, parseQuotedText(stripInlineComment(rest) == rest ? rest : rest, false));
		return remember(anchor, parsePlain(stripInlineComment(rest)));
	};

	parseMap = function(indent) {
		let obj = {};
		while (true) {
			let p = peek();
			if (p === null || p.indent != indent)
				break;
			if (chAt(p.text, 0) == "-" && (length(p.text) == 1 || chAt(p.text, 1) == " "))
				break;
			let kr = splitKey(p.text);
			if (kr === null)
				break;
			i = p.index + 1;
			obj[kr[0]] = parseRest(kr[1], indent);
		}
		return obj;
	};

	parseSeq = function(indent) {
		let arr = [];
		while (true) {
			let p = peek();
			if (p === null || p.indent != indent)
				break;
			if (!(chAt(p.text, 0) == "-" && (length(p.text) == 1 || chAt(p.text, 1) == " ")))
				break;
			i = p.index + 1;
			let rest = length(p.text) == 1 ? "" : trim(substr(p.text, 1));
			// "- item" — substr from 1 keeps a leading space that trim removes.
			if (chAt(p.text, 1) == " ")
				rest = trim(substr(p.text, 2));
			rest = stripTag(rest);
			let anchorPair = takeAnchor(rest);
			let anchor = anchorPair[0];
			rest = anchorPair[1];
			let structural = false;
			let head = length(rest) > 0 ? chAt(rest, 0) : "";
			if (head != "{" && head != "[" && head != "\"" && head != "'" && head != "|" && head != ">" && head != "*") {
				let kr = splitKey(rest);
				if (kr !== null) {
					structural = true;
					let obj = {};
					obj[kr[0]] = parseRest(kr[1], indent);
					let more = parseMap(indent + 2);
					for (let k, v in more)
						obj[k] = v;
					push(arr, remember(anchor, obj));
				}
			}
			if (!structural)
				push(arr, remember(anchor, parseRest(rest, indent)));
		}
		return arr;
	};

	parseBlock = function(minIndent) {
		let p = peek();
		if (p === null || p.indent < minIndent)
			return null;
		if (chAt(p.text, 0) == "-" && (length(p.text) == 1 || chAt(p.text, 1) == " "))
			return parseSeq(p.indent);
		if (chAt(p.text, 0) != "{" && chAt(p.text, 0) != "[" && splitKey(p.text) !== null)
			return parseMap(p.indent);
		i = p.index + 1;
		return parseRest(p.text, p.indent);
	};

	let doc = parseBlock(0);
	return doc;
};

parseClashNode = function(raw, remark) {
	if (raw === null || raw === false)
		return "";

	let data = null;
	try {
		data = parseYaml(raw);
	} catch (e) {
		return raw;
	}
	if (type(data) != "object" || data === null)
		return raw;
	if (data.proxies === null || data.proxies === false)
		return "";
	if (type(data.proxies) != "array")
		return "";

	api.log("检测到 Clash 订阅，正在进行转换 ...");

	let hosts = data.hosts;
	if (type(hosts) == "object" && hosts !== null) {
		for (let k, v in hosts) {
			if (type(k) == "string" && type(v) == "string") {
				if (api.datatypes.hostname(k) && api.datatypes.hostname(v))
					domain_redir[k] = v;
			}
		}
	}

	let links = [];
	for (let node in data.proxies) {
		let res = encode_node(node);
		if (res === null)
			continue;
		if (res[0] == 1 && res[1])
			api.log(res[1]);
		else if (res[1])
			push(links, res[1]);
	}

	return length(links) > 0 ? join("\n", links) : "";
};

format_size = function(bytes) {
	let units = ["B", "KB", "MB", "GB", "TB", "PB"];
	let i = 0;
	bytes = +bytes;
	while (bytes >= 1024 && i < length(units) - 1) {
		bytes = bytes / 1024.0;
		i++;
	}
	if (bytes >= 100)
		return sprintf("%.0f%s", bytes, units[i]);
	if (bytes >= 10)
		return sprintf("%.1f%s", bytes, units[i]);
	return sprintf("%.2f%s", bytes, units[i]);
};

parse_clash_sub_info = function(headers) {
	if (type(headers) != "string")
		return null;
	let m = match(headers, /[Ss]ubscription-userinfo:[ \t]*([^\r\n]+)/);
	if (m === null)
		return null;
	let userinfo = m[1];

	function takeInt(re) {
		let mm = match(userinfo, re);
		if (mm === null)
			return null;
		let n = int(mm[1]);
		return n == n ? n : null;
	}

	let upload = takeInt(/upload=([0-9]+)/);
	let download = takeInt(/download=([0-9]+)/);
	let total = takeInt(/total=([0-9]+)/);
	let expire = takeInt(/expire=([0-9]+)/);
	if (upload === null)
		upload = 0;
	if (download === null)
		download = 0;
	if (total === null)
		total = 0;
	let remain = total - (upload + download);
	if (remain < 0)
		remain = 0;

	let expired_date;
	if (expire !== null && expire > 0) {
		let t = localtime(expire);
		expired_date = sprintf("%d-%d-%d", t.year, t.mon, t.mday);
	} else {
		expired_date = "长期有效";
	}

	return {
		rem_traffic: format_size(remain),
		expired_date: expired_date
	};
};
export { parseClashNode, parse_clash_sub_info };
