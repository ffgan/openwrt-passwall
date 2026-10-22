'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require network';
'require view.passwall.tools as pw';
'require view.passwall.types.socks as socksType';
'require view.passwall.types.singbox as singboxType';
'require view.passwall.types.xray as xrayType';
'require view.passwall.types.ssrust as ssrustType';
'require view.passwall.types.ssr as ssrType';
'require view.passwall.types.hysteria2 as hysteria2Type';
'require view.passwall.types.naive as naiveType';

var HY2_KEEP = {
	hop: 1, hop_interval: 1, realms: 1, realm_url: 1, realm_stun: 1, realm_upnp: 1,
	auth_password: 1, obfs_type: 1, obfs_password: 1, obfs_MinPacketSize: 1, obfs_MaxPacketSize: 1,
	up_mbps: 1, down_mbps: 1, stream_recv_win: 1, conn_recv_win: 1, idle_timeout: 1,
	keep_alive_period: 1, disable_mtu_discovery: 1, lazy_start: 1
};

function resolveName(raw) {
	var name = String(raw || '');
	var prefixed = name.match(/^(?:ssrust_|ssr_|xray_|singbox_|naive_|socks_)(.*)$/);
	if (prefixed)
		name = prefixed[1];
	var hy = name.match(/^hysteria2_(.*)$/);
	if (hy && !HY2_KEEP[hy[1]])
		return hy[1];
	return name;
}

function padright(str, cnt, pad) {
	return str + Array(cnt + 1).join(pad);
}

function b64EncodeUnicode(str) {
	return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function(match, p1) {
		return String.fromCharCode('0x' + p1);
	}));
}

function b64encutf8safe(str) {
	return b64EncodeUnicode(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64DecodeUnicode(str) {
	try {
		return decodeURIComponent(Array.prototype.map.call(atob(str), function(c) {
			return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
		}).join(''));
	}
	catch (e) {}
	return str;
}

function b64decutf8safe(str) {
	var orig = str;
	str = String(str).replace(/-/g, '+').replace(/_/g, '/');
	var l = (4 - str.length % 4) % 4;
	if (l)
		str = padright(str, l, '=');
	var text = b64DecodeUnicode(str);
	if (text !== str)
		return text;
	return orig;
}

function b64encsafe(str) {
	return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64decsafe(str) {
	var orig = str;
	try {
		str = String(str).replace(/-/g, '+').replace(/_/g, '/');
		var pad = (4 - str.length % 4) % 4;
		if (pad)
			str += '='.repeat(pad);
		return atob(str);
	}
	catch (e) {
		return orig;
	}
}

function dictvalue(d, key) {
	var v = d[key];
	if (typeof v === 'undefined' || v === '')
		return '';
	return b64decsafe(v);
}

function isJson(str) {
	try {
		var result = JSON.parse(str);
		return typeof result === 'object' && result !== null;
	}
	catch (e) {
		return false;
	}
}

function unbracketIP(server) {
	if (!server)
		return '';
	return String(server).replace(/^\[/, '').replace(/\]$/, '');
}

function dec(s) {
	try { return decodeURIComponent(s == null ? '' : s); }
	catch (e) { return s || ''; }
}

function parseNodeUrl(url) {
	var protoEnd = url.indexOf('://');
	var str = 'http' + url.substring(protoEnd);
	var parsedUrl = new URL(str);
	return {
		hash: parsedUrl.hash,
		host: parsedUrl.host,
		hostname: parsedUrl.hostname,
		port: parsedUrl.port,
		search: parsedUrl.search,
		passwd: parsedUrl.username || parsedUrl.password
	};
}

function queryObject(search) {
	var queryParam = {};
	if (!search || search.length <= 1)
		return queryParam;
	var query = search.replace('/?', '?').split('?');
	var queryParams = query[1] || '';
	queryParams.split('&').forEach(function(part) {
		var params = part.split('=');
		queryParam[dec(params[0])] = dec(params[1] || '');
	});
	return queryParam;
}

function insecureOn(q) {
	return !((q.allowinsecure ?? '0') === '0' && (q.allowInsecure ?? '0') === '0' && (q.insecure ?? '0') === '0');
}

function corePref(field, candidates) {
	var sub = (uci.sections('passwall', 'global_subscribe') || [])[0] || {};
	var v = sub[field] || '';
	var i;
	if (v) {
		for (i = 0; i < candidates.length; i++)
			if (candidates[i][1] === v && candidates[i][0])
				return v;
	}
	for (i = 0; i < candidates.length; i++)
		if (candidates[i][0])
			return candidates[i][1];
	return '';
}

function mapTransport(typeName, queryParam, values) {
	var prefixType = typeName === 'sing-box' ? 'singbox_' : 'xray_';
	queryParam.type = (queryParam.type || 'tcp').toLowerCase();
	if (queryParam.type === 'kcp')
		queryParam.type = 'mkcp';
	if (queryParam.type === 'h2')
		queryParam.type = 'http';
	if (prefixType === 'singbox_' && queryParam.type === 'raw')
		queryParam.type = 'tcp';
	else if (prefixType === 'xray_' && queryParam.type === 'tcp')
		queryParam.type = 'raw';
	if (prefixType === 'xray_' && queryParam.type === 'http')
		values.transport = 'xhttp';
	else
		values.transport = queryParam.type;
	if (queryParam.type === 'raw' || queryParam.type === 'tcp') {
		values.tcp_guise = queryParam.headerType || 'none';
		if (queryParam.headerType && queryParam.headerType !== 'none') {
			values.tcp_guise_http_host = queryParam.host || '';
			values.tcp_guise_http_path = queryParam.path || '';
		}
	}
	else if (queryParam.type === 'ws') {
		values.ws_host = queryParam.host || '';
		values.ws_path = queryParam.path || '';
	}
	else if (queryParam.type === 'http') {
		if (prefixType === 'xray_') {
			values.xhttp_mode = 'stream-one';
			values.xhttp_host = queryParam.host || '';
			values.xhttp_path = queryParam.path || '';
		}
		else {
			values.http_host = queryParam.host || '';
			values.http_path = queryParam.path || '';
		}
	}
	else if (queryParam.type === 'quic') {
		values.quic_guise = queryParam.headerType || 'none';
		values.quic_security = queryParam.quicSecurity;
		values.quic_key = queryParam.key;
	}
	else if (queryParam.type === 'mkcp') {
		values.mkcp_guise = queryParam.headerType || 'none';
		values.mkcp_seed = queryParam.seed || '';
	}
	else if (queryParam.type === 'grpc') {
		values.grpc_serviceName = (queryParam.serviceName || queryParam.path) || '';
		values.grpc_mode = queryParam.mode || 'gun';
	}
	else if (queryParam.type === 'xhttp') {
		values.xhttp_host = queryParam.host || '';
		values.xhttp_path = queryParam.path || '';
		values.xhttp_mode = queryParam.mode || 'auto';
		values.use_xhttp_extra = !!queryParam.extra;
		values.xhttp_extra = queryParam.extra || '';
	}
	else if (queryParam.type === 'httpupgrade') {
		values.httpupgrade_host = queryParam.host || '';
		values.httpupgrade_path = queryParam.path || '';
	}
}

function applySecurity(values, queryParam) {
	if (!queryParam.security)
		return;
	if (queryParam.security === 'tls') {
		values.tls = true;
		values.reality = false;
		values.alpn = queryParam.alpn || 'default';
		values.tls_serverName = queryParam.sni || queryParam.peer || '';
		values.tls_allowInsecure = insecureOn(queryParam);
		if (queryParam.fp && String(queryParam.fp).trim() !== '') {
			values.utls = true;
			values.fingerprint = queryParam.fp;
		}
		values.ech = !!queryParam.ech;
		values.ech_config = queryParam.ech || '';
		values.tls_pinSHA256 = queryParam.pcs || '';
		values.tls_CertByName = queryParam.vcn || '';
		if (queryParam.flow)
			values.flow = queryParam.flow;
	}
	if (queryParam.security === 'reality') {
		values.tls = true;
		values.reality = true;
		values.alpn = queryParam.alpn || 'default';
		values.tls_serverName = queryParam.sni || queryParam.peer || '';
		if (queryParam.fp && String(queryParam.fp).trim() !== '') {
			values.utls = true;
			values.fingerprint = queryParam.fp;
		}
		values.reality_publicKey = queryParam.pbk || '';
		values.reality_shortId = queryParam.sid || '';
		values.reality_spiderX = queryParam.spx || '';
		values.use_mldsa65Verify = !!queryParam.pqv;
		values.reality_mldsa65Verify = queryParam.pqv || '';
		if (queryParam.flow)
			values.flow = queryParam.flow;
	}
}

function parseShadowTLS(base64Str) {
	try {
		var obj = JSON.parse(b64decsafe(base64Str));
		var out = [];
		if (obj.version)
			out.push('v' + obj.version + '=1');
		if (obj.password)
			out.push('passwd=' + obj.password);
		Object.keys(obj).forEach(function(k) {
			if (k !== 'version' && k !== 'password')
				out.push(k + '=' + obj[k]);
		});
		return { text: out.join(';'), obj: obj };
	}
	catch (e) {
		return { text: '', obj: {} };
	}
}

function parseLink(link, caps) {
	link = String(link || '').split(/\r\n|\r|\n/, 1)[0];
	link = link.replace(/&amp;/gi, '&').replace(/\s*#\s*/, '#').trim();
	var parts = link.split('://');
	var linkType = parts[0];
	var values = {};
	var typeName = '';
	var hasXray = !!caps.xray;
	var hasSingbox = !!caps.singbox;
	var hasHysteria2 = !!caps.hysteria;
	var ssType = corePref('ss_type', [ [ !!caps.sslocal, 'shadowsocks-rust' ], [ hasSingbox, 'sing-box' ], [ hasXray, 'xray' ] ]);
	var trojanType = corePref('trojan_type', [ [ hasSingbox, 'sing-box' ], [ hasXray, 'xray' ] ]);
	var vmessType = corePref('vmess_type', [ [ hasXray, 'xray' ], [ hasSingbox, 'sing-box' ] ]);
	var vlessType = corePref('vless_type', [ [ hasXray, 'xray' ], [ hasSingbox, 'sing-box' ] ]);
	var hysteria2Type = corePref('hysteria2_type', [ [ hasHysteria2, 'hysteria2' ], [ hasSingbox, 'sing-box' ], [ hasXray, 'xray' ] ]);

	function chooseCore(preferSing, preferXray) {
		if (preferSing && hasSingbox) {
			typeName = 'sing-box';
			return 'singbox_';
		}
		if (preferXray && hasXray) {
			typeName = 'Xray';
			return 'xray_';
		}
		return '';
	}

	if (linkType === 'ssr') {
		var sstr = b64decsafe((parts[1] || '').replace(/#.*/, '').trim());
		var ploc = sstr.indexOf('/?');
		var url0 = ploc > 0 ? sstr.substr(0, ploc) : sstr;
		var param = ploc > 0 ? sstr.substr(ploc + 2) : '';
		var ssm = url0.match(/^(.+):([^:]+):([^:]*):([^:]+):([^:]*):([^:]+)/);
		if (!ssm || ssm.length < 7)
			return { error: _('Invalid Share URL Format') };
		var pdict = {};
		if (param.length > 2) {
			param.split('&').forEach(function(a) {
				var b = a.split('=');
				pdict[dec(b[0])] = dec(b[1] || '');
			});
		}
		typeName = 'SSR';
		values.address = unbracketIP(ssm[1]);
		values.port = ssm[2];
		values.protocol = ssm[3];
		values.method = ssm[4];
		values.obfs = ssm[5];
		values.password = b64decsafe(ssm[6]);
		values.obfs_param = dictvalue(pdict, 'obfsparam');
		values.protocol_param = dictvalue(pdict, 'protoparam');
		if (pdict.remarks)
			values.remarks = b64decutf8safe(pdict.remarks);
	}
	else if (linkType === 'ss') {
		var body = parts[1] || '';
		var hash = '';
		var hashAt = body.indexOf('#');
		if (hashAt >= 0) {
			hash = body.substr(hashAt + 1);
			body = body.substr(0, hashAt);
		}
		body = body.replace('/?', '?');
		var queryIndex = body.indexOf('?');
		var queryStr = '';
		if (queryIndex >= 0) {
			queryStr = body.substr(queryIndex + 1);
			body = body.substr(0, queryIndex);
		}
		var queryParam = {};
		try {
			new URLSearchParams(queryStr).forEach(function(v, k) { queryParam[k] = v; });
		}
		catch (e) {}
		var server, port, method, password, plugin, pluginOpts;
		var sipIndex = body.indexOf('@');
		if (sipIndex !== -1) {
			var userInfo = b64decsafe(dec(body.substr(0, sipIndex)));
			var serverInfo = body.substr(sipIndex + 1).split(':');
			server = serverInfo[0];
			port = serverInfo[1];
			var userSplit = userInfo.indexOf(':');
			if (userSplit !== -1) {
				method = userInfo.substr(0, userSplit);
				password = userInfo.substr(userSplit + 1);
			}
			else {
				password = body.substr(0, sipIndex);
			}
		}
		else {
			var decoded = b64decsafe(dec(body));
			var m2022 = decoded.match(/^([^:]+):([^:]+):([^@]+)@([^:]+):(\d+)$/);
			var mNormal = decoded.match(/^([^:]+):([^@]+)@([^:]+):(\d+)$/);
			if (m2022) {
				method = m2022[1];
				password = m2022[2] + ':' + m2022[3];
				server = m2022[4];
				port = m2022[5];
			}
			else if (mNormal) {
				method = mNormal[1];
				password = mNormal[2];
				server = mNormal[3];
				port = mNormal[4];
			}
		}
		if (password && /%[0-9A-Fa-f]{2}/.test(password)) {
			try {
				var decodedPwd = decodeURIComponent(password.replace(/\+/g, '%20'));
				if (encodeURIComponent(decodedPwd) === password)
					password = decodedPwd;
			}
			catch (e) {}
		}
		if (queryParam.plugin) {
			var pluginParams = dec(queryParam.plugin).split(';');
			plugin = pluginParams.shift();
			pluginOpts = pluginParams.join(';');
		}
		var needUpgrade = ssType !== 'Xray' && ssType !== 'sing-box' &&
			queryParam.type && queryParam.type !== 'tcp' &&
			queryParam.headerType && queryParam.headerType !== 'none';
		var dom = '';
		if (hasXray && (ssType === 'xray' || needUpgrade || queryParam.type === 'xhttp')) {
			typeName = 'Xray';
			dom = 'xray_';
			values.protocol = 'shadowsocks';
		}
		else if (hasSingbox && (ssType === 'sing-box' || needUpgrade)) {
			typeName = 'sing-box';
			dom = 'singbox_';
			values.protocol = 'shadowsocks';
		}
		else {
			typeName = 'SS-Rust';
			dom = 'ssrust_';
		}
		var mapped = { 'chacha20-poly1305': 'chacha20-ietf-poly1305', 'xchacha20-poly1305': 'xchacha20-ietf-poly1305' };
		var methodNorm = mapped[(method || 'none').toLowerCase()] || (method || 'none').toLowerCase();
		values.address = unbracketIP(server);
		values.port = port;
		values.password = password || '';
		values.method = methodNorm || '';
		values.ss_method = methodNorm || '';
		if (queryParam.tfo != null)
			values.tcp_fast_open = queryParam.tfo;
		if (plugin && plugin !== 'none') {
			plugin = plugin === 'simple-obfs' ? 'obfs-local' : plugin;
			values.plugin_enabled = true;
			values.plugin = plugin || 'none';
			values.plugin_opts = pluginOpts || '';
			if (plugin === 'obfs-local' && dom === 'xray_') {
				var obfs = (pluginOpts || '').match(/obfs=([^;]+)/);
				var obfsHost = (pluginOpts || '').match(/obfs-host=([^;]+)/);
				obfs = obfs ? obfs[1] : '';
				obfsHost = obfsHost ? obfsHost[1] : '';
				if (obfs === 'http') {
					values.transport = 'raw';
					values.tcp_guise = 'http';
					values.tcp_guise_http_host = obfsHost || '';
					values.tcp_guise_http_path = '/';
				}
				else if (obfs === 'tls') {
					values.tls = true;
					values.tls_serverName = obfsHost || '';
					values.tls_allowInsecure = true;
				}
			}
			if (plugin === 'shadow-tls') {
				pluginOpts = (pluginOpts || '').replace(/(^|;)password=/, '$1passwd=').replace(/(^|;)version=([123])(?=;|$)/, '$1v$2=1');
				if (dom === 'ssrust_')
					values.plugin_opts = pluginOpts || '';
				else if (dom === 'singbox_') {
					var opts = {};
					pluginOpts.split(';').forEach(function(item) {
						var kv = item.split('=');
						if (kv[0])
							opts[kv[0]] = kv[1] || '';
					});
					var versionKey = Object.keys(opts).filter(function(key) { return /^v[123]$/.test(key); })[0];
					values.shadowtls = true;
					values.shadowtls_version = versionKey ? versionKey.slice(1) : '1';
					values.shadowtls_password = opts.passwd || '';
					values.shadowtls_serverName = opts.host || '';
					values.plugin_enabled = false;
				}
			}
		}
		else {
			values.plugin = 'none';
		}
		if (hash)
			values.remarks = dec(hash);
		if (Object.keys(queryParam).length > 0 && !queryParam.plugin) {
			applySecurity(values, queryParam);
			mapTransport(typeName, queryParam, values);
			if (queryParam.udp != null)
				values.uot = queryParam.udp;
			values.use_finalmask = !!queryParam.fm;
			values.finalmask = queryParam.fm || '';
			if (queryParam['shadow-tls']) {
				var parsedSt = parseShadowTLS(queryParam['shadow-tls']);
				if (dom === 'ssrust_') {
					values.plugin_enabled = true;
					values.plugin = 'shadow-tls';
					values.plugin_opts = parsedSt.text || '';
				}
				else if (dom === 'singbox_' && parsedSt.obj && Object.keys(parsedSt.obj).length) {
					values.shadowtls = true;
					values.shadowtls_version = parsedSt.obj.version || '1';
					values.shadowtls_password = parsedSt.obj.password || '';
					values.shadowtls_serverName = parsedSt.obj.host || '';
					if (parsedSt.obj.fingerprint) {
						values.shadowtls_utls = true;
						values.shadowtls_fingerprint = parsedSt.obj.fingerprint || 'chrome';
					}
				}
			}
		}
	}
	else if (linkType === 'trojan') {
		var trojanDom = '';
		if (trojanType === 'sing-box' && hasSingbox)
			trojanDom = chooseCore(true, false);
		else if (trojanType === 'xray' && hasXray)
			trojanDom = chooseCore(false, true);
		else
			trojanDom = chooseCore(hasSingbox, hasXray);
		var tm = parseNodeUrl(link);
		if (!tm.passwd)
			return { error: _('Invalid Share URL Format') };
		values.protocol = 'trojan';
		values.address = unbracketIP(tm.hostname);
		values.port = tm.port || '443';
		values.password = dec(tm.passwd);
		var tq = queryObject(tm.search);
		tq.type = tq.type || 'tcp';
		mapTransport(typeName, tq, values);
		tq.security = tq.security || 'tls';
		applySecurity(values, tq);
		if (tq.tfo != null)
			values.tcp_fast_open = tq.tfo;
		values.use_finalmask = !!tq.fm;
		values.finalmask = tq.fm || '';
		if (tm.hash)
			values.remarks = dec(tm.hash.substr(1));
	}
	else if (linkType === 'vmess') {
		var vsstr = b64DecodeUnicode((parts[1] || '').replace(/#.*/, '').trim());
		if (vmessType === 'sing-box' && hasSingbox)
			chooseCore(true, false);
		else if (hasXray)
			chooseCore(false, true);
		else
			chooseCore(true, false);
		values.protocol = 'vmess';
		var info = {};
		if (isJson(vsstr))
			info = JSON.parse(vsstr);
		else if (vsstr.indexOf('?') > 0) {
			vsstr = vsstr.replace('/?', '?');
			var vploc = vsstr.indexOf('?');
			var vurl = new URL('http://' + b64decsafe(vsstr.substr(0, vploc)));
			info.security = vurl.username || 'auto';
			info.id = vurl.password || vurl.username;
			info.add = unbracketIP(vurl.hostname);
			info.port = vurl.port || '443';
			var vparams = {};
			vsstr.substr(vploc + 1).split('&').forEach(function(v) {
				var s = v.indexOf('=');
				if (s > 0)
					vparams[v.substring(0, s)] = dec(v.substring(s + 1));
			});
			info.ps = vparams.remark || vparams.remarks;
			info.net = (vparams.obfs === 'websocket') ? 'ws' : (vparams.obfs || 'tcp');
			info.path = vparams.path;
			info.tls = vparams.tls;
			info.sni = vparams.peer;
			info.tfo = vparams.tfo;
			info.host = vparams.obfsParam;
		}
		else {
			return { error: _('Invalid Share URL Format') };
		}
		values.remarks = info.ps;
		values.address = unbracketIP(info.add);
		values.port = info.port;
		values.uuid = info.id;
		values.security = info.security || info.scy || 'auto';
		values.tls = info.tls === 'tls' || info.tls === '1';
		if (values.tls) {
			values.tls_serverName = info.sni || info.host;
			values.alpn = info.alpn || 'default';
			if (info.fp) {
				values.utls = true;
				values.fingerprint = info.fp;
			}
			values.tls_pinSHA256 = info.pcs || '';
			values.tls_allowInsecure = insecureOn(info);
		}
		info.net = String(info.net || 'tcp').toLowerCase();
		if (info.net === 'kcp' || info.net === 'mkcp')
			info.net = 'mkcp';
		if (typeName === 'sing-box' && info.net === 'raw')
			info.net = 'tcp';
		else if (typeName === 'Xray' && info.net === 'tcp')
			info.net = 'raw';
		if (info.net === 'h2' || info.net === 'http')
			info.net = 'http';
		if (typeName === 'Xray' && info.net === 'http')
			values.transport = 'xhttp';
		else
			values.transport = info.net;
		if (info.net === 'raw' || info.net === 'tcp') {
			values.tcp_guise = (info.host && info.host !== '') ? 'http' : 'none';
			if (info.host) {
				values.tcp_guise_http_host = info.host;
				values.tcp_guise_http_path = info.path || '';
			}
		}
		else if (info.net === 'ws') {
			values.ws_host = info.host;
			values.ws_path = info.path;
		}
		else if (info.net === 'http') {
			if (typeName === 'Xray') {
				values.xhttp_mode = 'stream-one';
				values.xhttp_host = info.host || '';
				values.xhttp_path = info.path || '';
			}
			else {
				values.http_host = info.host || '';
				values.http_path = info.path || '';
			}
		}
		else if (info.net === 'quic') {
			values.quic_security = info.securty;
			values.quic_key = info.key;
		}
		else if (info.net === 'mkcp') {
			values.mkcp_guise = info.type || 'none';
			values.mkcp_seed = info.seed || '';
		}
		else if (info.net === 'grpc') {
			values.grpc_serviceName = info.path;
		}
		if (info.tfo != null)
			values.tcp_fast_open = info.tfo;
		values.use_finalmask = !!info.fm;
		values.finalmask = info.fm || '';
	}
	else if (linkType === 'vless') {
		if (vlessType === 'sing-box' && hasSingbox)
			chooseCore(true, false);
		else if (hasXray)
			chooseCore(false, true);
		var vm = parseNodeUrl(link);
		if (!vm.passwd)
			return { error: _('Invalid Share URL Format') };
		var vq = queryObject(vm.search);
		vq.type = (vq.type || 'tcp').toLowerCase();
		if ([ 'xhttp', 'kcp', 'mkcp' ].indexOf(vq.type) >= 0 && vlessType !== 'xray' && hasXray)
			chooseCore(false, true);
		values.protocol = 'vless';
		values.uuid = vm.passwd;
		values.address = unbracketIP(vm.hostname);
		values.port = vm.port || '443';
		values.encryption = vq.encryption || 'none';
		vq.security = (!vq.security && vq.flow) ? 'tls' : vq.security;
		applySecurity(values, vq);
		mapTransport(typeName, vq, values);
		if (vq.tfo != null)
			values.tcp_fast_open = vq.tfo;
		values.use_finalmask = !!vq.fm;
		values.finalmask = vq.fm || '';
		if (vm.hash)
			values.remarks = dec(vm.hash.substr(1));
	}
	else if (linkType === 'hysteria2' || linkType === 'hy2') {
		var hm = parseNodeUrl(link);
		if (!hm.passwd)
			return { error: _('Invalid Share URL Format') };
		var hq = queryObject(hm.search);
		var useSing = hysteria2Type === 'sing-box' && hasSingbox;
		var useXray = hysteria2Type === 'xray' && hasXray;
		if (useSing || useXray) {
			typeName = useSing ? 'sing-box' : 'Xray';
			values.protocol = 'hysteria2';
			values.hysteria2_auth_password = dec(hm.passwd);
			if (hq['obfs-password'] || hq.obfs_password) {
				values.hysteria2_obfs_type = hq.obfs || 'salamander';
				values.hysteria2_obfs_password = hq['obfs-password'] || hq.obfs_password;
			}
			if (hq.obfs === 'gecko') {
				values.hysteria2_obfs_MinPacketSize = hq.minPacketSize || '512';
				values.hysteria2_obfs_MaxPacketSize = hq.maxPacketSize || '1200';
			}
			values.hysteria2_hop = hq.mport || '';
			values.use_finalmask = !!hq.fm;
			values.finalmask = hq.fm || '';
			if (useSing && (hq.pcs || hq.pinSHA256))
				hq.allowinsecure = '1';
		}
		else if (hasHysteria2) {
			typeName = 'Hysteria2';
			values.protocol = 'udp';
			values.hysteria2_auth_password = dec(hm.passwd);
			if (hq['obfs-password'] || hq.obfs_password) {
				values.hysteria2_obfs_type = hq.obfs || 'salamander';
				values.hysteria2_obfs_password = hq['obfs-password'] || hq.obfs_password;
			}
			if (hq.obfs === 'gecko') {
				values.hysteria2_obfs_MinPacketSize = hq.minPacketSize || '512';
				values.hysteria2_obfs_MaxPacketSize = hq.maxPacketSize || '1200';
			}
			values.hysteria2_hop = hq.mport || '';
			if (hq.pcs || hq.pinSHA256)
				hq.allowinsecure = '0';
		}
		values.address = unbracketIP(hm.hostname);
		values.port = hm.port || '443';
		values.tls_serverName = hq.sni || '';
		values.tls_allowInsecure = (hq.allowinsecure ?? hq.allowInsecure ?? hq.insecure ?? '0') === '1';
		values.tls_pinSHA256 = hq.pcs || hq.pinSHA256 || '';
		values.tls_CertByName = hq.vcn || '';
		values.ech = !!hq.ech;
		values.ech_config = hq.ech || '';
		if (hm.hash)
			values.remarks = dec(hm.hash.substr(1));
	}
	else if (linkType === 'tuic') {
		if (hasSingbox)
			typeName = 'sing-box';
		values.protocol = 'tuic';
		var tu = new URL('http://' + (parts[1] || ''));
		var user = tu.username;
		var pass = tu.password;
		if (!user || !pass) {
			var decodedUser = dec(user || pass || '');
			var colon = decodedUser.indexOf(':');
			if (colon > -1) {
				user = decodedUser.slice(0, colon);
				pass = decodedUser.slice(colon + 1);
			}
		}
		values.uuid = dec(user);
		values.password = dec(pass);
		values.address = unbracketIP(tu.hostname);
		values.port = tu.port || '443';
		var tq2 = {};
		if (tu.search.length > 1) {
			tu.search.replace(/^\?/, '').split('&').forEach(function(part) {
				var kv = part.split('=');
				tq2[dec(kv[0]).toLowerCase()] = dec(kv[1] || '');
			});
		}
		values.tuic_congestion_control = tq2.congestion_control || 'cubic';
		values.tuic_udp_relay_mode = tq2.udp_relay_mode || 'native';
		values.tuic_alpn = tq2.alpn || 'h3';
		values.tls_serverName = tq2.sni || '';
		values.tls_disable_sni = tq2.disable_sni === '1';
		values.tls_allowInsecure = !((tq2.allowinsecure ?? '0') === '0' && (tq2.insecure ?? '0') === '0' && (tq2.allow_insecure ?? '0') === '0');
		values.tls_pinSHA256 = tq2.pcs || tq2.pinsha256 || '';
		if (tu.hash)
			values.remarks = dec(tu.hash.substr(1));
	}
	else if (linkType === 'anytls') {
		if (hasSingbox)
			typeName = 'sing-box';
		values.protocol = 'anytls';
		var am = parseNodeUrl(link);
		if (!am.passwd)
			return { error: _('Invalid Share URL Format') };
		values.password = am.passwd;
		values.address = unbracketIP(am.hostname);
		values.port = am.port || '443';
		var aq = {};
		queryObject(am.search);
		Object.keys(queryObject(am.search)).forEach(function(k) {
			aq[k.toLowerCase()] = queryObject(am.search)[k];
		});
		var aqFull = queryObject(am.search);
		Object.keys(aqFull).forEach(function(k) { aq[k.toLowerCase()] = aqFull[k]; });
		aq.security = aq.security || 'tls';
		values.tls = true;
		values.reality = aq.security === 'reality';
		if (aq.security === 'reality') {
			values.reality_publicKey = aq.pbk || '';
			values.reality_shortId = aq.sid || '';
		}
		values.alpn = aq.alpn || 'default';
		values.tls_serverName = aq.sni || aq.peer || '';
		if (aq.fp && String(aq.fp).trim() !== '') {
			values.utls = true;
			values.fingerprint = aq.fp;
		}
		values.tls_allowInsecure = !((aq.allowinsecure ?? '0') === '0' && (aq.insecure ?? '0') === '0');
		values.tls_pinSHA256 = aq.pcs || aq.pinsha256 || '';
		if (am.hash)
			values.remarks = dec(am.hash.substr(1));
	}
	else if (linkType === 'naive+https' || linkType === 'naive+quic') {
		if (hasSingbox)
			typeName = 'sing-box';
		values.protocol = 'naive';
		var nu = new URL('http://' + (parts[1] || ''));
		var nuser = nu.username;
		var npass = nu.password;
		if (!nuser || !npass) {
			var nd = dec(nuser || npass || '');
			var ni = nd.indexOf(':');
			if (ni > -1) {
				nuser = nd.slice(0, ni);
				npass = nd.slice(ni + 1);
			}
		}
		values.username = dec(nuser);
		values.password = dec(npass);
		values.address = unbracketIP(nu.hostname);
		values.port = nu.port || '443';
		var nq = queryObject(nu.search);
		values.naive_insecure_concurrency = nq['insecure-concurrency'] || '0';
		values.uot = (nq.uot ?? '0') === '1';
		values.tls_serverName = nq.sni || '';
		values.ech = !!nq.ech;
		values.ech_config = nq.ech || '';
		if (linkType === 'naive+quic') {
			values.naive_quic = true;
			values.naive_congestion_control = nq.congestion_control || 'bbr';
		}
		if (nu.hash)
			values.remarks = dec(nu.hash.substr(1));
	}
	else if (linkType === 'snell') {
		if (hasSingbox)
			typeName = 'sing-box';
		values.protocol = 'snell';
		var sm = parseNodeUrl(link);
		values.address = unbracketIP(sm.hostname);
		values.port = sm.port || '443';
		var sqFull = queryObject(sm.search);
		var sq = {};
		Object.keys(sqFull).forEach(function(k) { sq[k.toLowerCase()] = sqFull[k]; });
		values.password = sq.userkey || '';
		values.snell_psk = sq.psk || sm.passwd || '';
		values.snell_version = sq.version || '4';
		values.snell_reuse = sq.reuse === '1';
		values.snell_obfs_mode = sq.obfs || 'none';
		values.snell_obfs_host = sq['obfs-host'] || sq.obfs_host || '';
		values.snell_mode = sq.mode || 'default';
		if (sm.hash)
			values.remarks = dec(sm.hash.substr(1));
	}
	else {
		return { error: _('Invalid Share URL Format') };
	}

	if (!typeName)
		return { error: _('Invalid Share URL Format') };
	return { type: typeName, values: values };
}

function ipv6Bracket(host) {
	var ipv6 = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
	if (host && ipv6.test(host))
		return '[' + host + ']';
	return host || '';
}

function deviceList(devs) {
	var out = [];
	var seen = {};
	(devs || []).forEach(function(dev) {
		if (!dev || typeof dev.getName !== 'function')
			return;
		var name = dev.getName();
		if (!name || name === 'lo' || /^(veth|ifb|gre|sit|ip6tnl|erspan)/.test(name) || seen[name])
			return;
		seen[name] = true;
		var kind = '';
		try { kind = dev.getType() || ''; }
		catch (e) {}
		out.push({ name: name, label: (kind ? kind + ': ' : '') + '"' + name + '"' });
	});
	return out;
}

function writeGroup(section_id, value, groups) {
	value = String(value == null ? '' : value).trim();
	var lower = value.toLowerCase();
	if (lower === '' || lower === 'default')
		return uci.unset('passwall', section_id, 'group');
	for (var i = 0; i < groups.length; i++) {
		if (String(groups[i]).toLowerCase() === lower)
			return uci.set('passwall', section_id, 'group', groups[i]);
	}
	return uci.set('passwall', section_id, 'group', value);
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('passwall'),
			pw.loadCaps(),
			network.getDevices().catch(function() { return []; })
		]);
	},

	render: function(data) {
		var caps = Object.assign({}, data[1] || {});
		var id = pw.routeArg();
		var nodes = uci.sections('passwall', 'nodes') || [];
		var node = null;
		var groups = [];
		var seen = {};
		for (var i = 0; i < nodes.length; i++) {
			if (nodes[i]['.name'] === id)
				node = nodes[i];
			else if (nodes[i].group && !seen[nodes[i].group]) {
				seen[nodes[i].group] = true;
				groups.push(nodes[i].group);
			}
		}
		if (!id || !node) {
			window.location.href = pw.pageUrl('node_list');
			return E('div');
		}

		caps.devices = deviceList(data[2]);
		var applying = false;
		var m = new form.Map('passwall');
		var s = m.section(form.NamedSection, id, 'nodes', _('Node Config'));
		s.addremove = false;

		function lookup(name) {
			var names = [ resolveName(name) ];
			if (names[0] === 'method')
				names.push('ss_method');
			else if (names[0] === 'ss_method')
				names.push('method');
			for (var n = 0; n < names.length; n++) {
				var found = m.lookupOption(names[n], id);
				if (found && found[0])
					return found[0];
			}
			return null;
		}

		function readWidget(name) {
			var opt = lookup(name);
			if (!opt)
				return null;
			var el = opt.getUIElement(id);
			if (!el)
				return uci.get('passwall', id, resolveName(name));
			return el.getValue();
		}

		function field(name) {
			var opt = lookup(name);
			if (!opt)
				return null;
			var el = opt.getUIElement(id);
			if (!el)
				return null;
			var value = el.getValue();
			var text = Array.isArray(value) ? (value[0] || '') : (value == null ? '' : String(value));
			return {
				value: text,
				checked: opt instanceof form.Flag ? (value === '1' || value === true || value === 1) : false
			};
		}

		function query(param, src, defaultValue) {
			var opt = lookup(src);
			if (!opt)
				return '';
			var el = opt.getUIElement(id);
			if (!el)
				return '';
			var ret = '&' + param + '=';
			if (opt instanceof form.Flag)
				return ret + (el.getValue() === '1' ? '1' : '0');
			var raw = el.getValue();
			var result = encodeURIComponent(raw == null ? '' : String(raw));
			if (result == null || String(raw == null ? '' : raw).trim() === '') {
				if (defaultValue)
					return ret + defaultValue;
				return '';
			}
			return ret + result;
		}

		function setOpt(name, value) {
			if (value === undefined)
				return;
			var opt = lookup(name);
			if (!opt)
				return;
			var el = opt.getUIElement(id);
			if (!el)
				return;
			if (opt instanceof form.DynamicList) {
				var cur = el.getValue();
				if (!Array.isArray(cur) || (cur.length === 1 && (cur[0] === '' || cur[0] == null)))
					cur = [];
				cur.push(String(value));
				el.setValue(cur);
			}
			else if (opt instanceof form.Flag) {
				var on = !(value === false || value === 0 || value === '0' || value === '' || value == null);
				if (value === true || value === 1 || value === '1' || value === 'true')
					on = true;
				el.setValue(on ? '1' : '0');
			}
			else {
				el.setValue(value == null ? '' : String(value));
			}
		}

		caps.onProtocolChange = function(option) {
			var prev = uci.get('passwall', id, 'protocol') || '';
			option.onchange = function(ev, section_id, value) {
				if (applying)
					return;
				var next = value || '';
				if (next === prev)
					return;
				if (next.charAt(0) === '_' || prev.charAt(0) === '_') {
					return m.save(null, true).then(function() {
						return uci.save();
					}).then(function() {
						window.location.reload();
					});
				}
			};
		};

		window.fetchCertSha256 = function(el) {
			if (el.getAttribute('data-loading') === '1')
				return;
			el.setAttribute('data-loading', '1');
			el.style.pointerEvents = 'none';
			el.style.color = 'red';
			pw.call('fetch_certsha256', { id: id }).then(function(res) {
				el.setAttribute('data-loading', '0');
				el.style.pointerEvents = '';
				el.style.color = '';
				var body = res;
				if (typeof body === 'string') {
					try { body = JSON.parse(body); }
					catch (e) {}
				}
				body = body && body.data && body.code == null ? body.data : body;
				if (body && typeof body === 'object' && body.output)
					body = body.output;
				if (typeof body === 'string') {
					try { body = JSON.parse(body); }
					catch (e) {}
				}
				if (!body || body.code !== 1 || !body.data) {
					alert((body && body.msg) ? body.msg : (_('Fetch Failed!') + '\n' +
						_('Requires OpenSSL to retrieve the TLS certificate chain fingerprint.') + '\n' +
						_('QUIC protocols such as HY2 also require curl with http3 support.')));
					return;
				}
				setOpt('tls_pinSHA256', body.data);
			}).catch(function() {
				el.setAttribute('data-loading', '0');
				el.style.pointerEvents = '';
				el.style.color = '';
				alert(_('Error'));
			});
		};

		var share = s.option(form.DummyValue, '_link_share', '　');
		share.rawhtml = true;
		share.write = function() {};
		share.remove = function() {};
		share.renderWidget = function() {
			var proto = uci.get('passwall', id, 'protocol') || '';
			var buttons = [];
			if (proto.charAt(0) !== '_') {
				buttons.push(E('input', {
					'id': 'fromUrlBtn',
					'type': 'button',
					'class': 'btn cbi-button cbi-button-apply',
					'value': _('From Share URL'),
					'click': function() { return onImport(); }
				}));
				buttons.push(E('input', {
					'id': 'exportUrlBtn',
					'type': 'button',
					'class': 'btn cbi-button cbi-button-apply',
					'value': _('Build Share URL'),
					'click': function() { return exportUrl(); }
				}));
				buttons.push(E('input', {
					'id': 'genQrcodeBtn',
					'type': 'button',
					'class': 'btn cbi-button cbi-button-apply',
					'value': _('Generate QRCode'),
					'click': function() { return genQrcode(); }
				}));
			}
			buttons.push(E('input', {
				'id': 'exportConfigFileBtn',
				'type': 'button',
				'class': 'btn cbi-button cbi-button-apply',
				'value': _('Export Config File'),
				'click': function() { return exportConfigFile(); }
			}));
			return E('div', {}, [
				E('style', {}, '.share-toolbar{display:inline-block;text-align:center;padding:5px 0;white-space:nowrap}.toolbar-buttons .cbi-button{margin-right:2px;margin-bottom:2px}.status-text{display:none}.status-text:not(:empty){display:inline-block;line-height:1;padding:5px 0}@media screen and (max-width:500px){.share-toolbar{white-space:normal}}'),
				E('script', { 'src': L.resource('view/passwall/qrcode.min.js') }),
				E('div', { 'class': 'share-toolbar' }, [
					E('div', { 'class': 'toolbar-buttons' }, buttons),
					E('div', { 'id': 'qrcode_div', 'style': 'padding:5px 0;display:none' }, [
						E('div', { 'id': 'qrcode', 'style': 'display:flex;justify-content:center;' })
					]),
					E('div', { 'style': 'text-align:center;padding:0;min-height:0;line-height:1;' }, [
						E('span', { 'id': 'share-status', 'class': 'status-text' })
					])
				])
			]);
		};

		var remarks = s.option(form.Value, 'remarks', _('Node Remarks'));
		remarks.default = _('Remarks');
		remarks.rmempty = false;

		var group = s.option(form.Value, 'group', _('Group Name'));
		group.default = '';
		group.value('', _('default'));
		groups.forEach(function(g) { group.value(g); });
		group.write = function(section_id, value) {
			return writeGroup(section_id, value, groups);
		};
		group.remove = function(section_id) {
			return uci.unset('passwall', section_id, 'group');
		};

		var typeOpt = s.option(form.ListValue, 'type', _('Type'));
		var typeChoices = [
			{ id: 'Socks', label: 'Socks', ok: (caps && Object.prototype.hasOwnProperty.call(caps, 'ipt2socks')) ? !!caps.ipt2socks : true, mod: socksType },
			{ id: 'sing-box', label: 'Sing-Box', ok: !!caps.singbox, mod: singboxType },
			{ id: 'Xray', label: 'Xray', ok: !!caps.xray, mod: xrayType },
			{ id: 'SS-Rust', label: 'Shadowsocks Rust', ok: !!caps.sslocal, mod: ssrustType },
			{ id: 'SSR', label: 'ShadowsocksR Libev', ok: !!caps.ssr, mod: ssrType },
			{ id: 'Hysteria2', label: 'Hysteria2', ok: !!caps.hysteria, mod: hysteria2Type },
			{ id: 'Naiveproxy', label: 'NaïveProxy', ok: !!caps.naive, mod: naiveType }
		];
		var currentType = node.type || '';
		if (!currentType) {
			if (caps.singbox)
				currentType = 'sing-box';
			else if (caps.xray)
				currentType = 'Xray';
		}
		var active = null;
		typeChoices.forEach(function(choice) {
			if (choice.ok || choice.id === node.type)
				typeOpt.value(choice.id, choice.label);
			if (choice.id === (node.type || currentType))
				active = choice;
		});
		if (currentType)
			typeOpt.default = currentType;
		typeOpt.onchange = function(ev, section_id, value) {
			if (applying || !value || value === (node.type || ''))
				return;
			uci.set('passwall', id, 'type', value);
			return m.save(null, true).then(function() {
				return uci.save();
			}).then(function() {
				window.location.reload();
			});
		};

		if (active && active.mod && typeof active.mod.addOptions === 'function' && (active.ok || active.id === node.type))
			active.mod.addOptions(s, caps);

		function status(html) {
			var el = document.getElementById('share-status');
			if (el)
				el.innerHTML = html;
		}

		function generateShadowTLSBase64(paramStr) {
			try {
				var obj = {};
				String(paramStr || '').split(';').forEach(function(item) {
					var kv = item.split('=');
					if (kv.length === 2) {
						var k = kv[0].trim();
						var v = kv[1].trim();
						var mm = k.match(/^v(\d+)$/);
						if (mm && v === '1')
							obj.version = mm[1];
						else if (k === 'passwd')
							obj.password = v;
						else
							obj[k] = v;
					}
				});
				return b64encsafe(JSON.stringify(obj));
			}
			catch (e) {
				return '';
			}
		}

		function buildUrl() {
			var vType = (field('type') || {}).value || node.type || '';
			var alias = (field('remarks') || {}).value || '';
			var dom = '';
			var protocol = '';
			if (vType === 'SS-Rust') {
				dom = 'ssrust_';
				protocol = 'ss';
			}
			else if (vType === 'SSR') {
				dom = 'ssr_';
				protocol = 'ssr';
			}
			else if (vType === 'Hysteria2') {
				dom = 'hysteria2_';
				protocol = 'hysteria2';
			}
			else if (vType === 'Xray')
				dom = 'xray_';
			else if (vType === 'sing-box')
				dom = 'singbox_';
			var address = '';
			if (dom) {
				try {
					var server = field(dom + 'address');
					address = ipv6Bracket(server && server.value);
				}
				catch (e) {}
			}
			var url = null;
			var protoField = field(dom + 'protocol');
			var protoVal = protoField ? protoField.value : '';
			if (vType === 'SS-Rust' || ((vType === 'sing-box' || vType === 'Xray') && protoVal === 'shadowsocks')) {
				protocol = 'ss';
				var method = field(dom + 'method') || field(dom + 'ss_method') || { value: '' };
				var password = field(dom + 'password') || { value: '' };
				var port = field(dom + 'port') || { value: '' };
				url = b64encsafe(method.value + ':' + password.value) + '@' + address + ':' + port.value + '/?';
				var shadowTls = 0;
				var params = '';
				var tfo = field(dom + 'tcp_fast_open');
				if (tfo && tfo.checked)
					params += '&tfo=1';
				var pluginDom = field(dom + 'plugin');
				if (pluginDom) {
					var plugin = pluginDom.value;
					if (plugin && plugin !== 'none') {
						if (plugin === 'simple-obfs' || plugin === 'obfs-local')
							plugin = 'obfs-local';
						var pluginOpts = (field(dom + 'plugin_opts') || {}).value || '';
						if (pluginOpts)
							plugin += ';' + pluginOpts;
						params += '&plugin=' + encodeURIComponent(plugin);
						if (pluginDom.value === 'shadow-tls' && pluginOpts) {
							params = 'shadow-tls=' + generateShadowTLSBase64(pluginOpts);
							shadowTls = 1;
						}
					}
				}
				else if (vType === 'sing-box' || vType === 'Xray') {
					var transport = (field(dom + 'transport') || {}).value || '';
					if (transport === 'ws') {
						params += query('host', dom + 'ws_host');
						params += query('path', dom + 'ws_path');
					}
					else if (transport === 'http') {
						params += query('host', dom + 'http_host');
						params += query('path', dom + 'http_path');
					}
					else if (transport === 'raw' || transport === 'tcp') {
						transport = 'tcp';
						params += query('headerType', dom + 'tcp_guise');
						params += query('host', dom + 'tcp_guise_http_host');
						params += query('path', dom + 'tcp_guise_http_path');
					}
					else if (transport === 'mkcp') {
						transport = 'kcp';
						params += query('headerType', dom + 'mkcp_guise');
						params += query('seed', dom + 'mkcp_seed');
					}
					else if (transport === 'quic') {
						params += query('headerType', dom + 'quic_guise');
						params += query('key', dom + 'quic_key');
						params += query('quicSecurity', dom + 'quic_security');
					}
					else if (transport === 'grpc') {
						params += query('path', dom + 'grpc_serviceName');
						params += query('serviceName', dom + 'grpc_serviceName');
						params += query('mode', dom + 'grpc_mode');
					}
					else if (transport === 'xhttp') {
						params += query('host', dom + 'xhttp_host');
						params += query('path', dom + 'xhttp_path');
						params += query('mode', dom + 'xhttp_mode');
						if ((field(dom + 'use_xhttp_extra') || {}).checked)
							params += query('extra', dom + 'xhttp_extra');
					}
					params += '&type=' + transport;
					if ((field(dom + 'tls') || {}).checked) {
						var security = 'tls';
						var fp = field(dom + 'fingerprint');
						if (fp && fp.value)
							params += '&fp=' + fp.value;
						if ((field(dom + 'reality') || {}).checked) {
							security = 'reality';
							params += query('pbk', dom + 'reality_publicKey');
							params += query('sid', dom + 'reality_shortId');
							params += query('spx', dom + 'reality_spiderX');
							params += query('pqv', dom + 'reality_mldsa65Verify');
						}
						params += '&security=' + security;
						params += query('alpn', dom + 'alpn');
						params += query('sni', dom + 'tls_serverName');
						params += query('allowinsecure', dom + 'tls_allowInsecure');
						params += query('pcs', dom + 'tls_pinSHA256');
						params += query('vcn', dom + 'tls_CertByName');
						params += query('ech', dom + 'ech_config');
					}
					if ((field(dom + 'uot') || {}).checked)
						params += '&udp=1';
					if ((field(dom + 'use_finalmask') || {}).checked)
						params += query('fm', dom + 'finalmask');
					if ((field(dom + 'shadowtls') || {}).checked) {
						var st = '';
						var stVersion = (field(dom + 'shadowtls_version') || {}).value;
						if (stVersion)
							st += 'v' + stVersion + '=1;';
						var stPassword = (field(dom + 'shadowtls_password') || {}).value;
						if (stPassword)
							st += 'passwd=' + stPassword + ';';
						var stHost = (field(dom + 'shadowtls_serverName') || {}).value;
						if (stHost)
							st += 'host=' + stHost + ';';
						if ((field(dom + 'shadowtls_utls') || {}).checked) {
							var stFp = (field(dom + 'shadowtls_fingerprint') || {}).value;
							if (stFp)
								st += 'fingerprint=' + stFp;
						}
						params = 'shadow-tls=' + generateShadowTLSBase64(st);
						shadowTls = 1;
					}
				}
				if (shadowTls) {
					url = b64encsafe(method.value + ':' + password.value + '@' + address + ':' + port.value) + '?';
				}
				else {
					params += '&group=';
				}
				params += '#' + encodeURIComponent(alias);
				if (params.charAt(0) === '&')
					params = params.substring(1);
				url += params;
			}
			else if (vType === 'SSR') {
				var ssr = address + ':' +
					(field(dom + 'port') || {}).value + ':' +
					(field(dom + 'protocol') || {}).value + ':' +
					(field(dom + 'method') || {}).value + ':' +
					(field(dom + 'obfs') || {}).value + ':' +
					b64encsafe((field(dom + 'password') || {}).value || '') +
					'/?obfsparam=' + b64encsafe((field(dom + 'obfs_param') || {}).value || '') +
					'&protoparam=' + b64encsafe((field(dom + 'protocol_param') || {}).value || '') +
					'&remarks=' + b64encutf8safe(alias);
				url = b64encsafe(ssr);
			}
			else if ((vType === 'sing-box' || vType === 'Xray') && protoVal === 'vmess') {
				protocol = 'vmess';
				var info = {};
				info.v = '2';
				info.ps = alias;
				info.add = (field(dom + 'address') || {}).value;
				info.port = (field(dom + 'port') || {}).value;
				info.id = (field(dom + 'uuid') || {}).value;
				var transport = (field(dom + 'transport') || {}).value || '';
				if (transport === 'ws') {
					info.host = (field(dom + 'ws_host') || {}).value;
					info.path = (field(dom + 'ws_path') || {}).value;
				}
				else if (transport === 'http') {
					info.host = (field(dom + 'http_host') || {}).value;
					info.path = (field(dom + 'http_path') || {}).value;
				}
				else if (transport === 'raw' || transport === 'tcp') {
					transport = 'tcp';
					info.type = (field(dom + 'tcp_guise') || {}).value;
					if (info.type === 'http') {
						info.host = (field(dom + 'tcp_guise_http_host') || {}).value;
						info.path = (field(dom + 'tcp_guise_http_path') || {}).value;
					}
				}
				else if (transport === 'mkcp') {
					transport = 'kcp';
					info.type = (field(dom + 'mkcp_guise') || {}).value;
					info.seed = (field(dom + 'mkcp_seed') || {}).value;
				}
				else if (transport === 'quic') {
					info.type = (field(dom + 'quic_guise') || {}).value;
					info.key = (field(dom + 'quic_key') || {}).value;
					info.securty = (field(dom + 'quic_security') || {}).value;
				}
				else if (transport === 'grpc') {
					info.path = (field(dom + 'grpc_serviceName') || {}).value;
				}
				info.net = transport;
				info.security = (field(dom + 'security') || {}).value || 'auto';
				info.scy = info.security;
				if ((field(dom + 'tls') || {}).checked) {
					info.tls = 'tls';
					info.sni = (field(dom + 'tls_serverName') || {}).value;
					info.alpn = (field(dom + 'alpn') || {}).value;
					if (info.alpn === 'default')
						info.alpn = undefined;
					info.fp = (field(dom + 'fingerprint') || {}).value;
					info.pcs = (field(dom + 'tls_pinSHA256') || {}).value;
					if ((field(dom + 'tls_allowInsecure') || {}).checked)
						info.insecure = '1';
				}
				if ((field(dom + 'tcp_fast_open') || {}).checked)
					info.tfo = '1';
				if ((field(dom + 'use_finalmask') || {}).checked) {
					info.fm = (field(dom + 'finalmask') || {}).value;
					if (info.fm)
						info.fm = encodeURI(info.fm);
				}
				url = b64EncodeUnicode(JSON.stringify(info));
			}
			else if ((vType === 'sing-box' || vType === 'Xray') && protoVal === 'vless') {
				protocol = 'vless';
				url = encodeURIComponent((field(dom + 'uuid') || {}).value || '') + '@' + address + ':' + ((field(dom + 'port') || {}).value || '') + '?';
				var params = '';
				var transport = (field(dom + 'transport') || {}).value || '';
				if (transport === 'ws') {
					params += query('host', dom + 'ws_host');
					params += query('path', dom + 'ws_path');
				}
				else if (transport === 'http') {
					params += query('host', dom + 'http_host');
					params += query('path', dom + 'http_path');
				}
				else if (transport === 'raw' || transport === 'tcp') {
					transport = 'tcp';
					params += query('headerType', dom + 'tcp_guise');
					params += query('host', dom + 'tcp_guise_http_host');
					params += query('path', dom + 'tcp_guise_http_path');
				}
				else if (transport === 'mkcp') {
					transport = 'kcp';
					params += query('headerType', dom + 'mkcp_guise');
					params += query('seed', dom + 'mkcp_seed');
				}
				else if (transport === 'quic') {
					params += query('headerType', dom + 'quic_guise');
					params += query('key', dom + 'quic_key');
					params += query('quicSecurity', dom + 'quic_security');
				}
				else if (transport === 'grpc') {
					params += query('path', dom + 'grpc_serviceName');
					params += query('serviceName', dom + 'grpc_serviceName');
					params += query('mode', dom + 'grpc_mode');
				}
				else if (transport === 'xhttp') {
					params += query('host', dom + 'xhttp_host');
					params += query('path', dom + 'xhttp_path');
					params += query('mode', dom + 'xhttp_mode');
					if ((field(dom + 'use_xhttp_extra') || {}).checked)
						params += query('extra', dom + 'xhttp_extra');
				}
				else if (transport === 'httpupgrade') {
					params += query('host', dom + 'httpupgrade_host');
					params += query('path', dom + 'httpupgrade_path');
				}
				params += '&type=' + transport;
				if (vType === 'sing-box')
					params += '&encryption=none';
				else
					params += query('encryption', dom + 'encryption');
				if ((field(dom + 'tls') || {}).checked) {
					var security = 'tls';
					var fp = field(dom + 'fingerprint');
					if (fp && fp.value)
						params += '&fp=' + fp.value;
					if ((field(dom + 'reality') || {}).checked) {
						security = 'reality';
						params += query('pbk', dom + 'reality_publicKey');
						params += query('sid', dom + 'reality_shortId');
						params += query('spx', dom + 'reality_spiderX');
						params += query('pqv', dom + 'reality_mldsa65Verify');
					}
					var flow = field(dom + 'flow');
					if (flow && flow.value)
						params += '&flow=' + flow.value;
					params += '&security=' + security;
					params += query('alpn', dom + 'alpn');
					params += query('sni', dom + 'tls_serverName');
					params += query('allowinsecure', dom + 'tls_allowInsecure');
					params += query('pcs', dom + 'tls_pinSHA256');
					params += query('vcn', dom + 'tls_CertByName');
					params += query('ech', dom + 'ech_config');
				}
				if ((field(dom + 'tcp_fast_open') || {}).checked)
					params += '&tfo=1';
				if ((field(dom + 'use_finalmask') || {}).checked)
					params += query('fm', dom + 'finalmask');
				params += '#' + encodeURI(alias);
				if (params.charAt(0) === '&')
					params = params.substring(1);
				url += params;
			}
			else if ((vType === 'sing-box' || vType === 'Xray') && protoVal === 'trojan') {
				protocol = 'trojan';
				url = encodeURIComponent((field(dom + 'password') || {}).value || '') + '@' + address + ':' + ((field(dom + 'port') || {}).value || '') + '/?';
				var params = '';
				var transport = (field(dom + 'transport') || {}).value || '';
				if (transport === 'ws') {
					params += query('host', dom + 'ws_host');
					params += query('path', dom + 'ws_path');
				}
				else if (transport === 'http') {
					params += query('host', dom + 'http_host');
					params += query('path', dom + 'http_path');
				}
				else if (transport === 'raw' || transport === 'tcp') {
					transport = 'tcp';
					params += query('headerType', dom + 'tcp_guise');
					params += query('host', dom + 'tcp_guise_http_host');
					params += query('path', dom + 'tcp_guise_http_path');
				}
				else if (transport === 'mkcp') {
					transport = 'kcp';
					params += query('headerType', dom + 'mkcp_guise');
					params += query('seed', dom + 'mkcp_seed');
				}
				else if (transport === 'quic') {
					params += query('headerType', dom + 'quic_guise');
					params += query('key', dom + 'quic_key');
					params += query('quicSecurity', dom + 'quic_security');
				}
				else if (transport === 'grpc') {
					params += query('path', dom + 'grpc_serviceName');
					params += query('serviceName', dom + 'grpc_serviceName');
					params += query('mode', dom + 'grpc_mode');
				}
				params += '&type=' + transport;
				var security = 'none';
				if ((field(dom + 'tls') || {}).checked) {
					security = 'tls';
					var fp = field(dom + 'fingerprint');
					if (fp && fp.value)
						params += '&fp=' + fp.value;
					if ((field(dom + 'reality') || {}).checked) {
						security = 'reality';
						params += query('pbk', dom + 'reality_publicKey');
						params += query('sid', dom + 'reality_shortId');
						params += query('spx', dom + 'reality_spiderX');
						params += query('pqv', dom + 'reality_mldsa65Verify');
					}
					params += query('alpn', dom + 'alpn');
					params += query('sni', dom + 'tls_serverName');
					params += query('allowinsecure', dom + 'tls_allowInsecure');
					params += query('pcs', dom + 'tls_pinSHA256');
					params += query('vcn', dom + 'tls_CertByName');
					params += query('ech', dom + 'ech_config');
				}
				params += '&security=' + security;
				if ((field(dom + 'tcp_fast_open') || {}).checked)
					params += '&tfo=1';
				if ((field(dom + 'use_finalmask') || {}).checked)
					params += query('fm', dom + 'finalmask');
				params += '#' + encodeURI(alias);
				if (params.charAt(0) === '&')
					params = params.substring(1);
				url += params;
			}
			else if (vType === 'Hysteria2' || ((vType === 'sing-box' || vType === 'Xray') && protoVal === 'hysteria2')) {
				protocol = 'hysteria2';
				var port = field(dom + 'port');
				var params = '';
				params += query('sni', dom + 'tls_serverName');
				params += query('insecure', dom + 'tls_allowInsecure');
				params += query('pinSHA256', dom + 'tls_pinSHA256');
				params += query('pcs', dom + 'tls_pinSHA256');
				params += query('vcn', dom + 'tls_CertByName');
				params += query('ech', dom + 'ech_config');
				var password = null;
				if (vType === 'Hysteria2') {
					password = field('hysteria2_auth_password');
					var obfs = field('hysteria2_obfs_type');
					if (obfs && obfs.value) {
						params += query('obfs', 'hysteria2_obfs_type');
						params += query('obfs-password', 'hysteria2_obfs_password');
						if (obfs.value === 'gecko') {
							params += query('minPacketSize', 'hysteria2_obfs_MinPacketSize');
							params += query('maxPacketSize', 'hysteria2_obfs_MaxPacketSize');
						}
					}
					params += query('mport', 'hysteria2_hop');
				}
				else {
					password = field(dom + 'hysteria2_auth_password');
					var obfs = field(dom + 'hysteria2_obfs_type');
					if (obfs && obfs.value) {
						params += query('obfs', dom + 'hysteria2_obfs_type');
						params += query('obfs-password', dom + 'hysteria2_obfs_password');
						if (obfs.value === 'gecko') {
							params += query('minPacketSize', dom + 'hysteria2_obfs_MinPacketSize');
							params += query('maxPacketSize', dom + 'hysteria2_obfs_MaxPacketSize');
						}
					}
					params += query('mport', dom + 'hysteria2_hop');
					if ((field(dom + 'use_finalmask') || {}).checked)
						params += query('fm', dom + 'finalmask');
				}
				params = params.replace(/^&/, '');
				url = address + ':' + ((port && port.value) || '443') + '?' + params + '#' + encodeURI(alias);
				if (password)
					url = encodeURIComponent(password.value) + '@' + url;
			}
			else if (vType === 'sing-box' && protoVal === 'tuic') {
				protocol = 'tuic';
				url = encodeURIComponent((field(dom + 'uuid') || {}).value || '') + ':' +
					encodeURIComponent((field(dom + 'password') || {}).value || '') + '@' + address + ':' +
					((field(dom + 'port') || {}).value || '') + '?';
				var params = '';
				params += query('sni', dom + 'tls_serverName');
				params += query('disable_sni', dom + 'tls_disable_sni');
				params += query('alpn', dom + 'tuic_alpn');
				params += query('congestion_control', dom + 'tuic_congestion_control');
				params += query('udp_relay_mode', dom + 'tuic_udp_relay_mode');
				params += query('allowinsecure', dom + 'tls_allowInsecure');
				params += query('pcs', dom + 'tls_pinSHA256');
				params += '#' + encodeURI(alias);
				if (params.charAt(0) === '&')
					params = params.substring(1);
				url += params;
			}
			else if (vType === 'sing-box' && protoVal === 'anytls') {
				protocol = 'anytls';
				url = encodeURIComponent((field(dom + 'password') || {}).value || '') + '@' + address + ':' + ((field(dom + 'port') || {}).value || '') + '?';
				var params = '';
				if ((field(dom + 'tls') || {}).checked) {
					var security = 'tls';
					var fp = field(dom + 'fingerprint');
					if (fp && fp.value)
						params += '&fp=' + fp.value;
					if ((field(dom + 'reality') || {}).checked) {
						security = 'reality';
						params += query('pbk', dom + 'reality_publicKey');
						params += query('sid', dom + 'reality_shortId');
					}
					params += '&security=' + security;
					params += query('alpn', dom + 'alpn');
					params += query('sni', dom + 'tls_serverName');
					params += query('insecure', dom + 'tls_allowInsecure');
					params += query('pcs', dom + 'tls_pinSHA256');
				}
				params += '#' + encodeURI(alias);
				if (params.charAt(0) === '&')
					params = params.substring(1);
				url += params;
			}
			else if (vType === 'sing-box' && protoVal === 'naive') {
				protocol = 'naive+https';
				url = encodeURIComponent((field(dom + 'username') || {}).value || '') + ':' +
					encodeURIComponent((field(dom + 'password') || {}).value || '') + '@' + address + ':' +
					((field(dom + 'port') || {}).value || '') + '?';
				var params = 'security=tls';
				params += query('sni', dom + 'tls_serverName');
				params += query('insecure-concurrency', dom + 'naive_insecure_concurrency');
				params += query('ech', dom + 'ech_config');
				params += query('uot', dom + 'uot');
				if ((field(dom + 'naive_quic') || {}).checked) {
					protocol = 'naive+quic';
					params += query('congestion_control', dom + 'naive_congestion_control');
				}
				params += '#' + encodeURI(alias);
				if (params.charAt(0) === '&')
					params = params.substring(1);
				url += params;
			}
			else if (vType === 'sing-box' && protoVal === 'snell') {
				protocol = 'snell';
				var psk = (field(dom + 'snell_psk') || {}).value || '';
				url = encodeURIComponent(psk) + '@' + address + ':' + ((field(dom + 'port') || {}).value || '') + '?';
				var params = 'psk=' + encodeURIComponent(psk);
				var userkey = (field(dom + 'password') || {}).value || '';
				if (userkey !== '')
					params += '&userkey=' + encodeURIComponent(userkey);
				params += query('version', dom + 'snell_version');
				if ((field(dom + 'snell_version') || {}).value === '4') {
					params += query('obfs', dom + 'snell_obfs_mode');
					params += query('obfs-host', dom + 'snell_obfs_host');
				}
				else {
					params += query('mode', dom + 'snell_mode');
				}
				params += query('reuse', dom + 'snell_reuse');
				params += '#' + encodeURI(alias);
				if (params.charAt(0) === '&')
					params = params.substring(1);
				url += params;
			}

			if (url)
				return protocol.toLowerCase() + '://' + url;
			alert(_('Not a supported scheme:') + ' ' + vType);
			return false;
		}

		function exportUrl() {
			var url = buildUrl();
			if (!url)
				return false;
			var done = function(ok) {
				status(ok ? '<span class="pw-ok">' + _('Share URL to clipboard successfully.') + '</span>' :
					'<span class="pw-warn">' + _('Share URL to clipboard unable.') + '</span>');
			};
			if (navigator.clipboard && navigator.clipboard.writeText) {
				navigator.clipboard.writeText(url).then(function() { done(true); }).catch(function() { done(false); });
			}
			else {
				var textarea = document.createElement('textarea');
				textarea.textContent = url;
				textarea.style.position = 'fixed';
				document.body.appendChild(textarea);
				textarea.select();
				try {
					done(document.execCommand('copy'));
				}
				catch (ex) {
					done(false);
				}
				document.body.removeChild(textarea);
			}
			return false;
		}

		function genQrcode() {
			var url = buildUrl();
			var box = document.getElementById('qrcode_div');
			var target = document.getElementById('qrcode');
			if (!box || !target)
				return false;
			box.style.display = '';
			target.innerHTML = '';
			if (url && window.QRCode) {
				var qrcode = new QRCode(target, { width: 150, height: 150 });
				qrcode.makeCode(url);
			}
			return false;
		}

		function exportConfigFile() {
			return pw.call('gen_client_config', { id: id }).then(function(res) {
				var text = pw.unwrap(res);
				if (text && typeof text === 'object')
					text = JSON.stringify(text, null, 2);
				ui.showModal(_('Export Config File'), [
					E('textarea', { 'style': 'width:100%;min-height:240px', 'readonly': 'readonly' }, [ text == null ? '' : String(text) ]),
					E('div', { 'class': 'right' }, [
						E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Close'))
					])
				]);
			}).catch(function(err) {
				ui.addNotification(null, E('p', {}, err.message || String(err)));
			});
		}

		function linkAddNode(text, group) {
			var chunkSize = 1000;
			var total = Math.max(1, Math.ceil(text.length / chunkSize));
			var index = 0;
			function next() {
				if (index >= total) {
					window.location.href = pw.pageUrl('node_list');
					return;
				}
				var chunk = text.substring(index * chunkSize, (index + 1) * chunkSize);
				var current = index;
				index++;
				return pw.call('link_add_node', {
					chunk: chunk,
					chunk_index: String(current),
					total_chunks: String(total),
					group: group || 'default'
				}).then(next);
			}
			return next();
		}

		function applyParsed(parsed) {
			applying = true;
			if (parsed.values.protocol)
				setOpt('protocol', parsed.values.protocol);
			Object.keys(parsed.values).forEach(function(key) {
				if (key !== 'protocol')
					setOpt(key, parsed.values[key]);
			});
			applying = false;
			status('<span class="pw-ok">' + _('Import Finished ') + '</span>');
			sessionStorage.removeItem('fromUrl');
		}

		function fromUrl(link) {
			var parsed = parseLink(link, caps);
			if (!parsed || parsed.error) {
				status('<span class="pw-warn">' + (parsed && parsed.error ? parsed.error : _('Invalid Share URL Format')) + '</span>');
				sessionStorage.removeItem('fromUrl');
				return false;
			}
			var current = node.type || (field('type') || {}).value || '';
			if (parsed.type && parsed.type !== current) {
				sessionStorage.setItem('fromUrl', JSON.stringify({
					timestamp: Date.now(),
					savetime: 60 * 1000,
					link: link
				}));
				uci.set('passwall', id, 'type', parsed.type);
				return uci.save().then(function() {
					window.location.reload();
				});
			}
			applyParsed(parsed);
			return true;
		}

		function onImport() {
			var link = prompt(_('Paste Share URL Here'), '');
			if (link === null || link === '')
				return false;
			var lines = String(link).split(/\r?\n/).map(function(s) { return s.trim(); }).filter(Boolean);
			var urls = lines.filter(function(line) { return line.indexOf('://') > 0; });
			if (urls.length > 1)
				return linkAddNode(urls.join('\n'), uci.get('passwall', id, 'group') || 'default');
			return fromUrl(urls[0] || link);
		}

		return m.render().then(function(nodeEl) {
			var raw = null;
			try { raw = sessionStorage.getItem('fromUrl'); }
			catch (e) {}
			if (raw) {
				try {
					var cache = JSON.parse(raw);
					if (cache && cache.link && cache.savetime && (Date.now() - cache.timestamp) < cache.savetime)
						fromUrl(cache.link);
					else
						sessionStorage.removeItem('fromUrl');
				}
				catch (e) {
					sessionStorage.removeItem('fromUrl');
				}
			}
			return nodeEl;
		});
	}
});
