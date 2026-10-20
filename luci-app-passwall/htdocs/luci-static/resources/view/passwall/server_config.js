'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require poll';
'require fs';
'require network';
'require view.passwall.tools as pw';

var PKG = 'passwall_server';
var Upload = form.FileUpload || form.Value;

var SS_SINGBOX = [
	'none', 'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
	'2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'
];

var SS_XRAY = [
	'aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305', 'xchacha20-poly1305',
	'2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'
];

var SS_RUST = [
	'plain', 'none',
	'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
	'2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'
];

var SSR_METHOD = [
	'none', 'table', 'rc2-cfb', 'rc4', 'rc4-md5', 'rc4-md5-6', 'aes-128-cfb',
	'aes-192-cfb', 'aes-256-cfb', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
	'bf-cfb', 'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
	'cast5-cfb', 'des-cfb', 'idea-cfb', 'seed-cfb', 'salsa20', 'chacha20',
	'chacha20-ietf'
];

var SSR_PROTOCOL = [
	'origin', 'verify_simple', 'verify_deflate', 'verify_sha1', 'auth_simple',
	'auth_sha1', 'auth_sha1_v2', 'auth_sha1_v4', 'auth_aes128_md5',
	'auth_aes128_sha1', 'auth_chain_a', 'auth_chain_b', 'auth_chain_c',
	'auth_chain_d', 'auth_chain_e', 'auth_chain_f'
];

var SSR_OBFS = [
	'plain', 'http_simple', 'http_post', 'random_head', 'tls_simple',
	'tls1.0_session_auth', 'tls1.2_ticket_auth'
];

var HEADER_TYPES = [
	'none', 'srtp', 'utp', 'wechat-video', 'dtls', 'wireguard', 'dns'
];

var USER_PROTOS_SINGBOX = [
	'mixed', 'socks', 'http', 'shadowsocks', 'vmess', 'vless', 'trojan', 'naive', 'anytls',
	'hysteria', 'tuic', 'hysteria2', 'masque', 'wireguard', 'snell'
];

var USER_PROTOS_XRAY = [
	'http', 'socks', 'shadowsocks', 'vmess', 'vless', 'trojan', 'hysteria2', 'wireguard', 'masque'
];

function values(o, list) {
	(list || []).forEach(function(item) {
		if (Array.isArray(item))
			o.value(item[0], item[1]);
		else
			o.value(item);
	});
	return o;
}

function dep(o, list) {
	(list || []).forEach(function(item) {
		o.depends(item);
	});
	return o;
}

function fillUsers(o, users) {
	(users || []).forEach(function(user) {
		if (!user || !user['.name'])
			return;
		o.value(user['.name'], user.username || user['.name']);
	});
	return o;
}

function b64encode(str) {
	return btoa(unescape(encodeURIComponent(String(str == null ? '' : str))));
}

function b64decode(str) {
	if (!str)
		return '';
	var src = String(str).replace(/\s/g, '');
	if (!/^[A-Za-z0-9+/]*={0,2}$/.test(src))
		return String(str);
	try {
		var bin = atob(src);
		try {
			return decodeURIComponent(escape(bin));
		}
		catch (e) {
			return bin;
		}
	}
	catch (e2) {
		return String(str);
	}
}

function normalizePem(value) {
	return String(value || '').trim().replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/[ \t]*\n[ \t]*/g, '\n').replace(/\n+/g, '\n');
}

function bindBase64(o, name) {
	o.cfgvalue = function(section_id) {
		var raw = uci.get(PKG, section_id, name);
		if (!raw)
			return '';
		return b64decode(raw);
	};
	o.write = function(section_id, value) {
		return uci.set(PKG, section_id, name, b64encode(value || ''));
	};
	o.remove = function(section_id) {
		return uci.unset(PKG, section_id, name);
	};
	return o;
}

function bindPem(o, name) {
	o.cfgvalue = function(section_id) {
		return String(uci.get(PKG, section_id, name) || '').replace(/\\n/g, '\n');
	};
	o.write = function(section_id, value) {
		value = normalizePem(value);
		if (!value)
			return uci.unset(PKG, section_id, name);
		return uci.set(PKG, section_id, name, value.replace(/\n/g, '\\n'));
	};
	o.remove = function(section_id) {
		return uci.unset(PKG, section_id, name);
	};
	return o;
}

function bindStrip(o, name) {
	o.write = function(section_id, value) {
		value = String(value || '').trim().replace(/[\r\n]/g, '');
		if (!value)
			return uci.unset(PKG, section_id, name);
		return uci.set(PKG, section_id, name, value);
	};
	return o;
}

function jsonText(section_id, value) {
	var text = String(value == null ? '' : value).trim();
	if (!text)
		return _('Custom Config') + ' ' + _('Must be JSON text!');
	try {
		var parsed = JSON.parse(text);
		if (parsed && typeof parsed === 'object')
			return true;
	}
	catch (e) {}
	return _('Custom Config') + ' ' + _('Must be JSON text!');
}

function parseRealm(uri) {
	uri = String(uri || '').trim();
	if (!uri)
		return null;
	if (uri.indexOf('realm+http://') !== 0 && uri.indexOf('realm://') !== 0)
		return null;
	var rest = uri.replace(/^realm\+http:\/\//, '').replace(/^realm:\/\//, '');
	var match = rest.match(/^([^@]+)@([^/]+)\/([^?]*)\??(.*)$/);
	if (!match || !match[1] || !match[2] || match[3] == null)
		return null;
	return true;
}

function validateRealm(section_id, value) {
	if (parseRealm(value))
		return true;
	return _('Invalid Realm URL.');
}

function mustFile(section_id, value) {
	if (value && String(value) !== '') {
		return fs.stat(String(value)).then(function() {
			return true;
		}).catch(function() {
			return _('Can\'t find this file!');
		});
	}
	return _('Can\'t find this file!');
}

function fillAlpn(o, extra) {
	o.default = 'default';
	o.value('default', _('Default'));
	o.value('h3');
	o.value('h2');
	o.value('h3,h2');
	o.value('http/1.1');
	o.value('h2,http/1.1');
	o.value('h3,h2,http/1.1');
	(extra || []).forEach(function(item) {
		o.value(item);
	});
	return o;
}

function asList(name) {
	return {
		cfgvalue: function(section_id) {
			var v = uci.get(PKG, section_id, name);
			if (v == null || v === '')
				return [];
			return Array.isArray(v) ? v : String(v).split(/\s+/).filter(Boolean);
		},
		write: function(section_id, value) {
			var arr = Array.isArray(value) ? value.filter(Boolean) : String(value || '').split(/\s+/).filter(Boolean);
			if (!arr.length)
				return uci.unset(PKG, section_id, name);
			return uci.set(PKG, section_id, name, arr);
		},
		remove: function(section_id) {
			return uci.unset(PKG, section_id, name);
		}
	};
}

function protoShort(protocol) {
	switch (protocol) {
	case 'vmess':
		return 'VMess';
	case 'vless':
		return 'VLESS';
	case 'shadowsocks':
		return 'SS';
	case 'shadowsocksr':
		return 'SSR';
	case 'wireguard':
		return 'WG';
	case 'hysteria':
		return 'HY';
	case 'hysteria2':
		return 'HY2';
	case 'anytls':
		return 'AnyTLS';
	case 'ssh':
		return 'SSH';
	default:
		return protocol ? (protocol.charAt(0).toUpperCase() + protocol.slice(1)) : '';
	}
}

function nodeRemark(n, showInfo) {
	var typeName = n.type === 'sing-box' ? 'Sing-Box' : (n.type || '');
	var protocol = n.protocol || '';
	if ((n.type === 'sing-box' || n.type === 'Xray') && protocol && protocol.charAt(0) !== '_')
		typeName += ' ' + protoShort(protocol);
	var realm = (n.type === 'Hysteria2' || protocol === 'hysteria2') && n.hysteria2_realms && String(n.hysteria2_realms) !== '0';
	if (realm)
		typeName += ' Realm';
	var remark = (typeName + '：[' + (n.remarks || '') + ']').trim();
	if (showInfo && !realm && n.address) {
		var port = String(n.port || n.hysteria_hop || n.hysteria2_hop || '').replace(/:/g, '-');
		if (port)
			remark = (typeName + '：[' + (n.remarks || '') + '] ' + n.address + ':' + port).trim();
	}
	return remark;
}

function isNormalNode(n) {
	if (!n || !n.type || !n.remarks)
		return false;
	var protocol = n.protocol || '';
	var realm = (n.type === 'Hysteria2' || protocol === 'hysteria2') && n.hysteria2_realms && String(n.hysteria2_realms) !== '0';
	if (realm)
		return true;
	return !!(n.address && (n.port || n.hysteria_hop || n.hysteria2_hop));
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
		try {
			kind = dev.getType() || '';
		}
		catch (e) {}
		out.push({ name: name, label: (kind ? kind + ': ' : '') + '"' + name + '"' });
	});
	return out;
}

function groupedList(option, items) {
	items.forEach(function(it) {
		option.value(it.value, it.label);
	});
	option.formvalue = function(section_id) {
		var sel = document.getElementById(this.cbid(section_id));
		if (sel)
			return sel.value;
		var stored = uci.get(PKG, section_id, this.option);
		return stored == null ? '' : stored;
	};
	option.write = function(section_id, value) {
		if (value == null || value === '') {
			if (this.rmempty !== false)
				return uci.unset(PKG, section_id, this.option);
		}
		return uci.set(PKG, section_id, this.option, value);
	};
	option.remove = function(section_id) {
		return uci.unset(PKG, section_id, this.option);
	};
	option.renderWidget = function(section_id, option_index, cfgvalue) {
		var current = cfgvalue == null ? '' : String(Array.isArray(cfgvalue) ? (cfgvalue[0] || '') : cfgvalue);
		var sel = E('select', { 'id': this.cbid(section_id), 'class': 'cbi-input-select' });
		var ungrouped = [];
		var groups = [];
		var map = {};
		items.forEach(function(it) {
			if (!it.group) {
				ungrouped.push(it);
				return;
			}
			if (!map[it.group]) {
				map[it.group] = [];
				groups.push(it.group);
			}
			map[it.group].push(it);
		});
		function addOption(parent, it) {
			parent.appendChild(E('option', { 'value': it.value }, it.label));
		}
		ungrouped.forEach(function(it) {
			addOption(sel, it);
		});
		groups.forEach(function(group) {
			var og = E('optgroup', { 'label': group });
			map[group].forEach(function(it) {
				addOption(og, it);
			});
			sel.appendChild(og);
		});
		var seen = false;
		items.forEach(function(it) {
			if (String(it.value) === current)
				seen = true;
		});
		if (current && !seen)
			sel.appendChild(E('option', { 'value': current }, current));
		sel.value = current;
		sel.addEventListener('change', function(ev) {
			if (typeof option.onchange === 'function')
				option.onchange(ev, section_id, sel.value);
		});
		return sel;
	};
	return option;
}

function present(value) {
	return !(value == null || value === false || value === 0 || value === '0' || value === '');
}

function capOk(caps, keys) {
	var seen = false;
	for (var i = 0; i < keys.length; i++) {
		if (caps && Object.prototype.hasOwnProperty.call(caps, keys[i])) {
			seen = true;
			if (present(caps[keys[i]]))
				return true;
		}
	}
	return !seen;
}

function zoneNames() {
	var names = [];
	var seen = {};
	(uci.sections('firewall', 'zone') || []).forEach(function(zone) {
		var name = zone.name || zone['.name'];
		if (name && !seen[name]) {
			seen[name] = true;
			names.push(name);
		}
	});
	if (!seen.wan)
		names.push('wan');
	return names;
}

function addZone(section, dependsOn) {
	var o = section.option(form.ListValue, 'firewall_allow_src', _('Source zone'));
	o.rmempty = false;
	o.default = 'wan';
	o.value('*', _('any'));
	zoneNames().forEach(function(name) {
		o.value(name, name);
	});
	return dep(o, dependsOn);
}

function addCustom(section, title) {
	var o = section.option(form.Flag, 'custom', _('Use Custom Config'));
	o = section.option(form.TextValue, 'custom_config', title);
	o.rows = 10;
	o.wrap = 'off';
	o.depends({ custom: true });
	o.datatype = 'json';
	o.validate = jsonText;
	bindBase64(o, 'config_str');
	return o;
}

function addUsers(section, users, dependsOn) {
	var o = section.option(form.MultiValue, 'users', _('User'));
	fillUsers(o, users);
	var list = asList('users');
	o.cfgvalue = list.cfgvalue;
	o.write = list.write;
	o.remove = list.remove;
	return dep(o, dependsOn);
}

function addUpload(section, name, title, description, fallback, dependsOn) {
	var o = section.option(Upload, name, title, description);
	if (fallback)
		o.default = fallback;
	o.validate = mustFile;
	return dep(o, dependsOn);
}

function addPem(section, name, title, description) {
	var o = section.option(form.TextValue, name, title, description);
	o.default = '';
	o.rows = 5;
	o.wrap = 'off';
	o.depends({ tls_use_pem: true });
	return bindPem(o, name);
}

function addLog(section, levels, levelDefault) {
	var o = section.option(form.Flag, 'log', _('Log'));
	o.default = '1';
	o.rmempty = false;
	o = section.option(form.ListValue, 'loglevel', _('Log Level'));
	o.default = levelDefault;
	values(o, levels);
	o.depends({ log: true });
	return o;
}

function addFirewall(section, custom) {
	var o = section.option(form.Flag, 'firewall_allow', _('Firewall Allow'));
	o.default = '0';
	if (custom)
		o.depends({ custom: false });
	addZone(section, [ custom ? { custom: false, firewall_allow: true } : { firewall_allow: true } ]);
	return o;
}

function addGenKey(section, id, applyKey) {
	var o = section.option(form.DummyValue, 'gen_wireguard_key', _('Generate key'));
	o.depends({ protocol: 'wireguard' });
	o.write = function() {};
	o.remove = function() {};
	o.renderWidget = function() {
		return E('button', {
			'class': 'btn cbi-button',
			'click': ui.createHandlerFn(section, function() {
				return genWireguard(id, applyKey);
			})
		}, _('Generate key'));
	};
	return o;
}

function asObject(res) {
	if (res == null)
		return null;
	if (typeof res === 'string') {
		try {
			return JSON.parse(res);
		}
		catch (e) {
			return null;
		}
	}
	if (typeof res === 'object' && typeof res.output === 'string') {
		try {
			return JSON.parse(res.output);
		}
		catch (e2) {
			return res;
		}
	}
	return res;
}

function keyPayload(res) {
	var body = asObject(res) || {};
	if (body.code != null && String(body.code) !== '1')
		return null;
	if (body.data && body.data.private_key)
		return body.data;
	if (body.private_key)
		return body;
	return null;
}

function genWireguard(id, applyKey) {
	return pw.call('gen_wireguard_key').then(function(res) {
		var data = keyPayload(res);
		if (!data) {
			alert(_('Error'));
			return;
		}
		applyKey('wireguard_private_key', data.private_key || '');
		applyKey('wireguard_public_key', data.public_key || '');
	}).catch(function() {
		alert(_('Error'));
	});
}

function addOutbound(section, ctx) {
	var items = [
		{ value: '', label: _('Close'), group: '' },
		{ value: '_socks', label: _('Custom Socks'), group: '' },
		{ value: '_http', label: _('Custom HTTP'), group: '' },
		{ value: '_iface', label: _('Custom Interface'), group: '' }
	];
	(ctx.nodes || []).forEach(function(n) {
		if (!n || n.type !== ctx.typeName || !isNormalNode(n))
			return;
		var group = (n.group && n.group !== '') ? n.group : _('default');
		items.push({ value: n['.name'], label: nodeRemark(n, ctx.showInfo), group: group });
	});
	var o = section.option(form.ListValue, 'outbound_node', _('outbound node'));
	o.depends({ custom: false });
	groupedList(o, items);

	o = section.option(form.Value, 'outbound_node_address', _('Address (Support Domain Name)'));
	o.depends({ outbound_node: '_socks' });
	o.depends({ outbound_node: '_http' });

	o = section.option(form.Value, 'outbound_node_port', _('Port'));
	o.datatype = 'port';
	o.depends({ outbound_node: '_socks' });
	o.depends({ outbound_node: '_http' });

	o = section.option(form.Value, 'outbound_node_username', _('Username'));
	o.depends({ outbound_node: '_socks' });
	o.depends({ outbound_node: '_http' });

	o = section.option(form.Value, 'outbound_node_password', _('Password'));
	o.password = true;
	o.depends({ outbound_node: '_socks' });
	o.depends({ outbound_node: '_http' });

	o = section.option(form.Value, 'outbound_node_iface', _('Interface'));
	o.depends({ outbound_node: '_iface' });
	(ctx.devices || []).forEach(function(dev) {
		o.value(dev.name, dev.label);
	});
}

function addRealmBlock(section, prefix, protocolDep) {
	var realms = prefix + 'realms';
	var obfs = prefix + 'obfs_type';
	var o = section.option(form.Flag, realms, _('Realms'));
	o.default = '0';
	if (protocolDep)
		o.depends(protocolDep);

	o = section.option(form.Value, prefix + 'realm_url', _('Realm URL'), _('Example:') + 'realm://public@realm.hy2.io/your-realm-name');
	var realmDep = {};
	realmDep[realms] = '1';
	o.depends(realmDep);
	o.validate = validateRealm;
	o.write = function(section_id, value) {
		return uci.set(PKG, section_id, prefix + 'realm_url', String(value || '').trim());
	};

	o = section.option(form.DynamicList, prefix + 'realm_stun', _('Realm STUN'));
	o.default = [ 'stun.sip.us:3478', 'stun.nextcloud.com:3478', 'global.stun.twilio.com:3478' ];
	o.depends(realmDep);

	o = section.option(form.Flag, prefix + 'realm_upnp', _('Enable') + ' UPnP/NAT-PMP', _('Enable UPnP/NAT-PMP port mapping on your gateway to improve hole punching success.'));
	o.default = '0';
	o.depends(realmDep);

	o = section.option(form.ListValue, obfs, _('Obfs Type'));
	o.value('', _('Disable'));
	o.value('salamander');
	o.value('gecko');
	if (protocolDep)
		o.depends(protocolDep);

	o = section.option(form.Value, prefix + 'obfs_password', _('Obfs Password'));
	var salamander = {};
	salamander[obfs] = 'salamander';
	var gecko = {};
	gecko[obfs] = 'gecko';
	o.depends(salamander);
	o.depends(gecko);

	o = section.option(form.Value, prefix + 'obfs_MinPacketSize', _('Gecko Packet Size (min)'));
	o.datatype = 'uinteger';
	o.placeholder = '512';
	o.default = '512';
	o.depends(gecko);

	o = section.option(form.Value, prefix + 'obfs_MaxPacketSize', _('Gecko Packet Size (max)'));
	o.datatype = 'uinteger';
	o.placeholder = '1200';
	o.default = '1200';
	o.depends(gecko);
}

function readField(map, id, name) {
	var opts = map.lookupOption(name, id) || [];
	if (opts[0] && typeof opts[0].formvalue === 'function') {
		try {
			var value = opts[0].formvalue(id);
			if (value != null && value !== '')
				return value;
		}
		catch (e) {}
	}
	var stored = uci.get(PKG, id, name);
	return stored == null ? '' : stored;
}

function validateTls(map, id, section_id, value) {
	if (value !== '1' && value !== 1 && value !== true)
		return true;
	if (String(readField(map, id, 'reality') || '') === '1')
		return true;
	if (String(readField(map, id, 'tls_use_pem') || '') !== '1') {
		if (!readField(map, id, 'tls_certificateFile') || !readField(map, id, 'tls_keyFile'))
			return _('Certificate and Private key path can not be empty!');
	}
	else if (!String(readField(map, id, 'tls_certificate') || '').trim() || !String(readField(map, id, 'tls_key') || '').trim()) {
		return _('Certificate and Private key PEM can not be empty!');
	}
	return true;
}

function addSocks(section, ctx) {
	var o = section.option(form.Value, 'port', _('Listen Port'));
	o.datatype = 'port';

	o = section.option(form.Flag, 'auth', _('Auth'));

	o = section.option(form.ListValue, 'user', _('User'));
	fillUsers(o, ctx.users);
	o.depends({ auth: true });

	addFirewall(section, false);

	o = section.option(form.Flag, 'log', _('Log'));
	o.default = '1';
}

function addSingbox(section, ctx) {
	var id = ctx.id;
	var map = ctx.map;
	var crt = '/etc/config/ssl/' + id + '.crt';
	var key = '/etc/config/ssl/' + id + '.key';
	var o;

	addCustom(section, _('Custom Config') + ' (JSON)');

	o = section.option(form.ListValue, 'protocol', _('Protocol'));
	o.value('direct', 'Direct');
	o.value('mixed', 'Mixed');
	o.value('socks', 'Socks');
	o.value('http', 'HTTP');
	o.value('shadowsocks', 'Shadowsocks');
	o.value('vmess', 'Vmess');
	o.value('vless', 'VLESS');
	o.value('trojan', 'Trojan');
	o.value('naive', 'Naive');
	o.value('anytls', 'AnyTLS');
	o.value('hysteria', 'Hysteria');
	o.value('tuic', 'TUIC');
	o.value('hysteria2', 'Hysteria2');
	o.value('masque', 'MASQUE');
	o.value('wireguard', 'WireGuard');
	o.value('snell', 'Snell');
	o.depends({ custom: false });

	o = section.option(form.Value, 'port', _('Listen Port'));
	o.datatype = 'port';
	o.depends({ custom: false });

	addUsers(section, ctx.users, USER_PROTOS_SINGBOX.map(function(proto) {
		return { protocol: proto };
	}));

	o = section.option(form.Value, 'hysteria_obfs', _('Obfs Password'));
	o.depends({ protocol: 'hysteria' });

	o = section.option(form.Value, 'hysteria_up_mbps', _('Max upload Mbps'));
	o.default = '100';
	o.depends({ protocol: 'hysteria' });

	o = section.option(form.Value, 'hysteria_down_mbps', _('Max download Mbps'));
	o.default = '100';
	o.depends({ protocol: 'hysteria' });

	o = section.option(form.Value, 'hysteria_recv_window_conn', _('QUIC stream receive window'));
	o.depends({ protocol: 'hysteria' });

	o = section.option(form.Value, 'hysteria_recv_window_client', _('QUIC connection receive window'));
	o.depends({ protocol: 'hysteria' });

	o = section.option(form.Value, 'hysteria_max_conn_client', _('QUIC concurrent bidirectional streams'));
	o.default = '1024';
	o.depends({ protocol: 'hysteria' });

	o = section.option(form.Flag, 'hysteria_disable_mtu_discovery', _('Disable MTU detection'));
	o.depends({ protocol: 'hysteria' });

	o = section.option(form.ListValue, 'tuic_congestion_control', _('Congestion control algorithm'));
	o.default = 'cubic';
	o.value('bbr', _('BBR'));
	o.value('cubic', _('CUBIC'));
	o.value('new_reno', _('New Reno'));
	o.depends({ protocol: 'tuic' });

	o = section.option(form.Flag, 'tuic_zero_rtt_handshake', _('Enable 0-RTT QUIC handshake'));
	o.default = '0';
	o.depends({ protocol: 'tuic' });

	o = section.option(form.Value, 'tuic_heartbeat', _('Heartbeat interval(second)'));
	o.datatype = 'uinteger';
	o.default = '3';
	o.depends({ protocol: 'tuic' });

	o = section.option(form.ListValue, 'tuic_alpn', _('QUIC TLS ALPN'));
	fillAlpn(o, [ 'spdy/3.1', 'h3,spdy/3.1' ]);
	o.depends({ protocol: 'tuic' });

	addRealmBlock(section, 'hysteria2_', { protocol: 'hysteria2' });

	o = section.option(form.Flag, 'hysteria2_ignore_client_bandwidth', _('Client BBR Flow Control'), _('Commands the client to use the BBR flow control algorithm'));
	o.default = '0';
	o.depends({ protocol: 'hysteria2' });

	o = section.option(form.Value, 'hysteria2_up_mbps', _('Max upload Mbps'));
	o.depends({ protocol: 'hysteria2', hysteria2_ignore_client_bandwidth: false });

	o = section.option(form.Value, 'hysteria2_down_mbps', _('Max download Mbps'));
	o.depends({ protocol: 'hysteria2', hysteria2_ignore_client_bandwidth: false });

	o = section.option(form.ListValue, 'd_protocol', _('Destination protocol'));
	o.value('tcp', 'TCP');
	o.value('udp', 'UDP');
	o.value('tcp,udp', 'TCP,UDP');
	o.depends({ protocol: 'direct' });

	o = section.option(form.Value, 'd_address', _('Destination address'));
	o.depends({ protocol: 'direct' });

	o = section.option(form.Value, 'd_port', _('Destination port'));
	o.datatype = 'port';
	o.depends({ protocol: 'direct' });

	o = section.option(form.Value, 'decryption', _('Encrypt Method'));
	o.default = 'none';
	o.depends({ protocol: 'vless' });

	o = section.option(form.ListValue, 'method', _('Encrypt Method'));
	values(o, SS_SINGBOX);
	o.depends({ protocol: 'shadowsocks' });

	o = section.option(form.Value, 'ss_password', _('Password'));
	o.depends({ protocol: 'shadowsocks' });

	o = section.option(form.ListValue, 'flow', _('flow'));
	o.default = '';
	o.value('', _('Disable'));
	o.value('xtls-rprx-vision');
	o.depends({ protocol: 'vless', tls: true });

	o = section.option(form.Value, 'masque_path', _('MASQUE Path'));
	o.depends({ protocol: 'masque' });

	o = section.option(form.DynamicList, 'masque_address', _('MASQUE Address'));
	o.rmempty = false;
	o.depends({ protocol: 'masque' });

	o = section.option(form.Value, 'masque_mtu', 'MTU');
	o.datatype = 'uinteger';
	o.default = '1280';
	o.depends({ protocol: 'masque' });

	o = section.option(form.Flag, 'tls', _('TLS'));
	o.default = '0';
	o.validate = function(section_id, value) {
		return validateTls(map, id, section_id, value);
	};
	o.depends({ protocol: 'http' });
	o.depends({ protocol: 'vmess' });
	o.depends({ protocol: 'vless' });
	o.depends({ protocol: 'trojan' });
	o.depends({ protocol: 'anytls' });

	o = section.option(form.Flag, 'reality', _('REALITY'));
	o.default = '0';
	o.depends({ protocol: 'http', tls: true });
	o.depends({ protocol: 'vmess', tls: true });
	o.depends({ protocol: 'vless', tls: true });
	o.depends({ protocol: 'trojan', tls: true });
	o.depends({ protocol: 'anytls', tls: true });

	o = section.option(form.Value, 'reality_private_key', _('Private Key'));
	o.depends({ reality: true });

	o = section.option(form.Value, 'reality_shortId', _('Short Id'));
	o.depends({ reality: true });

	o = section.option(form.Value, 'reality_handshake_server', _('Handshake Server'));
	o.default = 'google.com';
	o.depends({ reality: true });

	o = section.option(form.Value, 'reality_handshake_server_port', _('Handshake Server Port'));
	o.datatype = 'port';
	o.default = '443';
	o.depends({ reality: true });

	o = section.option(form.ListValue, 'alpn', _('ALPN'));
	fillAlpn(o);
	o.depends({ tls: true, reality: false });
	o.depends({ protocol: 'hysteria' });

	o = section.option(form.Flag, 'tls_use_pem', _('Use PEM'), _('Use certificate and private key PEM content.'));
	o.depends({ tls: true, reality: false });
	o.depends({ protocol: 'naive' });
	o.depends({ protocol: 'hysteria' });
	o.depends({ protocol: 'tuic' });
	o.depends({ protocol: 'hysteria2' });
	o.depends({ protocol: 'masque' });

	addUpload(section, 'tls_certificateFile', _('Path to the certificate file'), _('as:') + '/etc/ssl/fullchain.crt', crt, [
		{ tls: true, reality: false, tls_use_pem: false },
		{ protocol: 'naive', tls_use_pem: false },
		{ protocol: 'hysteria', tls_use_pem: false },
		{ protocol: 'tuic', tls_use_pem: false },
		{ protocol: 'hysteria2', tls_use_pem: false },
		{ protocol: 'masque', tls_use_pem: false }
	]);
	addUpload(section, 'tls_keyFile', _('Path to the private key file'), _('as:') + '/etc/ssl/private.key', key, [
		{ tls: true, reality: false, tls_use_pem: false },
		{ protocol: 'naive', tls_use_pem: false },
		{ protocol: 'hysteria', tls_use_pem: false },
		{ protocol: 'tuic', tls_use_pem: false },
		{ protocol: 'hysteria2', tls_use_pem: false },
		{ protocol: 'masque', tls_use_pem: false }
	]);

	addPem(section, 'tls_certificate', _('TLS Certificate (PEM)'), _('Full certificate (chain), PEM format.'));
	addPem(section, 'tls_key', _('TLS Private Key (PEM)'), _('Private key in PEM format.'));

	o = section.option(form.Flag, 'ech', _('ECH'));
	o.default = '0';
	o.depends({ tls: true, flow: '', reality: false });
	o.depends({ protocol: 'naive' });
	o.depends({ protocol: 'hysteria' });
	o.depends({ protocol: 'tuic' });
	o.depends({ protocol: 'hysteria2', hysteria2_realms: false });
	o.depends({ protocol: 'masque' });

	o = section.option(form.TextValue, 'ech_key', _('ECH Key'));
	o.default = '';
	o.rows = 5;
	o.wrap = 'off';
	o.depends({ ech: true });
	bindPem(o, 'ech_key');

	o = section.option(form.ListValue, 'transport', _('Transport'));
	o.value('tcp', 'TCP');
	o.value('http', 'HTTP');
	o.value('ws', 'WebSocket');
	o.value('httpupgrade', 'HTTPUpgrade');
	o.value('quic', 'QUIC');
	o.value('grpc', 'gRPC');
	o.depends({ protocol: 'shadowsocks' });
	o.depends({ protocol: 'vmess' });
	o.depends({ protocol: 'vless' });
	o.depends({ protocol: 'trojan' });

	o = section.option(form.DynamicList, 'http_host', _('HTTP Host'));
	o.depends({ transport: 'http' });

	o = section.option(form.Value, 'http_path', _('HTTP Path'));
	o.depends({ transport: 'http' });

	o = section.option(form.Value, 'ws_host', _('WebSocket Host'));
	o.depends({ transport: 'ws' });

	o = section.option(form.Value, 'ws_path', _('WebSocket Path'));
	o.depends({ transport: 'ws' });

	o = section.option(form.Value, 'ws_earlyDataHeaderName', _('Early data header name'), _('Recommended value: Sec-WebSocket-Protocol'));
	o.placeholder = 'Sec-WebSocket-Protocol';
	o.depends({ transport: 'ws' });

	o = section.option(form.Value, 'httpupgrade_host', _('HTTPUpgrade Host'));
	o.depends({ transport: 'httpupgrade' });

	o = section.option(form.Value, 'httpupgrade_path', _('HTTPUpgrade Path'));
	o.depends({ transport: 'httpupgrade' });

	o = section.option(form.Value, 'grpc_serviceName', 'ServiceName');
	o.depends({ transport: 'grpc' });

	o = section.option(form.Flag, 'mux', _('Mux'));
	o.rmempty = false;
	o.depends({ protocol: 'vmess' });
	o.depends({ protocol: 'vless', flow: '' });
	o.depends({ protocol: 'shadowsocks' });
	o.depends({ protocol: 'trojan' });

	o = section.option(form.Flag, 'tcpbrutal', _('TCP Brutal'));
	o.default = '0';
	o.depends({ mux: true });

	o = section.option(form.Value, 'tcpbrutal_up_mbps', _('Max upload Mbps'));
	o.default = '10';
	o.depends({ tcpbrutal: true });

	o = section.option(form.Value, 'tcpbrutal_down_mbps', _('Max download Mbps'));
	o.default = '50';
	o.depends({ tcpbrutal: true });

	o = section.option(form.Flag, 'wireguard_system_interface', _('System interface'));
	o.default = '0';
	o.depends({ protocol: 'wireguard' });

	o = section.option(form.Value, 'wireguard_mtu', 'MTU');
	o.default = '1408';
	o.depends({ protocol: 'wireguard' });

	o = section.option(form.DynamicList, 'wireguard_local_address', _('Local Address'));
	o.depends({ protocol: 'wireguard' });

	o = section.option(form.Value, 'wireguard_private_key', _('Private Key'));
	o.datatype = 'base64';
	o.depends({ protocol: 'wireguard' });

	o = section.option(form.Value, 'wireguard_public_key', _('Public Key'));
	o.datatype = 'base64';
	o.depends({ protocol: 'wireguard' });

	addGenKey(section, id, ctx.applyKey);

	o = section.option(form.ListValue, 'snell_version', _('Version'));
	o.value('5');
	o.value('6');
	o.depends({ protocol: 'snell' });

	o = section.option(form.Value, 'snell_psk', _('Pre shared key'));
	o.rmempty = false;
	o.depends({ protocol: 'snell' });

	o = section.option(form.ListValue, 'snell_obfs_mode', _('Obfs'));
	o.value('none');
	o.value('http');
	o.depends({ protocol: 'snell', snell_version: '5' });

	o = section.option(form.ListValue, 'snell_mode', _('Mode'));
	o.value('default');
	o.value('unshaped');
	o.value('unsafe-raw');
	o.depends({ protocol: 'snell', snell_version: '6' });

	addFirewall(section, true);

	o = section.option(form.Flag, 'accept_lan', _('Accept LAN Access'), _('When selected, it can accessed lan , this will not be safe!'));
	o.default = '0';
	o.depends({ custom: false });

	addOutbound(section, ctx);
	addLog(section, [ 'debug', 'info', 'warn', 'error' ], 'info');
}

function addXray(section, ctx) {
	var id = ctx.id;
	var map = ctx.map;
	var crt = '/etc/config/ssl/' + id + '.crt';
	var key = '/etc/config/ssl/' + id + '.key';
	var o;

	addCustom(section, _('Custom Config') + ' (JSON)');

	o = section.option(form.ListValue, 'protocol', _('Protocol'));
	o.value('socks', 'Socks');
	o.value('http', 'HTTP');
	o.value('vmess', 'Vmess');
	o.value('vless', 'VLESS');
	o.value('shadowsocks', 'Shadowsocks');
	o.value('trojan', 'Trojan');
	o.value('hysteria2', 'Hysteria2');
	o.value('wireguard', 'WireGuard');
	o.value('masque', 'MASQUE');
	o.value('tunnel', 'Tunnel');
	o.depends({ custom: false });

	o = section.option(form.Value, 'port', _('Listen Port'));
	o.datatype = 'port';
	o.depends({ custom: false });

	addUsers(section, ctx.users, USER_PROTOS_XRAY.map(function(proto) {
		return { protocol: proto };
	}));

	o = section.option(form.ListValue, 'd_protocol', _('Destination protocol'));
	o.value('tcp', 'TCP');
	o.value('udp', 'UDP');
	o.value('tcp,udp', 'TCP,UDP');
	o.depends({ protocol: 'tunnel' });

	o = section.option(form.Value, 'd_address', _('Destination address'));
	o.depends({ protocol: 'tunnel' });

	o = section.option(form.Value, 'd_port', _('Destination port'));
	o.datatype = 'port';
	o.depends({ protocol: 'tunnel' });

	o = section.option(form.Value, 'decryption', _('Encrypt Method') + ' (decryption)');
	o.default = 'none';
	o.placeholder = 'none';
	o.depends({ protocol: 'vless' });
	o.write = function(section_id, value) {
		value = String(value || '').trim();
		return uci.set(PKG, section_id, 'decryption', value === '' ? 'none' : value);
	};

	o = section.option(form.ListValue, 'method', _('Encrypt Method'));
	values(o, SS_XRAY);
	o.depends({ protocol: 'shadowsocks' });

	o = section.option(form.Value, 'ss_password', _('Password'));
	o.depends({ protocol: 'shadowsocks' });

	o = section.option(form.ListValue, 'ss_network', _('Transport'));
	o.default = 'tcp,udp';
	o.value('tcp', 'TCP');
	o.value('udp', 'UDP');
	o.value('tcp,udp', 'TCP,UDP');
	o.depends({ protocol: 'shadowsocks' });

	o = section.option(form.Flag, 'udp_forward', _('UDP Forward'));
	o.default = '1';
	o.rmempty = false;
	o.depends({ protocol: 'socks' });

	o = section.option(form.ListValue, 'flow', _('flow'));
	o.default = '';
	o.value('', _('Disable'));
	o.value('xtls-rprx-vision');
	o.depends({ protocol: 'vless' });

	addRealmBlock(section, 'hysteria2_', { protocol: 'hysteria2' });

	o = section.option(form.Flag, 'hysteria2_ignore_client_bandwidth', _('Client BBR Flow Control'));
	o.default = '0';
	o.depends({ protocol: 'hysteria2' });

	o = section.option(form.Value, 'hysteria2_up_mbps', _('Max upload Mbps'));
	o.depends({ protocol: 'hysteria2', hysteria2_ignore_client_bandwidth: false });

	o = section.option(form.Value, 'hysteria2_down_mbps', _('Max download Mbps'));
	o.depends({ protocol: 'hysteria2', hysteria2_ignore_client_bandwidth: false });

	o = section.option(form.Value, 'masque_path', _('MASQUE Path'));
	o.depends({ protocol: 'masque' });

	o = section.option(form.DynamicList, 'masque_address', _('MASQUE Address'));
	o.rmempty = false;
	o.depends({ protocol: 'masque' });

	o = section.option(form.Value, 'masque_mtu', 'MTU');
	o.datatype = 'uinteger';
	o.default = '1280';
	o.depends({ protocol: 'masque' });

	o = section.option(form.Flag, 'tls', _('TLS'));
	o.default = '0';
	o.validate = function(section_id, value) {
		return validateTls(map, id, section_id, value);
	};
	o.depends({ protocol: 'vmess' });
	o.depends({ protocol: 'vless' });
	o.depends({ protocol: 'http' });
	o.depends({ protocol: 'shadowsocks' });
	o.depends({ protocol: 'trojan' });

	o = section.option(form.Flag, 'reality', _('REALITY'));
	o.default = '0';
	o.depends({ tls: true, transport: 'raw' });
	o.depends({ tls: true, transport: 'ws' });
	o.depends({ tls: true, transport: 'grpc' });
	o.depends({ tls: true, transport: 'httpupgrade' });
	o.depends({ tls: true, transport: 'xhttp' });

	o = section.option(form.Value, 'reality_private_key', _('Private Key'));
	o.depends({ reality: true });

	o = section.option(form.DynamicList, 'reality_shortId', _('Short Id'));
	o.depends({ reality: true });

	o = section.option(form.Value, 'reality_dest', _('Dest'));
	o.default = 'google.com:443';
	o.depends({ reality: true });

	o = section.option(form.DynamicList, 'reality_serverNames', _('serverNames'));
	o.depends({ reality: true });

	o = section.option(form.ListValue, 'alpn', _('alpn'));
	fillAlpn(o);
	o.depends({ tls: true, reality: false });

	o = section.option(form.Flag, 'use_mldsa65Seed', _('ML-DSA-65'));
	o.default = '0';
	o.depends({ reality: true });

	o = section.option(form.TextValue, 'reality_mldsa65Seed', 'ML-DSA-65 ' + _('Private Key'));
	o.default = '';
	o.rows = 5;
	o.wrap = 'soft';
	o.depends({ use_mldsa65Seed: true });
	bindStrip(o, 'reality_mldsa65Seed');

	o = section.option(form.Flag, 'tls_use_pem', _('Use PEM'), _('Use certificate and private key PEM content.'));
	o.depends({ tls: true, reality: false });
	o.depends({ protocol: 'hysteria2' });
	o.depends({ protocol: 'masque' });

	addUpload(section, 'tls_certificateFile', _('Path to the certificate file'), _('as:') + '/etc/ssl/fullchain.crt', crt, [
		{ tls: true, reality: false, tls_use_pem: false },
		{ protocol: 'hysteria2', tls_use_pem: false },
		{ protocol: 'masque', tls_use_pem: false }
	]);
	addUpload(section, 'tls_keyFile', _('Path to the private key file'), _('as:') + '/etc/ssl/private.key', key, [
		{ tls: true, reality: false, tls_use_pem: false },
		{ protocol: 'hysteria2', tls_use_pem: false },
		{ protocol: 'masque', tls_use_pem: false }
	]);

	addPem(section, 'tls_certificate', _('TLS Certificate (PEM)'), _('Full certificate (chain), PEM format.'));
	addPem(section, 'tls_key', _('TLS Private Key (PEM)'), _('Private key in PEM format.'));

	o = section.option(form.Flag, 'ech', _('ECH'));
	o.default = '0';
	o.depends({ tls: true, reality: false });
	o.depends({ protocol: 'masque' });

	o = section.option(form.TextValue, 'ech_key', _('ECH Key'));
	o.default = '';
	o.rows = 5;
	o.wrap = 'soft';
	o.depends({ ech: true });
	bindStrip(o, 'ech_key');

	o = section.option(form.ListValue, 'transport', _('Transport'));
	o.value('raw', 'RAW');
	o.value('mkcp', 'mKCP');
	o.value('ws', 'WebSocket');
	o.value('grpc', 'gRPC');
	o.value('httpupgrade', 'HttpUpgrade');
	o.value('xhttp', 'XHTTP');
	o.depends({ protocol: 'vmess' });
	o.depends({ protocol: 'vless' });
	o.depends({ protocol: 'shadowsocks' });
	o.depends({ protocol: 'trojan' });

	o = section.option(form.Value, 'ws_host', _('WebSocket Host'));
	o.depends({ transport: 'ws' });

	o = section.option(form.Value, 'ws_path', _('WebSocket Path'));
	o.depends({ transport: 'ws' });

	o = section.option(form.Value, 'httpupgrade_host', _('HttpUpgrade Host'));
	o.depends({ transport: 'httpupgrade' });

	o = section.option(form.Value, 'httpupgrade_path', _('HttpUpgrade Path'));
	o.placeholder = '/';
	o.depends({ transport: 'httpupgrade' });

	o = section.option(form.Value, 'xhttp_host', _('XHTTP Host'));
	o.depends({ transport: 'xhttp' });

	o = section.option(form.Value, 'xhttp_path', _('XHTTP Path'));
	o.placeholder = '/';
	o.depends({ transport: 'xhttp' });

	o = section.option(form.Value, 'xhttp_maxuploadsize', _('maxUploadSize'));
	o.default = '1000000';
	o.depends({ transport: 'xhttp' });

	o = section.option(form.Value, 'xhttp_maxconcurrentuploads', _('maxConcurrentUploads'));
	o.default = '10';
	o.depends({ transport: 'xhttp' });

	o = section.option(form.ListValue, 'tcp_guise', _('Camouflage Type'));
	o.value('none', 'none');
	o.value('http', 'http');
	o.depends({ transport: 'raw' });

	o = section.option(form.DynamicList, 'tcp_guise_http_host', _('HTTP Host'));
	o.depends({ tcp_guise: 'http' });

	o = section.option(form.DynamicList, 'tcp_guise_http_path', _('HTTP Path'));
	o.depends({ tcp_guise: 'http' });

	o = section.option(form.ListValue, 'mkcp_guise', _('Camouflage Type'), _('<br />none: default, no masquerade, data sent is packets with no characteristics.<br />srtp: disguised as an SRTP packet, it will be recognized as video call data (such as FaceTime).<br />utp: packets disguised as uTP will be recognized as bittorrent downloaded data.<br />wechat-video: packets disguised as WeChat video calls.<br />dtls: disguised as DTLS 1.2 packet.<br />wireguard: disguised as a WireGuard packet. (not really WireGuard protocol)<br />dns: Disguising traffic as DNS requests.'));
	values(o, HEADER_TYPES);
	o.depends({ transport: 'mkcp' });

	o = section.option(form.Value, 'mkcp_domain', _('Camouflage Domain'), _('Use it together with the DNS disguised type. You can fill in any domain.'));
	o.depends({ mkcp_guise: 'dns' });

	o = section.option(form.Value, 'mkcp_mtu', _('KCP MTU'));
	o.datatype = 'uinteger';
	o.default = '1350';
	o.depends({ transport: 'mkcp' });

	o = section.option(form.Value, 'mkcp_seed', _('KCP Seed'));
	o.depends({ transport: 'mkcp' });

	o = section.option(form.Value, 'grpc_serviceName', 'ServiceName');
	o.depends({ transport: 'grpc' });

	o = section.option(form.Flag, 'use_finalmask', 'FinalMask');
	o.default = '0';
	o.depends({ custom: false, protocol: 'vmess' });
	o.depends({ custom: false, protocol: 'vless' });
	o.depends({ custom: false, protocol: 'trojan' });
	o.depends({ custom: false, protocol: 'shadowsocks' });
	o.depends({ custom: false, protocol: 'hysteria2', hysteria2_realms: false });

	o = section.option(form.TextValue, 'finalmask', 'FinalMask JSON');
	o.depends({ use_finalmask: true });
	o.rows = 10;
	o.wrap = 'off';
	o.datatype = 'json';
	o.validate = function(section_id, value) {
		var text = String(value == null ? '' : value).trim();
		if (!text)
			return _('Must be JSON text!');
		try {
			var parsed = JSON.parse(text);
			if (parsed && typeof parsed === 'object')
				return true;
		}
		catch (e) {}
		return _('Must be JSON text!');
	};
	bindBase64(o, 'finalmask');

	o = section.option(form.Flag, 'acceptProxyProtocol', _('acceptProxyProtocol'), _('Whether to receive PROXY protocol, when this node want to be fallback or forwarded by proxy, it must be enable, otherwise it cannot be used.'));
	o.default = '0';
	o.depends({ transport: 'raw' });
	o.depends({ transport: 'ws' });

	o = section.option(form.Flag, 'tcp_fast_open', 'TCP ' + _('Fast Open'));
	o.default = '0';
	o.depends({ protocol: 'vmess', custom: false });
	o.depends({ protocol: 'vless', custom: false });
	o.depends({ protocol: 'shadowsocks', custom: false });
	o.depends({ protocol: 'trojan', custom: false });

	o = section.option(form.Flag, 'fallback', _('Fallback'));
	o.depends({ protocol: 'vless', transport: 'raw' });
	o.depends({ protocol: 'trojan', transport: 'raw' });

	o = section.option(form.DynamicList, 'fallback_list', 'Fallback', _('format: dest,path,xver'));
	o.depends({ fallback: true });

	o = section.option(form.Value, 'wireguard_mtu', 'MTU');
	o.default = '1420';
	o.depends({ protocol: 'wireguard' });

	o = section.option(form.Value, 'wireguard_private_key', _('Private Key'));
	o.datatype = 'base64';
	o.depends({ protocol: 'wireguard' });

	o = section.option(form.Value, 'wireguard_public_key', _('Public Key'));
	o.datatype = 'base64';
	o.depends({ protocol: 'wireguard' });

	addGenKey(section, id, ctx.applyKey);
	addFirewall(section, true);

	o = section.option(form.Flag, 'accept_lan', _('Accept LAN Access'), _('When selected, it can accessed lan , this will not be safe!'));
	o.default = '0';
	o.depends({ custom: false });

	addOutbound(section, ctx);
	addLog(section, [ 'debug', 'info', 'warning', 'error' ], 'warning');
}

function addSsRust(section, ctx) {
	var o;
	addCustom(section, _('Custom Config') + ' (JSON)');

	o = section.option(form.Value, 'port', _('Listen Port'));
	o.datatype = 'port';
	o.depends({ custom: false });

	o = section.option(form.ListValue, 'user', _('User'));
	fillUsers(o, ctx.users);
	o.depends({ custom: false });

	o = section.option(form.ListValue, 'method', _('Encrypt Method'));
	values(o, SS_RUST);
	o.depends({ custom: false });

	o = section.option(form.Value, 'timeout', _('Connection Timeout'));
	o.datatype = 'uinteger';
	o.default = '300';
	o.depends({ custom: false });

	o = section.option(form.Flag, 'tcp_fast_open', 'TCP ' + _('Fast Open'));
	o.default = '0';
	o.depends({ custom: false });

	addFirewall(section, true);

	o = section.option(form.Flag, 'log', _('Log'));
	o.default = '1';
	o.rmempty = false;
}

function addSsr(section, ctx) {
	var o;
	addCustom(section, _('Custom Config') + ' (JSON)');

	o = section.option(form.Value, 'port', _('Listen Port'));
	o.datatype = 'port';
	o.depends({ custom: false });

	o = section.option(form.ListValue, 'user', _('User'));
	fillUsers(o, ctx.users);
	o.depends({ custom: false });

	o = section.option(form.ListValue, 'method', _('Encrypt Method'));
	values(o, SSR_METHOD);
	o.depends({ custom: false });

	o = section.option(form.ListValue, 'protocol', _('Protocol'));
	values(o, SSR_PROTOCOL);
	o.depends({ custom: false });

	o = section.option(form.Value, 'protocol_param', _('Protocol_param'));
	o.depends({ custom: false });

	o = section.option(form.ListValue, 'obfs', _('Obfs'));
	values(o, SSR_OBFS);
	o.depends({ custom: false });

	o = section.option(form.Value, 'obfs_param', _('Obfs_param'));
	o.depends({ custom: false });

	o = section.option(form.Value, 'timeout', _('Connection Timeout'));
	o.datatype = 'uinteger';
	o.default = '300';
	o.depends({ custom: false });

	o = section.option(form.Flag, 'tcp_fast_open', 'TCP ' + _('Fast Open'));
	o.default = '0';
	o.depends({ custom: false });

	o = section.option(form.Flag, 'udp_forward', _('UDP Forward'));
	o.default = '1';
	o.rmempty = false;

	addFirewall(section, true);

	o = section.option(form.Flag, 'log', _('Log'));
	o.default = '1';
	o.rmempty = false;
}

function addHysteria2(section, ctx) {
	var id = ctx.id;
	var crt = '/etc/config/ssl/' + id + '.crt';
	var key = '/etc/config/ssl/' + id + '.key';
	var o;

	addCustom(section, _('Custom Config'));

	o = section.option(form.Value, 'port', _('Listen Port'));
	o.datatype = 'port';
	o.depends({ custom: false });

	addUsers(section, ctx.users, [ { custom: false } ]);
	addRealmBlock(section, 'hysteria2_', { custom: false });

	o = section.option(form.Flag, 'hysteria2_udp', _('UDP'));
	o.default = '1';
	o.depends({ custom: false });

	o = section.option(form.Value, 'hysteria2_up_mbps', _('Max upload Mbps'));
	o.depends({ custom: false });

	o = section.option(form.Value, 'hysteria2_down_mbps', _('Max download Mbps'));
	o.depends({ custom: false });

	o = section.option(form.Flag, 'hysteria2_ignoreClientBandwidth', _('ignoreClientBandwidth'));
	o.default = '0';
	o.depends({ custom: false });

	addUpload(section, 'tls_certificateFile', _('Path to the certificate file'), _('as:') + '/etc/ssl/fullchain.crt', crt, [
		{ custom: false }
	]);
	addUpload(section, 'tls_keyFile', _('Path to the private key file'), _('as:') + '/etc/ssl/private.key', key, [
		{ custom: false }
	]);
	addUpload(section, 'ech_keyFile', _('Path to the ECH key file'), _('as:') + '/etc/ssl/ech.pem', '', [
		{ custom: false }
	]);

	addFirewall(section, true);

	o = section.option(form.Flag, 'log', _('Log'));
	o.default = '1';
	o.rmempty = false;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(PKG),
			uci.load('passwall').catch(function() { return null; }),
			uci.load('firewall').catch(function() { return null; }),
			pw.loadCaps().catch(function() { return {}; }),
			network.getDevices().catch(function() { return []; })
		]);
	},

	render: function(data) {
		var id = pw.routeArg();
		var servers = uci.sections(PKG, 'server') || [];
		var node = null;
		for (var i = 0; i < servers.length; i++) {
			if (servers[i]['.name'] === id) {
				node = servers[i];
				break;
			}
		}
		if (!id || !node) {
			window.location.href = pw.pageUrl('server');
			return E('div');
		}

		var caps = data[3] || {};
		var others = uci.sections('passwall', 'global_other') || [];
		var showInfo = !!(others.length && others[0].show_node_info === '1');
		var users = uci.sections(PKG, 'user') || [];
		var nodes = uci.sections('passwall', 'nodes') || [];
		var devices = deviceList(data[4]);
		var choices = [
			{ id: 'Socks', label: 'Socks', ok: capOk(caps, [ 'microsocks' ]), add: addSocks },
			{ id: 'sing-box', label: 'Sing-Box', ok: capOk(caps, [ 'singbox' ]), add: addSingbox },
			{ id: 'Xray', label: 'Xray', ok: capOk(caps, [ 'xray' ]), add: addXray },
			{ id: 'SS-Rust', label: _('Shadowsocks Rust'), ok: capOk(caps, [ 'ssserver' ]), add: addSsRust },
			{ id: 'SSR', label: _('ShadowsocksR'), ok: capOk(caps, [ 'ssr_server', 'ssr-server' ]), add: addSsr },
			{ id: 'Hysteria2', label: 'Hysteria2', ok: capOk(caps, [ 'hysteria' ]), add: addHysteria2 }
		];
		var currentType = node.type || '';
		if (!currentType) {
			if (capOk(caps, [ 'singbox' ]))
				currentType = 'sing-box';
			else if (capOk(caps, [ 'xray' ]))
				currentType = 'Xray';
			else {
				for (var c = 0; c < choices.length; c++) {
					if (choices[c].ok) {
						currentType = choices[c].id;
						break;
					}
				}
			}
		}
		var active = null;
		for (var n = 0; n < choices.length; n++) {
			if (choices[n].id === currentType)
				active = choices[n];
		}

		var applying = false;
		var m = new form.Map(PKG);
		var s = m.section(form.NamedSection, id, 'server', _('Server Config'));
		s.addremove = false;

		function applyKey(name, value) {
			uci.set(PKG, id, name, value || '');
			var input = document.getElementById('cbid.' + PKG + '.' + id + '.' + name);
			if (input) {
				input.value = value || '';
				input.dispatchEvent(new Event('change', { bubbles: true }));
			}
			var opts = m.lookupOption(name, id) || [];
			if (opts[0] && opts[0].getUIElement) {
				var widget = opts[0].getUIElement(id);
				if (widget && widget.setValue)
					widget.setValue(value || '');
			}
		}

		var enable = s.option(form.Flag, 'enable', _('Enable'));
		enable.default = '1';
		enable.rmempty = false;

		var remarks = s.option(form.Value, 'remarks', _('Remarks'));
		remarks.default = _('Remarks');
		remarks.rmempty = false;

		var typeOpt = s.option(form.ListValue, 'type', _('Type'));
		var knownType = false;
		choices.forEach(function(choice) {
			if (choice.ok || choice.id === node.type) {
				typeOpt.value(choice.id, choice.label);
				if (choice.id === currentType)
					knownType = true;
			}
		});
		if (currentType && !knownType)
			typeOpt.value(currentType, currentType);
		if (currentType)
			typeOpt.default = currentType;
		typeOpt.rmempty = false;
		typeOpt.onchange = function(ev, section_id, value) {
			if (applying || !value || value === currentType)
				return;
			applying = true;
			var enableVal = null;
			var remarksVal = null;
			try { enableVal = enable.formvalue(id); }
			catch (e) {}
			try { remarksVal = remarks.formvalue(id); }
			catch (e2) {}
			if (enableVal == null || enableVal === '')
				enableVal = uci.get(PKG, id, 'enable');
			if (remarksVal == null)
				remarksVal = uci.get(PKG, id, 'remarks');
			var on = enableVal === true || enableVal === 1 || enableVal === '1';
			var data = {
				enable: on ? '1' : '0',
				remarks: remarksVal == null ? '' : String(remarksVal),
				type: value,
				protocol: ''
			};
			uci.set(PKG, id, 'enable', data.enable);
			uci.set(PKG, id, 'remarks', data.remarks);
			uci.set(PKG, id, 'type', data.type);
			uci.set(PKG, id, 'protocol', data.protocol);
			return uci.save().then(function() {
				return pw.call('server_update_config', { id: id, data: JSON.stringify(data) }).catch(function() {
					return null;
				});
			}).then(function() {
				window.location.reload();
			}).catch(function(err) {
				applying = false;
				ui.addNotification(null, E('p', {}, (err && err.message) || String(err)));
			});
		};

		var ctx = {
			id: id,
			map: m,
			users: users,
			nodes: nodes,
			devices: devices,
			showInfo: showInfo,
			typeName: currentType,
			applyKey: applyKey
		};
		if (active && (active.ok || active.id === node.type)) {
			if (active.id === 'Socks')
				addSocks(s, ctx);
			else if (active.id === 'sing-box')
				addSingbox(s, ctx);
			else if (active.id === 'Xray')
				addXray(s, ctx);
			else if (active.id === 'SS-Rust')
				addSsRust(s, ctx);
			else if (active.id === 'SSR')
				addSsr(s, ctx);
			else if (active.id === 'Hysteria2')
				addHysteria2(s, ctx);
		}

		return m.render();
	}
});
