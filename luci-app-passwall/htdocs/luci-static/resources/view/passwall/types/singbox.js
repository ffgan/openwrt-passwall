'use strict';
'require baseclass';
'require form';
'require uci';

var ssMethodNew = [
	'none', 'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
	'2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'
];

var ssMethodOld = [
	'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
	'rc4-md5', 'chacha20-ietf', 'xchacha20'
];

var securityList = [ 'none', 'auto', 'aes-128-gcm', 'chacha20-poly1305', 'zero' ];

var normalProtos = [
	'socks', 'http', 'shadowsocks', 'vmess', 'trojan', 'wireguard', 'hysteria', 'vless', 'tuic',
	'hysteria2', 'anytls', 'ssh', 'naive', 'snell', 'masque'
];

var userAgents = [
	[ '', _('default') ],
	[ 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36', 'chrome' ],
	[ 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0', 'firefox' ],
	[ 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15', 'safari' ],
	[ 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.70', 'edge' ],
	[ 'Go-http-client/1.1', 'golang' ],
	[ 'curl/7.68.0', 'curl' ]
];

function urlEncode(s) {
	return encodeURIComponent(String(s)).replace(/[!'()*]/g, function(c) {
		return '%' + c.charCodeAt(0).toString(16).toUpperCase();
	});
}

function protoName(protocol) {
	var map = {
		vmess: 'VMess', vless: 'VLESS', shadowsocks: 'SS', shadowsocksr: 'SSR',
		wireguard: 'WG', hysteria: 'HY', hysteria2: 'HY2', anytls: 'AnyTLS', ssh: 'SSH'
	};
	if (map[protocol])
		return map[protocol];
	if (!protocol)
		return '';
	return protocol.charAt(0).toUpperCase() + protocol.slice(1);
}

function catalog(selfId) {
	var other = (uci.sections('passwall', 'global_other') || [])[0] || {};
	var showInfo = other.show_node_info === '1';
	var socks = [];
	var normal = [];
	var special = { balancing: [], shunt: [], iface: [], urltest: [] };
	var groups = [];
	var seen = {};

	(uci.sections('passwall', 'socks') || []).forEach(function(s) {
		if (s.enabled === '1' && s.node) {
			socks.push({
				id: s['.name'],
				remark: _('Socks Config') + ' [' + (s.port || '') + _('Port') + ']',
				group: 'Socks'
			});
		}
	});

	(uci.sections('passwall', 'nodes') || []).forEach(function(n) {
		if (n['.name'] !== selfId && n.group && !seen[n.group]) {
			seen[n.group] = true;
			groups.push(n.group);
		}
		if (!n.type || !n.remarks)
			return;
		var typeName = n.type === 'sing-box' ? 'Sing-Box' : n.type;
		var protocol = n.protocol || '';
		if (protocol === '_balancing' || protocol === '_shunt' || protocol === '_iface' || protocol === '_urltest') {
			special[protocol.substring(1)].push({
				id: n['.name'],
				remark: (typeName + ' ' + protocol + '：[' + n.remarks + ']').trim(),
				group: n.group || '',
				fallback: n.fallback_node || ''
			});
		}
		var port = n.port || n.hysteria_hop || n.hysteria2_hop;
		var realm = (n.type === 'Hysteria2' || protocol === 'hysteria2') && n.hysteria2_realms && n.hysteria2_realms !== '0';
		if ((port && n.address) || realm) {
			var tn = typeName;
			if ((n.type === 'sing-box' || n.type === 'Xray') && protocol && protocol.charAt(0) !== '_')
				tn += ' ' + protoName(protocol);
			if (realm)
				tn += ' Realm';
			var remark = (tn + '：[' + n.remarks + ']').trim();
			if (showInfo && !realm && n.address && port)
				remark = (tn + '：[' + n.remarks + '] ' + n.address + ':' + String(port).replace(/:/g, '-')).trim();
			normal.push({
				id: n['.name'],
				remark: remark,
				group: n.group || '',
				chain_proxy: n.chain_proxy || ''
			});
		}
	});

	return { socks: socks, normal: normal, special: special, groups: groups };
}

function nodeLabel(v) {
	return '[' + (v.group || _('default')) + '] ' + v.remark;
}

function addChoices(o, list, selfId) {
	(list || []).forEach(function(v) {
		if (v && v.id !== selfId)
			o.value(v.id, nodeLabel(v));
	});
}

function fillDevices(o, devices, withAll) {
	if (withAll)
		o.value('', _('All'));
	(devices || []).forEach(function(d) {
		if (d && d.name)
			o.value(d.name, d.label || d.name);
	});
}

function probeUrls(o) {
	o.value('https://cp.cloudflare.com/', 'Cloudflare');
	o.value('https://www.gstatic.com/generate_204', 'Gstatic');
	o.value('https://www.google.com/generate_204', 'Google');
	o.value('https://www.youtube.com/generate_204', 'YouTube');
	o.value('https://connect.rom.miui.com/generate_204', 'MIUI (CN)');
	o.value('https://connectivitycheck.platform.hicloud.com/generate_204', 'HiCloud (CN)');
	o.value('https://wifi.vivo.com.cn/generate_204', 'VIVO (CN)');
	o.default = 'https://www.google.com/generate_204';
	o.description = _('The URL used to detect the connection status.');
}

function timeHelp(which) {
	var head = which === 'idle' ? _('The idle timeout.') : _('The interval between initiating probes.');
	var body = head + '<br>' +
		_('The time format is numbers + units, such as \'10s\', \'2h45m\', and the supported time units are <code>s</code>, <code>m</code>, <code>h</code>, which correspond to seconds, minutes, and hours, respectively.') + '<br>' +
		_('When the unit is not filled in, it defaults to seconds.');
	if (which === 'interval')
		body += '<br>' + _('Test interval must be less or equal than idle timeout.');
	return body;
}

function matchHelp() {
	return _('Example: <code>^A && B && !C && D$</code><br>' +
		'This means the node remark must start with A (^), include B, exclude C (!), and end with D ($).<br>' +
		'Conditions are joined by <code>&&</code> (AND), and their order does not affect the result.<br>' +
		'Multiple groups can be separated by <code>||</code> (OR), matching succeeds if any group matches.<br>' +
		'Example: <code>A && B || C && D</code> means (A AND B) OR (C AND D).');
}

function alpn(o) {
	o.default = 'default';
	o.value('default', _('Default'));
	o.value('h3');
	o.value('h2');
	o.value('h3,h2');
	o.value('http/1.1');
	o.value('h2,http/1.1');
	o.value('h3,h2,http/1.1');
	return o;
}

function asList(name) {
	return {
		cfgvalue: function(section_id) {
			var v = uci.get('passwall', section_id, name);
			if (v == null || v === '')
				return [];
			return Array.isArray(v) ? v : String(v).split(/\s+/).filter(Boolean);
		},
		write: function(section_id, value) {
			var arr = Array.isArray(value) ? value.filter(Boolean) : String(value || '').split(/\s+/).filter(Boolean);
			if (!arr.length)
				return uci.unset('passwall', section_id, name);
			return uci.set('passwall', section_id, name, arr);
		}
	};
}

function asSpace(name) {
	return {
		cfgvalue: function(section_id) {
			var v = uci.get('passwall', section_id, name);
			if (v == null || v === '')
				return [];
			return Array.isArray(v) ? v : String(v).split(/\s+/).filter(Boolean);
		},
		write: function(section_id, value) {
			var arr = Array.isArray(value) ? value.filter(Boolean) : String(value || '').split(/\s+/).filter(Boolean);
			if (!arr.length)
				return uci.unset('passwall', section_id, name);
			return uci.set('passwall', section_id, name, arr.join(' '));
		}
	};
}

function escapedText(name) {
	return {
		cfgvalue: function(section_id) {
			return String(uci.get('passwall', section_id, name) || '').replace(/\\n/g, '\n');
		},
		write: function(section_id, value) {
			value = String(value || '').trim().replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/[ \t]*\n[ \t]*/g, '\n').replace(/\n+/g, '\n');
			if (!value)
				return uci.unset('passwall', section_id, name);
			return uci.set('passwall', section_id, name, value.replace(/\n/g, '\\n'));
		},
		remove: function(section_id) {
			return uci.unset('passwall', section_id, name);
		}
	};
}

function bindEscaped(o, name) {
	var spec = escapedText(name);
	o.cfgvalue = spec.cfgvalue;
	o.write = spec.write;
	o.remove = spec.remove;
	return o;
}

function parseRealm(uri) {
	uri = String(uri || '').trim();
	if (!uri)
		return false;
	if (uri.indexOf('realm+http://') !== 0 && uri.indexOf('realm://') !== 0)
		return false;
	var rest = uri.replace(/^realm\+http:\/\//, '').replace(/^realm:\/\//, '');
	var m = rest.match(/^([^@]+)@([^/]+)\/([^?]*)\??(.*)$/);
	return !!(m && m[1] && m[2] && m[3] != null);
}

function validateHeaders(value) {
	value = String(value || '').trim().replace(/\r\n/g, '\n').replace(/\r/g, '\n');
	var headers = {};
	var lines = value.split('\n');
	for (var i = 0; i < lines.length; i++) {
		var line = lines[i].trim();
		if (!line)
			continue;
		var m = line.match(/^\s*([^:]+):/);
		var key = m ? m[1].trim().toLowerCase() : '';
		if (!key || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(key) || headers[key])
			return _('Not true format, please re-enter!') + ' (' + line + ')';
		headers[key] = true;
	}
	return true;
}

function fingerprints(o, extended) {
	o.value('chrome');
	o.value('firefox');
	o.value('edge');
	o.value('safari');
	if (extended)
		o.value('360');
	o.value('qq');
	o.value('ios');
	if (extended)
		o.value('android');
	o.value('random');
	if (extended)
		o.value('randomized');
	o.default = 'chrome';
	return o;
}

function addShunt(section, selfId, caps) {
	var o;
	var cat = catalog(selfId);

	o = section.option(form.Flag, 'fakedns', '<a style="color:#FF8C00">FakeDNS</a> ' + _('Main switch'),
		_('Use FakeDNS work in the domain that proxy.') + '<br>' +
		_('Suitable scenarios for let the node servers get the target domain names.') + '<br>' +
		_('Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.'));

	o = section.option(form.ListValue, 'shunt_group', _('Shunt Rule Group'));
	o.value('', _('default'));
	var sseen = {};
	(uci.sections('passwall', 'shunt_rules') || []).forEach(function(r) {
		if (r.group && !sseen[r.group]) {
			sseen[r.group] = true;
			o.value(r.group);
		}
	});
	o.onchange = function(ev, section_id, value) {
		if (value)
			uci.set('passwall', section_id, 'shunt_group', value);
		else
			uci.unset('passwall', section_id, 'shunt_group');
		return uci.save().then(function() {
			window.location.reload();
		});
	};

	var groupVal = String(uci.get('passwall', selfId, 'shunt_group') || '').toLowerCase();
	var rules = [];
	(uci.sections('passwall', 'shunt_rules') || []).forEach(function(e) {
		if (String(e.group || '').toLowerCase() === groupVal) {
			rules.push({
				id: e['.name'],
				remarks: e.remarks || e['.name'],
				node: e['.name'],
				fakedns: e['.name'] + '_fakedns',
				proxy: e['.name'] + '_proxy_tag',
				nodeDefault: ''
			});
		}
	});
	rules.push({
		id: '.default',
		remarks: _('Default'),
		node: 'default_node',
		fakedns: 'default_fakedns',
		proxy: 'default_proxy_tag',
		nodeDefault: '_direct'
	});

	var pools = cat.socks.concat(cat.normal, cat.special.balancing, cat.special.iface, cat.special.urltest);
	rules.forEach(function(rule) {
		var nodeOpt = section.option(form.ListValue, rule.node, rule.remarks);
		if (rule.nodeDefault)
			nodeOpt.default = rule.nodeDefault;
		nodeOpt.value('', _('Close (Not use)'));
		if (rule.id !== '.default')
			nodeOpt.value('_default', _('Use default node'));
		nodeOpt.value('_direct', _('Direct Connection'));
		nodeOpt.value('_blackhole', _('Blackhole (Block)'));
		addChoices(nodeOpt, pools, null);
		if (rule.id !== '.default') {
			nodeOpt.description = '<a href="' + L.url('admin', 'services', 'passwall', 'shunt_rules', rule.id) + '" target="_blank">' + _('Rule') + '</a>';
		}

		var fake = section.option(form.Flag, rule.fakedns, 'FakeDNS');
		fake.description = _('Use FakeDNS work in the domain that proxy.') + '\n' +
			_('Suitable scenarios for let the node servers get the target domain names.') + '\n' +
			_('Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.');
		pools.forEach(function(v) {
			if (v.id && v.id !== '_direct')
				fake.depends(rule.node, v.id);
		});
		fake.depends(rule.node, '_default');
		fake.depends(rule.node, '_blackhole');

		var proxy = section.option(form.ListValue, rule.proxy, _('Preproxy'));
		proxy.description = _('Set the node to be used as a pre-proxy.') + '\n' +
			_('Each rule has a separate switch that controls whether this rule uses the pre-proxy or not.');
		proxy.value('', _('Close (Not use)'));
		addChoices(proxy, pools, null);
		cat.normal.forEach(function(v) {
			if (v.id && v.id.charAt(0) !== '_' && v.id.indexOf('socks_') !== 0)
				proxy.depends(rule.node, v.id);
		});
	});
}

return baseclass.extend({
	typeName: 'sing-box',

	addOptions: function(section, caps) {
		caps = caps || {};
		var selfId = section.section;
		var protocol = uci.get('passwall', selfId, 'protocol') || '';
		var isUrltest = protocol === '_urltest';
		var isShunt = protocol === '_shunt';
		var isIface = protocol === '_iface';
		var normal = protocol.charAt(0) !== '_';
		var cat = catalog(selfId);
		var o;

		o = section.option(form.ListValue, 'protocol', _('Protocol'));
		o.value('socks', 'Socks');
		o.value('http', 'HTTP');
		o.value('shadowsocks', 'Shadowsocks');
		o.value('vmess', 'Vmess');
		o.value('trojan', 'Trojan');
		o.value('wireguard', 'WireGuard');
		o.value('hysteria', 'Hysteria');
		o.value('vless', 'VLESS');
		o.value('tuic', 'TUIC');
		o.value('hysteria2', 'Hysteria2');
		o.value('anytls', 'AnyTLS');
		o.value('ssh', 'SSH');
		o.value('naive', _('NaïveProxy'));
		o.value('snell', 'Snell');
		o.value('masque', 'MASQUE');
		o.value('_urltest', _('URLTest'));
		o.value('_shunt', _('Shunt'));
		o.value('_iface', _('Custom Interface'));
		if (typeof caps.onProtocolChange === 'function')
			caps.onProtocolChange(o);

		if (isUrltest) {
			o = section.option(form.ListValue, 'node_add_mode', _('Node Addition Method'));
			o.depends({ protocol: '_urltest' });
			o.default = 'manual';
			o.value('manual', _('Manual'));
			o.value('batch', _('Batch'));

			o = section.option(form.MultiValue, 'urltest_node', _('URLTest node list'), _('List of nodes to test, <a target=\'_blank\' href=\'https://sing-box.sagernet.org/configuration/outbound/urltest\'>document</a>'));
			o.depends({ node_add_mode: 'manual' });
			o.widget = 'checkbox';
			addChoices(o, cat.socks, null);
			addChoices(o, cat.normal, null);
			var urlList = asList('urltest_node');
			o.cfgvalue = urlList.cfgvalue;
			o.write = urlList.write;

			o = section.option(form.MultiValue, 'node_group', _('Select Group'));
			o.depends({ node_add_mode: 'batch' });
			o.widget = 'checkbox';
			o.value('default', _('default'));
			cat.groups.forEach(function(g) {
				o.value(urlEncode(g), g);
			});
			var grp = asSpace('node_group');
			o.cfgvalue = grp.cfgvalue;
			o.write = grp.write;

			o = section.option(form.Value, 'node_match_rule', _('Node Matching Rules'));
			o.depends({ node_add_mode: 'batch' });
			o.description = matchHelp();

			o = section.option(form.Value, 'urltest_url', _('Probe URL'));
			o.depends({ protocol: '_urltest' });
			probeUrls(o);

			o = section.option(form.Value, 'urltest_interval', _('Test interval'));
			o.depends({ protocol: '_urltest' });
			o.default = '3m';
			o.placeholder = '3m';
			o.description = timeHelp('interval');

			o = section.option(form.Value, 'urltest_tolerance', _('Test tolerance'), _('The test tolerance in milliseconds.'));
			o.depends({ protocol: '_urltest' });
			o.datatype = 'uinteger';
			o.placeholder = '50';
			o.default = '50';

			o = section.option(form.Value, 'urltest_idle_timeout', _('Idle timeout'));
			o.depends({ protocol: '_urltest' });
			o.placeholder = '30m';
			o.default = '30m';
			o.description = timeHelp('idle');

			o = section.option(form.Flag, 'urltest_interrupt_exist_connections', _('Interrupt existing connections'));
			o.depends({ protocol: '_urltest' });
			o.default = '0';
			o.description = _('Interrupt existing connections when the selected outbound has changed.');
		}

		if (isIface) {
			o = section.option(form.Value, 'iface', _('Interface'));
			o.depends({ protocol: '_iface' });
			fillDevices(o, caps.devices, false);
		}

		if (normal) {
			var address = section.option(form.Value, 'address', _('Address (Support Domain Name)'));
			var port = section.option(form.Value, 'port', _('Port'));
			port.datatype = 'port';

			o = section.option(form.Value, 'uuid', _('ID'));
			o.password = true;
			o.depends({ protocol: 'vmess' });
			o.depends({ protocol: 'vless' });
			o.depends({ protocol: 'tuic' });

			o = section.option(form.Value, 'username', _('Username'));
			o.depends({ protocol: 'http' });
			o.depends({ protocol: 'socks' });
			o.depends({ protocol: 'ssh' });
			o.depends({ protocol: 'naive' });
			o.depends({ protocol: 'masque' });

			var password = section.option(form.Value, 'password', _('Password'));
			password.password = true;
			password.depends({ protocol: 'http' });
			password.depends({ protocol: 'socks' });
			password.depends({ protocol: 'shadowsocks' });
			password.depends({ protocol: 'trojan' });
			password.depends({ protocol: 'tuic' });
			password.depends({ protocol: 'anytls' });
			password.depends({ protocol: 'ssh' });
			password.depends({ protocol: 'naive' });
			password.depends({ protocol: 'masque' });
			password.depends({ protocol: 'snell' });

			o = section.option(form.Value, 'masque_path', _('MASQUE Path'));
			o.depends({ protocol: 'masque' });

			o = section.option(form.TextValue, 'masque_headers', _('Custom HTTP Headers'));
			o.rows = 5;
			o.wrap = 'off';
			o.depends({ protocol: 'masque' });
			o.validate = function(section_id, value) {
				return validateHeaders(value);
			};
			bindEscaped(o, 'masque_headers');

			o = section.option(form.Value, 'snell_psk', _('Pre shared key'));
			o.rmempty = false;
			o.depends({ protocol: 'snell' });

			o = section.option(form.ListValue, 'snell_version', _('Version'));
			o.value('4');
			o.value('6');
			o.depends({ protocol: 'snell' });

			o = section.option(form.Flag, 'snell_reuse', _('Connection Reuse'));
			o.depends({ protocol: 'snell' });

			o = section.option(form.ListValue, 'snell_network', _('Transport'));
			o.value('', 'TCP UDP');
			o.value('tcp', 'TCP');
			o.value('udp', 'UDP');
			o.depends({ protocol: 'snell' });

			o = section.option(form.ListValue, 'snell_obfs_mode', _('Camouflage Type'));
			o.value('none');
			o.value('http');
			o.depends({ protocol: 'snell', snell_version: '4' });

			o = section.option(form.Value, 'snell_obfs_host', _('HTTP Host'));
			o.depends({ protocol: 'snell', snell_version: '4', snell_obfs_mode: 'http' });

			o = section.option(form.ListValue, 'snell_mode', _('Mode'));
			o.value('default');
			o.value('unshaped');
			o.value('unsafe-raw');
			o.depends({ protocol: 'snell', snell_version: '6' });

			o = section.option(form.ListValue, 'security', _('Encrypt Method'));
			securityList.forEach(function(v) { o.value(v); });
			o.depends({ protocol: 'vmess' });

			/* ss_method is rewritten onto the UCI key "method". */
			o = section.option(form.ListValue, 'method', _('Encrypt Method'));
			ssMethodNew.forEach(function(v) { o.value(v); });
			ssMethodOld.forEach(function(v) { o.value(v); });
			o.depends({ protocol: 'shadowsocks' });

			o = section.option(form.Flag, 'uot', _('UDP over TCP'));
			o.depends({ protocol: 'socks' });
			o.depends({ protocol: 'shadowsocks' });
			o.depends({ protocol: 'naive' });

			o = section.option(form.Value, 'alter_id', 'Alter ID');
			o.datatype = 'uinteger';
			o.default = '0';
			o.depends({ protocol: 'vmess' });

			o = section.option(form.Flag, 'global_padding', 'global_padding', _('Protocol parameter. Will waste traffic randomly if enabled.'));
			o.default = '0';
			o.depends({ protocol: 'vmess' });

			o = section.option(form.Flag, 'authenticated_length', 'authenticated_length', _('Protocol parameter. Enable length block encryption.'));
			o.default = '0';
			o.depends({ protocol: 'vmess' });

			o = section.option(form.ListValue, 'flow', _('flow'));
			o.default = '';
			o.value('', _('Disable'));
			o.value('xtls-rprx-vision');
			o.depends({ protocol: 'vless', tls: true });

			o = section.option(form.Value, 'hysteria_hop', _('Port hopping range'));
			o.description = _('Format as 1000:2000 or 1000-2000 Multiple groups are separated by commas (,).');
			o.depends({ protocol: 'hysteria' });

			o = section.option(form.Value, 'hysteria_hop_interval', _('Hop Interval(second)'), _('Example:') + '30 (≥5)');
			o.datatype = 'uinteger';
			o.placeholder = '30';
			o.default = '30';
			o.depends({ protocol: 'hysteria' });

			o = section.option(form.Value, 'hysteria_obfs', _('Obfs Password'));
			o.depends({ protocol: 'hysteria' });

			o = section.option(form.ListValue, 'hysteria_auth_type', _('Auth Type'));
			o.value('disable', _('Disable'));
			o.value('string', _('STRING'));
			o.value('base64', _('BASE64'));
			o.depends({ protocol: 'hysteria' });

			o = section.option(form.Value, 'hysteria_auth_password', _('Auth Password'));
			o.password = true;
			o.depends({ protocol: 'hysteria', hysteria_auth_type: 'string' });
			o.depends({ protocol: 'hysteria', hysteria_auth_type: 'base64' });

			o = section.option(form.Value, 'hysteria_up_mbps', _('Max upload Mbps'));
			o.default = '10';
			o.depends({ protocol: 'hysteria' });

			o = section.option(form.Value, 'hysteria_down_mbps', _('Max download Mbps'));
			o.default = '50';
			o.depends({ protocol: 'hysteria' });

			o = section.option(form.Value, 'hysteria_recv_window_conn', _('QUIC stream receive window'));
			o.depends({ protocol: 'hysteria' });

			o = section.option(form.Value, 'hysteria_recv_window', _('QUIC connection receive window'));
			o.depends({ protocol: 'hysteria' });

			o = section.option(form.Flag, 'hysteria_disable_mtu_discovery', _('Disable MTU detection'));
			o.depends({ protocol: 'hysteria' });

			o = section.option(form.ListValue, 'tuic_congestion_control', _('Congestion control algorithm'));
			o.default = 'cubic';
			o.value('bbr', _('BBR'));
			o.value('cubic', _('CUBIC'));
			o.value('new_reno', _('New Reno'));
			o.depends({ protocol: 'tuic' });

			o = section.option(form.ListValue, 'tuic_udp_relay_mode', _('UDP relay mode'));
			o.default = 'native';
			o.value('native', _('native'));
			o.value('quic', _('QUIC'));
			o.depends({ protocol: 'tuic' });

			o = section.option(form.Flag, 'tuic_zero_rtt_handshake', _('Enable 0-RTT QUIC handshake'));
			o.default = '0';
			o.depends({ protocol: 'tuic' });

			o = section.option(form.Value, 'tuic_heartbeat', _('Heartbeat interval(second)'));
			o.datatype = 'uinteger';
			o.default = '3';
			o.depends({ protocol: 'tuic' });

			o = section.option(form.ListValue, 'tuic_alpn', _('QUIC TLS ALPN'));
			o.default = 'default';
			o.value('default', _('Default'));
			o.value('h3');
			o.value('h2');
			o.value('h3,h2');
			o.value('http/1.1');
			o.value('h2,http/1.1');
			o.value('h3,h2,http/1.1');
			o.value('spdy/3.1');
			o.value('h3,spdy/3.1');
			o.depends({ protocol: 'tuic' });

			o = section.option(form.Value, 'hysteria2_hop', _('Port hopping range'));
			o.description = _('Format as 1000:2000 or 1000-2000 Multiple groups are separated by commas (,).');
			o.depends({ protocol: 'hysteria2', hysteria2_realms: false });

			o = section.option(form.Value, 'hysteria2_hop_interval', _('Hop Interval(second)'), _('Supports a fixed value or a random range (e.g., 30, 5-30), minimum 5.'));
			o.datatype = 'or(uinteger,portrange)';
			o.placeholder = '30';
			o.default = '30';
			o.depends({ protocol: 'hysteria2', hysteria2_realms: false });

			o = section.option(form.Flag, 'hysteria2_realms', _('Realms'));
			o.default = '0';
			o.depends({ protocol: 'hysteria2' });

			o = section.option(form.Value, 'hysteria2_realm_url', _('Realm URL'), _('Example:') + 'realm://public@realm.hy2.io/your-realm-name');
			o.depends({ hysteria2_realms: '1' });
			o.validate = function(section_id, value) {
				if (parseRealm(value))
					return true;
				return _('Invalid Realm URL.');
			};
			o.write = function(section_id, value) {
				return uci.set('passwall', section_id, 'hysteria2_realm_url', String(value || '').trim());
			};

			o = section.option(form.DynamicList, 'hysteria2_realm_stun', _('Realm STUN'));
			o.default = [ 'stun.sip.us:3478', 'stun.nextcloud.com:3478', 'global.stun.twilio.com:3478' ];
			o.depends({ hysteria2_realms: '1' });

			o = section.option(form.Flag, 'hysteria2_realm_upnp', _('Enable') + ' UPnP/NAT-PMP', _('Enable UPnP/NAT-PMP port mapping on your gateway to improve hole punching success.'));
			o.default = '0';
			o.depends({ hysteria2_realms: '1' });

			o = section.option(form.Value, 'hysteria2_auth_password', _('Auth Password'));
			o.password = true;
			o.depends({ protocol: 'hysteria2' });

			o = section.option(form.ListValue, 'hysteria2_obfs_type', _('Obfs Type'));
			o.value('', _('Disable'));
			o.value('salamander');
			o.value('gecko');
			o.depends({ protocol: 'hysteria2' });

			o = section.option(form.Value, 'hysteria2_obfs_password', _('Obfs Password'));
			o.depends({ hysteria2_obfs_type: 'salamander' });
			o.depends({ hysteria2_obfs_type: 'gecko' });

			o = section.option(form.Value, 'hysteria2_obfs_MinPacketSize', _('Gecko Packet Size (min)'));
			o.datatype = 'uinteger';
			o.placeholder = '512';
			o.default = '512';
			o.depends({ hysteria2_obfs_type: 'gecko' });

			o = section.option(form.Value, 'hysteria2_obfs_MaxPacketSize', _('Gecko Packet Size (max)'));
			o.datatype = 'uinteger';
			o.placeholder = '1200';
			o.default = '1200';
			o.depends({ hysteria2_obfs_type: 'gecko' });

			o = section.option(form.Value, 'hysteria2_up_mbps', _('Max upload Mbps'));
			o.depends({ protocol: 'hysteria2' });

			o = section.option(form.Value, 'hysteria2_down_mbps', _('Max download Mbps'));
			o.depends({ protocol: 'hysteria2' });

			o = section.option(form.Value, 'hysteria2_stream_recv_win', _('QUIC stream receive window') + ' (MB)');
			o.datatype = 'range(1,1000)';
			o.placeholder = '8';
			o.depends({ protocol: 'hysteria2' });

			o = section.option(form.Value, 'hysteria2_conn_recv_win', _('QUIC connection receive window') + ' (MB)');
			o.datatype = 'range(1,1000)';
			o.placeholder = '20';
			o.depends({ protocol: 'hysteria2' });

			o = section.option(form.Value, 'hysteria2_idle_timeout', _('Idle Timeout'), _('Units:seconds') + ' (4~120)');
			o.datatype = 'range(4,120)';
			o.depends({ protocol: 'hysteria2' });

			o = section.option(form.Value, 'hysteria2_keep_alive_period', _('QUIC KeepAlive interval'), _('Units:seconds') + ' (2~60)');
			o.datatype = 'range(2,60)';
			o.depends({ protocol: 'hysteria2' });

			o = section.option(form.Flag, 'hysteria2_disable_mtu_discovery', _('Disable MTU detection'));
			o.default = '0';
			o.depends({ protocol: 'hysteria2' });

			o = section.option(form.TextValue, 'ssh_priv_key', _('Private Key'));
			o.rows = 5;
			o.wrap = 'off';
			o.depends({ protocol: 'ssh' });
			o.write = function(section_id, value) {
				value = String(value || '').trim().replace(/\r\n/g, '\n').replace(/[ \t]*\n[ \t]*/g, '\n').replace(/\n+/g, '\n');
				if (!value)
					return uci.unset('passwall', section_id, 'ssh_priv_key');
				return uci.set('passwall', section_id, 'ssh_priv_key', value);
			};

			o = section.option(form.Value, 'ssh_priv_key_pp', _('Private Key Passphrase'));
			o.password = true;
			o.depends({ protocol: 'ssh' });

			o = section.option(form.DynamicList, 'ssh_host_key', _('Host Key'), _('Accept any if empty.'));
			o.depends({ protocol: 'ssh' });

			o = section.option(form.DynamicList, 'ssh_host_key_algo', _('Host Key Algorithms'));
			o.depends({ protocol: 'ssh' });

			o = section.option(form.Value, 'ssh_client_version', _('Client Version'), _('Random version will be used if empty.'));
			o.depends({ protocol: 'ssh' });

			o = section.option(form.Value, 'naive_insecure_concurrency', _('Concurrent Tunnels'));
			o.datatype = 'uinteger';
			o.placeholder = '0';
			o.default = '0';
			o.depends({ protocol: 'naive' });

			o = section.option(form.Flag, 'naive_quic', _('QUIC'));
			o.default = '0';
			o.depends({ protocol: 'naive' });

			o = section.option(form.ListValue, 'naive_congestion_control', _('Congestion control algorithm'));
			o.default = 'bbr';
			o.value('bbr', _('BBR'));
			o.value('bbr2', _('BBRv2'));
			o.value('cubic', _('CUBIC'));
			o.value('reno', _('New Reno'));
			o.depends({ naive_quic: '1' });

			o = section.option(form.Flag, 'tls', _('TLS'));
			o.default = '0';
			o.depends({ protocol: 'vmess' });
			o.depends({ protocol: 'vless' });
			o.depends({ protocol: 'http' });
			o.depends({ protocol: 'trojan' });
			o.depends({ protocol: 'shadowsocks' });
			o.depends({ protocol: 'anytls' });

			o = section.option(form.ListValue, 'alpn', _('ALPN'));
			alpn(o);
			o.depends({ tls: true });
			o.depends({ protocol: 'hysteria' });

			o = section.option(form.Flag, 'tls_disable_sni', _('Disable SNI'), _('Do not send server name in ClientHello.'));
			o.default = '0';
			o.depends({ tls: true });
			o.depends({ protocol: 'hysteria' });
			o.depends({ protocol: 'tuic' });
			o.depends({ protocol: 'hysteria2' });
			o.depends({ protocol: 'masque' });

			o = section.option(form.Value, 'tls_serverName', 'SNI ' + _('Domain'));
			o.depends({ tls: true });
			o.depends({ protocol: 'hysteria' });
			o.depends({ protocol: 'tuic' });
			o.depends({ protocol: 'hysteria2' });
			o.depends({ protocol: 'naive' });
			o.depends({ protocol: 'masque' });

			o = section.option(form.Flag, 'tls_allowInsecure', _('allowInsecure'), _('Whether unsafe connections are allowed. When checked, Certificate validation will be skipped.'));
			o.default = '0';
			o.depends({ tls: true });
			o.depends({ protocol: 'hysteria' });
			o.depends({ protocol: 'tuic' });
			o.depends({ protocol: 'hysteria2' });
			o.depends({ protocol: 'masque' });

			o = section.option(form.Value, 'tls_pinSHA256', _('TLS Chain Fingerprint (SHA256)'));
			o.depends({ tls: true });
			o.depends({ protocol: 'hysteria' });
			o.depends({ protocol: 'tuic' });
			o.depends({ protocol: 'hysteria2' });
			o.depends({ protocol: 'masque' });
			o.description = _('Once set, connects only when the server’s chain fingerprint matches.') +
				'<a href="javascript:void(0)" onclick="fetchCertSha256(this)">→ ' + _('Fetch Manually') + '</a>';

			o = section.option(form.Flag, 'tls_certificate', _('TLS Certificate (PEM)'));
			o.default = '0';
			o.depends({ tls: true, reality: false });
			o.depends({ protocol: 'hysteria' });
			o.depends({ protocol: 'tuic' });
			o.depends({ protocol: 'hysteria2' });
			o.depends({ protocol: 'naive' });
			o.depends({ protocol: 'masque' });

			o = section.option(form.TextValue, 'tls_certificate_pem', '　', _('Full certificate (chain), PEM format.'));
			o.default = '';
			o.rows = 5;
			o.wrap = 'off';
			o.depends({ tls_certificate: true });
			bindEscaped(o, 'tls_certificate_pem');

			o = section.option(form.Value, 'cipherSuites', _('Cipher Suites'), '<a href="https://go.dev/src/crypto/tls/cipher_suites.go#L44" target="_blank">***</a> ' + _('Configures the list of supported cipher suites, separated by :'));
			o.depends({ tls: true });
			o.depends({ protocol: 'masque' });

			o = section.option(form.Flag, 'ech', _('ECH'));
			o.default = '0';
			o.depends({ tls: true, flow: '', reality: false });
			o.depends({ protocol: 'tuic' });
			o.depends({ protocol: 'hysteria' });
			o.depends({ protocol: 'hysteria2', hysteria2_realms: false });
			o.depends({ protocol: 'naive' });
			o.depends({ protocol: 'masque' });

			o = section.option(form.TextValue, 'ech_config', _('ECH Config'));
			o.default = '';
			o.rows = 5;
			o.wrap = 'off';
			o.depends({ ech: true });
			bindEscaped(o, 'ech_config');

			o = section.option(form.Value, 'ech_query_server_name', _('ECH Query Domain'), _('Overrides the domain name used for ECH HTTPS record queries.'));
			o.depends({ ech: true });

			o = section.option(form.Flag, 'utls', _('uTLS'));
			o.default = '0';
			o.depends({ tls: true });

			o = section.option(form.ListValue, 'fingerprint', _('Finger Print'));
			fingerprints(o, true);
			o.depends({ utls: true });

			o = section.option(form.Flag, 'reality', _('REALITY'));
			o.default = '0';
			o.depends({ protocol: 'vless', tls: true });
			o.depends({ protocol: 'vmess', tls: true });
			o.depends({ protocol: 'shadowsocks', tls: true });
			o.depends({ protocol: 'trojan', tls: true });
			o.depends({ protocol: 'anytls', tls: true });
			o.depends({ protocol: 'http', tls: true });

			o = section.option(form.Value, 'reality_publicKey', _('Public Key'));
			o.depends({ reality: true });

			o = section.option(form.Value, 'reality_shortId', _('Short Id'));
			o.depends({ reality: true });

			o = section.option(form.ListValue, 'transport', _('Transport'));
			o.value('tcp', 'TCP');
			o.value('http', 'HTTP');
			o.value('ws', 'WebSocket');
			o.value('httpupgrade', 'HTTPUpgrade');
			o.value('quic', 'QUIC');
			o.value('grpc', 'gRPC');
			o.value('grpc', 'gRPC-lite');
			o.depends({ protocol: 'vmess' });
			o.depends({ protocol: 'vless' });
			o.depends({ protocol: 'shadowsocks' });
			o.depends({ protocol: 'trojan' });

			o = section.option(form.Value, 'wireguard_public_key', _('Public Key'));
			o.depends({ protocol: 'wireguard' });

			o = section.option(form.Value, 'wireguard_secret_key', _('Private Key'));
			o.depends({ protocol: 'wireguard' });

			o = section.option(form.Value, 'wireguard_preSharedKey', _('Pre shared key'));
			o.depends({ protocol: 'wireguard' });

			o = section.option(form.DynamicList, 'wireguard_local_address', _('Local Address'));
			o.depends({ protocol: 'wireguard' });

			o = section.option(form.Value, 'wireguard_mtu', _('MTU'));
			o.default = '1420';
			o.depends({ protocol: 'wireguard' });

			o = section.option(form.Value, 'wireguard_reserved', _('Reserved'), _('Decimal numbers separated by "," or Base64-encoded strings.'));
			o.depends({ protocol: 'wireguard' });

			o = section.option(form.ListValue, 'tcp_guise', _('Camouflage Type'));
			o.value('none', 'none');
			o.value('http', 'http');
			o.depends({ transport: 'tcp' });

			o = section.option(form.DynamicList, 'tcp_guise_http_host', _('HTTP Host'));
			o.depends({ tcp_guise: 'http' });

			o = section.option(form.DynamicList, 'tcp_guise_http_path', _('HTTP Path'));
			o.placeholder = '/';
			o.depends({ tcp_guise: 'http' });

			o = section.option(form.DynamicList, 'http_host', _('HTTP Host'));
			o.depends({ transport: 'http' });

			o = section.option(form.Value, 'http_path', _('HTTP Path'));
			o.placeholder = '/';
			o.depends({ transport: 'http' });

			o = section.option(form.Flag, 'http_h2_health_check', _('Health check'));
			o.depends({ tls: true, transport: 'http' });

			o = section.option(form.Value, 'http_h2_read_idle_timeout', _('Idle timeout'));
			o.default = '15';
			o.depends({ http_h2_health_check: true });

			o = section.option(form.Value, 'http_h2_health_check_timeout', _('Health check timeout'));
			o.default = '15';
			o.depends({ http_h2_health_check: true });

			o = section.option(form.Value, 'ws_host', _('WebSocket Host'));
			o.depends({ transport: 'ws' });

			o = section.option(form.Value, 'ws_path', _('WebSocket Path'));
			o.placeholder = '/';
			o.depends({ transport: 'ws' });

			o = section.option(form.Value, 'httpupgrade_host', _('HTTPUpgrade Host'));
			o.depends({ transport: 'httpupgrade' });

			o = section.option(form.Value, 'httpupgrade_path', _('HTTPUpgrade Path'));
			o.placeholder = '/';
			o.depends({ transport: 'httpupgrade' });

			o = section.option(form.Value, 'grpc_serviceName', 'ServiceName');
			o.depends({ transport: 'grpc' });

			o = section.option(form.Flag, 'grpc_health_check', _('Health check'));
			o.depends({ transport: 'grpc' });

			o = section.option(form.Value, 'grpc_idle_timeout', _('Idle timeout'));
			o.default = '15';
			o.depends({ grpc_health_check: true });

			o = section.option(form.Value, 'grpc_health_check_timeout', _('Health check timeout'));
			o.default = '15';
			o.depends({ grpc_health_check: true });

			o = section.option(form.Flag, 'grpc_permit_without_stream', _('Permit without stream'));
			o.default = '0';
			o.depends({ grpc_health_check: true });

			o = section.option(form.Value, 'user_agent', _('User-Agent'));
			o.default = '';
			userAgents.forEach(function(pair) { o.value(pair[0], pair[1]); });
			o.depends({ tcp_guise: 'http' });
			o.depends({ transport: 'http' });
			o.depends({ transport: 'ws' });
			o.depends({ transport: 'httpupgrade' });
			o.depends({ protocol: 'naive' });
			o.depends({ protocol: 'masque' });

			o = section.option(form.Flag, 'mux', _('Mux'));
			o.rmempty = false;
			o.depends({ protocol: 'vmess' });
			o.depends({ protocol: 'vless', flow: '' });
			o.depends({ protocol: 'shadowsocks', uot: '' });
			o.depends({ protocol: 'trojan' });

			o = section.option(form.ListValue, 'mux_type', _('Mux'));
			o.value('smux');
			o.value('yamux');
			o.value('h2mux');
			o.depends({ mux: true });

			o = section.option(form.Value, 'mux_concurrency', _('Mux concurrency'));
			o.default = '4';
			o.depends({ mux: true, tcpbrutal: false });

			o = section.option(form.Flag, 'mux_padding', _('Padding'));
			o.default = '0';
			o.depends({ mux: true });

			o = section.option(form.Flag, 'tcpbrutal', _('TCP Brutal'));
			o.default = '0';
			o.depends({ mux: true });

			o = section.option(form.Value, 'tcpbrutal_up_mbps', _('Max upload Mbps'));
			o.default = '10';
			o.depends({ tcpbrutal: true });

			o = section.option(form.Value, 'tcpbrutal_down_mbps', _('Max download Mbps'));
			o.default = '50';
			o.depends({ tcpbrutal: true });

			o = section.option(form.Flag, 'shadowtls', 'ShadowTLS');
			o.default = '0';
			o.depends({ protocol: 'vmess', tls: false });
			o.depends({ protocol: 'shadowsocks', tls: false });

			o = section.option(form.ListValue, 'shadowtls_version', 'ShadowTLS ' + _('Version'));
			o.default = '1';
			o.value('1', 'ShadowTLS v1');
			o.value('2', 'ShadowTLS v2');
			o.value('3', 'ShadowTLS v3');
			o.depends({ shadowtls: true });

			o = section.option(form.Value, 'shadowtls_password', 'ShadowTLS ' + _('Password'));
			o.password = true;
			o.depends({ shadowtls: true, shadowtls_version: '2' });
			o.depends({ shadowtls: true, shadowtls_version: '3' });

			o = section.option(form.Value, 'shadowtls_serverName', 'ShadowTLS ' + _('Domain'));
			o.depends({ shadowtls: true });

			o = section.option(form.Flag, 'shadowtls_utls', 'ShadowTLS ' + _('uTLS'));
			o.default = '0';
			o.depends({ shadowtls: true });

			o = section.option(form.ListValue, 'shadowtls_fingerprint', 'ShadowTLS ' + _('Finger Print'));
			fingerprints(o, false);
			o.depends({ shadowtls: true, shadowtls_utls: true });

			o = section.option(form.Flag, 'plugin_enabled', _('plugin'));
			o.default = '0';
			o.depends({ protocol: 'shadowsocks' });

			o = section.option(form.ListValue, 'plugin', 'SIP003 ' + _('plugin'));
			o.default = 'obfs-local';
			o.depends({ plugin_enabled: true });
			o.value('obfs-local');
			o.value('v2ray-plugin');

			o = section.option(form.Value, 'plugin_opts', _('opts'));
			o.depends({ plugin_enabled: true });

			var domainResolver = section.option(form.ListValue, 'domain_resolver', _('Domain DNS Resolve'));
			domainResolver.description = _('If the node address is a domain name, this DNS will be used for resolution.') + '<br>' +
				'<font color="red">' + _('Note: For node-specific DNS only. Keep Auto to avoid extra overhead.') + '</font>';
			domainResolver.value('', _('Auto'));
			domainResolver.value('tcp', 'TCP');
			domainResolver.value('udp', 'UDP');
			domainResolver.value('https', 'DoH');

			o = section.option(form.Value, 'domain_resolver_dns', 'DNS');
			o.datatype = 'or(ipaddr,ipaddrport)';
			o.value('114.114.114.114');
			o.value('223.5.5.5:53');
			o.default = '114.114.114.114';
			o.depends({ domain_resolver: 'tcp' });
			o.depends({ domain_resolver: 'udp' });

			o = section.option(form.Value, 'domain_resolver_dns_https', 'DNS');
			o.value('https://120.53.53.53/dns-query', 'DNSPod');
			o.value('https://223.5.5.5/dns-query', 'AliDNS');
			o.default = 'https://120.53.53.53/dns-query';
			o.depends({ domain_resolver: 'https' });

			var domainStrategy = section.option(form.ListValue, 'domain_strategy', _('Domain Strategy'), _('If is domain name, The requested domain name will be resolved to IP before connect.'));
			domainStrategy.default = '';
			domainStrategy.value('', _('Auto'));
			domainStrategy.value('prefer_ipv4', _('Prefer IPv4'));
			domainStrategy.value('prefer_ipv6', _('Prefer IPv6'));
			domainStrategy.value('ipv4_only', _('IPv4 Only'));
			domainStrategy.value('ipv6_only', _('IPv6 Only'));

			normalProtos.forEach(function(p) {
				var dep = { protocol: p };
				if (p === 'hysteria2')
					dep.hysteria2_realms = false;
				address.depends(dep);
				port.depends(dep);
				domainResolver.depends(dep);
				domainStrategy.depends(dep);
			});
		}

		if (!isShunt) {
			o = section.option(form.ListValue, 'chain_proxy', _('Chain Proxy'));
			o.value('', _('Close(Not use)'));
			if (!(isIface || isUrltest)) {
				o.value('1', _('Preproxy Node'));
				o.value('3', _('Outbound Interface'));
			}
			o.value('2', _('Landing Node'));

			var pre = section.option(form.ListValue, 'preproxy_node', _('Preproxy Node'), _('Only support a layer of proxy.'));
			pre.depends({ chain_proxy: '1', hysteria2_realms: false });
			addChoices(pre, cat.socks, selfId);
			addChoices(pre, cat.normal, selfId);
			addChoices(pre, cat.special.urltest, selfId);
			addChoices(pre, cat.special.balancing, selfId);

			o = section.option(form.Value, 'outbound_iface', _('Outbound Interface'));
			o.depends({ chain_proxy: '3' });
			fillDevices(o, caps.devices, true);

			var land = section.option(form.ListValue, 'to_node', _('Landing Node'), _('Only support a layer of proxy.'));
			land.depends({ chain_proxy: '2', hysteria2_realms: false });
			addChoices(land, cat.normal, selfId);
		}

		if (isShunt)
			addShunt(section, selfId, caps);
	}
});
