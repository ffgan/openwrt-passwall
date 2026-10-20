'use strict';
'require baseclass';
'require form';
'require uci';

var ssMethodList = [
	'aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305', 'chacha20-ietf-poly1305', 'xchacha20-poly1305', 'xchacha20-ietf-poly1305',
	'2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'
];

var securityList = [ 'auto', 'aes-128-gcm', 'chacha20-poly1305' ];

var headerTypeList = [ 'none', 'srtp', 'utp', 'wechat-video', 'dtls', 'wireguard', 'dns' ];

var normalProtos = [ 'socks', 'http', 'vmess', 'vless', 'shadowsocks', 'trojan', 'wireguard', 'hysteria2', 'masque' ];

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

function b64enc(str) {
	return btoa(unescape(encodeURIComponent(String(str))));
}

function b64dec(str) {
	try {
		return decodeURIComponent(escape(atob(String(str))));
	}
	catch (e) {
		try { return atob(String(str)); }
		catch (e2) { return ''; }
	}
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
				group: n.group || ''
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

function matchHelp() {
	return _('Example: <code>^A && B && !C && D$</code><br>' +
		'This means the node remark must start with A (^), include B, exclude C (!), and end with D ($).<br>' +
		'Conditions are joined by <code>&&</code> (AND), and their order does not affect the result.<br>' +
		'Multiple groups can be separated by <code>||</code> (OR), matching succeeds if any group matches.<br>' +
		'Example: <code>A && B || C && D</code> means (A AND B) OR (C AND D).');
}

function probeIntervalHelp() {
	return _('The interval between initiating probes.') + '<br>' +
		_('The time format is numbers + units, such as \'10s\', \'2h45m\', and the supported time units are <code>s</code>, <code>m</code>, <code>h</code>, which correspond to seconds, minutes, and hours, respectively.') + '<br>' +
		_('When the unit is not filled in, it defaults to seconds.');
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

function bindEscaped(o, name) {
	o.cfgvalue = function(section_id) {
		return String(uci.get('passwall', section_id, name) || '').replace(/\\n/g, '\n');
	};
	o.write = function(section_id, value) {
		value = String(value || '').trim().replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/[ \t]*\n[ \t]*/g, '\n').replace(/\n+/g, '\n');
		if (!value)
			return uci.unset('passwall', section_id, name);
		return uci.set('passwall', section_id, name, value.replace(/\n/g, '\\n'));
	};
	o.remove = function(section_id) {
		return uci.unset('passwall', section_id, name);
	};
	return o;
}

function bindNewlineEscape(o, name) {
	o.cfgvalue = function(section_id) {
		return String(uci.get('passwall', section_id, name) || '').replace(/\\n/g, '\n');
	};
	o.write = function(section_id, value) {
		value = String(value || '').trim().replace(/\r\n/g, '\n').replace(/\r/g, '\n');
		if (!value)
			return uci.unset('passwall', section_id, name);
		return uci.set('passwall', section_id, name, value.replace(/\n/g, '\\n'));
	};
	return o;
}

function stripNewlines(name) {
	return function(section_id, value) {
		value = String(value || '').replace(/[\r\n]/g, '').trim();
		if (!value)
			return uci.unset('passwall', section_id, name);
		return uci.set('passwall', section_id, name, value);
	};
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
		if (!key || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(key) || headers[key] || key === 'host' || key === 'capsule-protocol')
			return _('Not true format, please re-enter!') + ' (' + line + ')';
		headers[key] = true;
	}
	return true;
}

function trimJson(value) {
	return String(value || '').trim().replace(/\r\n/g, '\n').replace(/^[ \t]*\n/, '').replace(/\n[ \t]*$/, '').replace(/\n[ \t]*\n/g, '\n');
}

function addShunt(section, selfId) {
	var o;
	var cat = catalog(selfId);

	o = section.option(form.ListValue, 'domainStrategy', _('Domain Strategy'));
	o.value('AsIs');
	o.value('IPIfNonMatch');
	o.value('IPOnDemand');
	o.default = 'IPOnDemand';
	o.description = '<br /><ul><li>' + _('\'AsIs\': Only use domain for routing. Default value.') +
		'</li><li>' + _('\'IPIfNonMatch\': When no rule matches current domain, resolves it into IP addresses (A or AAAA records) and try all rules again.') +
		'</li><li>' + _('\'IPOnDemand\': As long as there is a IP-based rule, resolves the domain into IP immediately.') +
		'</li></ul>';

	o = section.option(form.ListValue, 'domainMatcher', _('Domain matcher'));
	o.value('hybrid');
	o.value('linear');

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
				proxy: e['.name'] + '_proxy_tag'
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
		if (rule.id !== '.default')
			nodeOpt.description = '<a href="' + L.url('admin', 'services', 'passwall', 'shunt_rules', rule.id) + '" target="_blank">' + _('Rule') + '</a>';

		var fake = section.option(form.Flag, rule.fakedns, 'FakeDNS');
		fake.description = _('Use FakeDNS work in the domain that proxy.') + '\n' +
			_('Suitable scenarios for let the node servers get the target domain names.') + '\n' +
			_('Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.');
		pools.forEach(function(v) {
			if (v.id)
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

function addFallback(o, selfId, cat) {
	var MAX_FALLBACK_DEPTH = 3;
	var list = (cat.special.balancing || []).filter(function(v) {
		return v.id !== selfId;
	});

	function getDepth(id, depth) {
		depth = depth || 0;
		if (depth >= MAX_FALLBACK_DEPTH)
			return depth;
		for (var i = 0; i < list.length; i++) {
			if (list[i].id === id) {
				var fb = list[i].fallback;
				if (!fb || fb === '' || fb === '_direct')
					return depth;
				return getDepth(fb, depth + 1);
			}
		}
		return depth;
	}

	function willLoop(start, target, depth) {
		depth = depth || 0;
		if (depth >= MAX_FALLBACK_DEPTH)
			return false;
		for (var i = 0; i < list.length; i++) {
			if (list[i].id === target) {
				var fb = list[i].fallback;
				if (!fb || fb === '' || fb === '_direct')
					return false;
				if (fb === start)
					return true;
				return willLoop(start, fb, depth + 1);
			}
		}
		return false;
	}

	o.value('', _('Close(Not use)'));
	o.value('_direct', _('Direct Connection'));
	list.forEach(function(v) {
		if (getDepth(v.id) < MAX_FALLBACK_DEPTH && !willLoop(selfId, v.id))
			o.value(v.id, nodeLabel(v));
	});
	addChoices(o, cat.socks, selfId);
	addChoices(o, cat.normal, selfId);
	addChoices(o, cat.special.urltest, selfId);
}

return baseclass.extend({
	typeName: 'Xray',

	addOptions: function(section, caps) {
		caps = caps || {};
		var selfId = section.section;
		var protocol = uci.get('passwall', selfId, 'protocol') || '';
		var isBalancing = protocol === '_balancing';
		var isShunt = protocol === '_shunt';
		var isIface = protocol === '_iface';
		var normal = protocol.charAt(0) !== '_';
		var cat = catalog(selfId);
		var o;

		o = section.option(form.ListValue, 'protocol', _('Protocol'));
		o.value('socks', _('Socks'));
		o.value('http', _('HTTP'));
		o.value('vmess', _('Vmess'));
		o.value('vless', _('VLESS'));
		o.value('shadowsocks', _('Shadowsocks'));
		o.value('trojan', _('Trojan'));
		o.value('wireguard', _('WireGuard'));
		o.value('hysteria2', _('Hysteria2'));
		o.value('masque', 'MASQUE');
		o.value('_balancing', _('Balancing'));
		o.value('_shunt', _('Shunt'));
		o.value('_iface', _('Custom Interface'));
		if (typeof caps.onProtocolChange === 'function')
			caps.onProtocolChange(o);

		if (isBalancing) {
			o = section.option(form.ListValue, 'node_add_mode', _('Node Addition Method'));
			o.depends({ protocol: '_balancing' });
			o.default = 'manual';
			o.value('manual', _('Manual'));
			o.value('batch', _('Batch'));

			o = section.option(form.MultiValue, 'balancing_node', _('Load balancing node list'), _('Load balancing node list, <a target=\'_blank\' href=\'https://xtls.github.io/config/routing.html#balancerobject\'>document</a>'));
			o.depends({ node_add_mode: 'manual' });
			o.widget = 'checkbox';
			addChoices(o, cat.socks, null);
			addChoices(o, cat.normal, null);
			var balList = asList('balancing_node');
			o.cfgvalue = balList.cfgvalue;
			o.write = balList.write;

			o = section.option(form.MultiValue, 'node_group', _('Select Group'));
			o.depends({ node_add_mode: 'batch' });
			o.widget = 'checkbox';
			o.value('default', _('default'));
			cat.groups.forEach(function(g) { o.value(urlEncode(g), g); });
			var grp = asSpace('node_group');
			o.cfgvalue = grp.cfgvalue;
			o.write = grp.write;

			o = section.option(form.Value, 'node_match_rule', _('Node Matching Rules'));
			o.depends({ node_add_mode: 'batch' });
			o.description = matchHelp();

			o = section.option(form.ListValue, 'balancingStrategy', _('Balancing Strategy'));
			o.depends({ protocol: '_balancing' });
			o.value('random');
			o.value('roundRobin');
			o.value('leastPing');
			o.value('leastLoad');
			o.default = 'random';

			o = section.option(form.ListValue, 'fallback_node', _('Fallback Node'));
			o.depends({ protocol: '_balancing' });
			addFallback(o, selfId, cat);

			o = section.option(form.Flag, 'useCustomProbeUrl', _('Use Custom Probe URL'), _('By default the built-in probe URL will be used, enable this option to use a custom probe URL.'));
			o.depends({ protocol: '_balancing' });

			o = section.option(form.Value, 'probeUrl', _('Probe URL'));
			o.depends({ useCustomProbeUrl: true });
			probeUrls(o);

			o = section.option(form.Value, 'probeInterval', _('Probe Interval'));
			o.depends({ protocol: '_balancing' });
			o.default = '1m';
			o.placeholder = '1m';
			o.description = probeIntervalHelp();

			o = section.option(form.Value, 'expected', _('Preferred Node Count'));
			o.depends({ balancingStrategy: 'leastLoad' });
			o.datatype = 'uinteger';
			o.default = '2';
			o.placeholder = '2';
			o.description = _('The load balancer selects the optimal number of nodes, and traffic is randomly distributed among them.');

			o = section.option(form.Value, 'tolerance', _('Failure Tolerance (%)'));
			o.depends({ balancingStrategy: 'leastLoad' });
			o.datatype = 'uinteger';
			o.default = '10';
			o.placeholder = '10';
			o.description = _('The maximum acceptable speed test failure rate. For example, 1 means allowing a 1% failure rate.');
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

			o = section.option(form.Value, 'username', _('Username'));
			o.depends({ protocol: 'http' });
			o.depends({ protocol: 'socks' });
			o.depends({ protocol: 'masque' });

			o = section.option(form.Value, 'password', _('Password'));
			o.password = true;
			o.depends({ protocol: 'http' });
			o.depends({ protocol: 'socks' });
			o.depends({ protocol: 'shadowsocks' });
			o.depends({ protocol: 'trojan' });
			o.depends({ protocol: 'masque' });

			o = section.option(form.Flag, 'masque_warp', 'WARP');
			o.default = '0';
			o.depends({ protocol: 'masque' });

			o = section.option(form.TextValue, 'masque_warp_private_key', _('WARP Device Private Key'));
			o.rows = 3;
			o.wrap = 'off';
			o.depends({ protocol: 'masque', masque_warp: '1' });
			bindNewlineEscape(o, 'masque_warp_private_key');

			o = section.option(form.TextValue, 'masque_warp_public_key', _('WARP Endpoint Public Key'));
			o.rows = 3;
			o.wrap = 'off';
			o.depends({ protocol: 'masque', masque_warp: '1' });
			bindNewlineEscape(o, 'masque_warp_public_key');

			o = section.option(form.DynamicList, 'masque_warp_address', 'WARP ' + _('Local Address'));
			o.depends({ protocol: 'masque', masque_warp: '1' });

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

			o = section.option(form.ListValue, 'security', _('Encrypt Method'));
			securityList.forEach(function(v) { o.value(v); });
			o.depends({ protocol: 'vmess' });

			o = section.option(form.Value, 'encryption', _('Encrypt Method') + ' (encryption)');
			o.default = 'none';
			o.placeholder = 'none';
			o.depends({ protocol: 'vless' });
			o.validate = function(section_id, value) {
				return true;
			};
			o.write = function(section_id, value) {
				value = String(value || '').trim();
				return uci.set('passwall', section_id, 'encryption', value === '' ? 'none' : value);
			};

			/* ss_method is rewritten onto the UCI key "method". */
			o = section.option(form.ListValue, 'method', _('Encrypt Method'));
			ssMethodList.forEach(function(v) { o.value(v); });
			o.depends({ protocol: 'shadowsocks' });

			o = section.option(form.ListValue, 'flow', _('flow'));
			o.default = '';
			o.value('', _('Disable'));
			o.value('xtls-rprx-vision');
			o.value('xtls-rprx-vision-udp443');
			o.depends({ protocol: 'vless' });

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

			o = section.option(form.Flag, 'tls', _('TLS'));
			o.default = '0';
			o.depends({ protocol: 'vmess' });
			o.depends({ protocol: 'vless' });
			o.depends({ protocol: 'http' });
			o.depends({ protocol: 'trojan' });
			o.depends({ protocol: 'shadowsocks' });

			o = section.option(form.Flag, 'reality', _('REALITY'), _('Only recommend to use with VLESS-TCP-XTLS-Vision.'));
			o.default = '0';
			o.depends({ tls: true, transport: 'raw' });
			o.depends({ tls: true, transport: 'ws' });
			o.depends({ tls: true, transport: 'grpc' });
			o.depends({ tls: true, transport: 'httpupgrade' });
			o.depends({ tls: true, transport: 'xhttp' });

			o = section.option(form.ListValue, 'alpn', _('alpn'));
			o.default = 'default';
			o.value('default', _('Default'));
			o.value('h3');
			o.value('h2');
			o.value('h3,h2');
			o.value('http/1.1');
			o.value('h2,http/1.1');
			o.value('h3,h2,http/1.1');
			o.depends({ tls: true, reality: false });
			o.depends({ protocol: 'masque' });

			o = section.option(form.Value, 'tls_serverName', 'SNI ' + _('Domain'));
			o.depends({ tls: true });
			o.depends({ protocol: 'hysteria2' });
			o.depends({ protocol: 'masque' });

			o = section.option(form.Value, 'tls_pinSHA256', _('TLS Chain Fingerprint (SHA256)'));
			o.depends({ tls: true, reality: false });
			o.depends({ protocol: 'hysteria2' });
			o.depends({ protocol: 'masque' });
			o.description = _('Once set, connects only when the server’s chain fingerprint matches.') +
				'<a href="javascript:void(0)" onclick="fetchCertSha256(this)">→ ' + _('Fetch Manually') + '</a>';

			o = section.option(form.Value, 'tls_CertByName', _('TLS Certificate Name (CertName)'), _('TLS is used to verify the leaf certificate name.'));
			o.depends({ tls: true, reality: false });
			o.depends({ protocol: 'hysteria2' });
			o.depends({ protocol: 'masque' });

			o = section.option(form.Flag, 'tls_certificate', _('TLS Certificate (PEM)'));
			o.default = '0';
			o.depends({ tls: true, reality: false });
			o.depends({ protocol: 'hysteria2' });
			o.depends({ protocol: 'masque' });

			o = section.option(form.TextValue, 'tls_certificate_pem', '　', _('Full certificate (chain), PEM format.'));
			o.default = '';
			o.rows = 5;
			o.wrap = 'off';
			o.depends({ tls_certificate: true });
			bindEscaped(o, 'tls_certificate_pem');

			o = section.option(form.Flag, 'ech', _('ECH'));
			o.default = '0';
			o.depends({ tls: true, reality: false });
			o.depends({ protocol: 'hysteria2', hysteria2_realms: false });
			o.depends({ protocol: 'masque' });

			o = section.option(form.TextValue, 'ech_config', _('ECH Config'));
			o.default = '';
			o.rows = 5;
			o.wrap = 'soft';
			o.depends({ ech: true });
			o.write = stripNewlines('ech_config');

			o = section.option(form.Value, 'reality_publicKey', _('Public Key'));
			o.depends({ tls: true, reality: true });

			o = section.option(form.Value, 'reality_shortId', _('Short Id'));
			o.depends({ tls: true, reality: true });

			o = section.option(form.Value, 'reality_spiderX', _('Spider X'));
			o.placeholder = '/';
			o.depends({ tls: true, reality: true });

			o = section.option(form.Flag, 'utls', _('uTLS'));
			o.default = '0';
			o.depends({ tls: true, reality: false });

			o = section.option(form.ListValue, 'fingerprint', _('Finger Print'));
			[ 'chrome', 'firefox', 'edge', 'safari', '360', 'qq', 'ios', 'android', 'random', 'randomized', 'unsafe' ].forEach(function(v) {
				o.value(v);
			});
			o.default = 'chrome';
			o.depends({ tls: true, utls: true });
			o.depends({ tls: true, reality: true });

			o = section.option(form.Value, 'cipherSuites', _('Cipher Suites'), '<a href="https://go.dev/src/crypto/tls/cipher_suites.go#L44" target="_blank">***</a> ' + _('Configures the list of supported cipher suites, separated by :'));
			o.depends({ tls: true, reality: false });
			o.depends({ protocol: 'masque' });

			o = section.option(form.Flag, 'use_mldsa65Verify', _('ML-DSA-65'));
			o.default = '0';
			o.depends({ tls: true, reality: true });

			o = section.option(form.TextValue, 'reality_mldsa65Verify', 'ML-DSA-65 ' + _('Public key'));
			o.default = '';
			o.rows = 5;
			o.wrap = 'soft';
			o.depends({ use_mldsa65Verify: true });
			o.write = stripNewlines('reality_mldsa65Verify');

			o = section.option(form.ListValue, 'transport', _('Transport'));
			o.value('raw', 'RAW (TCP)');
			o.value('mkcp', 'mKCP');
			o.value('ws', 'WebSocket');
			o.value('grpc', 'gRPC');
			o.value('httpupgrade', 'HttpUpgrade');
			o.value('xhttp', 'XHTTP');
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

			o = section.option(form.Value, 'wireguard_keepAlive', _('Keep Alive'));
			o.default = '0';
			o.depends({ protocol: 'wireguard' });

			o = section.option(form.ListValue, 'tcp_guise', _('Camouflage Type'));
			o.value('none', 'none');
			o.value('http', 'http');
			o.depends({ transport: 'raw' });

			o = section.option(form.DynamicList, 'tcp_guise_http_host', _('HTTP Host'));
			o.depends({ tcp_guise: 'http' });

			o = section.option(form.DynamicList, 'tcp_guise_http_path', _('HTTP Path'));
			o.placeholder = '/';
			o.depends({ tcp_guise: 'http' });

			o = section.option(form.ListValue, 'mkcp_guise', _('Camouflage Type'), _('<br />none: default, no masquerade, data sent is packets with no characteristics.<br />srtp: disguised as an SRTP packet, it will be recognized as video call data (such as FaceTime).<br />utp: packets disguised as uTP will be recognized as bittorrent downloaded data.<br />wechat-video: packets disguised as WeChat video calls.<br />dtls: disguised as DTLS 1.2 packet.<br />wireguard: disguised as a WireGuard packet. (not really WireGuard protocol)<br />dns: Disguising traffic as DNS requests.'));
			headerTypeList.forEach(function(v) { o.value(v); });
			o.depends({ transport: 'mkcp' });

			o = section.option(form.Value, 'mkcp_domain', _('Camouflage Domain'), _('Use it together with the DNS disguised type. You can fill in any domain.'));
			o.depends({ mkcp_guise: 'dns' });

			o = section.option(form.Value, 'mkcp_mtu', _('KCP MTU'));
			o.datatype = 'uinteger';
			o.default = '1350';
			o.depends({ transport: 'mkcp' });

			o = section.option(form.Value, 'mkcp_seed', _('KCP Seed'));
			o.depends({ transport: 'mkcp' });

			o = section.option(form.Value, 'ws_host', _('WebSocket Host'));
			o.depends({ transport: 'ws' });

			o = section.option(form.Value, 'ws_path', _('WebSocket Path'));
			o.placeholder = '/';
			o.depends({ transport: 'ws' });

			o = section.option(form.Value, 'ws_heartbeatPeriod', _('HeartbeatPeriod(second)'));
			o.datatype = 'integer';
			o.depends({ transport: 'ws' });

			o = section.option(form.Value, 'grpc_serviceName', 'ServiceName');
			o.depends({ transport: 'grpc' });

			o = section.option(form.ListValue, 'grpc_mode', 'gRPC ' + _('Transfer mode'));
			o.value('gun');
			o.value('multi');
			o.depends({ transport: 'grpc' });

			o = section.option(form.Flag, 'grpc_health_check', _('Health check'));
			o.depends({ transport: 'grpc' });

			o = section.option(form.Value, 'grpc_idle_timeout', _('Idle timeout'));
			o.default = '10';
			o.depends({ grpc_health_check: true });

			o = section.option(form.Value, 'grpc_health_check_timeout', _('Health check timeout'));
			o.default = '20';
			o.depends({ grpc_health_check: true });

			o = section.option(form.Flag, 'grpc_permit_without_stream', _('Permit without stream'));
			o.default = '0';
			o.depends({ grpc_health_check: true });

			o = section.option(form.Value, 'grpc_initial_windows_size', _('Initial Windows Size'));
			o.default = '0';
			o.depends({ transport: 'grpc' });

			o = section.option(form.Value, 'httpupgrade_host', _('HttpUpgrade Host'));
			o.depends({ transport: 'httpupgrade' });

			o = section.option(form.Value, 'httpupgrade_path', _('HttpUpgrade Path'));
			o.placeholder = '/';
			o.depends({ transport: 'httpupgrade' });

			o = section.option(form.ListValue, 'xhttp_mode', 'XHTTP ' + _('Mode'));
			o.depends({ transport: 'xhttp' });
			o.default = 'auto';
			o.value('auto');
			o.value('packet-up');
			o.value('stream-up');
			o.value('stream-one');

			o = section.option(form.Value, 'xhttp_host', _('XHTTP Host'));
			o.depends({ transport: 'xhttp' });

			o = section.option(form.Value, 'xhttp_path', _('XHTTP Path'));
			o.placeholder = '/';
			o.depends({ transport: 'xhttp' });

			o = section.option(form.Flag, 'use_xhttp_extra', _('XHTTP Extra'));
			o.default = '0';
			o.depends({ transport: 'xhttp' });

			o = section.option(form.TextValue, 'xhttp_extra', '　', _('An XHttpObject in JSON format, used for sharing.'));
			o.depends({ use_xhttp_extra: true });
			o.rows = 10;
			o.wrap = 'off';
			o.datatype = 'json';
			o.cfgvalue = function(section_id) {
				var raw = uci.get('passwall', section_id, 'xhttp_extra');
				return raw ? b64dec(raw) : '';
			};
			o.validate = function(section_id, value) {
				value = trimJson(value);
				if (!value)
					return true;
				try {
					JSON.parse(value);
					return true;
				}
				catch (e) {
					return 'XHTTP Extra ' + _('Must be JSON text!');
				}
			};
			o.write = function(section_id, value) {
				value = trimJson(value);
				uci.set('passwall', section_id, 'xhttp_extra', value ? b64enc(value) : '');
				try {
					var data = JSON.parse(value);
					var dl = (data.extra && data.extra.downloadSettings && data.extra.downloadSettings.address) ||
						(data.downloadSettings && data.downloadSettings.address);
					if (dl) {
						dl = String(dl).replace(/^\[/, '').replace(/\]$/, '');
						uci.set('passwall', section_id, 'download_address', dl);
					}
					else {
						uci.unset('passwall', section_id, 'download_address');
					}
				}
				catch (e) {
					uci.unset('passwall', section_id, 'download_address');
				}
			};
			o.remove = function(section_id) {
				uci.unset('passwall', section_id, 'xhttp_extra');
				uci.unset('passwall', section_id, 'download_address');
			};

			o = section.option(form.Value, 'user_agent', _('User-Agent'));
			o.default = '';
			userAgents.forEach(function(pair) { o.value(pair[0], pair[1]); });
			o.depends({ tcp_guise: 'http' });
			o.depends({ transport: 'ws' });
			o.depends({ transport: 'httpupgrade' });
			o.depends({ transport: 'xhttp' });
			o.depends({ transport: 'grpc' });
			o.depends({ protocol: 'masque' });

			o = section.option(form.Flag, 'mux', 'Mux', _('Enable Mux.Cool'));
			o.depends({ protocol: 'vmess' });
			o.depends({ protocol: 'vless', transport: 'raw' });
			o.depends({ protocol: 'vless', transport: 'ws' });
			o.depends({ protocol: 'vless', transport: 'grpc' });
			o.depends({ protocol: 'vless', transport: 'httpupgrade' });
			o.depends({ protocol: 'http' });
			o.depends({ protocol: 'socks' });
			o.depends({ protocol: 'shadowsocks' });
			o.depends({ protocol: 'trojan' });

			o = section.option(form.Value, 'mux_concurrency', _('Mux concurrency'));
			o.default = '-1';
			o.depends({ mux: true });

			o = section.option(form.Value, 'xudp_concurrency', _('XUDP Mux concurrency'));
			o.default = '8';
			o.depends({ mux: true });

			o = section.option(form.Flag, 'use_finalmask', 'FinalMask');
			o.default = '0';
			o.depends({ protocol: 'vmess' });
			o.depends({ protocol: 'vless' });
			o.depends({ protocol: 'trojan' });
			o.depends({ protocol: 'shadowsocks' });
			o.depends({ protocol: 'wireguard' });
			o.depends({ protocol: 'hysteria2', hysteria2_realms: false });
			o.depends({ protocol: 'masque' });

			o = section.option(form.TextValue, 'finalmask', '　');
			o.depends({ use_finalmask: true });
			o.rows = 10;
			o.wrap = 'off';
			o.datatype = 'json';
			o.description = _('An FinalMaskObject in JSON format, used for sharing.') + '<br>' +
				_('Custom finalmask overrides mkcp, hysteria2, fragment, noise, and related settings.');
			o.cfgvalue = function(section_id) {
				var raw = uci.get('passwall', section_id, 'finalmask');
				return raw ? b64dec(raw) : '';
			};
			o.validate = function(section_id, value) {
				value = trimJson(value);
				if (!value)
					return true;
				try {
					JSON.parse(value);
					return true;
				}
				catch (e) {
					return 'FinalMask ' + _('Must be JSON text!');
				}
			};
			o.write = function(section_id, value) {
				value = trimJson(value);
				return uci.set('passwall', section_id, 'finalmask', value ? b64enc(value) : '');
			};
			o.remove = function(section_id) {
				return uci.unset('passwall', section_id, 'finalmask');
			};

			var tfo = section.option(form.Flag, 'tcp_fast_open', 'TCP ' + _('Fast Open'), _('Need node support required'));
			tfo.default = '0';

			var mptcp = section.option(form.Flag, 'tcpMptcp', 'tcpMptcp', _('Enable Multipath TCP, need to be enabled in both server and client configuration.'));
			mptcp.default = '0';

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
			domainStrategy.value('UseIPv4v6', _('Prefer IPv4'));
			domainStrategy.value('UseIPv6v4', _('Prefer IPv6'));
			domainStrategy.value('UseIPv4', _('IPv4 Only'));
			domainStrategy.value('UseIPv6', _('IPv6 Only'));

			var happy = section.option(form.Flag, 'happy_eyeballs', _('Enable Happy Eyeballs'), _('Attempts IPv4 and IPv6 simultaneously; automatically uses the faster connection.'));
			happy.default = '0';

			normalProtos.forEach(function(p) {
				var dep = { protocol: p };
				if (p === 'hysteria2')
					dep.hysteria2_realms = false;
				address.depends(dep);
				port.depends(dep);
				domainResolver.depends(dep);
				happy.depends(dep);
				var strategyDep = { protocol: p, happy_eyeballs: false };
				if (p === 'hysteria2')
					strategyDep.hysteria2_realms = false;
				domainStrategy.depends(strategyDep);
				if (p !== 'hysteria2') {
					tfo.depends({ protocol: p });
					mptcp.depends({ protocol: p });
				}
			});
		}

		if (!isShunt) {
			o = section.option(form.ListValue, 'chain_proxy', _('Chain Proxy'));
			o.value('', _('Close(Not use)'));
			if (!(isIface || isBalancing)) {
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
			addShunt(section, selfId);
	}
});
