'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require fs';
'require poll';
'require view.passwall.tools as pw';

var APP = 'passwall';

function cleanText(text) {
	return String(text == null ? '' : text)
		.replace(/\t/g, ' ')
		.replace(/\u00A0/g, ' ')
		.replace(/\u3000/g, ' ')
		.replace(/^\s+/, '')
		.replace(/\s+$/, '\n')
		.replace(/\r\n/g, '\n')
		.replace(/[ \t]*\n[ \t]*/g, '\n');
}

function isIPv4(v) {
	var m = String(v || '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	if (!m)
		return false;
	var i;
	for (i = 1; i <= 4; i++) {
		if (+m[i] > 255)
			return false;
	}
	return true;
}

function isIPv6(v) {
	v = String(v || '');
	if (!v || v.indexOf(':') < 0 || v.indexOf(':::') >= 0)
		return false;
	var halves = v.split('::');
	if (halves.length > 2)
		return false;
	function parseSide(side) {
		if (side === '')
			return 0;
		var bits = side.split(':');
		var i;
		for (i = 0; i < bits.length; i++) {
			if (i === bits.length - 1 && isIPv4(bits[i]))
				return (bits.length - 1) + 2;
			if (!/^[0-9A-Fa-f]{1,4}$/.test(bits[i]))
				return -1;
		}
		return bits.length;
	}
	if (halves.length === 1)
		return parseSide(v) === 8;
	var left = parseSide(halves[0]);
	var right = parseSide(halves[1]);
	if (left < 0 || right < 0)
		return false;
	return (left + right) < 8;
}

function isIp4Addr(v) {
	var parts = String(v || '').split('/');
	if (!isIPv4(parts[0]))
		return false;
	if (parts.length === 1)
		return true;
	if (parts.length !== 2 || !/^\d+$/.test(parts[1]))
		return false;
	var n = +parts[1];
	return n >= 0 && n <= 32;
}

function isDottedMask(v) {
	var m = String(v || '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	if (!m)
		return false;
	var i;
	for (i = 1; i <= 4; i++) {
		if (+m[i] > 255)
			return false;
	}
	return true;
}

function isIpMask4(v) {
	var parts = String(v || '').split('/');
	if (!isIPv4(parts[0]))
		return false;
	if (parts.length === 1)
		return true;
	if (parts.length !== 2)
		return false;
	if (/^\d+$/.test(parts[1])) {
		var n = +parts[1];
		return n >= 0 && n <= 32;
	}
	return isDottedMask(parts[1]);
}

function isIpMask6(v) {
	var text = String(v || '');
	var slash = text.lastIndexOf('/');
	if (slash < 0)
		return isIPv6(text);
	var addr = text.slice(0, slash);
	var pref = text.slice(slash + 1);
	if (!isIPv6(addr) || !/^\d+$/.test(pref))
		return false;
	var n = +pref;
	return n >= 0 && n <= 128;
}

function isHostname(value) {
	value = String(value || '');
	if (!(value.length < 254))
		return false;
	if (/^[a-zA-Z_]+$/.test(value))
		return true;
	return /^[a-zA-Z0-9_][a-zA-Z0-9_\-.]*[a-zA-Z0-9]$/.test(value) && /[^0-9.]/.test(value);
}

function listItems(value) {
	if (Array.isArray(value))
		return value;
	if (value == null || value === '')
		return [];
	return String(value).split(/\s+/).filter(function(part) { return part !== ''; });
}

function bulletDescription(option, lines) {
	option.description = ' ';
	var orig = option.render;
	option.render = function() {
		return Promise.resolve(orig.apply(this, arguments)).then(function(el) {
			var box = el.querySelector('.cbi-value-description');
			if (!box)
				return el;
			while (box.firstChild)
				box.removeChild(box.firstChild);
			var ul = E('ul', {});
			lines.forEach(function(line) {
				if (Array.isArray(line)) {
					var li = E('li', {}, line[0]);
					var nested = E('ul', {});
					line.slice(1).forEach(function(child) {
						nested.appendChild(E('li', {}, child));
					});
					li.appendChild(nested);
					ul.appendChild(li);
				}
				else {
					ul.appendChild(E('li', {}, line));
				}
			});
			box.appendChild(E('br'));
			box.appendChild(ul);
			return el;
		});
	};
}

function validateDomainList(section_id, value) {
	var lines = cleanText(value).split('\n');
	var i;
	for (i = 0; i < lines.length; i++) {
		var host = lines[i];
		if (!host)
			continue;
		var flag = 1;
		var tmp = host;
		if (host.indexOf('#') < 0 && /\s/.test(host)) {
			flag = 1;
		}
		else if (host.indexOf('regexp:') === 0) {
			flag = 0;
		}
		else if (/^domain:./.test(host)) {
			tmp = host.replace('domain:', '');
		}
		else if (/^full:./.test(host)) {
			tmp = host.replace('full:', '');
		}
		else if (host.indexOf('geosite:') === 0) {
			flag = 0;
		}
		else if (host.indexOf('rule-set:') === 0 || host.indexOf('rs:') === 0) {
			var rest = host.substring(host.indexOf(':') + 1);
			if (rest.indexOf('local:') === 0 || rest.indexOf('remote:') === 0)
				flag = 0;
		}
		else if (host.indexOf('#') === 0) {
			flag = 0;
		}
		if (flag === 1 && !isHostname(tmp))
			return tmp + ' ' + _('Not valid domain name, please re-enter!');
	}
	return true;
}

function validateIpList(section_id, value) {
	var lines = cleanText(value).split('\n');
	var i;
	for (i = 0; i < lines.length; i++) {
		var ipmask = lines[i];
		if (!ipmask)
			continue;
		if (ipmask.indexOf('geoip:') === 0 && !/\s/.test(ipmask))
			continue;
		if (ipmask.indexOf('rule-set:') === 0 || ipmask.indexOf('rs:') === 0)
			continue;
		if (ipmask.indexOf('#') === 0)
			continue;
		if (!(isIpMask4(ipmask) || isIpMask6(ipmask)))
			return ipmask + ' ' + _('Not valid IP format, please re-enter!');
	}
	return true;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(APP),
			pw.loadCaps()
		]);
	},

	render: function() {
		var id = pw.routeArg();
		var section = id ? uci.get(APP, id) : null;
		if (!id || !section || section['.type'] !== 'shunt_rules') {
			window.location.href = pw.pageUrl('rule');
			return E('div', {});
		}

		var globals = uci.sections(APP, 'global') || [];
		var globalId = globals.length ? globals[0]['.name'] : null;
		var remarksLookup = {};
		var groups = {};
		(uci.sections(APP, 'shunt_rules') || []).forEach(function(rule) {
			if (rule['.name'] === id)
				return;
			if (rule.remarks)
				remarksLookup[rule.remarks] = rule['.name'];
			if (rule.group)
				groups[rule.group] = true;
		});

		var m = new form.Map(APP);
		var s = m.section(form.NamedSection, id, 'shunt_rules', 'Sing-Box/Xray ' + _('Shunt Rule'));
		s.addremove = false;
		s.anonymous = true;

		var remarks = s.option(form.Value, 'remarks', _('Remarks'));
		remarks.default = id;
		remarks.rmempty = false;
		remarks.validate = function(section_id, value) {
			value = String(value == null ? '' : value).trim();
			if (!value)
				return _('Remark cannot be empty.');
			if (remarksLookup[value])
				return _('This remark already exists, please change a new remark.');
			return true;
		};
		remarks.write = function(section_id, value) {
			return form.Value.prototype.write.call(this, section_id, String(value == null ? '' : value).trim());
		};

		var group = s.option(form.Value, 'group', _('Shunt Rule Group'));
		group.default = '';
		group.value('', _('default'));
		Object.keys(groups).forEach(function(name) {
			group.value(name, name);
		});
		group.write = function(section_id, value) {
			value = String(value == null ? '' : value).trim();
			var lower = value.toLowerCase();
			if (!lower || lower === 'default')
				return uci.unset(APP, section_id, 'group');
			var keys = this.keylist || [];
			var i;
			for (i = 0; i < keys.length; i++) {
				if (String(keys[i]).toLowerCase() === lower)
					return uci.set(APP, section_id, 'group', keys[i]);
			}
			return uci.set(APP, section_id, 'group', value);
		};
		group.remove = function(section_id) {
			return uci.unset(APP, section_id, 'group');
		};

		var protocol = s.option(form.MultiValue, 'protocol', _('Protocol'));
		protocol.value('http');
		protocol.value('tls');
		protocol.value('quic');
		protocol.value('bittorrent');
		protocol.rmempty = true;
		protocol.write = function(section_id, value) {
			var list = Array.isArray(value) ? value : (value ? [ value ] : []);
			if (!list.length)
				return uci.unset(APP, section_id, 'protocol');
			return form.MultiValue.prototype.write.call(this, section_id, list);
		};

		var inbound = s.option(form.MultiValue, 'inbound', _('Inbound Tag'));
		inbound.value('tproxy', _('Transparent proxy'));
		inbound.value('socks', 'Socks');
		inbound.rmempty = true;
		inbound.write = function(section_id, value) {
			var list = Array.isArray(value) ? value : (value ? [ value ] : []);
			if (!list.length)
				return uci.unset(APP, section_id, 'inbound');
			return form.MultiValue.prototype.write.call(this, section_id, list);
		};

		var network = s.option(form.ListValue, 'network', _('Network'));
		network.value('tcp,udp', 'TCP UDP');
		network.value('tcp', 'TCP');
		network.value('udp', 'UDP');

		var source = s.option(form.DynamicList, 'source', _('Source'));
		bulletDescription(source, [
			_('Example:'),
			_('IP') + ': 192.168.1.100',
			_('IP CIDR') + ': 192.168.1.0/24',
			_('GeoIP') + ': geoip:private'
		]);
		source.cfgvalue = function(section_id, set_value) {
			if (arguments.length === 2) {
				if (typeof set_value === 'string')
					set_value = listItems(set_value);
				return form.DynamicList.prototype.cfgvalue.call(this, section_id, set_value);
			}
			return form.DynamicList.prototype.cfgvalue.call(this, section_id);
		};
		source.write = function(section_id, value) {
			var seen = {};
			var out = [];
			listItems(value).forEach(function(item) {
				item = String(item || '').trim();
				if (!item || seen[item])
					return;
				seen[item] = true;
				out.push(item);
			});
			if (!out.length)
				return uci.unset(APP, section_id, 'source');
			return uci.set(APP, section_id, 'source', out.join(' '));
		};
		source.validate = function(section_id, value) {
			var err = [];
			listItems(value).forEach(function(item) {
				var ok = isIp4Addr(item) || item.indexOf('geoip:') === 0;
				if (!ok)
					err.push(item);
			});
			if (err.length)
				return _('Not true format, please re-enter!') + '\n' + err.join('\n');
			return true;
		};

		s.option(form.Value, 'port', _('port'));

		var domainList = s.option(form.TextValue, 'domain_list', _('Domain'));
		domainList.rows = 10;
		domainList.wrap = 'off';
		domainList.monospace = true;
		domainList.validate = validateDomainList;
		domainList.write = function(section_id, value) {
			return form.TextValue.prototype.write.call(this, section_id, cleanText(value));
		};
		bulletDescription(domainList, [
			_('Plaintext: If this string matches any part of the targeting domain, this rule takes effet. Example: rule \'sina.com\' matches targeting domain \'sina.com\', \'sina.com.cn\' and \'www.sina.com\', but not \'sina.cn\'.'),
			_('Regular expression: Begining with \'regexp:\', the rest is a regular expression. When the regexp matches targeting domain, this rule takes effect. Example: rule \'regexp:\\.goo.*\\.com$\' matches \'www.google.com\' and \'fonts.googleapis.com\', but not \'google.com\'.'),
			_('Subdomain (recommended): Begining with \'domain:\' and the rest is a domain. When the targeting domain is exactly the value, or is a subdomain of the value, this rule takes effect. Example: rule \'domain:v2ray.com\' matches \'www.v2ray.com\', \'v2ray.com\', but not \'xv2ray.com\'.'),
			_('Full domain: Begining with \'full:\' and the rest is a domain. When the targeting domain is exactly the value, the rule takes effect. Example: rule \'domain:v2ray.com\' matches \'v2ray.com\', but not \'www.v2ray.com\'.'),
			_('Pre-defined domain list: Begining with \'geosite:\' and the rest is a name, such as geosite:google or geosite:cn.'),
			[
				_('Sing-Box is compatible with Geo rules and rule-set. rule-set begin with \'rule-set:remote:\' or \'rule-set:local:\'.'),
				_('Such as:') + '\'rule-set:remote:https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs\'',
				_('Such as:') + '\'rule-set:local:/usr/share/sing-box/geosite-cn.srs\''
			],
			_('Annotation: Begining with #')
		]);

		var ipList = s.option(form.TextValue, 'ip_list', 'IP');
		ipList.rows = 10;
		ipList.wrap = 'off';
		ipList.monospace = true;
		ipList.validate = validateIpList;
		ipList.write = function(section_id, value) {
			return form.TextValue.prototype.write.call(this, section_id, cleanText(value));
		};
		bulletDescription(ipList, [
			_('IP: such as \'127.0.0.1\'.'),
			_('CIDR: such as \'127.0.0.0/8\'.'),
			_('GeoIP: such as \'geoip:cn\'. It begins with geoip: (lower case) and followed by two letter of country code.'),
			[
				_('Sing-Box is compatible with Geo rules and rule-set. rule-set begin with \'rule-set:remote:\' or \'rule-set:local:\'.'),
				_('Such as:') + '\'rule-set:remote:https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs\'',
				_('Such as:') + '\'rule-set:local:/usr/share/sing-box/geoip-cn.srs\''
			],
			_('Annotation: Begining with #')
		]);

		var invert = s.option(form.Flag, 'invert', 'Invert');
		invert.description = _('Invert match result.') + ' ' + _('Only support Sing-Box.');

		this.globalId = globalId;
		return m.render().then(function(node) {
			var style = E('style', {}, [
				'div[id^="cbid.passwall."] .cbi-value-field{display:flex;flex-wrap:wrap;gap:1em;}',
				'div[id^="cbid.passwall."] .cbi-checkbox{display:inline-flex;align-items:center;}'
			].join(''));
			var root = E('div', {}, [ style, node ]);
			pw.paintHtml(root);
			return root;
		});
	},

	handleSave: function(ev) {
		if (this.globalId)
			uci.set(APP, this.globalId, 'flush_set', '1');
		return this.super('handleSave', [ ev ]);
	}
});
