'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require fs';
'require poll';
'require view.passwall.tools as pw';

var APP = 'passwall';
var RULE_DIR = '/etc/passwall/rules/';

function present(v) {
	return !(v == null || v === false || v === '' || v === 0);
}

function fileExists(path) {
	return fs.stat(path).then(function() {
		return true;
	}).catch(function() {
		return false;
	});
}

function geoDir(loc) {
	var value = loc || '/usr/share/v2ray/';
	var match = String(value).match(/^(.*)\//);
	return match ? match[1] : value;
}

function versionGE(left, right) {
	function parts(v) {
		return String(v || '').split(/[.\-]/).map(function(part) {
			var n = parseInt(part, 10);
			return isNaN(n) ? 0 : n;
		});
	}
	var a = parts(left);
	var b = parts(right);
	var n = Math.max(a.length, b.length);
	var i;
	for (i = 0; i < n; i++) {
		var s1 = a[i] || 0;
		var s2 = b[i] || 0;
		if (s1 > s2)
			return true;
		if (s1 < s2)
			return false;
	}
	return true;
}

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

function linesOf(value) {
	var out = [];
	cleanText(value).split('\n').forEach(function(line) {
		var text = line.trim();
		if (text)
			out.push(text);
	});
	return out;
}

function isIPv4(v) {
	var m = String(v || '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	if (!m)
		return false;
	var i;
	for (i = 1; i <= 4; i++) {
		var n = +m[i];
		if (n > 255)
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
			if (i === bits.length - 1 && isIPv4(bits[i])) {
				if (bits.length === 1 && side.indexOf(':') < 0)
					return 2;
				return (bits.length - 1) + 2;
			}
			if (!/^[0-9A-Fa-f]{1,4}$/.test(bits[i]))
				return -1;
		}
		return bits.length;
	}
	if (halves.length === 1) {
		var count = parseSide(v);
		return count === 8;
	}
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

function fileOption(section, tab, name, path, description, validate) {
	var o = section.taboption(tab, form.TextValue, name, '', description);
	o.rows = 15;
	o.wrap = 'off';
	o.monospace = true;
	o.rmempty = true;
	o.load = function(section_id) {
		if (section_id == null)
			return Promise.resolve('');
		return pw.readText(path);
	};
	o.write = function(section_id, value) {
		return pw.writeText(path, cleanText(value));
	};
	o.remove = function() {
		return pw.writeText(path, '');
	};
	o.validate = function(section_id, value) {
		return validate(value);
	};
	return o;
}

function hostValidator(value) {
	var bad = null;
	linesOf(value).forEach(function(host) {
		if (bad)
			return;
		if (host.charAt(0) === '#' || host.indexOf('geosite:') === 0)
			return;
		if (!isHostname(host))
			bad = host + ' ' + _('Not valid domain name, please re-enter!');
	});
	return bad || true;
}

function ipValidator(value) {
	var bad = null;
	linesOf(value).forEach(function(ipmask) {
		if (bad)
			return;
		if (ipmask.charAt(0) === '#' || ipmask.indexOf('geoip:') === 0)
			return;
		if (!(isIpMask4(ipmask) || isIpMask6(ipmask)))
			bad = ipmask + ' ' + _('Not valid IP format, please re-enter!');
	});
	return bad || true;
}

function lanValidator(value, v6) {
	var bad = null;
	linesOf(value).forEach(function(ipmask) {
		if (bad)
			return;
		if (ipmask.charAt(0) === '#')
			return;
		var ok = v6 ? isIpMask6(ipmask) : isIpMask4(ipmask);
		if (!ok)
			bad = ipmask + ' ' + (v6 ? _('Not valid IPv6 format, please re-enter!') : _('Not valid IPv4 format, please re-enter!'));
	});
	return bad || true;
}

function readOnlyList(section, tab, id, type) {
	var o = section.taboption(tab, form.DummyValue, id, '');
	o.render = function() {
		return E('div', { 'class': 'cbi-value' }, [
			E('div', { 'style': 'display:flex;align-items:center;width:100%' }, [
				E('input', {
					'class': 'btn cbi-button cbi-button-add',
					'type': 'button',
					'value': _('Read List'),
					'click': function(ev) { loadList(ev.target, type, id); }
				}),
				E('label', { 'id': id + '_total_lines', 'style': 'margin-left:auto;margin-right:10px' })
			]),
			E('textarea', {
				'id': id + '_textarea',
				'class': 'cbi-input-textarea',
				'style': 'width:100%;margin-top:10px',
				'rows': '40',
				'wrap': 'off',
				'readonly': 'readonly'
			})
		]);
	};
}

function loadList(btn, type, id) {
	btn.disabled = true;
	pw.call('read_rulelist', { type: type }).then(function(res) {
		var data = '';
		if (typeof res === 'string')
			data = res;
		else if (res && typeof res.output === 'string')
			data = res.output;
		var lines = data.split('\n').filter(function(line) { return line.trim() !== ''; });
		var area = document.getElementById(id + '_textarea');
		var label = document.getElementById(id + '_total_lines');
		if (area)
			area.value = data;
		if (label)
			label.textContent = _('Total Lines') + ' ' + lines.length;
	}).catch(function(err) {
		ui.addNotification(null, E('p', {}, err.message || String(err)));
	}).then(function() {
		btn.disabled = false;
	});
}

function renderGeoView() {
	function query(btn, action, input, other) {
		var value = String(input.value || '').trim();
		if (!value) {
			alert(_('Please enter query content!'));
			return;
		}
		btn.disabled = true;
		other.disabled = true;
		var previous = btn.value;
		btn.value = _('Querying');
		var area = document.getElementById('geoview_textarea');
		if (area)
			area.value = '';
		pw.call('geo_view', { action: action, value: value }).then(function(res) {
			var data = '';
			if (typeof res === 'string')
				data = res;
			else if (res && typeof res.output === 'string')
				data = res.output;
			if (area)
				area.value = data;
		}).catch(function(err) {
			ui.addNotification(null, E('p', {}, err.message || String(err)));
		}).then(function() {
			btn.disabled = false;
			other.disabled = false;
			btn.value = previous;
		});
	}
	var lookupInput = E('input', {
		'type': 'text',
		'class': 'cbi-input-text',
		'id': 'geoview.lookup'
	});
	var extractInput = E('input', {
		'type': 'text',
		'class': 'cbi-input-text',
		'id': 'geoview.extract'
	});
	var lookupBtn = E('input', {
		'class': 'btn cbi-button cbi-button-apply',
		'type': 'button',
		'id': 'lookup-view_btn',
		'value': _('Query')
	});
	var extractBtn = E('input', {
		'class': 'btn cbi-button cbi-button-apply',
		'type': 'button',
		'id': 'extract-view_btn',
		'value': _('Query')
	});
	lookupBtn.addEventListener('click', function() {
		query(lookupBtn, 'lookup', lookupInput, extractBtn);
	});
	extractBtn.addEventListener('click', function() {
		query(extractBtn, 'extract', extractInput, lookupBtn);
	});
	function onEnter(input, btn) {
		input.addEventListener('keydown', function(ev) {
			if (ev.key !== 'Enter' && ev.keyCode !== 13)
				return;
			ev.stopPropagation();
			ev.preventDefault();
			input.blur();
			btn.click();
		});
	}
	onEnter(lookupInput, lookupBtn);
	onEnter(extractInput, extractBtn);
	return E('div', {}, [
		E('style', {}, [
			'.faq-title{color:var(--primary);font-weight:bolder;margin-bottom:0.5rem;display:inline-block;}',
			'.faq-item{margin-bottom:0.8rem;line-height:1.2rem;}',
			'.geoview-search{display:flex;gap:2px;align-items:center;white-space:nowrap;}'
		].join('')),
		E('div', { 'class': 'cbi-value' }, [
			E('ul', {}, [
				E('b', { 'class': 'faq-title' }, _('Tips:')),
				E('li', { 'class': 'faq-item' }, [ '1. ', E('span', {}, _('By entering a domain or IP, you can query the Geo rule list they belong to.')) ]),
				E('li', { 'class': 'faq-item' }, [ '2. ', E('span', {}, _('By entering a GeoIP or Geosite, you can extract the domains/IPs they contain.')) ]),
				E('li', { 'class': 'faq-item' }, [ '3. ', E('span', {}, _('Use the GeoIP/Geosite query function to verify if the entered Geo rules are correct.')) ])
			])
		]),
		E('div', { 'class': 'cbi-value', 'id': 'cbi-passwall-geoview-lookup' }, [
			E('label', { 'class': 'cbi-value-title', 'for': 'geoview.lookup' }, _('Domain/IP Query')),
			E('div', { 'class': 'cbi-value-field' }, [
				E('div', { 'class': 'geoview-search' }, [ lookupInput, lookupBtn ]),
				E('div', { 'class': 'cbi-value-description' }, _('Enter a domain or IP to query the Geo rule list they belong to.'))
			])
		]),
		E('div', { 'class': 'cbi-value', 'id': 'cbi-passwall-geoview-extract' }, [
			E('label', { 'class': 'cbi-value-title', 'for': 'geoview.extract' }, _('GeoIP/Geosite Query')),
			E('div', { 'class': 'cbi-value-field' }, [
				E('div', { 'class': 'geoview-search' }, [ extractInput, extractBtn ]),
				E('div', { 'class': 'cbi-value-description' }, _('Enter a GeoIP or Geosite to extract the domains/IPs they contain. Format: geoip:cn or geosite:gfw'))
			])
		]),
		E('div', { 'class': 'cbi-value' }, [
			E('textarea', {
				'id': 'geoview_textarea',
				'class': 'cbi-input-textarea',
				'style': 'width:100%;margin-top:10px',
				'rows': '25',
				'wrap': 'off',
				'readonly': 'readonly'
			})
		])
	]);
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(APP),
			pw.loadCaps()
		]).then(function(data) {
			var caps = data[1] || {};
			var rules = uci.sections(APP, 'global_rules') || [];
			var sid = rules.length ? rules[0]['.name'] : null;
			var loc = sid ? (uci.get(APP, sid, 'v2ray_location_asset') || '/usr/share/v2ray/') : '/usr/share/v2ray/';
			var dir = geoDir(loc);
			return Promise.all([
				fileExists(dir + '/geosite.dat'),
				fileExists(dir + '/geoip.dat'),
				present(caps.geoview) ? pw.call('com_version', { com: 'geoview' }).catch(function() { return null; }) : null
			]).then(function(geo) {
				var version = geo[2] && geo[2].data;
				if (version && typeof version === 'object')
					version = version.version || version.ver || '';
				return {
					caps: caps,
					sid: sid,
					geoFiles: !!(geo[0] && geo[1]),
					geoVersion: version || ''
				};
			});
		});
	},

	render: function(data) {
		var caps = data.caps || {};
		var sid = data.sid;
		var globals = uci.sections(APP, 'global') || [];
		var globalId = globals.length ? globals[0]['.name'] : null;
		if (!sid)
			return E('div', { 'class': 'alert-message warning' }, _('Rule status'));

		var showGeo = present(caps.geoview) && data.geoFiles && versionGE(data.geoVersion, '0.1.0');
		var m = new form.Map(APP);
		var s = m.section(form.NamedSection, sid, 'global_rules');
		s.anonymous = true;
		s.tab('direct_list', _('Direct List'));
		s.tab('proxy_list', _('Proxy List'));
		s.tab('block_list', _('Block List'));
		s.tab('lan_ip_list', _('Lan IP List'));
		s.tab('route_hosts', _('Route Hosts'));

		fileOption(s, 'direct_list', 'direct_host', RULE_DIR + 'direct_host',
			_('Join the direct hosts list of domain names will not proxy.'), hostValidator);
		fileOption(s, 'direct_list', 'direct_ip', RULE_DIR + 'direct_ip',
			_('These had been joined ip addresses will not proxy. Please input the ip address or ip address segment,every line can input only one ip address. For example: 192.168.0.0/24 or 223.5.5.5.'), ipValidator);
		fileOption(s, 'proxy_list', 'proxy_host', RULE_DIR + 'proxy_host',
			_('These had been joined websites will use proxy. Please input the domain names of websites, every line can input only one website domain. For example: google.com.'), hostValidator);
		fileOption(s, 'proxy_list', 'proxy_ip', RULE_DIR + 'proxy_ip',
			_('These had been joined ip addresses will use proxy. Please input the ip address or ip address segment, every line can input only one ip address. For example: 35.24.0.0/24 or 8.8.4.4.'), ipValidator);
		fileOption(s, 'block_list', 'block_host', RULE_DIR + 'block_host',
			_('These had been joined websites will be block. Please input the domain names of websites, every line can input only one website domain. For example: twitter.com.'), hostValidator);
		fileOption(s, 'block_list', 'block_ip', RULE_DIR + 'block_ip',
			_('These had been joined ip addresses will be block. Please input the ip address or ip address segment, every line can input only one ip address.'), ipValidator);
		fileOption(s, 'lan_ip_list', 'lanlist_ipv4', RULE_DIR + 'lanlist_ipv4',
			_('The list is the IPv4 LAN IP list, which represents the direct connection IP of the LAN. If you need the LAN IP in the proxy list, please clear it from the list. Do not modify this list by default.'),
			function(value) { return lanValidator(value, false); });
		fileOption(s, 'lan_ip_list', 'lanlist_ipv6', RULE_DIR + 'lanlist_ipv6',
			_('The list is the IPv6 LAN IP list, which represents the direct connection IP of the LAN. If you need the LAN IP in the proxy list, please clear it from the list. Do not modify this list by default.'),
			function(value) { return lanValidator(value, true); });
		fileOption(s, 'route_hosts', 'hosts', '/etc/hosts',
			_('Configure routing etc/hosts file, if you don\'t know what you are doing, please don\'t change the content.'),
			function() { return true; });

		if (caps.has_gfwlist) {
			s.tab('gfw_list', _('GFW List'));
			readOnlyList(s, 'gfw_list', '_gfw', 'gfw');
		}
		if (caps.has_chnlist) {
			s.tab('chn_list', _('China List') + '(' + _('Domain') + ')');
			readOnlyList(s, 'chn_list', '_chn', 'chn');
		}
		if (caps.has_chnroute) {
			s.tab('chnroute_list', _('China List') + '(IP)');
			readOnlyList(s, 'chnroute_list', '_chnroute', 'chnroute');
		}
		if (showGeo) {
			s.tab('geoview', _('Geo View'));
			var geo = s.taboption('geoview', form.DummyValue, '_geoview_fieldset', '');
			geo.render = function() { return renderGeoView(); };
		}

		this.globalId = globalId;
		return m.render();
	},

	handleSave: function(ev) {
		if (this.globalId)
			uci.set(APP, this.globalId, 'flush_set', '1');
		return this.super('handleSave', [ ev ]);
	}
});
