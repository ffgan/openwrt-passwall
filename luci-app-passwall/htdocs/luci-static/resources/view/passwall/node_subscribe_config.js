'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require poll';
'require validation';
'require view.passwall.tools as pw';

var APP = 'passwall';

if (!validation.types.timehhmm) {
	validation.types.timehhmm = function() {
		var match = String(this.value == null ? '' : this.value).match(/^(\d?\d):(\d\d)$/);
		var ok = false;
		if (match) {
			var hour = parseInt(match[1], 10);
			var minute = parseInt(match[2], 10);
			ok = hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59;
		}
		return this.assert(ok, _('valid time (hh:mm)'));
	};
}

function present(v) {
	return !(v == null || v === false || v === '' || v === 0);
}

function urlEncode(text) {
	return String(text == null ? '' : text).replace(/[^A-Za-z0-9_.~-]/g, function(ch) {
		var bytes = unescape(encodeURIComponent(ch));
		var out = '';
		for (var i = 0; i < bytes.length; i++)
			out += '%' + ('0' + bytes.charCodeAt(i).toString(16).toUpperCase()).slice(-2);
		return out;
	});
}

function coreTypes(caps) {
	var ss = [];
	var trojan = [];
	var vmess = [];
	var vless = [];
	var hy2 = [];
	caps = caps || {};
	if (present(caps.sslocal))
		ss.push('shadowsocks-rust');
	if (present(caps.singbox)) {
		trojan.push('sing-box');
		ss.push('sing-box');
		vmess.push('sing-box');
		vless.push('sing-box');
		hy2.push('sing-box');
	}
	if (present(caps.xray)) {
		trojan.push('xray');
		ss.push('xray');
		vmess.push('xray');
		vless.push('xray');
		if (caps.xray_ge && caps.xray_ge['26.1.13'])
			hy2.push('xray');
	}
	if (present(caps.hysteria))
		hy2.push('hysteria2');
	return { ss: ss, trojan: trojan, vmess: vmess, vless: vless, hy2: hy2 };
}

function paintHtml(root) {
	if (!root || !root.querySelectorAll)
		return;
	root.querySelectorAll('.cbi-value-description, .cbi-section-descr, .cbi-map-descr').forEach(function(el) {
		var text = el.textContent || '';
		if (text.indexOf('<') === -1)
			return;
		el.innerHTML = text;
	});
}

function renameGroup(oldRemark, newRemark) {
	if (oldRemark === newRemark)
		return;
	var oldLower = String(oldRemark || '').toLowerCase();
	var oldEnc = urlEncode(oldRemark);
	var newEnc = urlEncode(newRemark);
	(uci.sections(APP, 'nodes') || []).forEach(function(node) {
		var id = node['.name'];
		if (node.group && String(node.group).toLowerCase() === oldLower)
			uci.set(APP, id, 'group', newRemark);
		if ((node.protocol === '_balancing' || node.protocol === '_urltest') && node.node_group) {
			var parts = String(node.node_group).match(/\S+/g) || [];
			var gs = parts.map(function(g) {
				return g === oldEnc ? newEnc : g;
			}).join(' ');
			uci.set(APP, id, 'node_group', gs.trim());
		}
	});
}

function chainNodes(caps) {
	var items = [];
	var nodes = (caps && Array.isArray(caps.nodes)) ? caps.nodes : [];
	nodes.forEach(function(node) {
		if (!node || node.node_type !== 'normal')
			return;
		if (node.type !== 'Xray' && node.type !== 'sing-box')
			return;
		if (node.chain_proxy)
			return;
		if (String(node.add_mode) === '2')
			return;
		var id = node.id || node['.name'];
		if (!id)
			return;
		var group = (node.group && node.group !== '') ? node.group : _('default');
		items.push({
			value: id,
			label: node.remark || id,
			group: group
		});
	});
	return items;
}

function fillGrouped(option, items) {
	var groups = {};
	var order = [];
	items.forEach(function(item) {
		option.value(item.value, item.label);
		var group = item.group || '';
		if (!groups[group]) {
			groups[group] = [];
			order.push(group);
		}
		groups[group].push(item);
	});
	option.renderWidget = function(section_id, option_index, cfgvalue) {
		var current = cfgvalue == null ? '' : String(cfgvalue);
		var sel = E('select', {
			'id': this.cbid(section_id),
			'class': 'cbi-input-select',
			'data-update': 'change'
		});
		var seen = {};
		order.forEach(function(group) {
			var parent = sel;
			if (group) {
				parent = E('optgroup', { label: group });
				sel.appendChild(parent);
			}
			groups[group].forEach(function(item) {
				seen[item.value] = true;
				parent.appendChild(E('option', { value: item.value }, item.label));
			});
		});
		if (current && !seen[current])
			sel.appendChild(E('option', { value: current }, current));
		sel.value = current;
		return sel;
	};
	option.formvalue = function(section_id) {
		var sel = document.getElementById(this.cbid(section_id));
		if (sel)
			return sel.value;
		var stored = uci.get(APP, section_id, this.option);
		return stored == null ? '' : stored;
	};
	return option;
}

function addCoreOption(section, name, label, values) {
	if (!values.length)
		return null;
	var o = section.option(form.ListValue, name, label);
	o.default = 'global';
	o.value('global', _('Use global config'));
	values.forEach(function(value) {
		o.value(value);
	});
	return o;
}

function hourOptions(option) {
	for (var t = 0; t < 24; t++)
		option.value(t + ':00');
	return option;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(APP),
			pw.loadCaps().catch(function() { return {}; })
		]);
	},

	render: function(data) {
		var id = pw.routeArg();
		var section = id ? uci.get(APP, id) : null;
		if (!id || !section || section['.type'] !== 'subscribe_list') {
			window.location.href = pw.pageUrl('node_subscribe');
			return E('div');
		}

		var caps = data[1] || {};
		var types = coreTypes(caps);
		var m = new form.Map(APP);
		var s = m.section(form.NamedSection, id, 'subscribe_list');
		s.addremove = false;

		var o = s.option(form.Value, 'remark', _('Subscribe Remark'));
		o.rmempty = false;
		o.validate = function(section_id, value) {
			var text = String(value == null ? '' : value).trim();
			if (text === '')
				return _('Remark cannot be empty.');
			var lower = text.toLowerCase();
			var duplicate = false;
			(uci.sections(APP, 'subscribe_list') || []).forEach(function(sec) {
				if (sec['.name'] !== section_id && sec.remark && String(sec.remark).toLowerCase() === lower)
					duplicate = true;
			});
			if (duplicate || lower === 'default')
				return _('This remark already exists, please change a new remark.');
			return true;
		};
		o.write = function(section_id, value) {
			value = String(value == null ? '' : value).trim();
			var old = uci.get(APP, section_id, 'remark') || '';
			if (old !== value)
				renameGroup(old, value);
			return uci.set(APP, section_id, 'remark', value);
		};

		o = s.option(form.TextValue, 'url', _('Subscribe URL'));
		o.rows = 5;
		o.rmempty = false;
		o.validate = function(section_id, value) {
			if (value == null || String(value) === '')
				return _('URL cannot be empty.');
			return true;
		};
		o.write = function(section_id, value) {
			value = String(value).replace(/\s+/g, '').replace(/\0/g, '');
			return uci.set(APP, section_id, 'url', value);
		};

		o = s.option(form.ListValue, 'domain_resolver', _('Domain DNS Resolve'));
		o.description = _('If the node address is a domain name, this DNS will be used for resolution.') + '<br>' +
			_('Supports only Xray or Sing-box node types.') + '<br>' +
			'<span class="pw-warn">' + _('Note: For node-specific DNS only. Keep Auto to avoid extra overhead.') + '</span>';
		o.value('', _('Auto'));
		o.value('tcp', 'TCP');
		o.value('udp', 'UDP');
		o.value('https', 'DoH');

		o = s.option(form.Value, 'domain_resolver_dns', 'DNS');
		o.datatype = 'or(ipaddr,ipaddrport)';
		o.value('114.114.114.114');
		o.value('223.5.5.5:53');
		o.default = '114.114.114.114';
		o.depends({ domain_resolver: 'tcp' });
		o.depends({ domain_resolver: 'udp' });

		o = s.option(form.Value, 'domain_resolver_dns_https', 'DNS');
		o.value('https://120.53.53.53/dns-query', 'DNSPod');
		o.value('https://223.5.5.5/dns-query', 'AliDNS');
		o.default = 'https://120.53.53.53/dns-query';
		o.depends({ domain_resolver: 'https' });

		o = s.option(form.ListValue, 'domain_strategy', _('Domain Strategy'), _('If is domain name, The requested domain name will be resolved to IP before connect.'));
		o.default = '';
		o.value('', _('Auto'));
		o.value('UseIPv4v6', _('Prefer IPv4'));
		o.value('UseIPv6v4', _('Prefer IPv6'));
		o.value('UseIPv4', _('IPv4 Only'));
		o.value('UseIPv6', _('IPv6 Only'));

		o = s.option(form.Flag, 'allowInsecure', _('allowInsecure'));
		o.enabled = '1';
		o.disabled = '0';
		o.default = '0';
		o.rmempty = false;
		o.description = _('Whether unsafe connections are allowed. When checked, Certificate validation will be skipped.') + '<br>' +
			_('Used when the node link does not include this parameter.');

		o = s.option(form.ListValue, 'filter_keyword_mode', _('Filter keyword Mode'));
		o.default = '5';
		o.value('0', _('Close'));
		o.value('1', _('Discard List'));
		o.value('2', _('Keep List'));
		o.value('3', _('Discard List,But Keep List First'));
		o.value('4', _('Keep List,But Discard List First'));
		o.value('5', _('Use global config'));

		o = s.option(form.DynamicList, 'filter_discard_list', _('Discard List'));
		o.depends('filter_keyword_mode', '1');
		o.depends('filter_keyword_mode', '3');
		o.depends('filter_keyword_mode', '4');

		o = s.option(form.DynamicList, 'filter_keep_list', _('Keep List'));
		o.depends('filter_keyword_mode', '2');
		o.depends('filter_keyword_mode', '3');
		o.depends('filter_keyword_mode', '4');

		addCoreOption(s, 'ss_type', _('%s Node Use Type').replace('%s', 'Shadowsocks'), types.ss);
		addCoreOption(s, 'trojan_type', _('%s Node Use Type').replace('%s', 'Trojan'), types.trojan);
		addCoreOption(s, 'vmess_type', _('%s Node Use Type').replace('%s', 'VMess'), types.vmess);
		addCoreOption(s, 'vless_type', _('%s Node Use Type').replace('%s', 'VLESS'), types.vless);
		if (types.hy2.length) {
			addCoreOption(s, 'hysteria2_type', _('%s Node Use Type').replace('%s', 'Hysteria2'), types.hy2);
			o = s.option(form.Value, 'hysteria_up_mbps', 'Hy/Hy2 ' + _('Max upload Mbps'));
			o.datatype = 'uinteger';
			o = s.option(form.Value, 'hysteria_down_mbps', 'Hy/Hy2 ' + _('Max download Mbps'));
			o.datatype = 'uinteger';
		}

		o = s.option(form.Flag, 'boot_update', _('Update Once on Boot'), _('Updates the subscription the first time PassWall runs automatically after each system boot.'));
		o.enabled = '1';
		o.disabled = '0';
		o.default = '0';

		o = s.option(form.ListValue, 'update_week_mode', _('Auto Update Mode'));
		pw.weekMode(o, true);

		o = s.option(form.Value, 'update_time_mode', _('Update Time'));
		hourOptions(o);
		o.default = '0:00';
		o.datatype = 'timehhmm';
		['0', '1', '2', '3', '4', '5', '6', '7'].forEach(function(day) {
			o.depends('update_week_mode', day);
		});

		o = s.option(form.ListValue, 'update_interval_mode', _('Update Interval(hour)'));
		for (var hour = 1; hour <= 24; hour++)
			o.value(String(hour), hour + ' ' + _('hour'));
		o.default = '2';
		o.depends('update_week_mode', '8');
		o.rmempty = true;

		o = s.option(form.ListValue, 'access_mode', _('Subscribe URL Access Method'));
		o.default = '';
		o.value('', _('Auto'));
		o.value('direct', _('Direct Connection'));
		o.value('proxy', _('Proxy'));

		o = s.option(form.Value, 'user_agent', _('User-Agent'));
		o.default = 'passwall';
		o.value('passwall', 'PassWall');
		o.value('v2rayN/9.99', 'v2rayN');
		o.value('clash.meta/v9.99.99', 'Clash.Meta');
		o.value('Shadowrocket/9999 CFNetwork/3896.100.1.2.1 Darwin/27.0.0 iPhone19,7', 'Shadowrocket');
		o.value('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0', 'Edge for Linux');
		o.value('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0', 'Edge for Windows');

		o = s.option(form.ListValue, 'chain_proxy', _('Chain Proxy'));
		o.value('', _('Close(Not use)'));
		o.value('1', _('Preproxy Node'));
		o.value('2', _('Landing Node'));
		o.value('3', _('Outbound Interface'));

		var descr = _('Chained proxy works only with Xray or Sing-box nodes.<br>You can only use manual or imported nodes as chained nodes.') +
			'<br>' + _('Only support a layer of proxy.');
		var nodes = chainNodes(caps);

		o = s.option(form.ListValue, 'preproxy_node', _('Preproxy Node'));
		o.depends({ chain_proxy: '1' });
		o.description = descr;
		fillGrouped(o, nodes);

		o = s.option(form.ListValue, 'to_node', _('Landing Node'));
		o.depends({ chain_proxy: '2' });
		o.description = descr;
		fillGrouped(o, nodes);

		o = s.option(form.Value, 'outbound_iface', _('Outbound Interface'));
		o.depends({ chain_proxy: '3' });
		o.value('', _('All'));
		(caps.devices || []).forEach(function(dev) {
			if (dev && dev.name)
				o.value(dev.name, dev.label || dev.name);
		});

		var view = this;
		return m.render().then(function(node) {
			view.map = m;
			paintHtml(node);
			return node;
		});
	},

	handleSave: function(ev) {
		var id = pw.routeArg();
		if (id)
			uci.unset(APP, id, 'md5');
		return this.super('handleSave', [ev]);
	}
});
