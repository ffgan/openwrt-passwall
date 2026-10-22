'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require fs';
'require poll';
'require view.passwall.tools as pw';

var APP = 'passwall';
var TMP = '/tmp/etc/passwall';

function present(v) {
	return !(v == null || v === false || v === '' || v === 0);
}

function tf(fmt, arg) {
	return _(fmt).replace('%s', arg);
}

function nodeIdOf(n) {
	if (!n)
		return '';
	return n.id || n['.name'] || '';
}

function groupName(v) {
	return (v && v.group && v.group !== '') ? v.group : _('default');
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

function isMac(v) {
	return /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/.test(String(v || ''));
}

function isIpRange(v) {
	var m = String(v || '').match(/^([^/]+)-([^/]+)$/);
	return !!(m && isIPv4(m[1]) && isIPv4(m[2]));
}

function listItems(value) {
	if (Array.isArray(value))
		return value;
	if (value == null || value === '')
		return [];
	return String(value).split(/\s+/).filter(function(part) { return part !== ''; });
}

function fileExists(path) {
	return fs.stat(path).then(function() { return true; }).catch(function() { return false; });
}

function asText(v) {
	if (typeof v === 'string')
		return v;
	if (v == null)
		return '';
	try { return JSON.stringify(v, null, 2); }
	catch (e) { return String(v); }
}

function openLog(getter) {
	return getter.then(function(res) {
		if (res && res.alert) {
			alert(res.alert);
			return;
		}
		var body = asText(res && typeof res.output === 'string' ? res.output : res);
		var w = window.open('', '_blank');
		if (!w) {
			ui.showModal(_('Log'), [
				E('pre', { 'style': 'white-space:pre-wrap;max-height:70vh;overflow:auto' }, body),
				E('div', { 'class': 'right' }, [
					E('button', { 'class': 'btn', 'click': ui.hideModal }, _('CLOSE WIN'))
				])
			]);
			return;
		}
		var pre = w.document.createElement('pre');
		pre.style.whiteSpace = 'pre-wrap';
		pre.textContent = body;
		w.document.body.appendChild(pre);
	});
}

function parseHints(leases, arp) {
	var list = [];
	var seen = {};
	String(leases || '').split('\n').forEach(function(line) {
		var m = line.match(/^\d+\s+([0-9a-fA-F:]+)\s+(\S+)/);
		if (!m || !isMac(m[1]))
			return;
		var mac = m[1].toLowerCase();
		if (seen[mac])
			return;
		seen[mac] = true;
		list.push({ mac: m[1], ip: m[2] });
	});
	String(arp || '').split('\n').forEach(function(line) {
		var parts = line.trim().split(/\s+/);
		if (parts.length < 4 || !isMac(parts[3]))
			return;
		var mac = parts[3].toLowerCase();
		if (seen[mac])
			return;
		seen[mac] = true;
		list.push({ mac: parts[3], ip: parts[0] });
	});
	list.sort(function(a, b) {
		if (a.ip.length !== b.ip.length)
			return a.ip.length - b.ip.length;
		if (a.ip < b.ip)
			return -1;
		if (a.ip > b.ip)
			return 1;
		return 0;
	});
	return list;
}

function buildSelect(id, items, current) {
	var sel = E('select', { 'id': id, 'class': 'cbi-input-select', 'style': 'min-width:220px' });
	var groups = {};
	var order = [];
	var seen = {};
	items.forEach(function(it) {
		seen[it.value] = true;
		if (!it.group) {
			sel.appendChild(E('option', { 'value': it.value }, it.label));
			return;
		}
		if (!groups[it.group]) {
			groups[it.group] = [];
			order.push(it.group);
		}
		groups[it.group].push(it);
	});
	order.forEach(function(g) {
		var og = E('optgroup', { 'label': g });
		groups[g].forEach(function(it) {
			og.appendChild(E('option', { 'value': it.value }, it.label));
		});
		sel.appendChild(og);
	});
	if (current != null && current !== '' && !seen[current])
		sel.appendChild(E('option', { 'value': current }, current));
	if (current != null)
		sel.value = current;
	return sel;
}

function groupedNode(option, items) {
	items.forEach(function(it) {
		option.value(it.value, it.label);
	});
	option.formvalue = function(section_id) {
		var sel = document.getElementById(this.cbid(section_id));
		if (sel)
			return sel.value;
		var v = uci.get(APP, section_id, this.option);
		return v == null ? '' : v;
	};
	option.write = function(section_id, value) {
		if (value == null || value === '') {
			if (this.rmempty !== false)
				return uci.unset(APP, section_id, this.option);
		}
		return uci.set(APP, section_id, this.option, value);
	};
	option.remove = function(section_id) {
		return uci.unset(APP, section_id, this.option);
	};
	option.renderWidget = function(section_id, option_index, cfgvalue) {
		var sel = buildSelect(this.cbid(section_id), items, cfgvalue == null ? '' : cfgvalue);
		sel.addEventListener('change', function() {
			var ev = document.createEvent('HTMLEvents');
			ev.initEvent('widget-change', true, true);
			sel.dispatchEvent(ev);
		});
		return sel;
	};
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
				ul.appendChild(E('li', {}, line));
			});
			box.appendChild(ul);
			return el;
		});
	};
}

function richText(option, html) {
	option.description = ' ';
	var orig = option.render;
	option.render = function() {
		return Promise.resolve(orig.apply(this, arguments)).then(function(el) {
			var box = el.querySelector('.cbi-value-description');
			if (!box)
				return el;
			while (box.firstChild)
				box.removeChild(box.firstChild);
			String(html).split(/<br\s*\/?>/i).forEach(function(line, index) {
				if (index)
					box.appendChild(E('br'));
				box.appendChild(document.createTextNode(line));
			});
			return el;
		});
	};
}

function ghost(section, name, reader) {
	var o = section.taboption('Main', form.Value, name, '');
	o.retain = true;
	o.write = function() {};
	o.remove = function() {};
	o.formvalue = function(section_id) {
		return reader(section_id);
	};
	o.renderWidget = function(section_id) {
		return E('input', { 'type': 'hidden', 'id': this.cbid(section_id), 'value': reader(section_id) });
	};
	return o;
}

function activeValue(opt, section_id) {
	if (!opt || !opt.isActive(section_id))
		return '';
	var v = opt.formvalue(section_id);
	return v == null ? '' : String(v);
}

function bindPort(opt) {
	opt.write = function(section_id, value) {
		return form.Value.prototype.write.call(this, section_id, pw.normalizePorts(value));
	};
}

function setFlag(opt, section, on) {
	if (!opt)
		return;
	var el = opt.getUIElement(section);
	if (el && typeof el.setValue === 'function')
		el.setValue(!!on);
	else
		uci.set(APP, section, opt.option, on ? '1' : '0');
}

function setList(opt, section, value) {
	if (!opt)
		return;
	var el = opt.getUIElement(section);
	if (el && typeof el.setValue === 'function')
		el.setValue(value);
	else
		uci.set(APP, section, opt.option, value);
}

function logButton(path, exists, opener) {
	var kids = [ E('code', {}, path), '\u00a0\u00a0' ];
	if (exists) {
		kids.push(E('input', {
			'class': 'btn cbi-button cbi-button-apply',
			'type': 'button',
			'value': _('View Log'),
			'click': function(ev) {
				ev.preventDefault();
				opener();
			}
		}));
	}
	return E('span', {}, kids);
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(APP),
			pw.loadCaps(),
			fs.read('/tmp/dhcp.leases').catch(function() { return ''; }),
			fs.read('/proc/net/arp').catch(function() { return ''; })
		]).then(function(data) {
			var id = pw.routeArg();
			var nodeLog = TMP + '/acl/' + id + '/node.log';
			var dnsLog = TMP + '/acl/' + id + '/chinadns_ng.log';
			return Promise.all([
				fileExists(nodeLog),
				fileExists(dnsLog)
			]).then(function(flags) {
				data.push(flags[0], flags[1]);
				return data;
			});
		});
	},

	render: function(data) {
		var view = this;
		var id = pw.routeArg();
		var section = id ? uci.get(APP, id) : null;
		if (!id || !section || section['.type'] !== 'acl_rule') {
			window.location.href = pw.pageUrl('acl');
			return E('div', {});
		}

		var caps = data[1] || {};
		var hints = parseHints(data[2], data[3]);
		var nodeLogExists = !!data[4];
		var dnsLogExists = !!data[5];
		var nodes = caps.nodes || [];
		var nodeList = caps.node_list || {};
		var hasSing = present(caps.singbox);
		var hasXray = present(caps.xray);
		var hasCore = hasSing || hasXray;
		var byId = {};
		nodes.forEach(function(n) { byId[nodeIdOf(n)] = n; });
		var shuntIds = {};
		nodes.forEach(function(n) {
			if (n.protocol === '_shunt')
				shuntIds[nodeIdOf(n)] = n;
		});

		var globals = uci.sections(APP, 'global') || [];
		var globalId = globals.length ? globals[0]['.name'] : null;
		var globalNode = globalId ? (uci.get(APP, globalId, 'node') || '') : '';
		var fwdList = uci.sections(APP, 'global_forwarding') || [];
		var fwd = fwdList.length ? fwdList[0] : {};
		var gTcpNo = fwd.tcp_no_redir_ports || '';
		var gUdpNo = fwd.udp_no_redir_ports || '';
		var gTcpDrop = fwd.tcp_proxy_drop_ports || '';
		var gUdpDrop = fwd.udp_proxy_drop_ports || '';
		var gTcpRedir = fwd.tcp_redir_ports || '';
		var gUdpRedir = fwd.udp_redir_ports || '';

		var loadedId = uci.get(APP, id, 'node') || '';
		var loaded = byId[loadedId] || null;
		var showShunt = !!(loaded && loaded.protocol === '_shunt' && loadedId !== globalNode);

		var m = new form.Map(APP);
		var s = m.section(form.NamedSection, id, 'acl_rule', _('ACLs'));
		s.anonymous = true;
		s.tab('Main', _('Main'));
		if (showShunt)
			s.tab('Shunt', _('Shunt Rule'));
		s.tab('Proxy', _('Proxy'));
		s.tab('DNS', _('DNS'));
		s.tab('Log', _('Log'));

		var o = s.taboption('Main', form.Flag, 'enabled', _('Enable'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('Main', form.Value, 'remarks', _('Remarks'));
		o.default = id;
		o.rmempty = false;

		o = s.taboption('Main', form.Value, 'interface', _('Source Interface'));
		o.value('', _('All'));
		(caps.devices || []).forEach(function(dev) {
			if (dev && dev.name)
				o.value(dev.name, dev.label || dev.name);
		});
		o.validate = function(section_id, value) {
			value = value == null ? '' : String(value);
			if (value === '' || /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(value))
				return true;
			return _('Invalid interface name');
		};

		var sources = s.taboption('Main', form.DynamicList, 'sources', _('Source'));
		bulletDescription(sources, [
			_('Example:'),
			_('MAC') + ': 00:00:00:FF:FF:FF',
			_('IP') + ': 192.168.1.100',
			_('IP CIDR') + ': 192.168.1.0/24',
			_('IP range') + ': 192.168.1.100-192.168.1.200',
			_('IPSet') + ': ipset:lanlist'
		]);
		hints.forEach(function(item) {
			sources.value(item.mac, item.mac + ' (' + item.ip + ')');
		});
		sources.cfgvalue = function(section_id, set_value) {
			if (arguments.length === 2) {
				if (typeof set_value === 'string')
					set_value = listItems(set_value);
				return form.DynamicList.prototype.cfgvalue.call(this, section_id, set_value);
			}
			return form.DynamicList.prototype.cfgvalue.call(this, section_id);
		};
		sources.write = function(section_id, value) {
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
				return uci.unset(APP, section_id, 'sources');
			return uci.set(APP, section_id, 'sources', out.join(' '));
		};
		sources.validate = function(section_id, value) {
			var err = [];
			listItems(value).forEach(function(item) {
				var ok = false;
				if (item.indexOf('ipset:') === 0 && item.replace('ipset:', '') !== '')
					ok = true;
				if (!ok && isMac(item))
					ok = true;
				if (!ok && isIp4Addr(item))
					ok = true;
				if (!ok && isIpRange(item))
					ok = true;
				if (!ok)
					err.push(item);
			});
			if (err.length)
				return _('Not true format, please re-enter!') + '\n' + err.join('\n');
			return true;
		};

		var modeOpt = s.taboption('Main', form.ListValue, 'mode', _('Mode'));
		modeOpt.value('0', _('No Proxy'));
		modeOpt.value('1', _('Proxy'));

		var tcpNo = s.taboption('Proxy', form.Value, 'tcp_no_redir_ports', _('TCP No Redir Ports'));
		tcpNo.value('', _('Use global config') + '(' + gTcpNo + ')');
		tcpNo.value('disable', _('No patterns are used'));
		tcpNo.value('1:65535', _('All'));
		tcpNo.depends('mode', '1');
		bindPort(tcpNo);

		var udpNo = s.taboption('Proxy', form.Value, 'udp_no_redir_ports', _('UDP No Redir Ports'));
		udpNo.value('', _('Use global config') + '(' + gUdpNo + ')');
		udpNo.value('disable', _('No patterns are used'));
		udpNo.value('1:65535', _('All'));
		udpNo.depends('mode', '1');
		udpNo.description = _('Fill in the ports you don\'t want to be forwarded by the agent, with the highest priority.');
		bindPort(udpNo);

		ghost(s, '_hide_node_option', function(section_id) {
			if (activeValue(modeOpt, section_id) === '0')
				return '1';
			var tcp = activeValue(tcpNo, section_id);
			var udp = activeValue(udpNo, section_id);
			if (tcp === '1:65535' && udp === '1:65535')
				return '1';
			if (gTcpNo === '1:65535' && gUdpNo === '1:65535' && tcp === '' && udp === '')
				return '1';
			return '0';
		});

		var useGlobal = s.taboption('Main', form.Flag, 'use_global_config', _('Use global config'));
		useGlobal.default = '0';
		useGlobal.rmempty = false;
		useGlobal.depends({ '_hide_node_option': '1', '!reverse': true });

		var nodeItems = [];
		if (hasCore) {
			(nodeList.socks_list || []).forEach(function(v) {
				nodeItems.push({ value: v.id, label: v.remark, group: groupName(v) });
			});
		}
		var normalCount = (nodeList.normal_list || []).length;
		var addNodes = normalCount > 0 || !nodes.length;
		if (!normalCount && nodes.length) {
			/* dns_mode is created below; the extra dependency is attached after it exists */
		}
		if (addNodes) {
			nodes.forEach(function(n) {
				var nid = nodeIdOf(n);
				if (!nid)
					return;
				if (n.protocol === '_shunt') {
					if (n.type === 'Xray' && hasXray)
						nodeItems.push({ value: nid, label: n.remark || nid, group: groupName(n) });
					else if (n.type === 'sing-box' && hasSing)
						nodeItems.push({ value: nid, label: n.remark || nid, group: groupName(n) });
				}
				else {
					nodeItems.push({ value: nid, label: n.remark || nid, group: groupName(n) });
				}
			});
		}

		var nodeOpt = s.taboption('Main', form.ListValue, 'node', _('Proxy Node'));
		nodeOpt.description = _('Use global configuration when using the global node.');
		nodeOpt.depends({ '_hide_node_option': '0', 'use_global_config': '0' });
		groupedNode(nodeOpt, nodeItems);
		nodeOpt.onchange = function(ev, section_id, value) {
			if (shuntIds[value] && value !== loadedId) {
				m.save().then(function() { window.location.reload(); });
				return;
			}
			var tab = document.getElementById('tab.' + APP + '.' + id + '.Shunt');
			if (tab && tab.parentNode && tab.parentNode.tagName === 'LI')
				tab.parentNode.style.display = (value === loadedId) ? '' : 'none';
		};

		ghost(s, '_acl_node_bool', function(section_id) {
			if (!nodeOpt.isActive(section_id))
				return '';
			return nodeOpt.formvalue(section_id) ? '1' : '';
		});
		ghost(s, '_diff_global_node', function(section_id) {
			if (!nodeOpt.isActive(section_id))
				return '';
			var v = nodeOpt.formvalue(section_id) || '';
			if (globalNode)
				return (v && v !== globalNode) ? '1' : '';
			return v ? '1' : '';
		});
		ghost(s, '_node_sel_shunt', function(section_id) {
			var v = nodeOpt.isActive(section_id) ? (nodeOpt.formvalue(section_id) || '') : '';
			return shuntIds[v] ? '1' : '';
		});

		function proxyOr(opt) {
			opt.depends({ 'use_global_config': '1' });
			opt.depends({ '_acl_node_bool': '1' });
		}

		o = s.taboption('Proxy', form.Value, 'tcp_proxy_drop_ports', _('TCP Proxy Drop Ports'));
		o.value('', _('Use global config') + '(' + gTcpDrop + ')');
		o.value('disable', _('No patterns are used'));
		bindPort(o);
		proxyOr(o);

		o = s.taboption('Proxy', form.Value, 'udp_proxy_drop_ports', _('UDP Proxy Drop Ports'));
		o.value('', _('Use global config') + '(' + gUdpDrop + ')');
		o.value('disable', _('No patterns are used'));
		o.value('443', _('QUIC'));
		bindPort(o);
		proxyOr(o);

		o = s.taboption('Proxy', form.Value, 'tcp_redir_ports', _('TCP Redir Ports'), tf('Only work with using the %s node.', 'TCP'));
		o.value('', _('Use global config') + '(' + gTcpRedir + ')');
		o.value('1:65535', _('All'));
		o.value('80,443', '80,443');
		o.value('80:65535', '80 ' + _('or more'));
		o.value('1:443', '443 ' + _('or less'));
		bindPort(o);
		proxyOr(o);

		o = s.taboption('Proxy', form.Value, 'udp_redir_ports', _('UDP Redir Ports'), tf('Only work with using the %s node.', 'UDP'));
		o.value('', _('Use global config') + '(' + gUdpRedir + ')');
		o.value('1:65535', _('All'));
		o.value('53', '53');
		bindPort(o);
		proxyOr(o);

		o = s.taboption('Proxy', form.DummyValue, 'tips', '　');
		o.depends({ 'use_global_config': '1' });
		o.depends({ '_acl_node_bool': '1' });
		o.renderWidget = function() {
			var text = _('The port settings support single ports and ranges.<br>Separate multiple ports with commas (,).<br>Example: 21,80,443,1000:2000.');
			var kids = [];
			text.split(/<br\s*\/?>/i).forEach(function(line, index) {
				if (index)
					kids.push(E('br'));
				kids.push(document.createTextNode(line));
			});
			return E('font', { 'color': 'red' }, kids);
		};

		function diffDepends(opt) {
			opt.depends({ '_acl_node_bool': '1', '_diff_global_node': '1' });
		}

		var useDirect = s.taboption('Proxy', form.Flag, 'use_direct_list', tf('Use %s', _('Direct List')));
		useDirect.default = '1';
		diffDepends(useDirect);
		var useProxy = s.taboption('Proxy', form.Flag, 'use_proxy_list', tf('Use %s', _('Proxy List')));
		useProxy.default = '1';
		diffDepends(useProxy);
		var useBlock = s.taboption('Proxy', form.Flag, 'use_block_list', tf('Use %s', _('Block List')));
		useBlock.default = '1';
		diffDepends(useBlock);

		var useGfw = null;
		if (caps.has_gfwlist) {
			useGfw = s.taboption('Proxy', form.Flag, 'use_gfw_list', tf('Use %s', _('GFW List')));
			useGfw.default = '1';
			diffDepends(useGfw);
		}

		var chn = null;
		if (caps.has_chnlist || caps.has_chnroute) {
			chn = s.taboption('Proxy', form.ListValue, 'chn_list', _('China List'));
			chn.value('0', _('Close(Not use)'));
			chn.value('direct', _('Direct Connection'));
			chn.value('proxy', _('Proxy'));
			chn.default = 'direct';
			diffDepends(chn);
		}

		var tcpMode = s.taboption('Proxy', form.ListValue, 'tcp_proxy_mode', 'TCP ' + _('Proxy Mode'));
		tcpMode.value('disable', _('No Proxy'));
		tcpMode.value('proxy', _('Proxy'));
		diffDepends(tcpMode);

		var udpMode = s.taboption('Proxy', form.ListValue, 'udp_proxy_mode', 'UDP ' + _('Proxy Mode'));
		udpMode.value('disable', _('No Proxy'));
		udpMode.value('proxy', _('Proxy'));
		diffDepends(udpMode);

		o = s.taboption('Proxy', form.DummyValue, 'switch_mode', _('Switch Mode'));
		diffDepends(o);
		o.renderWidget = function() {
			function gfw() {
				setFlag(useGfw, id, true);
				setList(chn, id, '0');
				setList(tcpMode, id, 'disable');
				setList(udpMode, id, 'disable');
			}
			function chnMode() {
				setFlag(useGfw, id, true);
				setList(chn, id, 'direct');
				setList(tcpMode, id, 'proxy');
				setList(udpMode, id, 'proxy');
			}
			function home() {
				setFlag(useGfw, id, false);
				setList(chn, id, 'proxy');
				setList(tcpMode, id, 'disable');
				setList(udpMode, id, 'disable');
			}
			function globalMode() {
				setFlag(useGfw, id, false);
				setList(chn, id, '0');
				setList(tcpMode, id, 'proxy');
				setList(udpMode, id, 'proxy');
			}
			return E('div', {}, [
				E('input', { 'class': 'btn cbi-button cbi-button-apply', 'type': 'button', 'value': _('GFW List'), 'click': gfw }),
				' ',
				E('input', { 'class': 'btn cbi-button cbi-button-apply', 'type': 'button', 'value': _('Not China List'), 'click': chnMode }),
				' ',
				E('input', { 'class': 'btn cbi-button cbi-button-apply', 'type': 'button', 'value': _('China List'), 'click': home }),
				' ',
				E('input', { 'class': 'btn cbi-button cbi-button-apply', 'type': 'button', 'value': _('Global Proxy'), 'click': globalMode })
			]);
		};

		var dnsShunt = s.taboption('DNS', form.ListValue, 'dns_shunt', 'DNS ' + _('Shunt'));
		dnsShunt.default = 'chinadns-ng';
		dnsShunt.value('dnsmasq', 'Dnsmasq');
		dnsShunt.value('chinadns-ng', _('ChinaDNS-NG (recommended)'));
		diffDepends(dnsShunt);
		dnsShunt.write = function(section_id, value) {
			var old = uci.get(APP, section_id, 'dns_shunt');
			if (old && old !== value && globalId)
				uci.set(APP, globalId, 'flush_set', '1');
			return form.ListValue.prototype.write.call(this, section_id, value);
		};

		o = s.taboption('DNS', form.Flag, 'filter_proxy_ipv6', _('Filter Proxy Host IPv6'), _('Experimental feature.'));
		o.default = '0';
		diffDepends(o);

		var dnsMode = s.taboption('DNS', form.ListValue, 'dns_mode', _('Filter Mode'));
		if (present(caps.dns2socks))
			dnsMode.value('dns2socks', 'dns2socks');
		if (hasSing)
			dnsMode.value('sing-box', 'Sing-Box');
		if (hasXray)
			dnsMode.value('xray', 'Xray');
		dnsMode.depends({ '_acl_node_bool': '1', '_node_sel_shunt': '', '_diff_global_node': '1' });
		if (!normalCount && nodes.length)
			dnsMode.depends({ '_acl_node_bool': '1', '_diff_global_node': '1' });
		dnsMode.write = function(section_id, value) {
			if (value === 'dns2socks')
				uci.unset(APP, section_id, 'v2ray_dns_mode');
			return form.ListValue.prototype.write.call(this, section_id, value);
		};

		var xrayDns = s.taboption('DNS', form.ListValue, 'xray_dns_mode', _('Request protocol'));
		xrayDns.default = 'tcp';
		xrayDns.value('tcp', 'TCP');
		xrayDns.value('udp', 'UDP');
		xrayDns.value('doh', 'DoH');
		xrayDns.depends('dns_mode', 'xray');
		xrayDns.load = function(section_id) {
			return uci.get(APP, section_id, 'v2ray_dns_mode');
		};
		xrayDns.write = function(section_id, value) {
			if (dnsMode.formvalue(section_id) === 'xray')
				return uci.set(APP, section_id, 'v2ray_dns_mode', value);
		};
		xrayDns.remove = function() {};

		var singDns = s.taboption('DNS', form.ListValue, 'singbox_dns_mode', _('Request protocol'));
		singDns.default = 'tcp';
		singDns.value('tcp', 'TCP');
		singDns.value('udp', 'UDP');
		singDns.value('doh', 'DoH');
		singDns.value('http3', 'HTTP3(DoH3)');
		singDns.value('tls', 'TLS(DoT)');
		singDns.value('quic', 'QUIC(DoQ)');
		singDns.depends('dns_mode', 'sing-box');
		singDns.load = function(section_id) {
			return uci.get(APP, section_id, 'v2ray_dns_mode');
		};
		singDns.write = function(section_id, value) {
			if (dnsMode.formvalue(section_id) === 'sing-box')
				return uci.set(APP, section_id, 'v2ray_dns_mode', value);
		};
		singDns.remove = function() {};

		dnsMode.remove = function(section_id) {
			var idVal = nodeOpt.formvalue(section_id) || '';
			if (!idVal)
				return uci.unset(APP, section_id, 'dns_mode');
			var found = byId[idVal];
			if (!found)
				return;
			var newVal = (found.type === 'Xray') ? 'xray' : 'sing-box';
			uci.set(APP, section_id, 'dns_mode', newVal);
			var field = found.type === 'Xray' ? xrayDns : singDns;
			var v2 = field && field.formvalue(section_id);
			if (v2)
				uci.set(APP, section_id, 'v2ray_dns_mode', v2);
		};

		if (addNodes) {
			nodes.forEach(function(n) {
				if (n.protocol !== '_shunt')
					return;
				var nid = nodeIdOf(n);
				if (n.type === 'Xray' && hasXray) {
					xrayDns.depends({ '_acl_node_bool': '1', '_diff_global_node': '1', 'node': nid });
				}
				if (n.type === 'sing-box' && hasSing) {
					singDns.depends({ '_acl_node_bool': '1', '_diff_global_node': '1', 'node': nid });
				}
			});
		}

		o = s.taboption('DNS', form.Value, 'remote_dns', _('Remote DNS'));
		o.datatype = 'or(ipaddr,ipaddrport(1))';
		o.default = '1.1.1.1';
		o.value('1.1.1.1', '1.1.1.1 (CloudFlare)');
		o.value('1.1.1.2', '1.1.1.2 (CloudFlare-Security)');
		o.value('8.8.4.4', '8.8.4.4 (Google)');
		o.value('8.8.8.8', '8.8.8.8 (Google)');
		o.value('9.9.9.9', '9.9.9.9 (Quad9-Recommended)');
		o.value('149.112.112.112', '149.112.112.112 (Quad9-Recommended)');
		o.value('208.67.220.220', '208.67.220.220 (OpenDNS)');
		o.value('208.67.222.222', '208.67.222.222 (OpenDNS)');
		o.depends({ 'dns_mode': 'dns2socks' });
		o.depends({ 'xray_dns_mode': 'udp' });
		o.depends({ 'xray_dns_mode': 'tcp' });
		o.depends({ 'singbox_dns_mode': 'udp' });
		o.depends({ 'singbox_dns_mode': 'tcp' });
		o.depends({ 'singbox_dns_mode': 'tls' });
		o.depends({ 'singbox_dns_mode': 'quic' });

		o = s.taboption('DNS', form.Value, 'remote_dns_doh', _('Remote DNS DoH'));
		o.description = _('Format: URL[,IP] (optional IP to map the domain in the URL)');
		o.value('https://1.1.1.1/dns-query', '1.1.1.1 (CloudFlare)');
		o.value('https://1.1.1.2/dns-query', '1.1.1.2 (CloudFlare-Security)');
		o.value('https://8.8.4.4/dns-query', '8.8.4.4 (Google)');
		o.value('https://8.8.8.8/dns-query', '8.8.8.8 (Google)');
		o.value('https://9.9.9.9/dns-query', '9.9.9.9 (Quad9)');
		o.value('https://149.112.112.112/dns-query', '149.112.112.112 (Quad9)');
		o.value('https://208.67.222.222/dns-query', '208.67.222.222 (OpenDNS)');
		o.value('https://dns.adguard.com/dns-query,94.140.14.14', '94.140.14.14 (AdGuard)');
		o.value('https://doh.libredns.gr/dns-query,116.202.176.26', '116.202.176.26 (LibreDNS)');
		o.value('https://doh.libredns.gr/ads,116.202.176.26', '116.202.176.26 (LibreDNS-NoAds)');
		o.default = 'https://1.1.1.1/dns-query';
		o.validate = function(section_id, value) {
			value = String(value == null ? '' : value).trim();
			if (value) {
				var parts = value.split(',');
				var ok = true;
				var i;
				for (i = 1; i < parts.length; i++) {
					if (!isIpMask4(String(parts[i] || '').trim()))
						ok = false;
				}
				if (ok)
					return true;
			}
			return _('DoH request address') + ' ' + _('Format must be:') + ' URL,IP';
		};
		o.depends({ 'xray_dns_mode': 'doh' });
		o.depends({ 'singbox_dns_mode': 'doh' });
		o.depends({ 'singbox_dns_mode': 'http3' });

		o = s.taboption('DNS', form.Value, 'remote_dns_client_ip', _('EDNS Client Subnet'));
		richText(o, _('Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).') + '<br />' +
			_('This feature requires the DNS server to support the Edns Client Subnet (RFC7871).'));
		o.datatype = 'ipaddr';
		o.depends({ 'dns_mode': 'sing-box' });
		o.depends({ 'dns_mode': 'xray' });
		o.depends({ '_node_sel_shunt': '1', '_diff_global_node': '1' });

		o = s.taboption('DNS', form.Flag, 'remote_fakedns', 'FakeDNS', _('Use FakeDNS work in the domain that proxy.'));
		o.default = '0';
		o.rmempty = false;
		o.depends({ 'dns_mode': 'sing-box' });
		o.depends({ 'dns_mode': 'xray' });
		o.validate = function(section_id, value) {
			if (String(value) === '1') {
				var mode = dnsMode.formvalue(section_id);
				var node = nodeOpt.formvalue(section_id);
				if (mode && node) {
					var found = byId[node];
					var type = found && found.type ? String(found.type).toLowerCase() : '';
					if (type !== String(mode) && String(node).indexOf('socks_') < 0)
						return _('Node must be \'%s\' type to use FakeDNS.').replace('%s', mode);
				}
			}
			return true;
		};

		var ttl = s.taboption('DNS', form.Value, 'remote_rewrite_ttl', _('Remote DNS') + ' TTL');
		ttl.datatype = 'min(1)';
		ttl.default = '30';
		ttl.depends({ 'dns_mode': 'sing-box' });
		if (addNodes) {
			nodes.forEach(function(n) {
				if (n.protocol === '_shunt' && n.type === 'sing-box' && hasSing)
					ttl.depends({ '_acl_node_bool': '1', '_diff_global_node': '1', 'node': nodeIdOf(n) });
			});
		}

		var baseDns = [
			_('When not matching any domain name list:'),
			_('Remote DNS: Can avoid more DNS leaks, but some domestic domain names maybe to proxy!'),
			_('Direct DNS: Internet experience may be better, but DNS will be leaked!')
		];
		var smartDns = baseDns.concat([
			_('Smart: Forward to both direct and remote DNS, if the direct DNS resolution result is a mainland China IP, then use the direct result, otherwise use the remote result.'),
			_('In smart mode, no-ip reply from Direct DNS:'),
			_('Do not accept: Wait and use Remote DNS Reply.'),
			_('Accept: Trust the Reply, using this option can improve DNS resolution speeds for some mainland IPv4-only sites.')
		]);

		o = s.taboption('DNS', form.ListValue, 'chinadns_ng_default_tag', _('Default DNS'));
		o.default = 'none';
		o.value('gfw', _('Remote DNS'));
		o.value('chn', _('Direct DNS'));
		o.value('none', _('Smart, Do not accept no-ip reply from Direct DNS'));
		o.value('none_noip', _('Smart, Accept no-ip reply from Direct DNS'));
		bulletDescription(o, smartDns);
		o.depends({ 'dns_shunt': 'chinadns-ng', 'tcp_proxy_mode': 'proxy', 'chn_list': 'direct' });

		o = s.taboption('DNS', form.Flag, 'force_https_soa', _('Force HTTPS SOA'), _('Force queries with qtype 65 to respond with an SOA record.'));
		o.default = '0';
		o.rmempty = false;
		o.depends({ 'dns_shunt': 'chinadns-ng' });

		o = s.taboption('DNS', form.ListValue, 'use_default_dns', _('Default DNS'));
		o.default = 'direct';
		o.value('remote', _('Remote DNS'));
		o.value('direct', _('Direct DNS'));
		bulletDescription(o, baseDns);
		o.depends({ 'dns_shunt': 'dnsmasq', 'tcp_proxy_mode': 'proxy', 'chn_list': 'direct' });

		o = s.taboption('Log', form.Flag, 'log', _('Enable Node Log'));
		o.default = '0';
		o.rmempty = false;
		diffDepends(o);

		o = s.taboption('Log', form.ListValue, 'loglevel', _('Log Level'));
		o.default = 'warn';
		o.value('debug', 'Debug');
		o.value('info', 'Info');
		o.value('warn', 'Warning');
		o.value('error', 'Error');
		o.depends('log', '1');

		var nodeLog = TMP + '/acl/' + id + '/node.log';
		o = s.taboption('Log', form.DummyValue, '_node_log', _('Log File'));
		o.depends('log', '1');
		o.renderWidget = function() {
			return logButton(nodeLog, nodeLogExists, function() {
				openLog(pw.call('get_redir_log', { id: id }));
			});
		};

		o = s.taboption('Log', form.Flag, 'log_chinadns_ng', _('Enable') + ' ChinaDNS-NG ' + _('Log'));
		o.default = '0';
		o.rmempty = false;
		o.depends('dns_shunt', 'chinadns-ng');

		var dnsLog = TMP + '/acl/' + id + '/chinadns_ng.log';
		o = s.taboption('Log', form.DummyValue, '_chinadns_ng_log', _('Log File'));
		o.depends('log_chinadns_ng', '1');
		o.renderWidget = function() {
			return logButton(dnsLog, dnsLogExists, function() {
				openLog(pw.call('get_chinadns_log', { flag: id }));
			});
		};

		var shuntTable = null;
		if (showShunt) {
			var shuntNodeId = loadedId;
			function mirror(option, uciName, asFlag) {
				option.cfgvalue = function() {
					return uci.get(APP, shuntNodeId, uciName);
				};
				option.write = function(section_id, value) {
					uci.unset(APP, section_id, option.option);
					if (nodeOpt.formvalue(section_id) !== shuntNodeId)
						return;
					if (asFlag) {
						if (String(value) === '1')
							uci.set(APP, shuntNodeId, uciName, '1');
						else
							uci.unset(APP, shuntNodeId, uciName);
						return;
					}
					if (value == null || value === '')
						uci.unset(APP, shuntNodeId, uciName);
					else
						uci.set(APP, shuntNodeId, uciName, value);
				};
				option.remove = function(section_id) {
					uci.unset(APP, section_id, option.option);
					if (nodeOpt.formvalue(section_id) !== shuntNodeId)
						return;
					uci.unset(APP, shuntNodeId, uciName);
				};
				option.depends('node', shuntNodeId);
			}

			if (loaded.type === 'Xray') {
				o = s.taboption('Shunt', form.ListValue, 'domainStrategy', _('Domain Strategy'));
				o.value('AsIs');
				o.value('IPIfNonMatch');
				o.value('IPOnDemand');
				o.default = 'IPOnDemand';
				bulletDescription(o, [
					_('\'AsIs\': Only use domain for routing. Default value.'),
					_('\'IPIfNonMatch\': When no rule matches current domain, resolves it into IP addresses (A or AAAA records) and try all rules again.'),
					_('\'IPOnDemand\': As long as there is a IP-based rule, resolves the domain into IP immediately.')
				]);
				mirror(o, 'domainStrategy', false);
				o = s.taboption('Shunt', form.ListValue, 'domainMatcher', _('Domain matcher'));
				o.value('hybrid');
				o.value('linear');
				mirror(o, 'domainMatcher', false);
			}

			o = s.taboption('Shunt', form.Flag, 'fakedns', 'FakeDNS ' + _('Main switch'));
			o.description = _('Use FakeDNS work in the domain that proxy.') + ' ' +
				_('Suitable scenarios for let the node servers get the target domain names.') + ' ' +
				_('Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.');
			mirror(o, 'fakedns', true);

			var shuntGroup = s.taboption('Shunt', form.ListValue, 'shunt_group', _('Shunt Rule Group'));
			shuntGroup.value('', _('default'));
			var seenGroups = {};
			(uci.sections(APP, 'shunt_rules') || []).forEach(function(rule) {
				if (rule.group && !seenGroups[rule.group]) {
					seenGroups[rule.group] = true;
					shuntGroup.value(rule.group, rule.group);
				}
			});
			mirror(shuntGroup, 'shunt_group', false);
			shuntGroup.onchange = function(ev, section_id, value) {
				if (nodeOpt.formvalue(section_id) !== shuntNodeId)
					return;
				if (!value)
					uci.unset(APP, shuntNodeId, 'shunt_group');
				else
					uci.set(APP, shuntNodeId, 'shunt_group', value);
				uci.unset(APP, section_id, 'shunt_group');
				uci.save().then(function() { window.location.reload(); });
			};

			function appendNodeLists(items) {
				var order = [ 'socks_list', 'normal_list', 'balancing_list', 'urltest_list', 'iface_list' ];
				var seen = { 'shunt_list': true };
				order.forEach(function(key) { seen[key] = true; });
				function pushList(list) {
					(list || []).forEach(function(v) {
						items.push({
							value: v.id,
							label: v.remark,
							group: (v.group && v.group !== '') ? v.group : _('default')
						});
					});
				}
				order.forEach(function(key) { pushList(nodeList[key]); });
				Object.keys(nodeList).forEach(function(key) {
					if (!seen[key])
						pushList(nodeList[key]);
				});
			}

			var groupVal = String(uci.get(APP, shuntNodeId, 'shunt_group') || '').toLowerCase();
			var rules = [];
			(uci.sections(APP, 'shunt_rules') || []).forEach(function(e) {
				if (String(e.group || '').toLowerCase() === groupVal) {
					rules.push({
						id: e['.name'],
						remarks: e.remarks || e['.name'],
						nodeOption: e['.name'],
						nodeDefault: '',
						fakeOption: e['.name'] + '_fakedns',
						proxyOption: e['.name'] + '_proxy_tag',
						isDefault: false
					});
				}
			});
			rules.push({
				id: '.default',
				remarks: _('Default'),
				nodeOption: 'default_node',
				nodeDefault: '_direct',
				fakeOption: 'default_fakedns',
				proxyOption: 'default_proxy_tag',
				isDefault: true
			});
			var normalIds = {};
			(nodeList.normal_list || []).forEach(function(n) { normalIds[n.id] = true; });
			var preTitle = _('Set the node to be used as a pre-proxy.') + '\n' +
				_('Each rule has a separate switch that controls whether this rule uses the pre-proxy or not.');
			var fakeHead = _('Use FakeDNS work in the domain that proxy.') + '\n' +
				_('Suitable scenarios for let the node servers get the target domain names.') + '\n' +
				_('Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.');
			var body = [ E('tr', { 'class': 'cbi-section-table-titles' }, [
				E('th', { 'class': 'cbi-section-table-cell' }, _('Rule')),
				E('th', { 'class': 'cbi-section-table-cell' }, _('Node')),
				E('th', { 'class': 'cbi-section-table-cell' }, E('a', { 'style': 'color:#FF8C00', 'title': fakeHead }, 'FakeDNS')),
				E('th', { 'class': 'cbi-section-table-cell' }, E('a', { 'class': 'pw-warn', 'title': preTitle }, _('Preproxy')))
			]) ];
			rules.forEach(function(rule) {
				var curNode = uci.get(APP, shuntNodeId, rule.nodeOption);
				if (curNode == null || curNode === '')
					curNode = rule.nodeDefault;
				var curProxy = uci.get(APP, shuntNodeId, rule.proxyOption) || '';
				var curFake = uci.get(APP, shuntNodeId, rule.fakeOption) === '1';
				var items = [
					{ value: '', label: _('Close (Not use)'), group: '' }
				];
				if (!rule.isDefault)
					items.push({ value: '_default', label: _('Use default node'), group: '' });
				items.push({ value: '_direct', label: _('Direct Connection'), group: '' });
				items.push({ value: '_blackhole', label: _('Blackhole (Block)'), group: '' });
				appendNodeLists(items);
				var proxyItems = [ { value: '', label: _('Close (Not use)'), group: '' } ];
				appendNodeLists(proxyItems);
				var nodeSel = buildSelect('pw-acl-shunt-node-' + rule.id, items, curNode);
				var proxySel = buildSelect('pw-acl-shunt-proxy-' + rule.id, proxyItems, curProxy);
				var fake = E('input', { 'type': 'checkbox', 'class': 'cbi-input-checkbox' });
				if (curFake)
					fake.checked = true;
				nodeSel.setAttribute('data-shunt-option', rule.nodeOption);
				proxySel.setAttribute('data-shunt-option', rule.proxyOption);
				fake.setAttribute('data-shunt-option', rule.fakeOption);
				fake.setAttribute('data-shunt-flag', '1');
				function applyVisibility() {
					var val = nodeSel.value;
					var showFake = !(val === '' || val === '_direct');
					fake.style.display = showFake ? '' : 'none';
					if (!showFake)
						fake.checked = false;
					var showProxy = !(!val || val.charAt(0) === '_' || val.indexOf('socks_') === 0 || !normalIds[val]);
					proxySel.style.display = showProxy ? '' : 'none';
					if (!showProxy)
						proxySel.value = '';
				}
				nodeSel.addEventListener('change', applyVisibility);
				applyVisibility();
				var ruleCell = rule.isDefault
					? E('span', { 'class': 'pw-warn' }, rule.remarks)
					: E('a', { 'href': pw.pageUrl('shunt_rules', rule.id), 'target': '_blank' }, rule.remarks);
				var edit = E('a', {
					'href': '#',
					'click': function(ev) {
						ev.preventDefault();
						var val = nodeSel.value;
						if (!val || val.indexOf('tcp') === 0 || val.indexOf('_default') === 0 || val.indexOf('_direct') === 0 || val.indexOf('_blackhole') === 0)
							return;
						window.location.href = (val.indexOf('socks_') === 0)
							? pw.pageUrl('socks_config', val)
							: pw.pageUrl('node_config', val);
					}
				}, _('Edit'));
				body.push(E('tr', { 'class': 'cbi-section-table-row' }, [
					E('td', { 'class': 'cbi-section-table-cell' }, ruleCell),
					E('td', { 'class': 'cbi-section-table-cell' }, [ nodeSel, ' ', edit ]),
					E('td', { 'class': 'cbi-section-table-cell' }, fake),
					E('td', { 'class': 'cbi-section-table-cell' }, proxySel)
				]));
			});
			shuntTable = E('div', { 'id': 'cbi-passwall-shunt_option_list', 'data-node-id': shuntNodeId, 'class': 'cbi-section' }, [
				E('table', { 'class': 'table cbi-section-table' }, body)
			]);
			var anchor = s.taboption('Shunt', form.DummyValue, '_shunt_table', '');
			anchor.depends('node', shuntNodeId);
			anchor.renderWidget = function() { return shuntTable; };
		}

		view._flushShunt = function() {
			if (!shuntTable)
				return;
			var nodeId = shuntTable.getAttribute('data-node-id');
			if (nodeOpt.formvalue(id) !== nodeId)
				return;
			shuntTable.querySelectorAll('[data-shunt-option]').forEach(function(el) {
				var key = el.getAttribute('data-shunt-option');
				if (el.getAttribute('data-shunt-flag')) {
					if (el.checked)
						uci.set(APP, nodeId, key, '1');
					else
						uci.unset(APP, nodeId, key);
				}
				else if (!el.value) {
					uci.unset(APP, nodeId, key);
				}
				else {
					uci.set(APP, nodeId, key, el.value);
				}
			});
		};

		return m.render().then(function(node) {
			var style = E('style', {}, [
				'div.cbi-value[id$="-_hide_node_option"],div.cbi-value[id$="-_acl_node_bool"],div.cbi-value[id$="-_diff_global_node"],div.cbi-value[id$="-_node_sel_shunt"]{display:none !important;}',
				'.shunt_hidden{display:none !important;}'
			].join(''));
			return E('div', {}, [ style, node ]);
		});
	},

	handleSave: function(ev) {
		if (typeof this._flushShunt === 'function')
			this._flushShunt();
		return this.super('handleSave', [ ev ]);
	}
});
