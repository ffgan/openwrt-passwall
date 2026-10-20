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
var CACHE_VAR = TMP + '/var';

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

function parseCache(text) {
	var map = {};
	String(text || '').split('\n').forEach(function(line) {
		var m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
		if (!m)
			return;
		var val = m[2];
		if (val.length >= 2 && val.charAt(0) === "'" && val.charAt(val.length - 1) === "'")
			val = val.substring(1, val.length - 1);
		map[m[1]] = val;
	});
	return map;
}

function asText(v) {
	if (typeof v === 'string')
		return v;
	if (v == null)
		return '';
	try {
		return JSON.stringify(v, null, 2);
	}
	catch (e) {
		return String(v);
	}
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

function urlEncode(s) {
	var bytes = new TextEncoder().encode(String(s));
	var out = '';
	bytes.forEach(function(b) {
		var ch = String.fromCharCode(b);
		if (/[A-Za-z0-9\-_.~]/.test(ch))
			out += ch;
		else
			out += '%' + (b < 16 ? '0' : '') + b.toString(16).toUpperCase();
	});
	return out;
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

function renderRichDescription(option, builder) {
	option.description = ' ';
	var orig = option.render;
	option.render = function() {
		return Promise.resolve(orig.apply(this, arguments)).then(function(el) {
			var box = el.querySelector('.cbi-value-description');
			if (!box)
				return el;
			while (box.firstChild)
				box.removeChild(box.firstChild);
			var nodes = builder();
			(Array.isArray(nodes) ? nodes : [ nodes ]).forEach(function(node) {
				box.appendChild(node);
			});
			return el;
		});
	};
}

function matchRuleNodes() {
	var html = 'Example: <code>^A && B && !C && D$</code><br>' +
		'This means the node remark must start with A (^), include B, exclude C (!), and end with D ($).<br>' +
		'Conditions are joined by <code>&&</code> (AND), and their order does not affect the result.<br>' +
		'Multiple groups can be separated by <code>||</code> (OR), matching succeeds if any group matches.<br>' +
		'Example: <code>A && B || C && D</code> means (A AND B) OR (C AND D).';
	var nodes = [];
	String(_(html)).split(/<br\s*\/?>/i).forEach(function(line, index) {
		if (index)
			nodes.push(E('br'));
		var span = E('span');
		var re = /<code>([\s\S]*?)<\/code>/g;
		var last = 0;
		var m;
		while ((m = re.exec(line))) {
			if (m.index > last)
				span.appendChild(document.createTextNode(line.slice(last, m.index)));
			span.appendChild(E('code', {}, m[1]));
			last = m.index + m[0].length;
		}
		if (last < line.length)
			span.appendChild(document.createTextNode(line.slice(last)));
		nodes.push(span);
	});
	return nodes;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(APP),
			pw.loadCaps(),
			fs.read(CACHE_VAR).catch(function() { return ''; })
		]);
	},

	render: function(data) {
		var id = pw.routeArg();
		var section = id ? uci.get(APP, id) : null;
		if (!id || !section || section['.type'] !== 'socks') {
			window.location.href = pw.pageUrl();
			return E('div', {});
		}

		var caps = data[1] || {};
		var nodes = caps.nodes || [];
		var hasCore = present(caps.singbox) || present(caps.xray);
		var cache = parseCache(data[2] || '');
		var byId = {};
		nodes.forEach(function(n) {
			byId[nodeIdOf(n)] = n;
		});

		var count = 0;
		(uci.sections(APP, 'socks') || []).forEach(function() { count++; });
		var portDefault = String(count + 1 + 1080);

		var tip = '';
		var tipId = cache[id];
		if (tipId && String(uci.get(APP, id, 'enable_autoswitch') || '0') === '1' && byId[tipId])
			tip = tf('Current node: %s', byId[tipId].remark || tipId);

		var m = new form.Map(APP);
		var s = m.section(form.NamedSection, id, 'socks', _('Socks Config'));
		s.addremove = false;
		s.anonymous = true;

		var o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = '1';
		o.rmempty = false;

		var nodeItems = [];
		var backupItems = [];
		nodes.forEach(function(n) {
			var nid = nodeIdOf(n);
			if (!nid)
				return;
			nodeItems.push({ value: nid, label: n.remark || nid, group: groupName(n) });
			if (n.protocol !== '_shunt')
				backupItems.push({ value: nid, label: n.remark || nid, group: groupName(n) });
		});

		var socksNode = s.option(form.ListValue, 'node', _('Node'));
		groupedNode(socksNode, nodeItems);
		if (tip) {
			var tipLabel = tf('Current node: %s', '');
			renderRichDescription(socksNode, function() {
				return [
					document.createTextNode(tipLabel),
					E('a', { 'href': pw.pageUrl('node_config', tipId) }, byId[tipId].remark || tipId),
					E('br')
				];
			});
		}

		o = s.option(form.Flag, 'bind_local', _('Bind Local'), _('When selected, it can only be accessed localhost.'));
		o.default = '0';

		o = s.option(form.Value, 'port', 'Socks ' + _('Listen Port'));
		o.default = portDefault;
		o.datatype = 'range(1,65535)';
		o.rmempty = false;

		if (hasCore) {
			o = s.option(form.Value, 'http_port', 'HTTP ' + _('Listen Port') + ' ' + _('0 is not use'));
			o.default = '0';
			o.datatype = 'port';
		}

		o = s.option(form.Flag, 'log', _('Enable') + ' ' + _('Log'));
		o.default = '1';
		o.rmempty = false;

		var logPath = TMP + '/' + id + '.log';
		o = s.option(form.DummyValue, '_log', _('Log File'));
		o.depends('log', '1');
		o.renderWidget = function() {
			return E('span', {}, [
				E('code', {}, logPath),
				'\u00a0\u00a0',
				E('input', {
					'class': 'btn cbi-button cbi-button-apply',
					'type': 'button',
					'value': _('View Log'),
					'click': function(ev) {
						ev.preventDefault();
						openLog(pw.call('get_socks_log', { name: id }));
					}
				})
			]);
		};

		var auto = s.option(form.Flag, 'enable_autoswitch', _('Auto Switch'));
		auto.default = '0';
		auto.rmempty = false;
		backupItems.forEach(function(item) {
			auto.depends('node', item.value);
		});

		o = s.option(form.ListValue, 'backup_node_add_mode', _('Backup Node Addition Method'));
		o.depends('enable_autoswitch', '1');
		o.default = 'manual';
		o.value('manual', _('Manual'));
		o.value('batch', _('Batch'));

		var backup = s.option(form.DynamicList, 'autoswitch_backup_node', _('List of backup nodes'));
		backup.depends('backup_node_add_mode', 'manual');
		backupItems.forEach(function(item) {
			backup.value(item.value, item.label);
		});
		backup.write = function(section_id, value) {
			var current = socksNode.formvalue(section_id);
			var list = Array.isArray(value) ? value : (value ? [ value ] : []);
			var out = [];
			list.forEach(function(item) {
				if (item && item !== current)
					out.push(item);
			});
			return form.DynamicList.prototype.write.call(this, section_id, out);
		};

		o = s.option(form.MultiValue, 'backup_node_group', _('Select Group'));
		o.depends('backup_node_add_mode', 'batch');
		o.value('default', _('default'));
		var seenGroups = {};
		(uci.sections(APP, 'nodes') || []).forEach(function(node) {
			if (node.group && !seenGroups[node.group]) {
				seenGroups[node.group] = true;
				o.value(urlEncode(node.group), node.group);
			}
		});

		o = s.option(form.Value, 'backup_node_match_rule', _('Node Matching Rules'));
		o.depends('backup_node_add_mode', 'batch');
		renderRichDescription(o, matchRuleNodes);

		o = s.option(form.Value, 'autoswitch_testing_time', _('How often to test'), _('Units:seconds'));
		o.datatype = 'min(10)';
		o.default = '30';
		o.depends('enable_autoswitch', '1');

		o = s.option(form.Value, 'autoswitch_connect_timeout', _('Timeout seconds'), _('Units:seconds'));
		o.datatype = 'range(3,10)';
		o.default = '3';
		o.depends('enable_autoswitch', '1');

		o = s.option(form.Value, 'autoswitch_retry_num', _('Timeout retry num'));
		o.datatype = 'range(1,5)';
		o.default = '1';
		o.depends('enable_autoswitch', '1');

		o = s.option(form.Flag, 'autoswitch_restore_switch', _('Restore Switch'), _('Immediately switch back to the main node when it becomes available.'));
		o.depends('enable_autoswitch', '1');

		o = s.option(form.Value, 'autoswitch_probe_url', _('Probe URL'), _('The URL used to detect the connection status.'));
		o.value('https://cp.cloudflare.com/', 'Cloudflare');
		o.value('https://www.gstatic.com/generate_204', 'Gstatic');
		o.value('https://www.google.com/generate_204', 'Google');
		o.value('https://www.youtube.com/generate_204', 'YouTube');
		o.value('https://connect.rom.miui.com/generate_204', 'MIUI (CN)');
		o.value('https://connectivitycheck.platform.hicloud.com/generate_204', 'HiCloud (CN)');
		o.value('https://wifi.vivo.com.cn/generate_204', 'VIVO (CN)');
		o.default = 'https://www.google.com/generate_204';
		o.depends('enable_autoswitch', '1');

		var btn = s.option(form.DummyValue, 'btn', '');
		btn.depends('backup_node_add_mode', 'manual');
		btn.renderWidget = function() {
			function ask(method) {
				var key = prompt(_('Please enter the node keyword, pay attention to distinguish between spaces, uppercase and lowercase.'), '');
				if (!key)
					return;
				pw.call(method, { id: id, key: key }).then(function() {
					window.location.reload();
				}).catch(function(err) {
					ui.addNotification(null, E('p', {}, err.message || String(err)));
				});
			}
			return E('div', { 'class': 'key-btn-div' }, [
				E('input', {
					'class': 'btn cbi-button cbi-button-add',
					'type': 'button',
					'value': _('Add nodes to the standby node list by keywords'),
					'click': function() { ask('socks_autoswitch_add_node'); }
				}),
				' ',
				E('input', {
					'class': 'btn cbi-button cbi-button-remove',
					'type': 'button',
					'value': _('Delete nodes in the standby node list by keywords'),
					'click': function() { ask('socks_autoswitch_remove_node'); }
				})
			]);
		};

		return m.render().then(function(node) {
			var style = E('style', {}, [
				'.key-btn-div{display:table-cell;padding:5px 0 5px;}',
				'@media screen and (max-width:600px){.key-btn-div{display:block;}.key-label{display:none !important;}}',
				'.key-btn-div .cbi-button{margin-bottom:2px;}'
			].join(''));
			return E('div', {}, [ style, node ]);
		});
	}
});
