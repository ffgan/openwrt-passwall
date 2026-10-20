'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require poll';
'require view.passwall.tools as pw';

var PKG = 'passwall_server';

function protocolName(protocol, custom) {
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
	default:
		var label = protocol ? (protocol.charAt(0).toUpperCase() + protocol.slice(1)) : '';
		if (String(custom || '0') === '1')
			label = _('Custom Config');
		return label;
	}
}

function typeText(type, protocol, custom) {
	type = type || '';
	if (type === 'sing-box' || type === 'Xray') {
		var proto = protocolName(protocol || '', custom);
		if (type === 'sing-box')
			type = 'Sing-Box';
		type = type + ' ' + proto;
	}
	return _(type);
}

function asObject(res) {
	if (res == null)
		return null;
	if (typeof res === 'string') {
		var text = res.trim();
		if (!text)
			return null;
		try {
			return JSON.parse(text);
		}
		catch (e) {
			return { output: res };
		}
	}
	if (typeof res === 'object' && typeof res.output === 'string') {
		var raw = res.output.trim();
		if (!raw)
			return res;
		try {
			return JSON.parse(raw);
		}
		catch (e2) {
			return res;
		}
	}
	return res;
}

function logText(res) {
	if (res == null)
		return '';
	if (typeof res === 'string')
		return res;
	if (typeof res.output === 'string')
		return res.output;
	if (typeof res.data === 'string')
		return res.data;
	try {
		return JSON.stringify(res);
	}
	catch (e) {
		return String(res);
	}
}

function openServerLog(id) {
	return pw.call('server_log', { id: id }).then(function(res) {
		var text = logText(res);
		if (!text || /Not enabled log/.test(text) || /window\.close/.test(text)) {
			alert(_('Not enabled log'));
			return;
		}
		var body = text.replace(/<br\s*\/?>/gi, '\n').replace(/<[^>]+>/g, '');
		ui.showModal(_('Log'), [
			E('textarea', {
				'style': 'width:100%;min-height:24rem',
				'readonly': 'readonly',
				'wrap': 'off'
			}, body),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Close'))
			])
		]);
	}).catch(function() {
		alert(_('Error'));
	});
}

function sectionById(type, id) {
	var list = uci.sections(PKG, type) || [];
	for (var i = 0; i < list.length; i++)
		if (list[i]['.name'] === id)
			return list[i];
	return null;
}

function bindRow(section, page) {
	var base = form.GridSection.prototype.renderRow;
	section.renderRow = function(section_id) {
		var tr = base.apply(this, arguments);
		if (!tr || !tr.addEventListener)
			return tr;
		tr.setAttribute('data-sid', section_id);
		tr.addEventListener('click', function(ev) {
			var target = ev.target;
			if (target && target.closest && target.closest('button, a, input, select, textarea, .drag-handle'))
				return;
			window.location.href = pw.pageUrl(page, section_id);
		});
		return tr;
	};
}

function refreshStatus(root) {
	var nodes = root.querySelectorAll('._servers_status');
	Array.prototype.forEach.call(nodes, function(el, i) {
		var id = el.getAttribute('data-sid');
		if (!id)
			return;
		pw.call('server_status', { index: i, id: id }).then(function(res) {
			var body = asObject(res) || {};
			var idx = (body.index != null && body.index !== '') ? Number(body.index) : i;
			var target = nodes[idx] || el;
			var ok = body.status === true || body.status === 1 || body.status === '1';
			target.style.fontWeight = 'bold';
			target.style.color = ok ? 'green' : 'red';
			target.textContent = ok ? '✓' : 'X';
		}).catch(function() {});
	});
}

return view.extend({
	load: function() {
		return uci.load(PKG);
	},

	render: function() {
		var globals = uci.sections(PKG, 'global') || [];
		var gid = globals.length ? globals[0]['.name'] : null;
		if (!gid) {
			uci.add(PKG, 'global', 'global');
			gid = 'global';
		}

		var m = new form.Map(PKG);
		var globalSec = m.section(form.NamedSection, gid, 'global', _('Server-Side'));
		globalSec.addremove = false;

		var enable = globalSec.option(form.Flag, 'enable', _('Enable'));
		enable.rmempty = false;

		var delay = globalSec.option(form.Value, 'start_delay', _('Delay Start'), _('Units:seconds'));
		delay.default = '90';
		delay.datatype = 'range(0,600)';
		delay.rmempty = false;

		var servers = m.section(form.GridSection, 'server', _('Servers Manager'));
		servers.anonymous = true;
		servers.addremove = true;
		servers.sortable = true;
		servers.nodescriptions = true;
		servers.extedit = pw.pageUrl('server_config') + '/%s';
		servers.handleAdd = function() {
			var configName = this.uciconfig || this.map.config;
			var uid = pw.rand(8);
			this.uci.add(configName, 'server', uid);
			return this.map.save(null, true).then(function() {
				return uci.save();
			}).then(function() {
				window.location.href = pw.pageUrl('server_config', uid);
			});
		};
		bindRow(servers, 'server_config');

		var serverActions = form.GridSection.prototype.renderRowActions;
		servers.renderRowActions = function(section_id) {
			var cell = serverActions.apply(this, arguments);
			var btn = E('button', {
				'class': 'btn cbi-button cbi-button-add',
				'title': _('Log'),
				'click': ui.createHandlerFn(this, function(ev) {
					if (ev) {
						ev.preventDefault();
						ev.stopPropagation();
					}
					return openServerLog(section_id);
				})
			}, _('Log'));
			var box = (cell && cell.querySelector) ? (cell.querySelector('div') || cell) : null;
			if (box) {
				box.insertBefore(document.createTextNode('\u00a0\u00a0'), box.firstChild);
				box.insertBefore(btn, box.firstChild);
			}
			return cell;
		};

		var o = servers.option(form.Flag, 'enable', _('Enable'));
		o.rmempty = false;

		o = servers.option(form.DummyValue, 'status', _('Status'));
		o.write = function() {};
		o.remove = function() {};
		o.renderWidget = function(section_id) {
			return E('span', {
				'class': '_servers_status',
				'data-sid': section_id,
				'style': 'font-weight:bold'
			}, _('Collecting data...'));
		};

		o = servers.option(form.DummyValue, 'remarks', _('Remarks'));
		o.write = function() {};
		o.remove = function() {};

		o = servers.option(form.DummyValue, 'type', _('Type'));
		o.write = function() {};
		o.remove = function() {};
		o.cfgvalue = function(section_id) {
			var sec = sectionById('server', section_id) || {};
			return typeText(sec.type, sec.protocol, sec.custom);
		};

		o = servers.option(form.DummyValue, 'port', _('Port'));
		o.write = function() {};
		o.remove = function() {};

		o = servers.option(form.Flag, 'log', _('Log'));
		o.default = '1';
		o.rmempty = false;

		var users = m.section(form.GridSection, 'user', _('Users Manager'));
		users.anonymous = true;
		users.addremove = true;
		users.sortable = true;
		users.nodescriptions = true;
		users.extedit = pw.pageUrl('server_user_config') + '/%s';
		users.handleAdd = function() {
			var configName = this.uciconfig || this.map.config;
			var uid = pw.rand(8);
			this.uci.add(configName, 'user', uid);
			return this.map.save(null, true).then(function() {
				return uci.save();
			}).then(function() {
				window.location.href = pw.pageUrl('server_user_config', uid);
			});
		};
		users.handleRemove = function(section_id, ev) {
			(uci.sections(PKG, 'server') || []).forEach(function(server) {
				var sid = server['.name'];
				if (server.user && server.user === section_id)
					uci.set(PKG, sid, 'user', '');
				var list = server.users;
				if (list == null || list === '')
					return;
				if (!Array.isArray(list))
					list = String(list).split(/\s+/);
				var kept = [];
				var changed = false;
				list.forEach(function(item) {
					if (item === section_id)
						changed = true;
					else if (item)
						kept.push(item);
				});
				if (!changed)
					return;
				if (kept.length)
					uci.set(PKG, sid, 'users', kept);
				else
					uci.unset(PKG, sid, 'users');
			});
			return Promise.resolve(form.GridSection.prototype.handleRemove.call(this, section_id, ev)).then(function() {
				window.location.href = pw.pageUrl('server');
			});
		};
		bindRow(users, 'server_user_config');

		o = users.option(form.DummyValue, 'username', _('Username'));
		o.write = function() {};
		o.remove = function() {};

		o = users.option(form.DummyValue, 'password', _('Password'));
		o.write = function() {};
		o.remove = function() {};

		o = users.option(form.DummyValue, 'uuid', 'UUID');
		o.write = function() {};
		o.remove = function() {};

		var textarea = E('textarea', {
			'id': 'log_textarea',
			'class': 'cbi-input-textarea',
			'style': 'width:100%;margin-top:10px',
			'rows': 20,
			'wrap': 'off',
			'readonly': 'readonly'
		});
		var first = true;
		function scrollToBottom() {
			textarea.scrollTop = textarea.scrollHeight;
		}
		poll.add(function() {
			return pw.get('server_get_log').then(function(text) {
				var body = (typeof text === 'string') ? text : logText(text);
				var wasBottom = (textarea.scrollTop + textarea.clientHeight >= textarea.scrollHeight - 10);
				textarea.value = body;
				if (first) {
					scrollToBottom();
					first = false;
				}
				else if (wasBottom) {
					scrollToBottom();
				}
			}).catch(function() {});
		}, 3);

		var logBox = E('fieldset', { 'class': 'cbi-section', 'id': '_log_fieldset' }, [
			E('legend', {}, _('Logs')),
			E('button', {
				'class': 'btn cbi-button cbi-button-remove',
				'click': ui.createHandlerFn(this, function() {
					return pw.call('server_clear_log').then(function() {
						textarea.value = '';
						scrollToBottom();
					});
				})
			}, _('Clear logs')),
			textarea
		]);

		return m.render().then(function(mapNode) {
			refreshStatus(mapNode);
			return E('div', {}, [ mapNode, logBox ]);
		});
	}
});
