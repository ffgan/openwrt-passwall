'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require poll';
'require view.passwall.tools as pw';

var APP = 'passwall';

function present(v) {
	return !(v == null || v === false || v === '' || v === 0);
}

function asObject(res) {
	if (res && typeof res === 'object' && typeof res.output === 'string') {
		var text = res.output.trim();
		if (!text)
			return res;
		try {
			return JSON.parse(text);
		}
		catch (e) {
			return res;
		}
	}
	if (typeof res === 'string') {
		try {
			return JSON.parse(res);
		}
		catch (e2) {
			return { success: false, msg: res };
		}
	}
	return res || {};
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

function ensureSection(type) {
	var id = pw.sectionId(APP, type);
	if (!id)
		id = uci.add(APP, type);
	return id;
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

function bindRemark(o) {
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
}

function readOption(opt, section_id, name) {
	var value = null;
	if (opt && typeof opt.formvalue === 'function')
		value = opt.formvalue(section_id);
	if (value == null)
		value = uci.get(APP, section_id, name);
	return String(value == null ? '' : value).trim();
}

function subscribeInfo(section_id) {
	var remark = String(uci.get(APP, section_id, 'remark') || '');
	var extra = String(uci.get(APP, section_id, 'rem_traffic') || '');
	var expired = String(uci.get(APP, section_id, 'expired_date') || '');
	if (expired !== '')
		extra = extra + (extra !== '' ? '/' : '') + expired;
	var num = 0;
	(uci.sections(APP, 'nodes') || []).forEach(function(node) {
		if (node.group && String(node.group).toLowerCase() === remark.toLowerCase())
			num++;
	});
	var kids = [ _('Node num') + ': ' + num ];
	if (extra !== '')
		kids.push(E('br'), extra);
	return E('div', {}, kids);
}

function addCoreOption(section, name, label, values, last) {
	if (!values.length)
		return null;
	var o = section.option(form.ListValue, name, label);
	o.value('', _('Auto'));
	values.forEach(function(value) {
		o.value(value);
	});
	if (last)
		o.description = '<span class="pw-warn">' + _('The configured type also applies to the core specified when manually importing nodes.') + '</span>';
	return o;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(APP),
			pw.loadCaps().catch(function() { return {}; })
		]);
	},

	render: function(data) {
		var caps = data[1] || {};
		var types = coreTypes(caps);
		var order = [];
		if (types.ss.length)
			order.push('ss');
		if (types.trojan.length)
			order.push('trojan');
		if (types.vmess.length)
			order.push('vmess');
		if (types.vless.length)
			order.push('vless');
		if (types.hy2.length)
			order.push('hy2');
		var last = order.length ? order[order.length - 1] : '';
		var sid = ensureSection('global_subscribe');
		var m = new form.Map(APP);
		var s = m.section(form.NamedSection, sid, 'global_subscribe');

		var o = s.option(form.ListValue, 'filter_keyword_mode', _('Filter keyword Mode'));
		o.value('0', _('Close'));
		o.value('1', _('Discard List'));
		o.value('2', _('Keep List'));
		o.value('3', _('Discard List,But Keep List First'));
		o.value('4', _('Keep List,But Discard List First'));

		s.option(form.DynamicList, 'filter_discard_list', _('Discard List'));
		s.option(form.DynamicList, 'filter_keep_list', _('Keep List'));

		addCoreOption(s, 'ss_type', _('%s Node Use Type').replace('%s', 'Shadowsocks'), types.ss, last === 'ss');
		addCoreOption(s, 'trojan_type', _('%s Node Use Type').replace('%s', 'Trojan'), types.trojan, last === 'trojan');
		addCoreOption(s, 'vmess_type', _('%s Node Use Type').replace('%s', 'VMess'), types.vmess, last === 'vmess');
		addCoreOption(s, 'vless_type', _('%s Node Use Type').replace('%s', 'VLESS'), types.vless, last === 'vless');
		addCoreOption(s, 'hysteria2_type', _('%s Node Use Type').replace('%s', 'Hysteria2'), types.hy2, last === 'hy2');

		o = s.option(form.DummyValue, '_stop', _('Delete All Subscribe Node'));
		o.renderWidget = function() {
			return E('button', {
				'class': 'btn cbi-button cbi-button-remove',
				'click': function(ev) {
					ev.preventDefault();
					if (!confirm(_('Are you sure you want to delete all subscribed nodes?')))
						return;
					pw.call('subscribe_del_all').then(function() {
						window.location.reload();
					}).catch(function() {
						alert(_('Failed to delete.'));
					});
				}
			}, _('Delete All Subscribe Node'));
		};

		var grid;
		var remarkOpt;
		var urlOpt;

		function manualAll(ev) {
			if (ev)
				ev.preventDefault();
			var ids = [];
			var urls = [];
			var sections = uci.sections(APP, 'subscribe_list') || [];
			for (var i = 0; i < sections.length; i++) {
				var id = sections[i]['.name'];
				var current = readOption(urlOpt, id, 'url');
				if (!current) {
					alert(_('Subscribe URL cannot be empty.'));
					return;
				}
				ids.push(id);
				urls.push(current);
			}
			if (!ids.length)
				return;
			pw.call('subscribe_manual_all', {
				sections: ids.join(','),
				urls: urls.join(',')
			}).then(function(res) {
				var body = asObject(res);
				if (!body.success)
					alert(body.msg || 'Operation failed');
				else
					window.location.href = pw.pageUrl('log');
			}).catch(function(err) {
				alert((err && err.message) || 'Operation failed');
			});
		}

		o = s.option(form.DummyValue, '_update', _('Manual subscription All'));
		o.renderWidget = function() {
			return E('button', {
				'class': 'btn cbi-button cbi-button-apply',
				'click': manualAll
			}, _('Manual subscription All'));
		};

		grid = m.section(form.GridSection, 'subscribe_list', '',
			'<span class="pw-warn">' + _('When adding a new subscription, please save and apply before manually subscribing. If you only change the subscription URL, you can subscribe manually, and the system will save it automatically.') + '</span>');
		grid.anonymous = true;
		grid.addremove = true;
		grid.sortable = true;
		grid.nodescriptions = true;
		grid.extedit = pw.pageUrl('node_subscribe_config') + '/%s';
		grid.renderRowActions = function(section_id) {
			return form.TableSection.prototype.renderRowActions.call(this, section_id, null);
		};
		grid.handleAdd = function() {
			var section = this;
			(uci.sections(APP, 'subscribe_list') || []).forEach(function(sec) {
				uci.unset(APP, sec['.name'], 'md5');
			});
			return section.map.save().then(function() {
				var uid = 'sub_' + pw.rand(5);
				uci.add(APP, 'subscribe_list', uid);
				uci.set(APP, uid, 'hysteria_up_mbps', '100');
				uci.set(APP, uid, 'hysteria_down_mbps', '100');
				return uci.save().then(function() {
					window.location.href = pw.pageUrl('node_subscribe_config', uid);
				});
			});
		};

		remarkOpt = grid.option(form.Value, 'remark', _('Remarks'));
		remarkOpt.editable = true;
		remarkOpt.modalonly = false;
		bindRemark(remarkOpt);

		o = grid.option(form.DummyValue, '_node_count', _('Subscribe Info'));
		o.editable = true;
		o.modalonly = false;
		o.renderWidget = function(section_id) {
			return subscribeInfo(section_id);
		};

		urlOpt = grid.option(form.Value, 'url', _('Subscribe URL'));
		urlOpt.editable = true;
		urlOpt.modalonly = false;
		urlOpt.rmempty = false;
		urlOpt.parse = function(section_id) {
			if (!this.isActive(section_id))
				return this.retain ? null : this.remove(section_id);
			var value = this.formvalue(section_id);
			if (value == null)
				value = '';
			return this.write(section_id, value);
		};

		o = grid.option(form.DummyValue, '_remove', _('Delete the subscribed node'));
		o.editable = true;
		o.modalonly = false;
		o.renderWidget = function(section_id) {
			return E('button', {
				'class': 'btn cbi-button cbi-button-remove',
				'click': function(ev) {
					ev.preventDefault();
					ev.stopPropagation();
					var remark = readOption(remarkOpt, section_id, 'remark');
					if (!confirm(_('Delete the subscribed node') + ': ' + remark + ' ?'))
						return;
					pw.call('subscribe_del_node', { remark: remark }).then(function() {
						window.location.reload();
					}).catch(function() {
						alert(_('Failed to delete.'));
					});
				}
			}, _('Delete the subscribed node'));
		};

		o = grid.option(form.DummyValue, '_update', _('Manual subscription'));
		o.editable = true;
		o.modalonly = false;
		o.renderWidget = function(section_id) {
			return E('button', {
				'class': 'btn cbi-button cbi-button-apply',
				'click': function(ev) {
					ev.preventDefault();
					ev.stopPropagation();
					var current = readOption(urlOpt, section_id, 'url');
					if (!current) {
						alert(_('Subscribe URL cannot be empty.'));
						return;
					}
					pw.call('subscribe_manual', {
						section: section_id,
						url: current
					}).then(function(res) {
						var body = asObject(res);
						if (!body.success)
							alert(body.msg || 'Operation failed');
						else
							window.location.href = pw.pageUrl('log');
					}).catch(function(err) {
						alert((err && err.message) || 'Operation failed');
					});
				}
			}, _('Manual subscription'));
		};

		var view = this;
		return m.render().then(function(node) {
			view.map = m;
			paintHtml(node);
			node.querySelectorAll('#cbi-passwall-subscribe_list tr.cbi-section-table-row[data-sid]').forEach(function(row) {
				row.style.cursor = 'pointer';
				row.addEventListener('click', function(ev) {
					if (ev.target.closest('button, a, input, select, textarea, .cbi-button, .cbi-dropdown'))
						return;
					var id = row.getAttribute('data-sid');
					if (id)
						window.location.href = pw.pageUrl('node_subscribe_config', id);
				});
			});
			return node;
		});
	},

	handleSave: function(ev) {
		(uci.sections(APP, 'subscribe_list') || []).forEach(function(sec) {
			uci.unset(APP, sec['.name'], 'md5');
		});
		return this.super('handleSave', [ev]);
	}
});
