'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require fs';
'require poll';
'require view.passwall.tools as pw';

var APP = 'passwall';

var UPDATE_FLAGS = [
	'gfwlist_update',
	'chnroute_update',
	'chnroute6_update',
	'chnlist_update',
	'geoip_update',
	'geosite_update'
];

var UPDATE_NAMES = [ 'gfwlist', 'chnroute', 'chnroute6', 'chnlist', 'geoip', 'geosite' ];

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

function asArray(data) {
	if (Array.isArray(data))
		return data;
	if (!data || typeof data !== 'object')
		return [];
	if (typeof data.output === 'string') {
		try {
			return asArray(JSON.parse(data.output));
		}
		catch (e) {
			return [];
		}
	}
	if (data['.name'] || data.remarks)
		return [ data ];
	var keys = Object.keys(data).filter(function(k) { return /^\d+$/.test(k); });
	if (!keys.length)
		return [];
	keys.sort(function(a, b) { return (+a) - (+b); });
	return keys.map(function(k) { return data[k]; });
}

function sectionName(row) {
	if (!row)
		return '';
	return row['.name'] || row.name || row.id || '';
}

function ensureSortable() {
	if (window.Sortable)
		return Promise.resolve(window.Sortable);
	return new Promise(function(resolve) {
		var script = E('script', { 'src': L.resource('view/passwall/sortable.js') });
		script.onload = function() { resolve(window.Sortable || null); };
		script.onerror = function() { resolve(null); };
		document.head.appendChild(script);
	});
}

function hourChoices(option) {
	var t;
	for (t = 0; t <= 23; t++)
		option.value(t + ':00');
	return option;
}

function intervalChoices(option) {
	var t;
	for (t = 1; t <= 24; t++)
		option.value(String(t), t + ' ' + _('hour'));
	return option;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(APP),
			pw.loadCaps(),
			fileExists('/tmp/bak_v2ray/geoip.dat'),
			fileExists('/tmp/bak_v2ray/geosite.dat')
		]);
	},

	render: function(data) {
		var caps = data[1] || {};
		var hasOldGeoip = !!data[2];
		var hasOldGeosite = !!data[3];
		var hasCore = present(caps.singbox) || present(caps.xray);
		var hasGeoview = present(caps.geoview);
		var rules = uci.sections(APP, 'global_rules') || [];
		var sid = rules.length ? rules[0]['.name'] : null;
		var globals = uci.sections(APP, 'global') || [];
		var globalId = globals.length ? globals[0]['.name'] : null;
		var self = this;

		if (!sid)
			return E('div', { 'class': 'alert-message warning' }, _('Rule status'));

		var m = new form.Map(APP);
		var s = m.section(form.NamedSection, sid, 'global_rules', _('Rule status'));
		s.addremove = false;

		var o;
		o = s.option(form.DynamicList, 'gfwlist_url', _('GFW domains(gfwlist) Update URL'));
		o.value('https://cdn.jsdelivr.net/gh/YW5vbnltb3Vz/domain-list-community@release/gfwlist.txt', _('v2fly/domain-list-community'));
		o.value('https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt', _('Loyalsoldier/v2ray-rules-dat'));
		o.value('https://cdn.jsdelivr.net/gh/Loukky/gfwlist-by-loukky/gfwlist.txt', _('Loukky/gfwlist-by-loukky'));
		o.value('https://cdn.jsdelivr.net/gh/gfwlist/gfwlist/gfwlist.txt', _('gfwlist/gfwlist'));
		o.value('https://cdn.jsdelivr.net/gh/pexcn/daily@gh-pages/gfwlist/gfwlist.txt', _('pexcn/gfwlist'));
		o.default = 'https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt';

		o = s.option(form.DynamicList, 'chnroute_url', _('China IPs(chnroute) Update URL'));
		o.value('https://ispip.clang.cn/all_cn.txt', _('Clang.CN'));
		o.value('https://cdn.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china.txt', _('gaoyifan/china-operator-ip/china'));
		o.value('https://cdn.jsdelivr.net/gh/soffchen/GeoIP2-CN@release/CN-ip-cidr.txt', _('soffchen/GeoIP2-CN'));
		o.value('https://cdn.jsdelivr.net/gh/Hackl0us/GeoIP2-CN@release/CN-ip-cidr.txt', _('Hackl0us/GeoIP2-CN'));
		o.value('https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/ChinaMax/ChinaMax_IP_No_IPv6.txt', _('ios_rule_script/ChinaMax_IP_No_IPv6'));
		o.value('https://cdn.jsdelivr.net/gh/pexcn/daily@gh-pages/chnroute/chnroute.txt', _('pexcn/chnroute'));

		o = s.option(form.DynamicList, 'chnroute6_url', _('China IPv6s(chnroute6) Update URL'));
		o.value('https://ispip.clang.cn/all_cn_ipv6.txt', _('Clang.CN.IPv6'));
		o.value('https://cdn.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china6.txt', _('gaoyifan/china-operator-ip/china6'));
		o.value('https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/ChinaMax/ChinaMax_IP.txt', _('ios_rule_script/ChinaMax_IP'));
		o.value('https://cdn.jsdelivr.net/gh/pexcn/daily@gh-pages/chnroute/chnroute6.txt', _('pexcn/chnroute6'));

		o = s.option(form.DynamicList, 'chnlist_url', _('China List(Chnlist) Update URL'));
		o.value('https://cdn.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/accelerated-domains.china.conf', _('felixonmars/domains.china'));
		o.value('https://cdn.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/apple.china.conf', _('felixonmars/apple.china'));
		o.value('https://cdn.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/google.china.conf', _('felixonmars/google.china'));
		o.value('https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/china-list.txt', _('Loyalsoldier/china-list'));
		o.value('https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/apple-cn.txt', _('Loyalsoldier/apple-cn'));
		o.value('https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/google-cn.txt', _('Loyalsoldier/google-cn'));
		o.value('https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/ChinaMax/ChinaMax_Domain.txt', _('ios_rule_script/ChinaMax_Domain'));
		o.value('https://cdn.jsdelivr.net/gh/pexcn/daily@gh-pages/chinalist/chinalist.txt', _('pexcn/chinalist'));

		if (hasCore) {
			o = s.option(form.Value, 'geoip_url', _('GeoIP Update URL'));
			o.value('https://github.com/Loyalsoldier/geoip/releases/latest/download/geoip.dat', _('Loyalsoldier/geoip'));
			o.value('https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geoip.dat', _('MetaCubeX/geoip'));
			o.value('https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip.dat', _('Loyalsoldier/geoip (CDN)'));
			o.value('https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat', _('MetaCubeX/geoip (CDN)'));
			o.default = 'https://github.com/Loyalsoldier/geoip/releases/latest/download/geoip.dat';

			o = s.option(form.Value, 'geosite_url', _('Geosite Update URL'));
			o.value('https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat', _('Loyalsoldier/geosite'));
			o.value('https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.dat', _('MetaCubeX/geosite'));
			o.value('https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat', _('Loyalsoldier/geosite (CDN)'));
			o.value('https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat', _('MetaCubeX/geosite (CDN)'));
			o.default = 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat';

			o = s.option(form.Value, 'v2ray_location_asset', _('Location of Geo rule files'), _('This variable specifies a directory where geoip.dat and geosite.dat files are.'));
			o.default = '/usr/share/v2ray/';
			o.placeholder = '/usr/share/v2ray/';
			o.rmempty = false;

			if (hasGeoview) {
				o = s.option(form.Flag, 'geo2rule', _('Generate Rule List from Geo'));
				o.default = '0';
				o.rmempty = false;
				o.description = _('Generate rule lists such as GFW, China domains, and China IP ranges based on Geo files.') + ' ' +
					_('When manually updating with this option enabled, rules will be regenerated from existing Geo files even if no new version is available.');

				o = s.option(form.Flag, 'enable_geoview', _('Enable Geo Data Parsing'));
				o.default = '0';
				o.rmempty = false;
				o.description = _('Experimental feature.') + ' ' +
					_('Parses and preloads GeoIP/Geosite data to improve Sing-box/Xray routing performance.') + ' ' +
					_('Once enabled, the rule list can support GeoIP/Geosite rules.');
				o.write = function(section, value) {
					var old = uci.get(APP, section, 'enable_geoview') || '0';
					if (String(old) !== String(value) && globalId)
						uci.set(APP, globalId, 'flush_set', '1');
					return form.Flag.prototype.write.call(this, section, value);
				};
			}
		}

		if (hasGeoview && hasCore) {
			[ 'gfwlist_url', 'chnroute_url', 'chnroute6_url', 'chnlist_url' ].forEach(function(name) {
				var opt = m.lookupOption(name, sid);
				if (opt && opt[0])
					opt[0].depends('geo2rule', '0');
			});
		}

		o = s.option(form.ListValue, 'update_week_mode', _('Auto Update Mode'));
		pw.weekMode(o, true);

		o = s.option(form.Value, 'update_time_mode', _('Update Time'));
		hourChoices(o);
		o.default = '0:00';
		o.datatype = 'timehhmm';
		[ '0', '1', '2', '3', '4', '5', '6', '7' ].forEach(function(day) {
			o.depends('update_week_mode', day);
		});

		o = s.option(form.ListValue, 'update_interval_mode', _('Update Interval(hour)'));
		intervalChoices(o);
		o.default = '2';
		o.rmempty = true;
		o.depends('update_week_mode', '8');

		UPDATE_FLAGS.forEach(function(name) {
			var flag = s.option(form.Flag, name);
			flag.rmempty = false;
		});

		var updatePanel = s.option(form.DummyValue, '_rule_actions', _('Update Options'));
		updatePanel.render = function() {
			var checks = UPDATE_NAMES.map(function(name) {
				return E('label', { 'style': 'margin-right:0.75em' }, [
					E('input', {
						'class': 'cbi-input-checkbox',
						'type': 'checkbox',
						'data-rule': name
					}),
					' ' + name
				]);
			});
			var buttons = [
				E('input', {
					'class': 'btn cbi-button cbi-button-apply',
					'type': 'button',
					'id': 'update_rules_btn',
					'value': _('Manually update'),
					'click': function(ev) { self.updateRules(ev.target); }
				})
			];
			if (hasOldGeoip) {
				buttons.push(' ');
				buttons.push(E('input', {
					'class': 'btn cbi-button cbi-button-reset',
					'type': 'button',
					'value': _('Rollback') + ' GeoIP',
					'click': function(ev) { self.rollbackRules(ev.target, 'geoip'); }
				}));
			}
			if (hasOldGeosite) {
				buttons.push(' ');
				buttons.push(E('input', {
					'class': 'btn cbi-button cbi-button-reset',
					'type': 'button',
					'value': _('Rollback') + ' Geosite',
					'click': function(ev) { self.rollbackRules(ev.target, 'geosite'); }
				}));
			}
			return E('div', { 'class': 'cbi-value', 'id': '_rule_div' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Update Options')),
				E('div', { 'class': 'cbi-value-field' }, [
					E('div', {}, checks),
					E('div', { 'style': 'margin-top:0.75em' }, buttons)
				])
			]);
		};

		var shuntHost = null;
		if (hasCore) {
			var shuntAnchor = s.option(form.DummyValue, '_shunt_anchor', '');
			shuntAnchor.render = function() {
				return E('div', { 'id': 'pw-shunt-anchor' });
			};
		}

		this.map = m;
		this.sectionId = sid;
		this.hasCore = hasCore;

		return m.render().then(function(formNode) {
			var style = E('style', {}, [
				UPDATE_FLAGS.map(function(name) {
					return 'div.cbi-value[id$="-' + name + '"]{display:none !important;}';
				}).join('\n'),
				'table th,.table .th{text-align:center;}',
				'table td,.table .td{text-align:center;word-break:keep-all;}',
				'.td.cbi-section-actions{text-align:right !important;}',
				'.shunt_rule-wrapper{align-items:center;display:inline-flex !important;gap:4px;}',
				'.cbi-tabmenu > li{margin-right:2px !important;}',
				'.cbi-tabmenu > li:last-child{margin-right:0 !important;}',
				'.shunt_rule-wrapper .drag-handle{cursor:grab !important;display:inline-flex;align-items:center;justify-content:center;font-size:20px;font-weight:100;padding:0 !important;line-height:inherit;user-select:none;align-self:stretch;background-color:transparent;}',
				'.shunt_rule-wrapper .drag-handle:hover{background:transparent;}',
				'@media screen and (max-width:1152px){.cbi-section-table-row{display:flex;flex-direction:row;flex-wrap:wrap;justify-content:space-between;}.cbi-section-table-titles{display:none !important;}.td-actions{padding-top:0 !important;border-top-width:0 !important;flex:1 1 350px;}}',
				'@media screen and (max-width:500px){.shunt_rule-wrapper{gap:0;}.cbi-button{margin-left:0 !important;margin-right:1px !important;}.td-actions{padding-left:5px !important;padding-right:5px !important;}}',
				'.sortable-chosen{background-color:rgba(220,235,245,0.4) !important;opacity:0.7;}',
				'.sortable-ghost{background:#cce5ff !important;height:3px !important;}',
				'.dragging-row{background-color:rgba(131,191,255,0.7) !important;box-shadow:0 4px 6px rgba(0,0,0,0.1);}'
			].join('\n'));
			var root = E('div', {}, [ style, formNode ]);
			self.bindUpdateFlags(root, sid);
			if (hasCore) {
				shuntHost = E('div', { 'id': 'shunt_rule_host' });
				var anchor = root.querySelector('#pw-shunt-anchor');
				if (anchor)
					anchor.appendChild(shuntHost);
				else
					root.appendChild(shuntHost);
				self.listRoot = shuntHost;
				self.loadShuntRules();
			}
			return root;
		});
	},

	bindUpdateFlags: function(root, sid) {
		var self = this;
		function flagOption(name) {
			var found = self.map.lookupOption(name, sid);
			return found && found[0];
		}
		function syncOne(name) {
			var opt = flagOption(name + '_update');
			var box = root.querySelector('input[data-rule="' + name + '"]');
			if (!opt || !box)
				return;
			var uiEl = opt.getUIElement(sid);
			if (!uiEl)
				return;
			box.checked = !!uiEl.isChecked();
			if (!box._pwBound) {
				box._pwBound = true;
				box.addEventListener('change', function() {
					uiEl.setValue(box.checked ? '1' : '0');
				});
			}
		}
		UPDATE_NAMES.forEach(syncOne);
		function syncGeo() {
			var opt = flagOption('geo2rule');
			var on = false;
			if (opt) {
				var uiEl = opt.getUIElement(sid);
				on = !!(uiEl && uiEl.isChecked());
			}
			[ 'gfwlist', 'chnroute', 'chnroute6', 'chnlist' ].forEach(function(name) {
				var box = root.querySelector('input[data-rule="' + name + '"]');
				if (box && box.parentNode)
					box.parentNode.style.display = on ? 'none' : '';
			});
		}
		syncGeo();
		var geoRow = root.querySelector('#cbi-' + APP + '-' + sid + '-geo2rule');
		if (geoRow)
			geoRow.addEventListener('widget-change', syncGeo);
	},

	checkedRules: function(filter) {
		var root = document.getElementById('_rule_div');
		var names = [];
		if (!root)
			return names;
		root.querySelectorAll('input[data-rule]').forEach(function(box) {
			if (!box.checked)
				return;
			if (!filter || filter(box.getAttribute('data-rule')))
				names.push(box.getAttribute('data-rule'));
		});
		return names;
	},

	updateRules: function(btn) {
		var names = this.checkedRules();
		btn.disabled = true;
		btn.value = _('Updating...');
		pw.call('update_rules', { update: names.join(',') }).then(function(res) {
			if (res && res.code === 0) {
				alert(_('Error'));
				btn.disabled = false;
				btn.value = _('Manually update');
				return;
			}
			window.location.href = pw.pageUrl('log');
		}).catch(function() {
			alert(_('Error'));
			btn.disabled = false;
			btn.value = _('Manually update');
		});
	},

	rollbackRules: function(btn, type) {
		var original = btn.value;
		var names = this.checkedRules(function(name) {
			if (type === 'geoip')
				return name === 'chnroute' || name === 'chnroute6';
			if (type === 'geosite')
				return name === 'gfwlist' || name === 'chnlist';
			return false;
		});
		btn.disabled = true;
		btn.value = _('Rollbacking...');
		pw.call('rollback_rules', { type: type, rules: names.join(',') }).then(function(res) {
			if (res && res.code == 1) {
				alert(_('Success'));
				btn.style.display = 'none';
				return;
			}
			alert(_('Error'));
			btn.disabled = false;
			btn.value = original;
		}).catch(function() {
			alert(_('Error'));
			btn.disabled = false;
			btn.value = original;
		});
	},

	loadShuntRules: function() {
		var self = this;
		pw.call('get_shunt_rules', {}).then(function(res) {
			self.renderShuntRules(asArray(res));
		}).catch(function() {
			self.renderShuntRules([]);
		});
	},

	renderShuntRules: function(rows) {
		var self = this;
		var host = this.listRoot;
		if (!host)
			return;
		var groups = {};
		var order = [];
		if (!rows.length) {
			groups['default'] = [];
			order.push('default');
		}
		else {
			rows.forEach(function(row) {
				var group = row.group || 'default';
				if (!group)
					group = 'default';
				if (!groups[group]) {
					groups[group] = [];
					order.push(group);
				}
				groups[group].push(row);
			});
		}
		var tabs = E('ul', { 'class': 'cbi-tabmenu' });
		var body = E('div', { 'id': 'cbi-' + APP + '-shunt_rules' });
		order.forEach(function(group) {
			var label = group === 'default' ? _('default') : group;
			var tab = E('li', {
				'class': 'cbi-tab-disabled',
				'data-group': group
			}, [
				E('a', {
					'href': '#',
					'click': function(ev) {
						ev.preventDefault();
						self.switchShuntGroup(group);
					}
				}, [
					label,
					' | ',
					E('span', { 'class': 'pw-warn' }, String(groups[group].length))
				])
			]);
			tabs.appendChild(tab);
			var table = E('table', {
				'class': 'table cbi-section-table',
				'id': 'cbi-' + APP + '-shunt_rules-' + group + '-table',
				'data-group': group
			}, [
				E('tr', { 'class': 'tr cbi-section-table-titles anonymous' }, [
					E('th', { 'class': 'th cbi-section-table-cell', 'style': 'width:30%' }, 'ID'),
					E('th', { 'class': 'th cbi-section-table-cell', 'style': 'width:30%' }, _('Remarks')),
					E('th', { 'class': 'th cbi-section-table-cell cbi-section-actions' })
				])
			]);
			groups[group].forEach(function(row, index) {
				var id = sectionName(row);
				table.appendChild(E('tr', {
					'class': 'tr cbi-section-table-row cbi-rowstyle-' + ((index % 2) + 1),
					'id': 'cbi-' + APP + '-' + id,
					'data-sid': id
				}, [
					E('td', { 'class': 'td cbi-value-field' }, [ E('b', {}, id) ]),
					E('td', { 'class': 'td cbi-value-field' }, row.remarks || ''),
					E('td', { 'class': 'td cbi-section-table-cell nowrap cbi-section-actions td-actions' }, [
						E('div', { 'class': 'shunt_rule-wrapper' }, [
							E('input', {
								'class': 'btn cbi-button cbi-button-edit',
								'type': 'button',
								'value': _('To Top'),
								'title': _('To Top'),
								'click': function(ev) { self.rowTop(ev.target, group); }
							}),
							E('input', {
								'class': 'btn cbi-button cbi-button-edit',
								'type': 'button',
								'value': _('Edit'),
								'title': _('Edit'),
								'click': function() {
									window.location.href = pw.pageUrl('shunt_rules', id);
								}
							}),
							E('input', {
								'class': 'btn cbi-button cbi-button-remove',
								'type': 'button',
								'value': _('Delete'),
								'title': _('Delete'),
								'click': function() { self.deleteShunt(id); }
							}),
							E('span', { 'class': 'drag-handle center', 'title': _('Drag to reorder') }, '⠿')
						])
					])
				]));
			});
			var pane = E('div', {
				'class': 'cbi-tabcontainer',
				'id': 'container.' + APP + '.shunt_rules.' + group,
				'data-group': group,
				'style': 'display:none'
			}, [
				E('div', {
					'class': 'cbi-section cbi-tblsection',
					'id': 'cbi-' + APP + '-shunt_rules-' + group + '-fieldset'
				}, [
					table,
					E('input', { 'type': 'hidden', 'name': 'group.order.' + group, 'data-order': group }),
					E('div', { 'class': 'cbi-section-create cbi-tblsection-create' }, [
						E('input', { 'type': 'text', 'id': 'add_name_' + group }),
						' ',
						E('input', {
							'class': 'cbi-button cbi-button-add',
							'type': 'button',
							'value': _('Add'),
							'click': function() { self.addShunt(group); }
						})
					])
				])
			]);
			body.appendChild(pane);
		});
		host.innerHTML = '';
		host.appendChild(E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, [ 'Sing-Box/Xray ', _('Shunt Rule') ]),
			E('div', { 'class': 'cbi-section-descr' }, [
				E('a', { 'class': 'pw-warn' }, _('Please note attention to the priority, the higher the order, the higher the priority.'))
			]),
			E('div', { 'id': 'shunt_rule_list' }, [ tabs, body ])
		]));
		this.shuntGroups = groups;
		this.switchShuntGroup(order[0] || 'default');
		order.forEach(function(group) { self.writeOrder(group); });
		this.initSortable(order);
	},

	switchShuntGroup: function(group) {
		this.currentGroup = group;
		var root = this.listRoot;
		if (!root)
			return;
		root.querySelectorAll('.cbi-tabmenu > li').forEach(function(tab) {
			var on = tab.getAttribute('data-group') === group;
			tab.className = on ? 'cbi-tab' : 'cbi-tab-disabled';
		});
		root.querySelectorAll('.cbi-tabcontainer').forEach(function(pane) {
			pane.style.display = pane.getAttribute('data-group') === group ? 'block' : 'none';
		});
	},

	writeOrder: function(group) {
		var root = this.listRoot;
		if (!root)
			return;
		var table = root.querySelector('table[data-group="' + group + '"]');
		var input = root.querySelector('input[data-order="' + group + '"]');
		if (!table || !input)
			return;
		var ids = [];
		table.querySelectorAll('tr.cbi-section-table-row').forEach(function(row) {
			var sid = row.getAttribute('data-sid');
			if (sid)
				ids.push(sid);
		});
		input.value = ids.join(' ');
	},

	rowTop: function(btn, group) {
		var row = btn.closest('tr');
		if (!row || !row.parentNode)
			return;
		var parent = row.parentNode;
		var first = parent.querySelector('tr.cbi-section-table-row');
		if (first && first !== row)
			parent.insertBefore(row, first);
		this.writeOrder(group);
	},

	initSortable: function(groups) {
		var self = this;
		ensureSortable().then(function(Sortable) {
			if (!Sortable || !self.listRoot)
				return;
			groups.forEach(function(group) {
				var table = self.listRoot.querySelector('table[data-group="' + group + '"]');
				if (!table)
					return;
				var host = table.querySelector('tbody') || table;
				if (host._sortable_initialized)
					return;
				host._sortable_initialized = true;
				try {
					host._sortable_instance = Sortable.create(host, {
						handle: '.drag-handle',
						draggable: 'tr.cbi-section-table-row',
						animation: 150,
						ghostClass: 'dragging-row',
						fallbackOnBody: true,
						forceFallback: false,
						swapThreshold: 0.65,
						onEnd: function() { self.writeOrder(group); }
					});
				}
				catch (err) {
					host._sortable_initialized = false;
					console.error('Sortable init failed:', err);
				}
			});
		});
	},

	addShunt: function(group) {
		var input = document.getElementById('add_name_' + group);
		var name = input ? String(input.value || '') : '';
		if (name.length <= 1)
			return;
		pw.call('add_shunt_rule', {
			add_name: name,
			redirect: '0',
			group: group
		}).then(function(res) {
			var body = res || {};
			if (typeof body === 'string') {
				try { body = JSON.parse(body); }
				catch (e) {}
			}
			if (body && body.code == 1 && body.data && body.data.uid) {
				window.location.href = pw.pageUrl('shunt_rules', body.data.uid);
				return;
			}
			var message = body && body.data && body.data.message;
			alert(message ? _(message) : _('Save failed!'));
		}).catch(function() {
			alert(_('Save failed!'));
		});
	},

	deleteShunt: function(id) {
		pw.call('delete_select_shunt_rules', { ids: id, redirect: '1' }).then(function() {
			window.location.href = pw.pageUrl('rule');
		}).catch(function() {
			alert(_('Error'));
		});
	},

	applyShuntOrder: function() {
		var root = this.listRoot;
		if (!root || typeof uci.move !== 'function')
			return;
		var sections = uci.sections(APP, 'shunt_rules') || [];
		var current = sections.map(function(sec) { return sec['.name']; });
		var domOrder = {};
		root.querySelectorAll('table[data-group]').forEach(function(table) {
			var group = table.getAttribute('data-group');
			var ids = [];
			table.querySelectorAll('tr.cbi-section-table-row').forEach(function(row) {
				var sid = row.getAttribute('data-sid');
				if (sid)
					ids.push(sid);
			});
			domOrder[group] = ids;
		});
		if (!Object.keys(domOrder).length)
			return;
		var cursor = {};
		var desired = sections.map(function(sec) {
			var group = sec.group || 'default';
			var list = domOrder[group];
			if (!list || !list.length)
				return sec['.name'];
			var index = cursor[group] || 0;
			cursor[group] = index + 1;
			return list[index] || sec['.name'];
		});
		var same = current.length === desired.length;
		var i;
		for (i = 0; same && i < current.length; i++) {
			if (current[i] !== desired[i])
				same = false;
		}
		if (same || !desired.length)
			return;
		if (desired[0] !== current[0])
			uci.move(APP, desired[0], current[0], false);
		for (i = 1; i < desired.length; i++)
			uci.move(APP, desired[i], desired[i - 1], true);
	},

	handleSave: function(ev) {
		this.applyShuntOrder();
		return this.super('handleSave', [ ev ]);
	}
});
