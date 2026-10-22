'use strict';
'require view';
'require uci';
'require ui';
'require view.passwall.tools as pw';

var APP = 'passwall';

var URL_PRESETS = [
	[ 'https://cp.cloudflare.com/', 'Cloudflare' ],
	[ 'https://www.gstatic.com/generate_204', 'Gstatic' ],
	[ 'https://www.google.com/generate_204', 'Google' ],
	[ 'https://www.youtube.com/generate_204', 'YouTube' ],
	[ 'https://connect.rom.miui.com/generate_204', 'MIUI (CN)' ],
	[ 'https://connectivitycheck.platform.hicloud.com/generate_204', 'HiCloud (CN)' ],
	[ 'https://wifi.vivo.com.cn/generate_204', 'VIVO (CN)' ]
];

var CSS = [
	'table th, .table .th { text-align: center; }',
	'table td, .table .td { text-align: center; word-break: keep-all; }',
	'#set_node_div { display: none; width: min(30rem, 92vw); position: fixed; top: 45%; z-index: 99; text-align: center; background: var(--background-color-high, var(--background-color, #fff)); color: var(--text-color, inherit); border: 1px solid var(--border-color-medium, rgba(127,127,127,.3)); border-radius: .8rem; box-shadow: 0 12px 40px rgba(0,0,0,.28); padding: 0.5em; }',
	'._now_use_bg { background: color-mix(in srgb, var(--primary, #5e72e4) 22%, transparent) !important; }',
	'.ping a, .ping_value a, .tcping_value a { text-decoration: none; cursor: pointer; }',
	'.td.cbi-section-actions { text-align: right !important; }',
	'.node-wrapper { align-items: center; display: inline-flex !important; gap: 4px; }',
	'.cbi-tabmenu > li { margin-right: 2px !important; }',
	'.cbi-tabmenu > li:last-child { margin-right: 0 !important; }',
	'.node-wrapper .drag-handle { cursor: grab !important; display: inline-flex; align-items: center; justify-content: center; font-size: 20px; font-weight: 100; padding: 0 !important; line-height: inherit; user-select: none; align-self: stretch; background-color: transparent; }',
	'.node-wrapper .drag-handle:hover { background: transparent; }',
	'#cbi-' + APP + '-nodes .pw-checkbox, #cbi-' + APP + '-nodes th:nth-child(1) { padding-right: 0px; }',
	'#select_all_btn { display: none; }',
	'.pw-remark { cursor: pointer; }',
	'@media screen and (max-width: 1152px) {',
	'  .cbi-section-table-row { display: flex; flex-direction: row; flex-wrap: wrap; justify-content: space-between; }',
	'  #cbi-' + APP + '-nodes-default-fieldset { margin: 0; }',
	'  .cbi-section-table-titles { display: none !important; }',
	'  #cbi-' + APP + '-nodes .pw-checkbox, #cbi-' + APP + '-nodes th:nth-child(1) { flex: 0 0 40px; min-width: 0; }',
	'  #cbi-' + APP + '-nodes .pw-remark { flex: 1 1 30%; min-width: 0; }',
	'  #cbi-' + APP + '-nodes .pw-ping, #cbi-' + APP + '-nodes .pw-tcping, #cbi-' + APP + '-nodes .pw-urltest { flex: 0 0 50px; white-space: nowrap; min-width: 0; }',
	'  .pw-actions { padding-top: 0 !important; border-top-width: 0 !important; flex: 1 1 350px; }',
	'  #select_all_btn { display: inline-block !important; }',
	'}',
	'@media screen and (max-width: 500px) {',
	'  .node-wrapper { gap: 0; }',
	'  .cbi-button { margin-left: 0 !important; margin-right: 1px !important; }',
	'  .pw-actions { padding-left: 5px !important; padding-right: 5px !important; }',
	'}',
	'.sortable-chosen { background-color: rgba(220, 235, 245, 0.4) !important; opacity: 0.7; }',
	'.sortable-ghost { background: #cce5ff !important; height: 3px !important; }',
	'.dragging-row { background-color: rgba(131, 191, 255, 0.7) !important; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }',
	'.pw-toolbar, .pw-toolbar-field { width: 100%; text-align: center; }',
	'.pw-toolbar-field { display: inline-block; padding: 5px 0 5px; }',
	'#modal-mask { display: none; position: fixed; left: 0; top: 0; width: 100vw; height: 100vh; background: rgba(0,0,0,0.4); z-index: 999; }',
	'body.modal-open { overflow: hidden; pointer-events: none; }',
	'body.modal-open #add_link_div, body.modal-open #reassign_group_div { pointer-events: auto; }',
	'#add_link_div, #reassign_group_div { display: none; position: fixed; left: 50%; top: 50%; transform: translate(-50%, -50%); background: var(--background-color-high, var(--background-color, #fff)); color: var(--text-color, inherit); padding: 20px; border: 1px solid var(--border-color-medium, rgba(127,127,127,.35)); border-radius: .8rem; box-shadow: 0 12px 40px rgba(0,0,0,.28); z-index: 1000; width: 90%; max-width: 500px; }',
	'#add_link_modal_container, #reassign_group_modal_container { width: 100%; text-align: center; display: flex; flex-direction: column; align-items: center; padding-bottom: 20px; }',
	'#nodes_link { width: 100%; height: 180px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; padding: 5px; border: 1px solid var(--border-color-medium, rgba(127,127,127,.35)); border-radius: .5rem; background: var(--background-color, transparent); color: var(--text-color, inherit); }',
	'#add_link_div h3, #reassign_group_div h3 { background: inherit; }',
	'#nodes_link_text { color: #e0544a; font-size: 14px; margin-top: 5px; text-align: center; width: 100%; }',
	'#add_link_button_container, #reassign_group_button_container { display: flex; justify-content: space-between; width: 100%; max-width: 300px; margin-top: 10px; }',
	'.value-custom { display: flex; flex-direction: column; align-items: center; width: 100%; margin: 10px 0; padding: 0 5px; }',
	'.value-field-custom { display: inline-flex; align-items: center; gap: 10px; }',
	'.value-title-custom { font-size: 13px; line-height: 28px; white-space: nowrap; text-align: right; }',
	'.custom-dropdown { position: relative; border: 1px solid var(--border-color-medium, rgba(127,127,127,.35)); border-radius: .4rem; width: 180px; height: 28px; font-size: 13px; background: var(--background-color-high, var(--background-color, #fff)); color: var(--text-color, inherit); cursor: pointer; box-sizing: border-box; display: block; }',
	'.selected-display { display: flex; justify-content: space-between; align-items: center; padding: 0 8px; width: 100%; height: 100%; box-sizing: border-box; font-size: 12px; color: var(--text-color-medium, #666); }',
	'.selected-display:hover { background: color-mix(in srgb, var(--text-color, #000) 8%, transparent); }',
	'.dropdown-list { position: absolute; top: calc(100% + 2px); left: -1px; width: calc(100% + 2px); border: 1px solid var(--border-color-medium, rgba(127,127,127,.35)); border-radius: .4rem; border-top: none; box-shadow: 0 8px 24px rgba(0,0,0,.16); background: var(--background-color-high, var(--background-color, #fff)); color: var(--text-color, inherit); list-style: none; margin: 0; padding: 0; max-height: 200px; overflow-y: auto; overflow-x: hidden; z-index: 100; box-sizing: border-box; }',
	'.dropdown-item { padding: 4px 8px; line-height: 20px; cursor: pointer; }',
	'.dropdown-item.selected { background: var(--primary, #1e90ff); color: var(--primary-color-high, #fff); }',
	'.create-item-input::placeholder { text-align: center; }',
	'.dropdown-item.custom-input input { width: 100%; box-sizing: border-box; padding: 3px; font-size: 13px; line-height: 20px; border: 1px solid #ccc; text-align: left; }',
	'.arrow-down-small { width: 0; height: 0; border-left: 4px solid transparent; border-right: 4px solid transparent; border-top: 5px solid var(--text-color-medium, #555); display: inline-block; vertical-align: middle; }'
].join('\n');

function coerceJson(data) {
	if (typeof data === 'string') {
		var text = data.trim();
		if (!text)
			return null;
		try {
			return JSON.parse(text);
		}
		catch (e) {
			return data;
		}
	}
	return data;
}

function asNodeArray(data) {
	data = coerceJson(data);
	if (Array.isArray(data))
		return data;
	if (data && typeof data === 'object' && data['.name'])
		return [ data ];
	return [];
}

function firstSection(type) {
	var list = uci.sections(APP, type) || [];
	return list.length ? list[0] : null;
}

function copyNode(sec, extra) {
	var o = {};
	if (sec) {
		Object.keys(sec).forEach(function(key) {
			o[key] = sec[key];
		});
	}
	if (extra) {
		if (extra.full_address)
			o.full_address = extra.full_address;
		if (extra.ipv6)
			o.ipv6 = extra.ipv6;
	}
	return o;
}

function mergeNodes(sections, remote) {
	var extra = {};
	asNodeArray(remote).forEach(function(node) {
		if (node && node['.name'])
			extra[node['.name']] = node;
	});
	return (sections || []).map(function(sec) {
		return copyNode(sec, extra[sec['.name']]);
	});
}

function groupNodes(nodes) {
	var ungrouped = [];
	var grouped = [];
	(nodes || []).forEach(function(node) {
		if (!node.group)
			ungrouped.push(node);
		else
			grouped.push(node);
	});
	var ordered = ungrouped.concat(grouped);
	var groups = [];
	var map = {};
	ordered.forEach(function(node) {
		var name = node.group || 'default';
		if (!map[name]) {
			map[name] = [];
			groups.push(name);
		}
		map[name].push(node);
	});
	if (!groups.length) {
		groups.push('default');
		map.default = [];
	}
	return { groups: groups, map: map };
}

function protocolLabel(protocol) {
	switch (protocol) {
	case '_balancing':
		return _('Balancing');
	case '_urltest':
		return 'URLTest';
	case '_shunt':
		return _('Shunt');
	case '_iface':
		return _('Interface');
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
	case 'ssh':
		return 'SSH';
	default:
		if (protocol && protocol.length > 1)
			return protocol.charAt(0).toUpperCase() + protocol.slice(1);
		return '';
	}
}

function typeLabel(node) {
	var type = node.type || '';
	if (type !== 'sing-box' && type !== 'Xray')
		return type;
	var label = (type === 'sing-box') ? 'Sing-Box' : type;
	var proto = protocolLabel(node.protocol || '');
	return proto ? (label + ' ' + proto) : label;
}

function remarkText(node) {
	var remarks = node.remarks || '';
	var prefix = typeLabel(node);
	if ((node.type === 'Hysteria2' || node.protocol === 'hysteria2') && node.hysteria2_realms)
		return prefix + ' Realm：' + remarks;
	return prefix + '：' + remarks;
}

function displayPort(node) {
	var port = node.port || node.hysteria_hop || node.hysteria2_hop || '';
	return String(port).replace(/:/g, '-');
}

function decodeIfBase64(str) {
	try {
		var s = String(str).replace(/-/g, '+').replace(/_/g, '/');
		while (s.length % 4)
			s += '=';
		var decoded = decodeURIComponent(atob(s).split('').map(function(c) {
			return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
		}).join(''));
		var round = btoa(unescape(encodeURIComponent(decoded))).replace(/=+$/, '');
		if (round === s.replace(/=+$/, ''))
			return decoded;
	}
	catch (e) {}
	return str;
}

function pingColor(ms) {
	if (ms < 100)
		return 'green';
	if (ms < 200)
		return '#fb9a05';
	return 'red';
}

function urlColor(ms) {
	if (ms < 1000)
		return 'green';
	if (ms < 2000)
		return '#fb9a05';
	return 'red';
}

function storageGet(key) {
	try {
		return JSON.parse(localStorage.getItem(key));
	}
	catch (e) {
		return null;
	}
}

function storageSet(key, value) {
	try {
		localStorage.setItem(key, JSON.stringify(value));
	}
	catch (e) {}
}

function storageRemove(key) {
	try {
		localStorage.removeItem(key);
	}
	catch (e) {}
}

function cleanPingCache() {
	var now = Date.now();
	var drop = [];
	try {
		for (var i = 0; i < localStorage.length; i++) {
			var key = localStorage.key(i);
			if (!key || (key.indexOf('icmp:') !== 0 && key.indexOf('tcping:') !== 0))
				continue;
			var value = storageGet(key);
			if (!(value && value.savetime && (now - value.timestamp) < value.savetime))
				drop.push(key);
		}
	}
	catch (e) {}
	drop.forEach(storageRemove);
}

function getBg(el) {
	if (!el)
		return null;
	var style = getComputedStyle(el);
	var bgImage = style.backgroundImage;
	var bgColor = style.backgroundColor;
	if (bgImage !== 'none' || (!/rgba\([^,]+,[^,]+,[^,]+,\s*0\)/.test(bgColor) && bgColor !== 'transparent'))
		return style.background;
	return null;
}

function optionRow(title, field) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title' }, title),
		E('div', { 'class': 'cbi-value-field' }, field)
	]);
}

function ensureSortable() {
	if (window.Sortable)
		return Promise.resolve(window.Sortable);
	return new Promise(function(resolve) {
		var script = E('script', { src: L.resource('view/passwall/sortable.js') });
		script.onload = function() { resolve(window.Sortable || null); };
		script.onerror = function() { resolve(null); };
		document.head.appendChild(script);
	});
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(APP),
			pw.get('get_node').catch(function() { return []; }),
			pw.get('get_now_use_node').catch(function() { return {}; })
		]);
	},

	render: function(data) {
		var view = this;
		var other = firstSection('global_other');
		var globalSec = firstSection('global');
		var remote = asNodeArray(data && data[1]);
		var now = coerceJson(data && data[2]) || {};

		view.otherSid = other ? other['.name'] : null;
		view.autoDetection = (other && other.auto_detection_time) || '0';
		view.showNodeInfo = (other && String(other.show_node_info)) || '0';
		if (view.showNodeInfo !== '1')
			view.showNodeInfo = '0';
		view.urlTestUrl = (other && other.url_test_url) || URL_PRESETS[2][0];
		view.nodes = mergeNodes(uci.sections(APP, 'nodes') || [], remote);
		view.currentId = now.global || '';
		view.pingEpoch = 0;
		view.listRoot = E('div', { 'id': 'node_list', 'class': 'cbi-section' });

		var shuntNodeId = globalSec ? (globalSec.node || '') : '';
		var shuntNode = null;
		view.nodes.forEach(function(node) {
			if (node['.name'] === shuntNodeId)
				shuntNode = node;
		});
		var shuntRules = [];
		if (shuntNode && shuntNode.protocol === '_shunt') {
			(uci.sections(APP, 'shunt_rules') || []).forEach(function(rule) {
				if (rule['.name'] && rule.remarks && rule.group == shuntNode.shunt_group)
					shuntRules.push(rule);
			});
			shuntRules.push({ '.name': 'default_node', remarks: _('Default') });
		}

		var autoSelect = E('select', { 'class': 'cbi-input-select', 'id': 'cbid.' + APP + '.global_other.auto_detection_time' }, [
			E('option', { value: '0' }, _('Close')),
			E('option', { value: 'icmp' }, 'Ping'),
			E('option', { value: 'tcping' }, 'TCP Ping')
		]);
		autoSelect.value = view.autoDetection;
		autoSelect.addEventListener('change', function() {
			view.autoDetection = autoSelect.value || '0';
			if (view.otherSid)
				uci.set(APP, view.otherSid, 'auto_detection_time', view.autoDetection);
			view.pingEpoch++;
			view.rebuild();
		});

		var showBox = E('input', {
			'type': 'checkbox',
			'class': 'cbi-input-checkbox',
			'id': 'cbid.' + APP + '.global_other.show_node_info',
			'name': 'cbid.' + APP + '.global_other.show_node_info'
		});
		showBox.checked = view.showNodeInfo === '1';
		showBox.addEventListener('change', function() {
			showBox.blur();
			view.showNodeInfo = showBox.checked ? '1' : '0';
			if (view.otherSid)
				uci.set(APP, view.otherSid, 'show_node_info', view.showNodeInfo);
			pw.call('save_node_list_opt', {
				option: 'show_node_info',
				value: view.showNodeInfo
			}).then(function() {
				return pw.get('get_node');
			}).then(function(fresh) {
				view.nodes = mergeNodes(uci.sections(APP, 'nodes') || [], fresh);
				view.rebuild();
			}).catch(function() {
				alert(_('Error'));
				view.rebuild();
			});
		});

		var urlInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'id': 'cbid.' + APP + '.global_other.url_test_url',
			'list': 'pw-url-test-presets',
			'value': view.urlTestUrl
		});
		var urlList = E('datalist', { 'id': 'pw-url-test-presets' });
		URL_PRESETS.forEach(function(pair) {
			urlList.appendChild(E('option', { value: pair[0] }, pair[1]));
		});
		urlInput.addEventListener('change', function() {
			var value = urlInput.value || '';
			if (!value || value === view.urlTestUrl)
				return;
			view.urlTestUrl = value;
			if (view.otherSid)
				uci.set(APP, view.otherSid, 'url_test_url', value);
			pw.call('save_node_list_opt', {
				option: 'url_test_url',
				value: value
			}).catch(function() {
				alert(_('Error'));
			});
		});

		var settings = E('div', { 'class': 'cbi-section' }, [
			E('div', { 'class': 'cbi-section-node' }, [
				optionRow(_('Automatic detection delay'), autoSelect),
				optionRow(_('Show server address and port'), showBox),
				optionRow(_('URL Test Address'), [ urlInput, urlList ])
			])
		]);

		function btn(className, label, click, extra) {
			var attrs = {
				'class': 'btn cbi-button ' + className,
				'type': 'button',
				'value': label,
				'click': click
			};
			if (extra) {
				Object.keys(extra).forEach(function(key) {
					attrs[key] = extra[key];
				});
			}
			return E('input', attrs);
		}

		var toolbar = E('div', { 'class': 'pw-toolbar' }, [
			E('div', { 'class': 'pw-toolbar-field' }, [
				btn('cbi-button-add', _('Add'), function() { view.nodeAction('add'); }),
				' ',
				btn('cbi-button-add', _('Add the node via the link'), function() { view.openAddLink(); }),
				' ',
				btn('cbi-button-remove', _('Clear all nodes'), function() { view.nodeAction('del_all'); }),
				' ',
				btn('cbi-button-remove', _('Delete select nodes'), function() { view.deleteSelected(); }),
				' ',
				btn('cbi-button-edit', _('Select all'), function() {
					var mobile = document.getElementById('select_all_btn');
					view.setSelectAll(!(mobile && mobile.value === _('DeSelect all')));
				}, { id: 'select_all_btn' }),
				' ',
				btn('cbi-button-edit', _('Reassign Group'), function() { view.openReassign(); }),
				' ',
				btn('cbi-button-apply', _('Save & Apply'), function() { return view.handleSaveApply(null, '0'); })
			])
		]);

		var mask = E('div', { 'id': 'modal-mask' });
		view.mask = mask;

		var nodesLink = E('textarea', { 'id': 'nodes_link', 'rows': '10' });
		var addDropdown = view.makeGroupDropdown('addlink_group_custom');
		var addLinkDiv = E('div', { 'id': 'add_link_div' }, [
			E('div', { 'id': 'add_link_modal_container' }, [
				E('h3', {}, _('Add the node via the link')),
				E('div', { 'class': 'value-custom' }, [
					nodesLink,
					E('p', { 'id': 'nodes_link_text' }, _('Enter share links, one per line. Subscription links are not supported!'))
				]),
				E('div', { 'class': 'value-custom' }, [
					E('div', { 'class': 'value-field-custom' }, [
						E('label', { 'class': 'value-title-custom', 'for': 'addlink_group_custom' }, _('Group Name')),
						addDropdown
					])
				]),
				E('div', { 'id': 'add_link_button_container' }, [
					btn('cbi-button-add', _('Add'), function() { view.submitLinks(); }),
					btn('cbi-button-remove', _('Close'), function() { view.closeAddLink(); })
				])
			])
		]);
		view.nodesLink = nodesLink;
		view.addLinkDiv = addLinkDiv;
		view.addDropdown = addDropdown;

		var reDropdown = view.makeGroupDropdown('reassign_group_custom');
		var reassignDiv = E('div', { 'id': 'reassign_group_div' }, [
			E('div', { 'id': 'reassign_group_modal_container' }, [
				E('h3', {}, _('Reassign Node Group')),
				E('div', { 'class': 'value-custom' }, [
					E('div', { 'class': 'value-field-custom' }, [
						E('label', { 'class': 'value-title-custom', 'for': 'reassign_group_custom' }, _('Group Name')),
						reDropdown
					])
				]),
				E('div', { 'id': 'reassign_group_button_container' }, [
					btn('cbi-button-edit', _('Save'), function() { view.submitReassign(); }),
					btn('cbi-button-remove', _('Close'), function() { view.closeReassign(); })
				])
			])
		]);
		view.reassignDiv = reassignDiv;
		view.reDropdown = reDropdown;

		var setName = E('a', { 'id': 'set_node_name', 'class': 'pw-warn' });
		var shuntBox = null;
		if (shuntRules.length) {
			var shuntButtons = shuntRules.map(function(rule) {
				return E('input', {
					'class': 'btn cbi-button',
					'type': 'button',
					'value': rule.remarks || rule['.name'],
					'click': function() {
						view.applyChosenNode(shuntNodeId, rule['.name']);
					}
				});
			});
			shuntBox = E('div', {
				'id': 'set_node_shunt_div',
				'style': 'margin: 0.5em 0; padding: 0.5em; background: #f7f7f7; border-radius: 4px;'
			}, [
				E('div', { 'class': 'cbi-section-descr', 'style': 'text-align:left' }, [
					E('a', { 'style': 'color:#FF8C00' }, _('Set as the routing rule node:'))
				]),
				E('div', {}, shuntButtons)
			]);
		}
		var setNodeDiv = E('div', { 'id': 'set_node_div' }, [
			E('div', { 'class': 'cbi-value', 'style': 'display:flex; justify-content:center; align-items:center; margin:0.2em 0; height:2em;' }, [
				E('font', { 'color': '#666' }, _('You choose node is:')),
				setName,
				E('div', { 'style': 'position:absolute; right:0.5em; top:0.5em;' }, [
					E('input', {
						'class': 'btn cbi-button',
						'type': 'button',
						'value': 'X',
						'click': function() { view.closeUse(); }
					})
				])
			]),
			E('div', { 'class': 'cbi-value', 'style': 'justify-content:center; gap:8px; margin:0.2em 0;' }, [
				E('div', { 'style': 'margin:0.5em 0; padding:0.5em; background:#f7f7f7; border-radius:4px;' }, [
					E('div', { 'class': 'cbi-section-descr', 'style': 'text-align:left' }, [
						E('a', { 'style': 'color:#FF8C00' }, _('Set as the main proxy node:'))
					]),
					E('div', {}, [
						E('input', {
							'class': 'btn cbi-button',
							'type': 'button',
							'value': _('OK'),
							'click': function() { view.applyChosenNode('@global[0]', 'node'); }
						})
					])
				]),
				shuntBox || ''
			])
		]);
		view.setNodeDiv = setNodeDiv;
		view.setName = setName;
		view.shuntBox = shuntBox;
		view.useNodeId = '';

		view.rebuild = function() {
			view.pingEpoch++;
			view.renderList();
			window.setTimeout(function() {
				view.initSortable();
				cleanPingCache();
				view.markCurrent();
				view.pingAll();
			}, 0);
		};

		view.rebuild();

		return E('div', { 'id': 'pw-node-list-page' }, [
			E('style', { 'type': 'text/css' }, CSS),
			settings,
			toolbar,
			view.listRoot,
			mask,
			addLinkDiv,
			reassignDiv,
			E('div', { 'style': 'display:flex; align-items:center; justify-content:center;' }, [ setNodeDiv ])
		]);
	},

	makeGroupDropdown: function(id) {
		var hidden = E('input', { 'type': 'hidden', 'name': id, 'value': '' });
		var text = E('span', { 'class': 'text' }, _('default'));
		var input = E('input', {
			'type': 'text',
			'placeholder': '-- ' + _('custom') + ' --',
			'class': 'create-item-input',
			'inputmode': 'text',
			'enterkeyhint': 'done'
		});
		var custom = E('li', { 'class': 'dropdown-item custom-input' }, input);
		var list = E('ul', { 'class': 'dropdown-list', 'style': 'display:none' }, [
			E('li', { 'class': 'dropdown-item selected', 'data-value': '' }, _('default')),
			custom
		]);
		var display = E('div', { 'class': 'selected-display' }, [
			text,
			E('span', { 'class': 'arrow-down-small' })
		]);
		var box = E('div', { 'id': id, 'class': 'custom-dropdown' }, [ display, list, hidden ]);

		function selectItem(li) {
			list.querySelectorAll('.dropdown-item').forEach(function(el) {
				el.classList.remove('selected');
			});
			li.classList.add('selected');
			hidden.value = li.getAttribute('data-value') || '';
			text.textContent = hidden.value || _('default');
			list.style.display = 'none';
		}

		display.addEventListener('click', function(ev) {
			ev.stopPropagation();
			list.style.display = (list.style.display === 'none') ? 'block' : 'none';
			input.value = '';
		});

		list.addEventListener('click', function(ev) {
			var li = ev.target.closest ? ev.target.closest('.dropdown-item') : null;
			if (!li || li.classList.contains('custom-input'))
				return;
			selectItem(li);
		});

		input.addEventListener('keydown', function(ev) {
			var isEnter = ev.key === 'Enter' || ev.keyCode === 13;
			if (!isEnter)
				return;
			ev.stopPropagation();
			ev.preventDefault();
			var val = input.value.trim();
			if (!val)
				return;
			if (val.toLowerCase() === 'default') {
				var empty = null;
				list.querySelectorAll('.dropdown-item').forEach(function(el) {
					if (!el.getAttribute('data-value') && !el.classList.contains('custom-input'))
						empty = el;
				});
				if (empty)
					selectItem(empty);
				input.value = '';
				return;
			}
			var found = null;
			list.querySelectorAll('.dropdown-item').forEach(function(el) {
				var data = el.getAttribute('data-value') || '';
				if (data && data.toLowerCase() === val.toLowerCase())
					found = el;
			});
			if (!found) {
				found = E('li', { 'class': 'dropdown-item', 'data-value': val }, val);
				list.insertBefore(found, custom);
			}
			input.value = '';
			selectItem(found);
		});

		document.addEventListener('click', function(ev) {
			if (!box.contains(ev.target))
				list.style.display = 'none';
		});

		box._refresh = function(root) {
			var tabs = (root || document).querySelectorAll('.cbi-tabmenu li');
			tabs.forEach(function(tab) {
				var group = tab.getAttribute('data-group') || '';
				if (!group || group === 'default')
					return;
				var exists = false;
				list.querySelectorAll('.dropdown-item').forEach(function(el) {
					if ((el.getAttribute('data-value') || '') === group)
						exists = true;
				});
				if (exists)
					return;
				list.insertBefore(E('li', { 'class': 'dropdown-item', 'data-value': group }, group), custom);
			});
		};
		box._value = function() {
			return hidden.value || 'default';
		};
		return box;
	},

	renderList: function() {
		var view = this;
		var root = view.listRoot;
		while (root.firstChild)
			root.removeChild(root.firstChild);

		var grouped = groupNodes(view.nodes);
		var tabs = E('ul', { 'class': 'cbi-tabmenu' });
		var body = E('div', { 'class': 'cbi-section cbi-section-shunt_rule cbi-section-shunt_rule-tabbed', 'id': 'cbi-' + APP + '-nodes' });
		var first = grouped.groups[0];

		grouped.groups.forEach(function(group) {
			var label = (group === 'default') ? _('default') : group;
			var active = group === first;
			var tab = E('li', {
				'class': active ? 'cbi-tab' : 'cbi-tab-disabled',
				'id': 'tab.' + APP + '.nodes.' + group,
				'group_name': group,
				'data-group': group
			}, [
				E('a', {
					'href': '#',
					'click': function(ev) {
						ev.preventDefault();
						if (ev.target && ev.target.blur)
							ev.target.blur();
						view.switchTab(group);
					}
				}, [
					document.createTextNode(label + ' | '),
					E('span', { 'class': 'pw-warn' }, String(grouped.map[group].length))
				])
			]);
			tabs.appendChild(tab);

			var tbody = E('tbody');
			var table = E('table', {
				'class': 'table cbi-section-table',
				'id': 'cbi-' + APP + '-nodes-' + group + '-table',
				'data-group': group
			}, [
				E('thead', {}, [
					E('tr', { 'class': 'tr cbi-section-table-titles anonymous' }, [
						E('th', { 'class': 'th cbi-section-table-cell', 'style': 'width:20px' }, [
							E('input', {
								'class': 'cbi-input-checkbox nodes_select_all',
								'type': 'checkbox',
								'title': _('Select all'),
								'click': function(ev) { view.setSelectAll(!!ev.target.checked, ev.target); }
							})
						]),
						E('th', { 'class': 'th cbi-section-table-cell', 'style': 'width:40%' }, _('Remarks')),
						E('th', { 'class': 'th cbi-section-table-cell', 'style': 'width:8%' }, 'Ping'),
						E('th', { 'class': 'th cbi-section-table-cell', 'style': 'width:8%' }, 'TCPing'),
						E('th', { 'class': 'th cbi-section-table-cell', 'style': 'width:8%' }, _('URL Test')),
						E('th', { 'class': 'th cbi-section-table-cell cbi-section-actions' })
					])
				]),
				tbody
			]);

			grouped.map[group].forEach(function(node, index) {
				tbody.appendChild(view.renderRow(node, group, index));
			});

			var fieldset = E('div', {
				'class': 'cbi-section cbi-tblsection',
				'id': 'cbi-' + APP + '-nodes-' + group + '-fieldset'
			}, [
				table,
				E('input', { 'type': 'hidden', 'name': 'group.order.' + group }),
				E('div', { 'class': 'cbi-section-create cbi-tblsection-create' }, [
					E('input', {
						'class': 'cbi-button cbi-button-add',
						'type': 'button',
						'value': _('Add'),
						'click': function() { view.nodeAction('add'); }
					})
				])
			]);

			body.appendChild(E('div', {
				'class': 'cbi-tabcontainer',
				'id': 'container.' + APP + '.nodes.' + group,
				'style': active ? 'display:block' : 'display:none',
				'data-group': group
			}, [ fieldset ]));
		});

		root.appendChild(tabs);
		root.appendChild(body);
		if (view.addDropdown && view.addDropdown._refresh)
			view.addDropdown._refresh(root);
		if (view.reDropdown && view.reDropdown._refresh)
			view.reDropdown._refresh(root);
	},

	renderRow: function(node, group, index) {
		var view = this;
		var sid = node['.name'];
		var port = node.port || '';
		var hop = node.port || node.hysteria_hop || node.hysteria2_hop || '';
		var row = E('tr', {
			'class': 'tr cbi-section-table-row cbi-rowstyle-' + ((index % 2) + 1),
			'id': 'cbi-' + APP + '-' + sid,
			'data-sid': sid,
			'data-remarks': node.remarks || '',
			'data-address': node.address || '',
			'data-port': port,
			'data-protocol': node.protocol || ''
		});

		row.addEventListener('click', function(ev) {
			var skip = ev.target && ev.target.closest && ev.target.closest('button, input, a, .drag-handle');
			if (skip)
				return;
			window.location.href = pw.pageUrl('node_config', sid);
		});

		var remarkCell = E('td', { 'class': 'td cbi-value-field pw-remark', 'title': _('Edit') }, [
			document.createTextNode(remarkText(node))
		]);
		if (view.showNodeInfo === '1' && node.address && hop) {
			var shown = node.full_address || node.address;
			remarkCell.appendChild(E('br'));
			remarkCell.appendChild(document.createTextNode(shown + ':' + displayPort(node)));
		}

		row.appendChild(E('td', { 'class': 'td cbi-value-field pw-checkbox' }, [
			E('input', {
				'class': 'cbi-input-checkbox nodes_select',
				'type': 'checkbox',
				'cbid': sid,
				'click': function() { view.updateSelectState(); }
			})
		]));
		row.appendChild(remarkCell);
		row.appendChild(E('td', { 'class': 'td cbi-value-field pw-ping' }, [ view.pingCell(node, 'icmp') ]));
		row.appendChild(E('td', { 'class': 'td cbi-value-field pw-tcping' }, [ view.pingCell(node, 'tcping') ]));
		row.appendChild(E('td', { 'class': 'td cbi-value-field pw-urltest' }, [ view.urlCell(node, hop) ]));
		row.appendChild(E('td', { 'class': 'td cbi-section-table-cell nowrap cbi-section-actions pw-actions' }, [
			E('div', { 'class': 'node-wrapper' }, [
				E('input', {
					'class': 'btn cbi-button cbi-button-edit',
					'type': 'button',
					'value': _('To Top'),
					'title': _('To Top'),
					'click': function(ev) { view.nodeAction('row_top', sid, { btn: ev.target, group: group }); }
				}),
				E('input', {
					'class': 'btn cbi-button cbi-button-apply',
					'type': 'button',
					'id': 'apply_' + sid,
					'value': _('Use'),
					'click': function() { view.openUse(sid, node.protocol || ''); }
				}),
				E('input', {
					'class': 'btn cbi-button cbi-button-add',
					'type': 'button',
					'value': _('Copy'),
					'click': function() { view.nodeAction('copy', sid); }
				}),
				E('input', {
					'class': 'btn cbi-button cbi-button-edit',
					'type': 'button',
					'value': _('Edit'),
					'title': _('Edit'),
					'alt': _('Edit'),
					'click': function() { view.nodeAction('edit', sid); }
				}),
				E('input', {
					'class': 'btn cbi-button cbi-button-remove',
					'type': 'button',
					'value': _('Delete'),
					'title': _('Delete'),
					'alt': _('Delete'),
					'click': function() { view.nodeAction('del', sid); }
				}),
				E('span', { 'class': 'drag-handle center', 'title': _('Drag to reorder') }, '⠿')
			])
		]));
		return row;
	},

	pingCell: function(node, type) {
		var view = this;
		var sid = node['.name'];
		var manual = view.autoDetection !== type;
		var ready = type === 'icmp' ? !!node.address : !!(node.address && node.port);
		if (manual && ready) {
			return E('span', { 'class': 'ping' }, [
				E('a', {
					'href': '#',
					'click': function(ev) {
						ev.preventDefault();
						view.pingNode(sid, ev.currentTarget, type);
					}
				}, _('Test'))
			]);
		}
		return E('span', {
			'class': type === 'tcping' ? 'tcping_value' : 'ping_value',
			'cbiid': sid
		}, [
			E('a', {
				'href': '#',
				'style': 'color:inherit',
				'click': function(ev) { ev.preventDefault(); }
			}, '---')
		]);
	},

	urlCell: function(node, hop) {
		var view = this;
		var sid = node['.name'];
		if (node.address && hop) {
			return E('span', { 'class': 'ping' }, [
				E('a', {
					'href': '#',
					'title': _('HTTP request latency, for reference only'),
					'click': function(ev) {
						ev.preventDefault();
						view.urltestNode(sid, ev.currentTarget);
					}
				}, _('Test'))
			]);
		}
		return E('span', { 'class': 'ping', 'cbiid': sid }, '---');
	},

	switchTab: function(group) {
		this.setSelectAll(false);
		var root = document.getElementById('cbi-' + APP + '-nodes') || this.listRoot;
		root.querySelectorAll('.cbi-tabmenu li, #node_list .cbi-tabmenu li').forEach(function(tab) {
			var on = tab.getAttribute('data-group') === group;
			tab.className = on ? 'cbi-tab' : 'cbi-tab-disabled';
		});
		this.listRoot.querySelectorAll('.cbi-tabmenu li').forEach(function(tab) {
			var on = tab.getAttribute('data-group') === group;
			tab.className = on ? 'cbi-tab' : 'cbi-tab-disabled';
		});
		this.listRoot.querySelectorAll('.cbi-tabcontainer').forEach(function(box) {
			box.style.display = (box.getAttribute('data-group') === group) ? 'block' : 'none';
		});
	},

	visibleContainer: function() {
		var boxes = this.listRoot.querySelectorAll('.cbi-tabcontainer');
		for (var i = 0; i < boxes.length; i++) {
			if (boxes[i].style.display !== 'none')
				return boxes[i];
		}
		return null;
	},

	setSelectAll: function(checked) {
		var box = this.visibleContainer();
		if (!box)
			return;
		box.querySelectorAll('.nodes_select').forEach(function(el) {
			el.checked = checked;
		});
		var all = box.querySelector('.nodes_select_all');
		var mobile = document.getElementById('select_all_btn');
		var title = checked ? _('DeSelect all') : _('Select all');
		if (all) {
			all.checked = checked;
			all.title = title;
		}
		if (mobile)
			mobile.value = title;
	},

	updateSelectState: function() {
		var box = this.visibleContainer();
		if (!box)
			return;
		var nodes = box.querySelectorAll('.nodes_select');
		if (!nodes.length)
			return;
		var checked = 0;
		nodes.forEach(function(el) {
			if (el.checked)
				checked++;
		});
		var allOn = checked === nodes.length;
		var title = allOn ? _('DeSelect all') : _('Select all');
		var all = box.querySelector('.nodes_select_all');
		var mobile = document.getElementById('select_all_btn');
		if (all) {
			all.checked = allOn;
			all.title = title;
		}
		if (mobile)
			mobile.value = title;
	},

	selectedIds: function() {
		var box = this.visibleContainer();
		var ids = [];
		if (!box)
			return ids;
		box.querySelectorAll('.nodes_select').forEach(function(el) {
			if (el.checked)
				ids.push(el.getAttribute('cbid'));
		});
		return ids;
	},

	currentGroup: function() {
		var tabs = this.listRoot.querySelectorAll('.cbi-tabmenu li');
		for (var i = 0; i < tabs.length; i++) {
			if (tabs[i].className.indexOf('cbi-tab-disabled') === -1)
				return tabs[i].getAttribute('group_name') || 'default';
		}
		return 'default';
	},

	findRow: function(sid) {
		var row = document.getElementById('cbi-' + APP + '-' + sid);
		if (row || !this.listRoot)
			return row;
		var rows = this.listRoot.querySelectorAll('tr.cbi-section-table-row');
		for (var i = 0; i < rows.length; i++) {
			if (rows[i].getAttribute('data-sid') === sid)
				return rows[i];
		}
		return null;
	},

	addressOf: function(sid) {
		var row = this.findRow(sid);
		var address = row ? (row.getAttribute('data-address') || '') : '';
		var port = row ? (row.getAttribute('data-port') || '') : '';
		if (/[\u4E00-\u9FFF]/.test(address))
			address = '';
		return { address: address, port: port };
	},

	nodeAction: function(action, sid, extra) {
		var view = this;
		view.pingEpoch++;
		if (action === 'add') {
			var group = view.currentGroup();
			return pw.call('add_node', { redirect: '1', group: group }).then(function(res) {
				var uid = res && res.result;
				if (!uid)
					throw new Error(_('Error'));
				window.location.href = pw.pageUrl('node_config', uid);
			}).catch(function() {
				alert(_('Error'));
			});
		}
		if (action === 'copy') {
			return pw.call('copy_node', { section: sid }).then(function(res) {
				var uid = res && res.section;
				if (!uid)
					throw new Error(_('Error'));
				window.location.href = pw.pageUrl('node_config', uid);
			}).catch(function() {
				alert(_('Error'));
			});
		}
		if (action === 'edit') {
			window.location.href = pw.pageUrl('node_config', sid);
			return;
		}
		if (action === 'del') {
			return pw.call('delete_select_nodes', { ids: sid, redirect: '1' }).then(function() {
				window.location.href = pw.pageUrl('node_list');
			}).catch(function() {
				alert(_('Error'));
			});
		}
		if (action === 'del_all') {
			if (confirm(_('Are you sure to clear all nodes?')) !== true)
				return;
			return pw.call('clear_all_nodes').then(function() {
				window.location.href = pw.pageUrl('node_list');
			}).catch(function() {
				alert(_('Error'));
			});
		}
		if (action === 'row_top') {
			var button = extra && extra.btn;
			var row = button && button.closest ? button.closest('tr') : null;
			if (!row)
				return;
			var parent = row.parentNode;
			var first = parent.querySelector('tr.cbi-section-table-row');
			if (first && first !== row)
				parent.insertBefore(row, first);
			view.writeOrder(extra.group);
		}
	},

	deleteSelected: function() {
		var view = this;
		var ids = view.selectedIds();
		if (!ids.length) {
			alert(_('You no select nodes !'));
			return;
		}
		if (confirm(_('Are you sure to delete select nodes?')) !== true)
			return;
		view.showMask();
		view.pingEpoch++;
		pw.call('delete_select_nodes', { ids: ids.join(',') }).then(function() {
			window.location.href = pw.pageUrl('node_list');
		}).catch(function() {
			view.hideMask();
			alert(_('Error'));
		});
	},

	showMask: function() {
		var mask = this.mask;
		mask.style.display = 'block';
		while (mask.firstChild)
			mask.removeChild(mask.firstChild);
		mask.appendChild(E('div', {
			'style': 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:#fff;'
		}, _('Processing, please wait…')));
	},

	hideMask: function() {
		this.mask.style.display = 'none';
		while (this.mask.firstChild)
			this.mask.removeChild(this.mask.firstChild);
	},

	openAddLink: function() {
		document.body.classList.add('modal-open');
		this.mask.style.display = 'block';
		var section = document.querySelector('.cbi-section');
		this.addLinkDiv.style.background = getBg(section) || getBg(document.body) || '';
		this.addLinkDiv.style.display = 'block';
		if (this.addDropdown && this.addDropdown._refresh)
			this.addDropdown._refresh(this.listRoot);
		this.nodesLink.focus();
	},

	closeAddLink: function() {
		this.mask.style.display = 'none';
		this.addLinkDiv.style.display = 'none';
		document.body.classList.remove('modal-open');
	},

	submitLinks: function() {
		var view = this;
		var text = view.nodesLink.value || '';
		text = text.replace(/\t/g, '').replace(/\r\n|\r/g, '\n').replace(/<[^>]*>/g, '').trim();
		if (!text) {
			view.nodesLink.focus();
			return;
		}
		text = decodeIfBase64(text);
		if (text.split('://').length <= 1) {
			alert(_('Please enter the correct link.'));
			return;
		}
		var group = view.addDropdown._value();
		view.closeAddLink();
		view.showMask();
		view.pingEpoch++;
		var chunkSize = 1000;
		var total = Math.ceil(text.length / chunkSize);
		var index = 0;
		function next() {
			if (index >= total) {
				window.location.href = pw.pageUrl('node_list');
				return;
			}
			var chunk = text.substring(index * chunkSize, (index + 1) * chunkSize);
			return pw.call('link_add_node', {
				chunk: chunk,
				chunk_index: index,
				total_chunks: total,
				group: group
			}).then(function() {
				index++;
				return next();
			}).catch(function() {
				view.hideMask();
				alert(_('Error'));
			});
		}
		next();
	},

	openReassign: function() {
		var ids = this.selectedIds();
		if (!ids.length) {
			alert(_('You no select nodes !'));
			return;
		}
		document.body.classList.add('modal-open');
		this.mask.style.display = 'block';
		var section = document.querySelector('.cbi-section');
		this.reassignDiv.style.background = getBg(section) || getBg(document.body) || '';
		this.reassignDiv.style.display = 'block';
		if (this.reDropdown && this.reDropdown._refresh)
			this.reDropdown._refresh(this.listRoot);
	},

	closeReassign: function() {
		this.mask.style.display = 'none';
		this.reassignDiv.style.display = 'none';
		document.body.classList.remove('modal-open');
	},

	submitReassign: function() {
		var view = this;
		var ids = view.selectedIds();
		if (!ids.length)
			return;
		var group = view.reDropdown._value();
		view.pingEpoch++;
		pw.call('reassign_group', {
			group: group,
			ids: ids.join(',')
		}).then(function() {
			window.location.href = pw.pageUrl('node_list');
		}).catch(function() {
			alert(_('Error'));
		});
	},

	openUse: function(sid, protocol) {
		this.useNodeId = sid;
		var row = this.findRow(sid);
		this.setName.textContent = row ? (row.getAttribute('data-remarks') || '') : '';
		this.setNodeDiv.style.display = 'block';
		if (this.shuntBox)
			this.shuntBox.style.display = (protocol === '_shunt') ? 'none' : '';
	},

	closeUse: function() {
		this.setNodeDiv.style.display = 'none';
		this.setName.textContent = '';
		this.useNodeId = '';
	},

	applyChosenNode: function(target, option) {
		var view = this;
		if (confirm(_('Are you sure set this node?')) !== true)
			return;
		view.pingEpoch++;
		pw.call('set_node', {
			type: target,
			config: option,
			section: view.useNodeId
		}).then(function() {
			window.location.href = pw.pageUrl('log');
		}).catch(function() {
			alert(_('Error'));
		});
	},

	writeOrder: function(group) {
		var table = document.getElementById('cbi-' + APP + '-nodes-' + group + '-table');
		if (!table) {
			alert(_('No table!'));
			return;
		}
		var rows = table.querySelectorAll('tr.cbi-section-table-row');
		if (!rows.length) {
			alert(_('No nodes!'));
			return;
		}
		var ids = [];
		rows.forEach(function(row) {
			ids.push(row.getAttribute('data-sid'));
		});
		var input = document.getElementsByName('group.order.' + group)[0];
		if (input)
			input.value = ids.join(' ');
	},

	applyNodeOrder: function() {
		var nodes = uci.sections(APP, 'nodes') || [];
		var current = nodes.map(function(node) { return node['.name']; });
		var domOrder = {};
		this.listRoot.querySelectorAll('table[data-group]').forEach(function(table) {
			var group = table.getAttribute('data-group');
			var ids = [];
			table.querySelectorAll('tr.cbi-section-table-row').forEach(function(row) {
				var sid = row.getAttribute('data-sid');
				if (sid)
					ids.push(sid);
			});
			domOrder[group] = ids;
		});
		var cursor = {};
		var desired = nodes.map(function(node) {
			var group = node.group || 'default';
			var list = domOrder[group];
			if (!list || !list.length)
				return node['.name'];
			var index = cursor[group] || 0;
			cursor[group] = index + 1;
			return list[index] || node['.name'];
		});
		var same = current.length === desired.length;
		for (var i = 0; same && i < current.length; i++) {
			if (current[i] !== desired[i])
				same = false;
		}
		if (same || !desired.length || typeof uci.move !== 'function')
			return;
		if (desired[0] !== current[0])
			uci.move(APP, desired[0], current[0], false);
		for (var j = 1; j < desired.length; j++)
			uci.move(APP, desired[j], desired[j - 1], true);
	},

	initSortable: function() {
		var view = this;
		ensureSortable().then(function(Sortable) {
			if (!Sortable)
				return;
			view.listRoot.querySelectorAll('table[data-group]').forEach(function(table) {
				var group = table.getAttribute('data-group');
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
						onEnd: function() {
							view.writeOrder(group);
						}
					});
				}
				catch (err) {
					host._sortable_initialized = false;
					console.error('Sortable init failed:', err);
				}
			});
		});
	},

	markCurrent: function() {
		if (!this.currentId)
			return;
		var row = this.findRow(this.currentId);
		if (!row)
			return;
		row.title = _('Currently using node');
		row.classList.add('_now_use_bg');
		var remark = row.querySelector('td.pw-remark');
		if (remark)
			remark.style.color = 'red';
	},

	paintPing: function(anchor, value, sid, type, text) {
		var view = this;
		if (!anchor)
			return;
		if (value == null || value < 0) {
			anchor.textContent = _('Timeout');
			anchor.style.color = 'red';
		}
		else {
			anchor.textContent = (text || value) + ' ms';
			anchor.style.color = pingColor(value);
		}
		anchor.onclick = function(ev) {
			if (ev && ev.preventDefault)
				ev.preventDefault();
			view.pingNode(sid, anchor, type);
		};
	},

	pingNode: function(sid, el, type) {
		if (!el || el.dataset.busy === '1' || !sid)
			return;
		var full = this.addressOf(sid);
		var ok = (type === 'icmp' && full.address) || (type === 'tcping' && full.address && full.port);
		if (!ok)
			return;
		el.dataset.busy = '1';
		el.style.color = '';
		el.textContent = _('Check...');
		pw.call('ping_node', {
			address: full.address,
			port: full.port,
			type: type
		}).then(function(result) {
			var pingText = (result && result.ping != null) ? String(result.ping).trim() : '';
			if (!pingText) {
				el.textContent = _('Timeout');
				el.style.color = 'red';
			}
			else {
				var ms = parseInt(pingText, 10);
				el.textContent = pingText + ' ms';
				el.style.color = pingColor(ms);
			}
		}).catch(function() {
			el.textContent = _('Error');
			el.style.color = 'red';
		}).then(function() {
			el.dataset.busy = '0';
		});
	},

	urltestNode: function(sid, el) {
		if (!el || el.dataset.busy === '1' || !sid)
			return;
		el.dataset.busy = '1';
		el.title = _('HTTP request latency, for reference only');
		el.style.color = '';
		el.textContent = _('Check...');
		pw.call('urltest_node', { id: sid }).then(function(result) {
			var use = (result && result.use_time != null) ? String(result.use_time).trim() : '';
			var color = 'red';
			var text = _('Error');
			if (!use) {
				var code = result && parseInt(result.http_code, 10);
				text = (code >= 400) ? ('HTTP ' + code) : _('Timeout');
			}
			else {
				var ms = parseInt(use, 10);
				color = urlColor(ms);
				text = ms + ' ms';
				el.title += '\n' + _('Initial handshake time') + ': ' + result.handshake_time + ' ms';
			}
			el.textContent = text;
			el.style.color = color;
		}).catch(function() {
			el.textContent = _('Error');
			el.style.color = 'red';
		}).then(function() {
			el.dataset.busy = '0';
		});
	},

	pingAll: function() {
		var view = this;
		var mode = view.autoDetection;
		if (mode !== 'icmp' && mode !== 'tcping')
			return;
		var klass = mode === 'tcping' ? 'tcping_value' : 'ping_value';
		var cells = view.listRoot.getElementsByClassName(klass);
		var now = Date.now();
		var jobs = [];
		for (var i = 0; i < cells.length; i++) {
			var sid = cells[i].getAttribute('cbiid');
			var full = view.addressOf(sid);
			var ok = (mode === 'icmp' && full.address) || (mode === 'tcping' && full.address && full.port);
			if (!ok)
				continue;
			var merged = false;
			for (var j = 0; j < jobs.length; j++) {
				if (jobs[j].address === full.address && jobs[j].port === full.port) {
					jobs[j].indexs.push(i);
					merged = true;
					break;
				}
			}
			if (merged)
				continue;
			var key = mode + ':' + full.address + ':' + full.port;
			var cache = storageGet(key);
			if (cache && cache.savetime && (now - cache.timestamp) < cache.savetime) {
				view.paintPing(cells[i].firstElementChild, cache.value, sid, mode);
			}
			else {
				storageRemove(key);
				jobs.push({ indexs: [ i ], address: full.address, port: full.port, key: key });
			}
		}

		var task = 0;
		var epoch = view.pingEpoch;
		function finish(job, value, text) {
			var saveFor = value >= 0 ? 150 * 1000 : 60 * 1000;
			storageSet(job.key, {
				timestamp: Date.now(),
				savetime: saveFor,
				value: value
			});
			job.indexs.forEach(function(index) {
				var cell = cells[index];
				if (!cell)
					return;
				view.paintPing(cell.firstElementChild, value, cell.getAttribute('cbiid'), mode, text);
			});
		}
		function run() {
			var index = task++;
			if (epoch !== view.pingEpoch || !jobs[index])
				return;
			var job = jobs[index];
			var settled = false;
			var timer = new Promise(function(resolve) {
				window.setTimeout(function() { resolve({ timeout: true }); }, 5000);
			});
			var req = pw.call('ping_node', {
				index: job.indexs.join(','),
				address: job.address,
				port: job.port,
				type: mode
			}).then(function(result) {
				return { timeout: false, result: result || {} };
			}).catch(function() {
				return { timeout: true };
			});
			Promise.race([ timer, req ]).then(function(out) {
				if (settled || epoch !== view.pingEpoch)
					return;
				settled = true;
				var pingText = (!out || out.timeout || !out.result || out.result.ping == null) ? '' : String(out.result.ping).trim();
				if (!pingText)
					finish(job, -1);
				else
					finish(job, parseInt(pingText, 10), pingText);
				run();
			});
		}
		for (var n = 0; n < 20; n++)
			run();
	},

	handleSave: function() {
		if (this.otherSid) {
			uci.set(APP, this.otherSid, 'auto_detection_time', this.autoDetection || '0');
			uci.set(APP, this.otherSid, 'show_node_info', this.showNodeInfo || '0');
			uci.set(APP, this.otherSid, 'url_test_url', this.urlTestUrl || '');
		}
		if (this.applyNodeOrder)
			this.applyNodeOrder();
		return uci.save();
	},

	handleSaveApply: function(ev, mode) {
		return this.handleSave(ev).then(function() {
			ui.changes.apply(mode == '0');
		});
	},

	handleReset: function() {
		ui.changes.revert();
	}
});
