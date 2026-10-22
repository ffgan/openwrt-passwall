'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require poll';
'require view.passwall.tools as pw';

var APP = 'passwall';

var HAPROXY_CSS = [
	'@media screen and (min-width: 1152px) {',
	'  #cbi-passwall-haproxy_config input[id$=".haproxy_port"],',
	'  #cbi-passwall-haproxy_config input[id$=".lbweight"] {',
	'    width: 100px !important;',
	'    min-width: unset !important;',
	'    max-width: unset !important;',
	'    text-align: center !important;',
	'  }',
	'  #cbi-passwall-haproxy_config [id$=".export"] {',
	'    width: 130px !important;',
	'    min-width: unset !important;',
	'    max-width: unset !important;',
	'  }',
	'  #cbi-passwall-haproxy_config [id$=".backup"] {',
	'    width: 100px !important;',
	'    min-width: unset !important;',
	'    max-width: unset !important;',
	'  }',
	'}'
].join('\n');

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

function flag(section, name, title, description) {
	var o = section.option(form.Flag, name, title, description);
	o.enabled = '1';
	o.disabled = '0';
	return o;
}

function isIPv4(value) {
	var match = String(value || '').match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
	if (!match)
		return false;
	for (var i = 1; i <= 4; i++) {
		var n = +match[i];
		if (match[i] !== String(n) || n > 255)
			return false;
	}
	return true;
}

function isPort(value) {
	if (!/^\d+$/.test(String(value || '')))
		return false;
	var n = +value;
	return n >= 0 && n <= 65535;
}

function isHostname(value) {
	return /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/.test(value) ||
		/^[A-Za-z0-9]$/.test(value);
}

function splitHostPort(value) {
	var text = String(value || '');
	var match = text.match(/^\[(.+)\]:(\d+)$/);
	if (match)
		return { host: match[1], port: match[2], wrapped: true };
	var idx = text.lastIndexOf(':');
	if (idx <= 0)
		return null;
	return {
		host: text.substring(0, idx),
		port: text.substring(idx + 1),
		wrapped: false
	};
}

function isHostPort(value) {
	var parts = splitHostPort(value);
	if (!parts || parts.wrapped || !isPort(parts.port))
		return false;
	return isHostname(parts.host);
}

function isIPv4Port(value) {
	var parts = splitHostPort(value);
	return !!(parts && !parts.wrapped && isIPv4(parts.host) && isPort(parts.port));
}

function isIPv6Port(value) {
	var parts = splitHostPort(value);
	if (!parts || !parts.wrapped || !isPort(parts.port))
		return false;
	return parts.host.indexOf(':') >= 0 && /^[0-9A-Fa-f:]+$/.test(parts.host);
}

function normalNodes(caps) {
	var items = [];
	var nodes = (caps && Array.isArray(caps.nodes)) ? caps.nodes : [];
	nodes.forEach(function(node) {
		if (!node || node.node_type !== 'normal')
			return;
		var id = node.id || node['.name'];
		if (!id)
			return;
		var group = (node.group && node.group !== '') ? node.group : _('default');
		items.push({
			value: id,
			label: node.remark || node.remarks || id,
			group: group
		});
	});
	return items;
}

function networkInterfaces() {
	var names = [];
	(uci.sections('network', 'interface') || []).forEach(function(sec) {
		if (sec['.name'] && sec['.name'] !== 'loopback')
			names.push(sec['.name']);
	});
	return names;
}

function statusObject(result) {
	if (result && typeof result === 'object' && typeof result.output === 'string') {
		try {
			return JSON.parse(result.output);
		}
		catch (e) {
			return result;
		}
	}
	if (typeof result === 'string') {
		try {
			return JSON.parse(result);
		}
		catch (e2) {
			return {};
		}
	}
	return result || {};
}

function watchPorts(root) {
	var started = Date.now();
	var timer = window.setInterval(function() {
		if (Date.now() - started > 3000) {
			window.clearInterval(timer);
			return;
		}
		var rows = Array.prototype.filter.call(root.querySelectorAll('tr.cbi-section-table-row'), function(row) {
			return !row.classList.contains('placeholder');
		});
		if (rows.length <= 1)
			return;
		var lastRow = rows[rows.length - 1];
		var prevRow = rows[rows.length - 2];
		var lastInput = lastRow.querySelector('input[id$=".haproxy_port"], input[name$=".haproxy_port"]');
		var prevInput = prevRow.querySelector('input[id$=".haproxy_port"], input[name$=".haproxy_port"]');
		if (!lastInput || !prevInput)
			return;
		if (!lastInput.dataset.bindChange) {
			lastInput.dataset.bindChange = '1';
			lastInput.addEventListener('input', function() {
				lastInput.dataset.userModified = '1';
			});
		}
		if (lastInput.dataset.userModified === '1')
			return;
		var lastVal = lastInput.value.trim();
		var prevVal = prevInput.value.trim();
		var lbss = lastRow.querySelector('div.cbi-dropdown input[type="hidden"][id$=".lbss"], div.cbi-dropdown input[type="hidden"][name$=".lbss"]');
		if (!lbss && lastVal !== prevVal && prevVal !== '' && prevVal !== '0')
			lastInput.value = prevVal;
	}, 300);
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(APP),
			uci.load('network').catch(function() { return null; }),
			pw.loadCaps().catch(function() { return {}; })
		]);
	},

	render: function(data) {
		var caps = data[2] || {};
		var sid = ensureSection('global_haproxy');
		var m = new form.Map(APP, 'HAPROXY ' + _('Load Balancing'));
		var s = m.section(form.NamedSection, sid, 'global_haproxy', _('Basic Settings'));

		var o = s.option(form.DummyValue, '_status', '');
		o.renderWidget = function() {
			return E('div', { 'id': '_status' });
		};

		o = flag(s, 'balancing_enable', _('Enable Load Balancing'));
		o.rmempty = false;
		o.default = '0';

		o = flag(s, 'console_auth', _('Console Login Auth'));
		o.default = '0';
		o.depends('balancing_enable', '1');

		o = s.option(form.Value, 'console_user', _('Console Username'));
		o.default = '';
		o.depends('console_auth', '1');

		o = s.option(form.Value, 'console_password', _('Console Password'));
		o.password = true;
		o.default = '';
		o.depends('console_auth', '1');

		o = s.option(form.Value, 'console_port', _('Console Port'), _('In the browser input routing IP plus port access, such as:192.168.1.1:1188'));
		o.default = '1188';
		o.placeholder = '1188';
		o.datatype = 'range(1,65535)';
		o.depends('balancing_enable', '1');

		o = flag(s, 'bind_local', _('Haproxy Port') + ' ' + _('Bind Local'), _('When selected, it can only be accessed localhost.'));
		o.default = '0';
		o.depends('balancing_enable', '1');

		o = s.option(form.ListValue, 'balancingStrategy', _('Balancing Strategy'));
		o.value('roundrobin', 'roundRobin');
		o.value('random', 'random');
		o.value('leastconn', 'leastConn');
		o.value('source', 'source');
		o.default = 'roundrobin';
		o.depends('balancing_enable', '1');

		o = s.option(form.ListValue, 'health_check_type', _('Health Check Type'));
		o.default = 'script_logic';
		o.value('tcp', 'TCP');
		o.value('script_logic', _('URL Test') + '(passwall ' + _('Inner implement') + ')');
		o.depends('balancing_enable', '1');

		o = s.option(form.Value, 'health_probe_url', _('Probe URL'));
		o.value('https://cp.cloudflare.com/', 'Cloudflare');
		o.value('https://www.gstatic.com/generate_204', 'Gstatic');
		o.value('https://www.google.com/generate_204', 'Google');
		o.value('https://www.youtube.com/generate_204', 'YouTube');
		o.value('https://connect.rom.miui.com/generate_204', 'MIUI (CN)');
		o.value('https://connectivitycheck.platform.hicloud.com/generate_204', 'HiCloud (CN)');
		o.value('https://wifi.vivo.com.cn/generate_204', 'VIVO (CN)');
		o.default = 'https://www.google.com/generate_204';
		o.description = _('The URL used to detect the connection status.');
		o.depends('health_check_type', 'script_logic');

		o = s.option(form.Value, 'health_check_inter', _('Health Check Inter'));
		o.datatype = 'min(20)';
		o.default = '60';
		o.depends('balancing_enable', '1');
		o.description = _('Units:seconds') + ' ( ≥ 20s )<br>' +
			_('Note: Frequent health checks increase CPU usage; an interval ≥ 60 seconds is recommended.');

		o = s.option(form.DummyValue, 'health_check_tips', '　');
		o.depends('health_check_type', 'script_logic');
		o.cfgvalue = function() {
			return '<span class="pw-warn">' + _('When the URL test is used, the load balancing node will be converted into a Socks node. when node list set customizing, must be a Socks node, otherwise the health check will be invalid.') + '</span>';
		};
		o.rawhtml = true;
		o.renderWidget = function(section_id, option_index, cfgvalue) {
			var el = E('div');
			el.innerHTML = cfgvalue || '';
			return el;
		};

		var grid = m.section(form.GridSection, 'haproxy_config', _('Node List'),
			'<span class="pw-warn">' +
			_('Add a node, Export Of Multi WAN Only support Multi Wan. Load specific gravity range 1-256. Multiple primary servers can be load balanced, standby will only be enabled when the primary server is offline! Multiple groups can be set, Haproxy port same one for each group.') + '<br>' +
			_('Note that the node configuration parameters for load balancing must be consistent when use TCP health check type, otherwise it cannot be used normally!') +
			'</span>');
		grid.anonymous = true;
		grid.addremove = true;
		grid.sortable = true;
		grid.nodescriptions = true;
		grid.renderRowActions = function(section_id) {
			return form.TableSection.prototype.renderRowActions.call(this, section_id, null);
		};
		grid.handleAdd = function() {
			var section = this;
			return section.map.save().then(function() {
				var prev = uci.sections(APP, 'haproxy_config') || [];
				var port = '1181';
				if (prev.length) {
					var last = prev[prev.length - 1].haproxy_port;
					if (last && String(last) !== '0')
						port = String(last);
				}
				var uid = 'haproxy_' + pw.rand(5);
				uci.add(APP, 'haproxy_config', uid);
				uci.set(APP, uid, 'haproxy_port', port);
				return uci.save();
			}).then(function() {
				return section.map.load().then(function() {
					return section.map.renderContents();
				});
			});
		};

		o = flag(grid, 'enabled', _('Enable'));
		o.default = '1';
		o.rmempty = false;
		o.editable = true;
		o.modalonly = false;

		o = grid.option(form.Value, 'lbss', _('Node Address'));
		o.editable = true;
		o.modalonly = false;
		o.rmempty = false;
		o.value('', _('-- Please choose --'));
		normalNodes(caps).forEach(function(item) {
			var label = item.group ? ('[' + item.group + '] ' + item.label) : item.label;
			o.value(item.value, label);
		});
		o.validate = function(section_id, value) {
			if (value == null || String(value).trim() === '')
				return _('Node address cannot be empty.');
			value = String(value).trim();
			var node = uci.get(APP, value);
			if (node && node['.type'] === 'nodes')
				return true;
			if (isHostPort(value) || isIPv4Port(value) || isIPv6Port(value))
				return true;
			return _('Not valid IP format, please re-enter!') + ' (IP:Port)';
		};

		o = grid.option(form.Value, 'haproxy_port', _('Haproxy Port'));
		o.default = '1181';
		o.datatype = 'range(1,65535)';
		o.rmempty = false;
		o.editable = true;
		o.modalonly = false;

		o = grid.option(form.Value, 'lbweight', _('Node Weight'));
		o.datatype = 'min(1)';
		o.default = '5';
		o.rmempty = false;
		o.editable = true;
		o.modalonly = false;

		o = grid.option(form.ListValue, 'export', _('Export Of Multi WAN'));
		o.value('0', _('Auto'));
		networkInterfaces().forEach(function(name) {
			o.value(name);
		});
		o.default = '0';
		o.rmempty = false;
		o.editable = true;
		o.modalonly = false;
		o.titleref = L.url('admin', 'network', 'network');

		o = grid.option(form.ListValue, 'backup', _('Mode'));
		o.value('0', _('Primary'));
		o.value('1', _('Standby'));
		o.rmempty = false;
		o.editable = true;
		o.modalonly = false;

		var view = this;
		return m.render().then(function(node) {
			view.map = m;
			paintHtml(node);
			var style = E('style', {}, HAPROXY_CSS);
			if (node.firstChild)
				node.insertBefore(style, node.firstChild);
			else
				node.appendChild(style);
			if ((uci.get(APP, sid, 'balancing_enable') || '0') === '1') {
				var port = uci.get(APP, sid, 'console_port') || '1188';
				poll.add(function() {
					return pw.get('haproxy_status').then(function(result) {
						var box = document.getElementById('_status');
						if (!box)
							return;
						var body = statusObject(result);
						while (box.firstChild)
							box.removeChild(box.firstChild);
						if (body && body.status) {
							box.appendChild(E('button', {
								'class': 'btn cbi-button cbi-button-apply',
								'click': function(ev) {
									ev.preventDefault();
									window.open('http://' + window.location.hostname + ':' + port, 'target', '');
								}
							}, _('Enter interface')));
						}
					}).catch(function() {});
				}, 5);
			}
			watchPorts(node);
			return node;
		});
	}
});
