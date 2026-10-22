'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require poll';
'require validation';
'require view.passwall.tools as pw';

var APP = 'passwall';
var DOMAINS = '/etc/passwall/rules/domains_excluded';

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

function portOption(section, name, title, description) {
	var o = section.option(form.Value, name, title, description);
	o.write = function(section_id, value) {
		return uci.set(APP, section_id, name, pw.normalizePorts(value));
	};
	return o;
}

function hourOptions(option) {
	for (var t = 0; t < 24; t++)
		option.value(t + ':00');
	return option;
}

function weekDepends(option, name) {
	['0', '1', '2', '3', '4', '5', '6', '7'].forEach(function(day) {
		option.depends(name, day);
	});
	return option;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(APP),
			pw.loadCaps().catch(function() { return {}; }),
			pw.readText(DOMAINS)
		]);
	},

	render: function(data) {
		var caps = data[1] || {};
		var domains = data[2] || '';
		var mods = caps.lsmod || '';
		var hasProxy = (mods.indexOf('REDIRECT') >= 0 && mods.indexOf('TPROXY') >= 0) ||
			(mods.indexOf('nft_redir') >= 0 && mods.indexOf('nft_tproxy') >= 0);
		var hasV6 = mods.indexOf('ip6table_mangle') >= 0 || mods.indexOf('nft_tproxy') >= 0;
		var m = new form.Map(APP);

		var s = m.section(form.NamedSection, ensureSection('global_delay'), 'global_delay', _('Delay Settings'));
		var o = flag(s, 'start_daemon', _('Open and close Daemon'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.Value, 'start_delay', _('Delay Start'), _('Units:seconds'));
		o.default = '1';
		o.rmempty = true;

		['stop', 'start', 'restart'].forEach(function(action) {
			o = s.option(form.ListValue, action + '_week_mode', _(action + ' automatically mode'));
			pw.weekMode(o, action === 'restart');

			o = s.option(form.Value, action + '_time_mode', _(action + ' Time'));
			hourOptions(o);
			o.default = '0:00';
			o.datatype = 'timehhmm';
			weekDepends(o, action + '_week_mode');

			o = s.option(form.ListValue, action + '_interval_mode', _(action + ' Interval(Hour)'));
			for (var t = 1; t <= 24; t++)
				o.value(String(t), t + ' ' + _('Hour'));
			o.default = '2';
			o.depends(action + '_week_mode', '8');
		});

		s = m.section(form.NamedSection, ensureSection('global_forwarding'), 'global_forwarding', _('Forwarding Settings'));

		o = portOption(s, 'tcp_no_redir_ports', _('TCP No Redir Ports'));
		o.default = 'disable';
		o.value('disable', _('No patterns are used'));
		o.value('1:65535', _('All'));

		o = portOption(s, 'udp_no_redir_ports', _('UDP No Redir Ports'),
			'<span class="pw-warn">' + _('Fill in the ports you don\'t want to be forwarded by the agent, with the highest priority.') + '</span>');
		o.default = 'disable';
		o.value('disable', _('No patterns are used'));
		o.value('1:65535', _('All'));

		o = portOption(s, 'tcp_proxy_drop_ports', _('TCP Proxy Drop Ports'));
		o.default = 'disable';
		o.value('disable', _('No patterns are used'));

		o = portOption(s, 'udp_proxy_drop_ports', _('UDP Proxy Drop Ports'));
		o.default = '443';
		o.value('disable', _('No patterns are used'));
		o.value('443', _('QUIC'));

		o = portOption(s, 'tcp_redir_ports', _('TCP Redir Ports'));
		o.value('1:65535', _('All'));
		o.value('22,25,53,80,143,443,465,587,853,873,993,995,5222,8080,8443,9418', _('Common Use'));
		o.value('80,443', _('Only Web'));
		o.default = '22,25,53,80,143,443,465,587,853,873,993,995,5222,8080,8443,9418';

		o = portOption(s, 'udp_redir_ports', _('UDP Redir Ports'));
		o.default = '1:65535';
		o.value('1:65535', _('All'));
		o.value('53', 'DNS');

		o = s.option(form.DummyValue, 'tips', '　');
		o.rawhtml = true;
		o.cfgvalue = function() {
			return '<span class="pw-warn">' + _('The port settings support single ports and ranges.<br>Separate multiple ports with commas (,).<br>Example: 21,80,443,1000:2000.') + '</span>';
		};
		o.renderWidget = function(section_id, option_index, cfgvalue) {
			var el = E('div');
			el.innerHTML = cfgvalue || '';
			return el;
		};

		if (hasProxy) {
			o = s.option(form.ListValue, 'tcp_proxy_way', _('TCP Proxy Way'));
			o.default = 'redirect';
			o.value('redirect', 'REDIRECT');
			o.value('tproxy', 'TPROXY');
			o.retain = true;
			o.remove = function() {};
			if (hasV6)
				o.depends('ipv6_tproxy', '0');

			if (hasV6) {
				o = s.option(form.ListValue, '_tcp_proxy_way', _('TCP Proxy Way'));
				o.default = 'tproxy';
				o.value('tproxy', 'TPROXY');
				o.depends('ipv6_tproxy', '1');
				o.cfgvalue = function(section_id) {
					return uci.get(APP, section_id, 'tcp_proxy_way') || 'tproxy';
				};
				o.write = function(section_id, value) {
					return uci.set(APP, section_id, 'tcp_proxy_way', value);
				};
				o.remove = function() {};
				o.retain = true;

				o = flag(s, 'ipv6_tproxy', _('IPv6 TProxy'),
					'<span class="pw-warn">' + _('Experimental feature. Make sure that your node supports IPv6.') + '</span>');
				o.default = '0';
				o.rmempty = false;
			}
		}

		o = flag(s, 'accept_icmp', _('Hijacking ICMP (PING)'));
		o.default = '0';

		o = flag(s, 'accept_icmpv6', _('Hijacking ICMPv6 (IPv6 PING)'));
		o.depends('ipv6_tproxy', '1');
		o.default = '0';

		if (present(caps.xray)) {
			var sx = m.section(form.NamedSection, ensureSection('global_xray'), 'global_xray', 'Xray ' + _('Settings'));

			o = flag(sx, 'fragment', _('Fragment'), _('TCP fragments, which can deceive the censorship system in some cases, such as bypassing SNI blacklists.'));
			o.default = '0';

			o = sx.option(form.ListValue, 'fragment_packets', _('Fragment Packets'), _('\"1-3\" is for segmentation at TCP layer, applying to the beginning 1 to 3 data writes by the client. \"tlshello\" is for TLS client hello packet fragmentation.'));
			o.default = 'tlshello';
			o.value('tlshello', 'tlshello');
			o.value('1-1', '1-1');
			o.value('1-2', '1-2');
			o.value('1-3', '1-3');
			o.value('1-5', '1-5');
			o.depends('fragment', '1');

			o = sx.option(form.Value, 'fragment_lengths', _('Fragment Length'), _('Fragmented packet length (byte)'));
			o.default = '3-5,6-8,10-20';
			o.depends('fragment', '1');

			o = sx.option(form.Value, 'fragment_delays', _('Fragment Delay'), _('Fragmentation interval (ms)'));
			o.default = '10-20';
			o.depends('fragment', '1');

			o = sx.option(form.Value, 'fragment_maxSplit', _('Max Split'), _('Limit the maximum number of splits.'));
			o.datatype = 'or(uinteger,portrange)';
			o.default = '3-6';
			o.depends('fragment', '1');

			o = flag(sx, 'noise', _('Noise'), _('UDP noise, Under some circumstances it can bypass some UDP based protocol restrictions.'));
			o.default = '0';

			o = flag(sx, 'sniffing_override_dest', _('Override the connection destination address'));
			o.default = '0';
			o.description = _('Override the connection destination address with the sniffed domain.<br />Otherwise use sniffed domain for routing only.<br />If using shunt nodes, configure the domain shunt rules correctly.');

			o = sx.option(form.TextValue, 'excluded_domains', _('Excluded Domains'), _('If the traffic sniffing result is in this list, the destination address will not be overridden.'));
			o.rows = 15;
			o.wrap = 'off';
			o.rmempty = false;
			o.retain = true;
			o.depends({ sniffing_override_dest: '1' });
			o.cfgvalue = function() {
				return domains;
			};
			o.write = function(section_id, value) {
				domains = String(value == null ? '' : value).replace(/\r\n/g, '\n');
				return pw.writeText(DOMAINS, domains);
			};
			o.remove = function() {};

			o = sx.option(form.Value, 'buffer_size', _('Buffer Size'), _('Buffer size for every connection (kB)'));
			o.datatype = 'uinteger';

			var noise = m.section(form.TableSection, 'xray_noise_packets', _('Xray Noise Packets'),
				'<span class="pw-warn">' + _('To send noise packets, select "Noise" in Xray Settings.') + '</span>');
			noise.anonymous = true;
			noise.addremove = true;
			noise.sortable = true;
			noise.handleAdd = function() {
				var section = this;
				return section.map.save().then(function() {
					var uid = 'xray_noise_' + pw.rand(5);
					uci.add(APP, 'xray_noise_packets', uid);
					return uci.save();
				}).then(function() {
					return section.map.load().then(function() {
						return section.map.renderContents();
					});
				});
			};

			o = flag(noise, 'enabled', _('Enable'));
			o.default = '1';
			o.rmempty = false;

			o = noise.option(form.ListValue, 'type', _('Type'));
			o.value('rand', 'rand');
			o.value('array', 'array');
			o.value('str', 'str');
			o.value('hex', 'hex');
			o.value('base64', 'base64');

			o = noise.option(form.Value, 'packet', _('Packet | Rand Length'));
			o.datatype = 'minlength(1)';
			o.rmempty = false;

			o = noise.option(form.Value, 'delay', _('Delay (ms)'));
			o.datatype = 'or(uinteger,portrange)';
			o.rmempty = false;
		}

		if (present(caps.singbox)) {
			s = m.section(form.NamedSection, ensureSection('global_singbox'), 'global_singbox', 'Sing-Box ' + _('Settings'));

			o = flag(s, 'record_fragment', 'TLS Record ' + _('Fragment'),
				_('Split handshake data into multiple TLS records for better censorship evasion. Low overhead. Recommended to enable first.'));
			o.default = '0';

			o = flag(s, 'fragment', 'TLS TCP ' + _('Fragment'),
				_('Split handshake into multiple TCP segments. Enhances obfuscation. May increase delay. Use only if needed.'));
			o.default = '0';
		}

		var view = this;
		return m.render().then(function(node) {
			view.map = m;
			paintHtml(node);
			return node;
		});
	}
});
