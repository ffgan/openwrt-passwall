'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require fs';
'require poll';
'require view.passwall.tools as pw';

var APP = 'passwall';
var CACHE = '/tmp/etc/passwall_tmp';

function isMac(v) {
	return /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/.test(String(v || ''));
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
		list.push({ mac: mac, ip: m[2] });
	});
	String(arp || '').split('\n').forEach(function(line) {
		var parts = line.trim().split(/\s+/);
		if (parts.length < 4 || !isMac(parts[3]))
			return;
		var mac = parts[3].toLowerCase();
		if (seen[mac])
			return;
		seen[mac] = true;
		list.push({ mac: mac, ip: parts[0] });
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
	var map = {};
	list.forEach(function(item) {
		map[item.mac] = item.ip;
	});
	return map;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(APP),
			pw.loadCaps(),
			fs.read('/tmp/dhcp.leases').catch(function() { return ''; }),
			fs.read('/proc/net/arp').catch(function() { return ''; })
		]);
	},

	render: function(data) {
		var macMap = parseHints(data[2], data[3]);
		var globals = uci.sections(APP, 'global') || [];
		var sid = globals.length ? globals[0]['.name'] : null;
		if (!sid)
			return E('div', { 'class': 'alert-message warning' }, _('ACLs'));

		var m = new form.Map(APP);
		var s = m.section(form.NamedSection, sid, 'global', _('ACLs'), _('ACLs is a tools which used to designate specific IP proxy mode.'));
		s.anonymous = true;

		var o = s.option(form.Flag, 'acl_enable', _('Main switch'));
		o.rmempty = false;
		o.default = '0';

		var grid = m.section(form.GridSection, 'acl_rule');
		grid.anonymous = true;
		grid.addremove = true;
		grid.sortable = true;
		grid.nodescriptions = true;
		grid.extedit = pw.pageUrl('acl_config') + '/%s';
		grid.handleAdd = function() {
			var uid = 'acl_' + pw.rand(5);
			var configName = this.uciconfig || this.map.config;
			this.uci.add(configName, 'acl_rule', uid);
			return this.map.save().then(function() {
				window.location.href = pw.pageUrl('acl_config', uid);
			});
		};
		grid.handleRemove = function(section_id, ev) {
			var self = this;
			return fs.list(CACHE).then(function(entries) {
				var jobs = [];
				(entries || []).forEach(function(ent) {
					var name = ent && ent.name ? ent.name : String(ent || '');
					if (name.indexOf('dnsmasq_' + section_id) === 0)
						jobs.push(fs.remove(CACHE + '/' + name).catch(function() {}));
				});
				return Promise.all(jobs);
			}).catch(function() {
				return null;
			}).then(function() {
				return form.GridSection.prototype.handleRemove.call(self, section_id, ev);
			});
		};

		o = grid.option(form.Flag, 'enabled', _('Enable'));
		o.default = '1';
		o.rmempty = false;
		o.editable = true;

		o = grid.option(form.Value, 'remarks', _('Remarks'));
		o.rmempty = true;
		o.editable = true;

		o = grid.option(form.DummyValue, 'interface', _('Source Interface'));
		o.textvalue = function(section_id) {
			var v = uci.get(APP, section_id, 'interface') || '';
			return v === '' ? _('All') : v;
		};

		o = grid.option(form.DummyValue, 'sources', _('Source'));
		o.textvalue = function(section_id) {
			var v = uci.get(APP, section_id, 'sources');
			var parts = [];
			if (Array.isArray(v))
				parts = v;
			else if (v)
				parts = String(v).split(/\s+/).filter(function(item) { return item !== ''; });
			if (!parts.length)
				return null;
			var kids = [];
			parts.forEach(function(item, index) {
				if (index)
					kids.push(E('br'));
				var mac = String(item).toLowerCase();
				kids.push(macMap[mac] ? (item + ' (' + macMap[mac] + ')') : item);
			});
			return E('span', {}, kids);
		};

		o = grid.option(form.DummyValue, 'mode', _('Mode'));
		o.textvalue = function(section_id) {
			var v = uci.get(APP, section_id, 'mode') || '0';
			return v === '1' ? _('Proxy') : _('No Proxy');
		};

		return m.render();
	}
});
