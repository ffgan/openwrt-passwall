'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require poll';
'require view.passwall.tools as pw';

var PKG = 'passwall_server';

function genUuid() {
	var hex = '0123456789abcdef';
	var out = '';
	for (var i = 0; i < 36; i++) {
		if (i === 8 || i === 13 || i === 18 || i === 23)
			out += '-';
		else if (i === 14)
			out += '4';
		else if (i === 19)
			out += hex[(Math.floor(Math.random() * 4) + 8)];
		else
			out += hex[Math.floor(Math.random() * 16)];
	}
	return out;
}

function asObject(res) {
	if (res == null)
		return null;
	if (typeof res === 'string') {
		try {
			return JSON.parse(res);
		}
		catch (e) {
			return null;
		}
	}
	if (typeof res === 'object' && typeof res.output === 'string') {
		try {
			return JSON.parse(res.output);
		}
		catch (e2) {
			return res;
		}
	}
	return res;
}

function keyPayload(res) {
	var body = asObject(res) || {};
	if (body.code != null && String(body.code) !== '1')
		return null;
	if (body.data && body.data.private_key)
		return body.data;
	if (body.private_key)
		return body;
	return null;
}

return view.extend({
	load: function() {
		return uci.load(PKG);
	},

	render: function() {
		var id = pw.routeArg();
		var users = uci.sections(PKG, 'user') || [];
		var user = null;
		for (var i = 0; i < users.length; i++) {
			if (users[i]['.name'] === id) {
				user = users[i];
				break;
			}
		}
		if (!id || !user) {
			window.location.href = pw.pageUrl('server');
			return E('div');
		}

		var m = new form.Map(PKG);
		var s = m.section(form.NamedSection, id, 'user', _('User Config'));
		s.addremove = false;

		function applyKey(name, value) {
			uci.set(PKG, id, name, value || '');
			var input = document.getElementById('cbid.' + PKG + '.' + id + '.' + name);
			if (input) {
				input.value = value || '';
				input.dispatchEvent(new Event('change', { bubbles: true }));
			}
			var opts = m.lookupOption(name, id) || [];
			if (opts[0] && opts[0].getUIElement) {
				var widget = opts[0].getUIElement(id);
				if (widget && widget.setValue)
					widget.setValue(value || '');
			}
		}

		function genWireguard() {
			return pw.call('gen_wireguard_key').then(function(res) {
				var data = keyPayload(res);
				if (!data) {
					alert(_('Error'));
					return;
				}
				applyKey('wireguard_private_key', data.private_key || '');
				applyKey('wireguard_public_key', data.public_key || '');
			}).catch(function() {
				alert(_('Error'));
			});
		}

		var o = s.option(form.Value, 'username', _('Username'));
		o.datatype = 'and(uciname,maxlength(24))';
		o.rmempty = false;
		o.validate = function(section_id, value) {
			var exists = false;
			(uci.sections(PKG, 'user') || []).forEach(function(sec) {
				if (sec['.name'] !== section_id && sec.username === value)
					exists = true;
			});
			if (exists)
				return _('This username already exists.');
			return true;
		};

		o = s.option(form.Value, 'password', _('Password'));
		o.rmempty = false;

		o = s.option(form.Value, 'uuid', 'UUID');
		o.datatype = 'uuid';
		o.default = genUuid();
		o.rmempty = false;

		o = s.option(form.Value, 'wireguard_public_key', 'Wireguard ' + _('Public Key'));
		o.datatype = 'base64';

		o = s.option(form.Value, 'wireguard_private_key', 'Wireguard ' + _('Private Key'));
		o.datatype = 'base64';

		o = s.option(form.DummyValue, 'gen_wireguard_key', _('Generate key'));
		o.write = function() {};
		o.remove = function() {};
		o.renderWidget = function() {
			return E('button', {
				'class': 'btn cbi-button',
				'click': ui.createHandlerFn(this, genWireguard)
			}, _('Generate key'));
		};

		o = s.option(form.Value, 'wireguard_pre_shared_key', 'Wireguard ' + _('Pre shared key'));
		o.datatype = 'base64';

		o = s.option(form.DynamicList, 'allowed_ips', 'Wireguard ' + _('Allowed IPs'));

		return m.render();
	}
});
