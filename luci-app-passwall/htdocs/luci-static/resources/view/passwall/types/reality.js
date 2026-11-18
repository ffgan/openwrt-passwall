'use strict';
'require baseclass';
'require form';

return baseclass.extend({
	typeName: 'Reality',
	addOptions: function(section) {
		var o;
		o = section.option(form.Value, 'address', _('Address (Support Domain Name)'));
		o.rmempty = false;
		o = section.option(form.Value, 'port', _('Port'));
		o.datatype = 'port'; o.default = '443'; o.rmempty = false;
		o = section.option(form.Value, 'uuid', _('UUID'));
		o.rmempty = false;
		o = section.option(form.Value, 'tls_serverName', _('Server Name'));
		o.rmempty = false;
		o = section.option(form.Value, 'reality_publicKey', _('Public Key'));
		o.rmempty = false;
		o = section.option(form.Value, 'reality_shortId', _('Short Id'));
		o.datatype = 'and(hexstring,maxlength(16))';
	}
});
