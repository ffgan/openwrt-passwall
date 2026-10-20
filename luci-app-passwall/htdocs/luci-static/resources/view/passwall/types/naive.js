'use strict';
'require baseclass';
'require form';

return baseclass.extend({
	typeName: 'Naiveproxy',

	addOptions: function(section) {
		var o;

		o = section.option(form.ListValue, 'protocol', _('Protocol'));
		o.value('https', _('HTTPS'));
		o.value('quic', _('QUIC'));

		o = section.option(form.Value, 'address', _('Address (Support Domain Name)'));

		o = section.option(form.Value, 'port', _('Port'));
		o.datatype = 'port';

		o = section.option(form.Value, 'username', _('Username'));

		o = section.option(form.Value, 'password', _('Password'));
		o.password = true;
	}
});
