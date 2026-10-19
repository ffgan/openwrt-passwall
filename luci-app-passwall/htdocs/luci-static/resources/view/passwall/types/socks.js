'use strict';
'require baseclass';
'require form';

return baseclass.extend({
	typeName: 'Socks',

	addOptions: function(section) {
		var o;

		/* Hidden on purpose: clears a leftover protocol value when this type is saved. */
		o = section.option(form.ListValue, 'protocol', '　');
		o.depends({ __hide: '1' });

		o = section.option(form.Value, 'address', _('Address (Support Domain Name)'));

		o = section.option(form.Value, 'port', _('Port'));
		o.datatype = 'port';

		o = section.option(form.Value, 'username', _('Username'));

		o = section.option(form.Value, 'password', _('Password'));
		o.password = true;
	}
});
