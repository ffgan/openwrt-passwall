'use strict';
'require baseclass';
'require form';
'require fs';

var ssrustEncryptMethodList = [
	'none', 'plain',
	'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
	'2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'
];

return baseclass.extend({
	typeName: 'SS-Rust',

	addOptions: function(section) {
		var o;

		/* Hidden on purpose: clears a leftover protocol value when this type is saved. */
		o = section.option(form.ListValue, 'protocol');
		o.depends({ __hide: '1' });

		o = section.option(form.Value, 'address', _('Address (Support Domain Name)'));

		o = section.option(form.Value, 'port', _('Port'));
		o.datatype = 'port';

		o = section.option(form.Value, 'password', _('Password'));
		o.password = true;

		o = section.option(form.Value, 'ss_method', _('Encrypt Method'));
		for (var i = 0; i < ssrustEncryptMethodList.length; i++)
			o.value(ssrustEncryptMethodList[i]);

		o = section.option(form.Value, 'timeout', _('Connection Timeout'));
		o.datatype = 'uinteger';
		o.default = '300';

		o = section.option(form.Flag, 'tcp_fast_open', 'TCP ' + _('Fast Open'), _('Need node support required'));
		o.default = '0';

		o = section.option(form.Flag, 'plugin_enabled', _('plugin'));
		o.default = '0';

		o = section.option(form.Value, 'plugin', 'SIP003 ' + _('plugin'), _('Supports custom SIP003 plugins, Make sure the plugin is installed.'));
		o.default = 'none';
		o.value('none', _('none'));
		o.value('xray-plugin');
		o.value('v2ray-plugin');
		o.value('obfs-local');
		o.value('shadow-tls');
		o.depends({ plugin_enabled: true });
		o.validate = function(section_id, value) {
			if (value && value !== '' && value !== 'none') {
				var probe = (value.indexOf('/') >= 0) ? value : '/usr/bin/' + value;
				return fs.stat(probe).then(function() {
					return true;
				}).catch(function() {
					if (probe !== value)
						return fs.stat('/bin/' + value).then(function() {
							return true;
						}).catch(function() {
							return value + ': ' + _('Can\'t find this file!');
						});
					return value + ': ' + _('Can\'t find this file!');
				});
			}
			return true;
		};

		o = section.option(form.Value, 'plugin_opts', _('opts'));
		o.depends({ plugin_enabled: true });
	}
});
