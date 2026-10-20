'use strict';
'require baseclass';
'require form';

var ssrEncryptMethodList = [
	'none', 'table', 'rc2-cfb', 'rc4', 'rc4-md5', 'rc4-md5-6', 'aes-128-cfb',
	'aes-192-cfb', 'aes-256-cfb', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
	'bf-cfb', 'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
	'cast5-cfb', 'des-cfb', 'idea-cfb', 'seed-cfb', 'salsa20', 'chacha20',
	'chacha20-ietf'
];

var ssrProtocolList = [
	'origin', 'verify_simple', 'verify_deflate', 'verify_sha1', 'auth_simple',
	'auth_sha1', 'auth_sha1_v2', 'auth_sha1_v4', 'auth_aes128_md5',
	'auth_aes128_sha1', 'auth_chain_a', 'auth_chain_b', 'auth_chain_c',
	'auth_chain_d', 'auth_chain_e', 'auth_chain_f'
];

var ssrObfsList = [
	'plain', 'http_simple', 'http_post', 'random_head', 'tls_simple',
	'tls1.0_session_auth', 'tls1.2_ticket_auth'
];

function fill(o, list) {
	for (var i = 0; i < list.length; i++)
		o.value(list[i]);
	return o;
}

return baseclass.extend({
	typeName: 'SSR',

	addOptions: function(section) {
		var o;

		o = section.option(form.Value, 'address', _('Address (Support Domain Name)'));

		o = section.option(form.Value, 'port', _('Port'));
		o.datatype = 'port';

		o = section.option(form.Value, 'password', _('Password'));
		o.password = true;

		o = section.option(form.ListValue, 'method', _('Encrypt Method'));
		fill(o, ssrEncryptMethodList);

		o = section.option(form.ListValue, 'protocol', _('Protocol'));
		fill(o, ssrProtocolList);

		o = section.option(form.Value, 'protocol_param', _('Protocol_param'));

		o = section.option(form.ListValue, 'obfs', _('Obfs'));
		fill(o, ssrObfsList);

		o = section.option(form.Value, 'obfs_param', _('Obfs_param'));

		o = section.option(form.Value, 'timeout', _('Connection Timeout'));
		o.datatype = 'uinteger';
		o.default = '300';

		o = section.option(form.Flag, 'tcp_fast_open', 'TCP ' + _('Fast Open'), _('Need node support required'));
		o.default = '0';
	}
});
