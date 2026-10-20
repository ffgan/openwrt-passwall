'use strict';
'require baseclass';
'require form';
'require uci';

function parseRealm(uri) {
	uri = String(uri || '').trim();
	if (!uri)
		return null;
	var scheme = null;
	if (uri.indexOf('realm+http://') === 0)
		scheme = 'realm+http';
	else if (uri.indexOf('realm://') === 0)
		scheme = 'realm';
	if (!scheme)
		return null;
	var rest = uri.replace(/^realm\+http:\/\//, '').replace(/^realm:\/\//, '');
	var m = rest.match(/^([^@]+)@([^/]+)\/([^?]*)\??(.*)$/);
	if (!m || !m[1] || !m[2] || m[3] == null)
		return null;
	return true;
}

return baseclass.extend({
	typeName: 'Hysteria2',

	addOptions: function(section) {
		var o;

		/*
		 * set_type_cbi stores the plain option name, except where the Lua
		 * assigns rewrite_option = o.option after the hysteria2_ prefix is
		 * applied. Those keys are the prefixed names the runtime reads.
		 */
		o = section.option(form.ListValue, 'protocol', _('Protocol'));
		o.value('udp', 'UDP');

		var address = section.option(form.Value, 'address', _('Address (Support Domain Name)'));
		address.depends({ hysteria2_realms: false });

		var port = section.option(form.Value, 'port', _('Port'));
		port.datatype = 'port';
		port.depends({ hysteria2_realms: false });

		o = section.option(form.Value, 'hysteria2_hop', _('Port hopping range'));
		o.description = _('Format as 1000:2000 or 1000-2000 Multiple groups are separated by commas (,).');
		o.depends({ hysteria2_realms: false });

		o = section.option(form.Value, 'hysteria2_hop_interval', _('Hop Interval(second)'), _('Supports a fixed value or a random range (e.g., 30, 5-30), minimum 5.'));
		o.datatype = 'or(uinteger,portrange)';
		o.placeholder = '30';
		o.default = '30';
		o.depends({ hysteria2_realms: false });

		o = section.option(form.Flag, 'hysteria2_realms', _('Realms'));
		o.default = '0';

		o = section.option(form.Value, 'hysteria2_realm_url', _('Realm URL'), _('Example:') + 'realm://public@realm.hy2.io/your-realm-name');
		o.depends({ hysteria2_realms: '1' });
		o.validate = function(section_id, value) {
			value = String(value || '').trim();
			if (parseRealm(value))
				return true;
			return _('Invalid Realm URL.');
		};
		o.write = function(section_id, value) {
			return uci.set('passwall', section_id, 'hysteria2_realm_url', String(value || '').trim());
		};

		o = section.option(form.DynamicList, 'hysteria2_realm_stun', _('Realm STUN'));
		o.default = [ 'stun.sip.us:3478', 'stun.nextcloud.com:3478', 'global.stun.twilio.com:3478' ];
		o.depends({ hysteria2_realms: '1' });

		o = section.option(form.Flag, 'hysteria2_realm_upnp', _('Enable') + ' UPnP/NAT-PMP', _('Enable UPnP/NAT-PMP port mapping on your gateway to improve hole punching success.'));
		o.default = '0';
		o.depends({ hysteria2_realms: '1' });

		o = section.option(form.Value, 'hysteria2_auth_password', _('Auth Password'));
		o.password = true;

		o = section.option(form.ListValue, 'hysteria2_obfs_type', _('Obfs Type'));
		o.value('', _('Disable'));
		o.value('salamander');
		o.value('gecko');

		o = section.option(form.Value, 'hysteria2_obfs_password', _('Obfs Password'));
		o.depends({ hysteria2_obfs_type: 'salamander' });
		o.depends({ hysteria2_obfs_type: 'gecko' });

		o = section.option(form.Value, 'hysteria2_obfs_MinPacketSize', _('Gecko Packet Size (min)'));
		o.datatype = 'uinteger';
		o.placeholder = '512';
		o.default = '512';
		o.depends({ hysteria2_obfs_type: 'gecko' });

		o = section.option(form.Value, 'hysteria2_obfs_MaxPacketSize', _('Gecko Packet Size (max)'));
		o.datatype = 'uinteger';
		o.placeholder = '1200';
		o.default = '1200';
		o.depends({ hysteria2_obfs_type: 'gecko' });

		o = section.option(form.Flag, 'fast_open', _('Fast Open'));
		o.default = '0';

		o = section.option(form.Value, 'tls_serverName', _('Domain'));

		o = section.option(form.Flag, 'tls_allowInsecure', _('allowInsecure'), _('Whether unsafe connections are allowed. When checked, Certificate validation will be skipped.'));
		o.default = '0';

		o = section.option(form.Value, 'tls_pinSHA256', _('TLS Chain Fingerprint (SHA256)'));

		o = section.option(form.Value, 'hysteria2_up_mbps', _('Max upload Mbps'));

		o = section.option(form.Value, 'hysteria2_down_mbps', _('Max download Mbps'));

		o = section.option(form.Value, 'hysteria2_stream_recv_win', _('QUIC stream receive window') + ' (MB)');
		o.datatype = 'range(1,1000)';
		o.placeholder = '8';

		o = section.option(form.Value, 'hysteria2_conn_recv_win', _('QUIC connection receive window') + ' (MB)');
		o.datatype = 'range(1,1000)';
		o.placeholder = '20';

		o = section.option(form.Value, 'hysteria2_idle_timeout', _('Idle Timeout'), _('Units:seconds') + ' (4~120)');
		o.datatype = 'range(4,120)';

		o = section.option(form.Value, 'hysteria2_keep_alive_period', _('QUIC KeepAlive interval'), _('Units:seconds') + ' (2~60)');
		o.datatype = 'range(2,60)';

		o = section.option(form.Flag, 'hysteria2_disable_mtu_discovery', _('Disable MTU detection'));
		o.default = '0';

		o = section.option(form.Flag, 'ech', _('ECH'));
		o.default = '0';
		o.depends({ hysteria2_realms: false });

		o = section.option(form.TextValue, 'ech_config', _('ECH Config'));
		o.default = '';
		o.rows = 5;
		o.wrap = 'soft';
		o.depends({ ech: '1' });
		o.write = function(section_id, value) {
			value = String(value || '').replace(/[\r\n]/g, '').trim();
			if (value === '')
				return uci.unset('passwall', section_id, 'ech_config');
			return uci.set('passwall', section_id, 'ech_config', value);
		};

		o = section.option(form.Flag, 'hysteria2_lazy_start', _('Lazy Start'));
		o.default = '0';
	}
});
