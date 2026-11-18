'use strict';

// A dedicated backend rather than translating an Xray JSON configuration.
export function node_config(node, options) {
	if (node?.type != 'Reality') die('Expected a Reality node');
	if (node.protocol && node.protocol != 'vless') die('reality supports only VLESS');
	if (node.transport && node.transport != 'raw' && node.transport != 'tcp') die('reality requires raw TCP');
	if (node.flow && node.flow != 'xtls-rprx-vision') die('reality requires Vision');
	if ((node.fingerprint ?? 'chrome') != 'chrome' ||
	    (node.encryption && node.encryption != 'none') ||
	    node.use_mldsa65Verify == '1' || node.ech == '1' || node.mux == '1' ||
	    node.use_finalmask == '1' || (node.tcp_guise && node.tcp_guise != 'none') ||
	    node.chain_proxy == '1' || node.chain_proxy == '2')
		die('Unsupported reality node options');
	if ((node.tls && node.tls != '1') || (node.reality && node.reality != '1'))
		die('reality requires REALITY security');
	let socks_port = int(options.socks_port);
	if (socks_port < 1 || socks_port > 65535) die('Invalid SOCKS port');
	let bind = options.bind || '127.0.0.1';
	if (index(bind, ':') >= 0 && substr(bind, 0, 1) != '[') bind = '[' + bind + ']';
	let id = node.uuid ?? node.password;
	if (!node.address || !node.port || !id || !node.tls_serverName || !node.reality_publicKey)
		die('Incomplete reality node');
	let host = options.server_host || node.address;
	if (index(host, ':') >= 0 && substr(host, 0, 1) != '[') host = '[' + host + ']';
	let config = {
		server: host + ':' + (options.server_port || node.port),
		uuid: id, sni: node.tls_serverName, pbk: node.reality_publicKey,
		sid: node.reality_shortId ?? '', fp: 'chrome',
		listen: bind + ':' + socks_port
	};
	if (options.redir_port) {
		config.redirect = '' + options.redir_port;
		config.tproxy = options.tcp_proxy_way == 'tproxy';
	}
	return config;
};
