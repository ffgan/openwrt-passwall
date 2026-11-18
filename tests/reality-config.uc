'use strict';
import { node_config } from 'passwall.reality_config';
function expect(ok, message) { if (!ok) die(message); }
let node = {
	type: 'Reality', protocol: 'vless', transport: 'raw', flow: 'xtls-rprx-vision',
	tls: '1', reality: '1', address: '198.51.100.2', port: '443',
	uuid: '42000000-0000-0000-0000-000000000000', tls_serverName: 'example.com',
	reality_publicKey: 'test', reality_shortId: 'ab', fingerprint: 'chrome'
};
let config = node_config(node, { socks_port: '1070', redir_port: '1041', tcp_proxy_way: 'redirect' });
expect(config.server == '198.51.100.2:443' && config.listen == '127.0.0.1:1070', 'Endpoints');
expect(config.redirect == '1041' && config.tproxy == false, 'REDIRECT TCP');
let v6 = json(sprintf('%J', node)); v6.address = '2001:db8::1';
let cfg6 = node_config(v6, { bind: '::1', socks_port: '1070', redir_port: '1041', tcp_proxy_way: 'tproxy' });
expect(cfg6.server == '[2001:db8::1]:443' && cfg6.listen == '[::1]:1070' && cfg6.tproxy, 'IPv6 / TProxy');
for (let change in [{type:'Xray'}, {protocol:'vmess'}, {transport:'ws'}, {flow:'unknown'},
                    {fingerprint:'firefox'}, {encryption:'something'}, {ech:'1'},
                    {use_mldsa65Verify:'1'}, {chain_proxy:'1'}, {tls:'0'}, {uuid:''}]) {
	let candidate = json(sprintf('%J',node));
	for (let key, value in change) candidate[key] = value;
	let rejected = false;
	try { node_config(candidate, {socks_port:'1070'}); } catch (e) { rejected = true; }
	expect(rejected, 'Reject unsupported settings');
}
print('14 REALITY configuration assertions passed\n');
