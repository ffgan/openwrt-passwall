'use strict';
import * as fs from 'fs';
import { gen_config, gen_config_server } from 'passwall.util_xray';
import { merge_config } from 'passwall.xray_config';
import { check_config, install_config } from 'passwall.xray_runtime';
let out = ARGV[0];
let executable = ARGV[1];
if (!out || !executable) die('Usage: xray-fixtures.uc OUTPUT XRAY');
global.xray_test_config = {
	passwall: {
		app:{'.name':'app','.type':'global_app',xray_file:executable},
		xray:{'.name':'xray','.type':'global_xray'},
		rules:{'.name':'rules','.type':'global_rules',v2ray_location_asset:'/usr/share/v2ray/'}
	},
	passwall_server:{
		user:{'.name':'user','.type':'user',username:'test',password:'test-password',uuid:'00000000-0000-4000-8000-000000000001'}
	}
};
let number = 0;
function emit(name, config) {
	if (type(config) == 'string') config = json(config);
	if (!install_config(config, out + '/' + name + '.json')) die('Cannot write fixture ' + name);
	number++;
}
for (let protocol in ['socks','http','vmess','vless','trojan','shadowsocks']) {
	for (let transport in ['raw','mkcp','ws','grpc','httpupgrade','xhttp','xdrive']) {
		if (transport == 'xdrive' && protocol != 'vless') continue;
		if ((protocol == 'socks' || protocol == 'http') && transport != 'raw') continue;
		let node = {
			'.name':'node','.type':'nodes',type:'Xray',protocol:protocol,
			address:'127.0.0.1',port:'443',transport:transport,tcp_guise:'none',mkcp_guise:'none',
			uuid:'00000000-0000-4000-8000-000000000001',password:'test-password',method:'aes-128-gcm',
			security:'auto',encryption:'none',xhttp_mode:'auto',
			xdrive_settings:'{"service":"local","remoteFolder":"/tmp/passwall-xdrive-fixture","secrets":["test-secret"]}'
		};
		if (transport == 'xdrive') node.encryption = 'mlkem768x25519plus.native.0rtt.Ype9Y4XCCbRW_ujqbRY2UQXeUrnzyT0IBGtJWqL-0jQ';
		global.xray_test_config.passwall.node = node;
		emit('client-' + protocol + '-' + transport,gen_config({flag:'global',node:'node',no_run:'1',local_socks_port:'1080',local_socks_address:'127.0.0.1',redir_port:'1041',tcp_proxy_way:'tproxy'}));
	}
	let server = {
		protocol:protocol,port:'1443',transport:'raw',tcp_guise:'none',users:['user'],
		method:'aes-128-gcm',ss_password:'test-password',password:'test-password',decryption:'none',log:'0'
	};
	emit('server-' + protocol,gen_config_server(server));
	if (protocol != 'socks' && protocol != 'http') {
		for (let transport in ['mkcp','ws','grpc','httpupgrade','xhttp','xdrive']) {
			if (transport == 'xdrive' && protocol != 'vless') continue;
			let variant = json(sprintf('%J', server));
			variant.transport = transport;
			variant.mkcp_guise = 'none';
			if (transport == 'xdrive') {
				variant.decryption = 'mlkem768x25519plus.native.600s.wMlRKRTz7bfF5PxJeEz6xNCOBQqGp7TcNiQsNEIu5Gs';
				variant.xdrive_settings = '{"service":"local","remoteFolder":"/tmp/passwall-xdrive-fixture","secrets":["test-secret"]}';
			}
			emit('server-' + protocol + '-' + transport,gen_config_server(variant));
		}
	}
}
let main = {
	inbounds:[{tag:'socks-in',protocol:'socks',listen:'127.0.0.1',port:1080,settings:{udp:true}}],
	outbounds:[{tag:'direct',protocol:'freedom',streamSettings:{sockopt:{mark:255}}}],
	version:{min:'26.11.9'}
};
emit('advanced',merge_config(main,{
	stats:{}, policy:{system:{statsOutboundUplink:true,statsOutboundDownlink:true}},
	api:{tag:'api',services:['StatsService','HandlerService']},
	inbounds:[{tag:'api-in',protocol:'dokodemo-door',listen:'127.0.0.1',port:10085,settings:{address:'127.0.0.1'}}],
	routing:{rules:[{inboundTag:['api-in'],outboundTag:'api'}]}
},false));
let checked = check_config(main);
if (checked.code != 0) die('Runtime core checker rejected valid fixture');
checked = check_config({outbounds:[{protocol:'definitely-invalid',settings:{password:'must-not-leak'}}]});
if (checked.code == 0 || index(checked.error,'must-not-leak') >= 0) die('Runtime checker must reject invalid config without exposing credentials');
global.xray_test_config.passwall.node = {
    '.name':'node','.type':'nodes',type:'Xray',protocol:'vmess',transport:'xdrive',address:'127.0.0.1',port:'443'
};
let rejected = false;
try { gen_config({flag:'global',node:'node',no_run:'1',local_socks_port:'1080'}); }
catch (e) { rejected = index(e.message, 'XDRIVE requires VLESS') >= 0; }
if (!rejected) die('Non-VLESS XDRIVE must fail generation');
print('generated ' + number + ' fixtures; runtime validator passed\n');
