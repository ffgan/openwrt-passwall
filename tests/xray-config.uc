'use strict';
import { merge_config, apply_config } from 'passwall.xray_config';
import { latest_release } from 'passwall.xray_release';
let count = 0;
function eq(got, want) {
	count++;
	if (sprintf('%J', got) != sprintf('%J', want)) die('Assertion ' + count + ': ' + sprintf('%J != %J', got, want));
}
function reject(base, patch, server, path) {
	let error = '';
	try { merge_config(base, patch, server); } catch (e) { error = e.message; }
	count++;
	if (index(error, path) < 0) die('Expected conflict at ' + path + ', got ' + error);
}
let base = {
	inbounds: [{tag:'proxy-in', protocol:'dokodemo-door', port:1041, settings:{network:'tcp,udp'}}],
	outbounds: [{tag:'proxy', protocol:'socks', settings:{servers:[{address:'127.0.0.1',port:1080}]}, streamSettings:{sockopt:{mark:255}}}],
	routing: {rules:[{inboundTag:['proxy-in'],outboundTag:'proxy'}]},
	dns: {servers:['223.5.5.5']}, version:{min:'26.11.9'}
};
let saved = sprintf('%J', base);
eq(apply_config(base, {json_merge:'0',json_config:'bad'}, false), base);
eq(merge_config(base, {}, false), base);
eq(merge_config(base, {futureFeature:{values:[1,2],enabled:true}},false).futureFeature,{values:[1,2],enabled:true});
eq(merge_config({futureFeature:{values:[1,2],enabled:true}}, {futureFeature:{values:[3],enabled:null}},false).futureFeature,{values:[3],enabled:null});
eq(merge_config(base, {outbounds:[{tag:'proxy', settings:{servers:[{address:'example.com',port:1081}]}}]},false).outbounds[0].settings.servers,[{address:'example.com',port:1081}]);
eq(merge_config(base, {outbounds:[{tag:'new',protocol:'freedom'}]},false).outbounds[1].streamSettings.sockopt.mark,255);
eq(merge_config(base, {routing:{rules:[{domain:['example.com'],outboundTag:'proxy'}]}},false).routing.rules[0],base.routing.rules[0]);
eq(length(merge_config(base, {routing:{rules:[{domain:['example.com'],outboundTag:'proxy'}]}},false).routing.rules),2);
eq(merge_config(base, {dns:{queryStrategy:'UseIPv4'}},false).dns.servers,base.dns.servers);
reject(base, [], false, '$');
reject(base, {inbounds:[{tag:'proxy-in',port:9999}]},false,'$.inbounds[0].port');
reject(base, {outbounds:[{tag:'proxy',protocol:'freedom'}]},false,'$.outbounds[0].protocol');
reject(base, {outbounds:[{tag:'proxy',streamSettings:{sockopt:{mark:0}}}]},false,'.mark');
reject(base, {outbounds:[{tag:'proxy',streamSettings:null}]},false,'.streamSettings');
reject(base, {outbounds:[{tag:'proxy',streamSettings:{sockopt:null}}]},false,'.sockopt');
reject(base, {outbounds:[{protocol:'freedom'}]},false,'.tag');
reject(base, {outbounds:[{tag:'x'},{tag:'x'}]},false,'.tag');
reject(base, {outbounds:null},false,'$.outbounds');
reject(base, {dns:{servers:null}},false,'$.dns.servers');
eq(merge_config(base, {dns:{servers:['8.8.8.8']}},false).dns.servers,['223.5.5.5','8.8.8.8']);
reject(base, {version:{min:'1.0'}},false,'$.version.min');
reject(base, {routing:{rules:[{outboundTag:'missing'}]}},false,'.outboundTag');
reject(base, {routing:{rules:[{inboundTag:['missing'],outboundTag:'proxy'}]}},false,'.inboundTag');
reject(base, {routing:{rules:[{balancerTag:'missing'}]}},false,'.balancerTag');
reject(base, {outbounds:[{tag:'new',protocol:'socks',proxySettings:{tag:'missing'}}]},false,'$.outbounds');
eq(merge_config(base, {inbounds:[{tag:'proxy-in',settings:{network:'tcp'}}]},true).inbounds[0].settings.network,'tcp');
reject(base, {inbounds:[{tag:'proxy-in',port:9999}]},true,'.port');
eq(merge_config({}, {api:{tag:'api'},routing:{rules:[{outboundTag:'api'}]}},true).api.tag,'api');
eq(sprintf('%J', base),saved);
eq(latest_release([{tag_name:'v1',published_at:'2026-01-01',draft:false},{tag_name:'v3',published_at:'2026-03-01',draft:true},{tag_name:'v2',published_at:'2026-02-01',prerelease:true}]).tag_name,'v2');
eq(latest_release([]),{});
reject({}, {outbounds:[{tag:'a',protocol:'freedom',streamSettings:{sockopt:{dialerProxy:'b'}}},{tag:'b',protocol:'freedom',streamSettings:{sockopt:{dialerProxy:'a'}}}]},true,'$.outbounds');
eq(merge_config({}, {outbounds:[{tag:'loop',protocol:'loopback',settings:{inboundTag:'virtual-in'}}],routing:{rules:[{inboundTag:['virtual-in'],outboundTag:'loop'}]}},true).outbounds[0].tag,'loop');
eq(merge_config({dns:{servers:[{address:'1.1.1.1',port:53}]}},{dns:{servers:[{port:53,address:'1.1.1.1'}]}},false).dns.servers[0].port,53);
eq(length(merge_config({outbounds:[{tag:'direct',protocol:'freedom'}],routing:{balancers:[{tag:'old',selector:['direct']}] }},{routing:{balancers:[{tag:'new',selector:['direct']}] }},true).routing.balancers),2);
print('ok ' + count + ' Xray merge/release assertions\n');
