'use strict';
import { inspect_firewall } from 'passwall.firewall_health';
function expect(ok, message) { if (!ok) die(message); }
let snapshot = {nftables:[
 {table:{family:'inet',name:'fw4'}},
 {chain:{family:'inet',table:'fw4',name:'forward',hook:'forward'}},
 {rule:{family:'inet',table:'fw4',chain:'srcnat_wan',expr:[{masquerade:null}]}}
]};
expect(inspect_firewall(snapshot, ['wan'], true).ok, 'Valid OpenWrt NAT forwarding');
expect(inspect_firewall(null, ['wan'], true).reason == 'fw4_missing', 'Global ruleset loss');
expect(inspect_firewall({nftables:[snapshot.nftables[0]]}, [], true).reason == 'forward_chain_missing', 'Empty fw4 table');
expect(inspect_firewall(snapshot, ['wan'], false).reason == 'ipv4_forwarding_disabled', 'Forwarding sysctl');
expect(inspect_firewall(snapshot, ['guest'], true).reason == 'masquerade_missing', 'NAT zone missing');
expect(inspect_firewall(snapshot, [], true).ok, 'Routed networks do not require NAT');
print('6 firewall health assertions passed\n');
