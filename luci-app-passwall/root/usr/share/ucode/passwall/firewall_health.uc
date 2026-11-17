'use strict';

// Inspect a read-only nft JSON snapshot. Proxy-process liveness alone cannot
// establish whether LAN forwarding and configured IPv4 NAT are available.
export function inspect_firewall(snapshot, nat_zones, ipv4_forwarding) {
	let present = false, forward = false, masquerade = {};
	for (let entry in snapshot?.nftables ?? []) {
		if (entry.table?.family == 'inet' && entry.table?.name == 'fw4') present = true;
		if (entry.chain?.family == 'inet' && entry.chain?.table == 'fw4' && entry.chain?.hook == 'forward') forward = true;
		let rule = entry.rule;
		if (rule?.family != 'inet' || rule?.table != 'fw4') continue;
		for (let expr in rule.expr ?? [])
			if (type(expr) == 'object' && index(keys(expr), 'masquerade') >= 0) masquerade[rule.chain] = true;
	}
	if (!present) return { ok:false, reason:'fw4_missing' };
	if (!forward) return { ok:false, reason:'forward_chain_missing' };
	if (!ipv4_forwarding) return { ok:false, reason:'ipv4_forwarding_disabled' };
	for (let zone in nat_zones ?? [])
		if (!masquerade['srcnat_' + zone]) return { ok:false, reason:'masquerade_missing' };
	return { ok:true, reason:'' };
};
