'use strict';
import { apply_ttl_limits } from 'passwall.dns_policy';
function eq(value, expected) { if (sprintf('%J',value) != sprintf('%J',expected)) die('DNS TTL policy mismatch'); }
eq(apply_ttl_limits(['port=11400'], null), ['port=11400','max-cache-ttl=3600','max-ttl=3600']);
eq(apply_ttl_limits(['max-cache-ttl=120','max-ttl=300'], null), ['max-cache-ttl=120','max-ttl=120']);
eq(apply_ttl_limits(['max-cache-ttl=90000','max-ttl=80000'], '600'), ['max-cache-ttl=600','max-ttl=600']);
eq(apply_ttl_limits(['max-ttl=0'], null), ['max-cache-ttl=3600','max-ttl=0']);
eq(apply_ttl_limits(['max-ttl=60','max-ttl=600','server=127.0.0.1#53'], null), ['server=127.0.0.1#53','max-cache-ttl=3600','max-ttl=60']);
eq(apply_ttl_limits(['conf-file=/etc/dnsmasq.conf'], null, {'max-ttl':10,'max-cache-ttl':10}), ['conf-file=/etc/dnsmasq.conf']);
let rejected = false;
try { apply_ttl_limits([], '172800'); } catch (e) { rejected = true; }
if (!rejected) die('TTL beyond safety boundary accepted');
print('7 DNS TTL policy assertions passed\n');
