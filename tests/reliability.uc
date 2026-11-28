'use strict';
import { valid_address, bounded_integer, retry_delay, haproxy_limits, chinadns_bind_port, chinadns_needs_start, skip_external_check, skip_media_probe } from 'passwall.reliability';
let assertions = 0;
function expect(value, message) {
	assertions++;
	if (!value) die(message);
}
for (let address in ['0.0.0.0/0','192.168.1.1','255.255.255.255/32']) expect(valid_address(address, false), address);
for (let address in ['256.256.256.256','1.2.3','1.2.3.4/33','1.2.3.4/','1.2.3.4;flush ruleset','01.2.3.4']) expect(!valid_address(address, false), address);
for (let address in ['::','::1','2001:db8::/32','2001:db8:1:2:3:4:5:6/128']) expect(valid_address(address, true), address);
for (let address in [':::','1::2::3','1:2:3','::1/129','::1/','::gg','1:2:3:4:5:6:7:8::']) expect(!valid_address(address, true), address);
expect(retry_delay(1) == 5 && retry_delay(2) == 10 && retry_delay(30) == 300, 'bounded exponential retry');
let small = haproxy_limits(239024, 2);
expect(small.maxconn == 1024 && small.server_maxconn == 256 && small.stick_size == 1024 && small.nbthread == 1, '256MB router keeps one thread and a small table');
let medium = haproxy_limits(524288, 4);
expect(medium.maxconn == 4096 && medium.nbthread == 2 && medium.stick_size == 4096, '512MB caps threads at two');
let large = haproxy_limits(2097152, 4);
expect(large.maxconn == 16384 && large.nbthread == 4 && large.server_maxconn == 3000, 'large router keeps a wider table');
expect(haproxy_limits(null, 0).nbthread == 1 && haproxy_limits('', 1).maxconn == 1024, 'missing memory uses the small budget');
expect(chinadns_bind_port("bind-addr ::\nbind-port 15354\n") == '15354', 'read chinadns port');
expect(chinadns_bind_port("bind-port\t15354\n") == '15354', 'tab separated port');
expect(chinadns_bind_port("") == '' && chinadns_bind_port(null) == '', 'missing port');
expect(chinadns_needs_start(true, '15354', true) == false, 'listening dns stays');
expect(chinadns_needs_start(true, '15354', false) == true, 'process without a listener is restarted');
expect(chinadns_needs_start(false, '', false) == true, 'missing process is restarted');
expect(chinadns_needs_start(false, '15354', true) == true, 'foreign listener does not count as chinadns');
expect(skip_external_check(20000) && !skip_external_check(30000) && !skip_external_check(null), 'fork a check only with memory to spare');
expect(skip_media_probe(40000) && !skip_media_probe(60000) && !skip_media_probe(''), 'skip the body download when memory is tight');
expect(bounded_integer('', 1, 10, null) == null, 'preserve default');
expect(bounded_integer('4', 1, 8, null) == 4, 'numeric conversion');
let rejected = false;
try { bounded_integer('0', 1, 8, null); } catch (e) { rejected = true; }
expect(rejected, 'reject out-of-range option');
print(assertions + ' reliability assertions passed\n');
