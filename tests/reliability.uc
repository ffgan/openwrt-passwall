'use strict';
import { valid_address, bounded_integer, retry_delay } from 'passwall.reliability';
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
expect(bounded_integer('', 1, 10, null) == null, 'preserve default');
expect(bounded_integer('4', 1, 8, null) == 4, 'numeric conversion');
let rejected = false;
try { bounded_integer('0', 1, 8, null); } catch (e) { rejected = true; }
expect(rejected, 'reject out-of-range option');
print(assertions + ' reliability assertions passed\n');
