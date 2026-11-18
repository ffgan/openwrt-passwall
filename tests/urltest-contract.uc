'use strict';
// These are public API functions used by the node URL probe. In particular,
// rand_int must be exported, not merely declared inside passwall.api.
import * as api from 'passwall.api';
import { url_test_node } from 'passwall.urltest';
for (let name in ['rand_int', 'get_new_port', 'proc_lines', 'uci_get_c'])
	if (type(api[name]) != 'function') die('URL probe API missing: ' + name);
if (url_test_node('') != '0') die('Empty node must not launch a probe');
print('Node URL probe API contract passed\n');
