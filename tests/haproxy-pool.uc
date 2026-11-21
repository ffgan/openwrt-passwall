'use strict';

import { peer_recent } from 'passwall.haproxy_pool';

let now = 1000;
let window = 12;
if (peer_recent(now, '2001', { '2002': now - 5 }, window) != true)
	die('a peer that just succeeded should let this server leave');
if (peer_recent(now, '2001', { '2001': now - 1, '2002': now - 20 }, window) != false)
	die('a stale peer must not empty the pool');
if (peer_recent(now, '2001', { '2001': now }, window) != false)
	die('this server is not its own peer');
if (peer_recent(now, '2001', {}, window) != false)
	die('an empty pool stays up');
if (peer_recent(now, '2001', { '2002': now - window }, window) != true)
	die('the window boundary is inclusive');
if (peer_recent(now, '2001', { '2002': 'nope' }, window) != false)
	die('a corrupt stamp is ignored');
print('probe failures stay in the pool unless another exit just worked\n');
