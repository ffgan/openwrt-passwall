'use strict';

// A failed probe may drop this server only when another server has succeeded
// inside the recent window. Timeouts that hit every exit together must not
// empty the pool.
function peer_recent(now, self_port, stamps, window) {
	if (type(stamps) != 'object' || stamps == null)
		return false;
	self_port = '' + self_port;
	now = int(now);
	window = int(window);
	if (now != now || window != window || window < 0)
		return false;
	for (let port, stamp in stamps) {
		if ('' + port == self_port)
			continue;
		stamp = int(stamp);
		if (stamp != stamp)
			continue;
		let age = now - stamp;
		if (age >= 0 && age <= window)
			return true;
	}
	return false;
}

export { peer_recent };
