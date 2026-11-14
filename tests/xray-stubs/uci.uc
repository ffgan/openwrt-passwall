'use strict';

// Isolated in-memory UCI fixture. Configuration lives in global.xray_test_config;
// no real router configuration is read or written.
function cursor() {
	return {
		get: function(config, section, option) {
			let node = global.xray_test_config?.[config]?.[section];
			return option == null ? node?.['.type'] : node?.[option];
		},
		get_all: function(config, section) {
			return global.xray_test_config?.[config]?.[section] ?? {};
		},
		set: function() { return true; },
		add: function() { return "s"; },
		delete: function() { return true; },
		foreach: function(config, kind, callback) {
			for (let id, node in global.xray_test_config?.[config] ?? {}) {
				if (node['.type'] == kind) callback(node);
			}
		},
		revert: function() { return null; },
		commit: function() { return true; },
		save: function() { return true; },
		add_list: function() { return true; },
		del_list: function() { return true; },
		rename: function() { return true; },
		reorder: function() { return true; },
		changes: function() { return {}; },
		unload: function() { return null; }
	};
}

export { cursor };
