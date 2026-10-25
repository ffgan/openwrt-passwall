'use strict';

// In-memory stand-in for ucode-mod-uci. The rpcd plugin imports passwall.api,
// which opens a cursor while the module is loading. Tests never touch a real
// /etc/config, so an empty cursor is enough for capabilities and index_status.
function cursor() {
	return {
		get: function() { return null; },
		get_all: function() { return {}; },
		set: function() { return true; },
		add: function() { return "s"; },
		delete: function() { return true; },
		foreach: function() { return null; },
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
