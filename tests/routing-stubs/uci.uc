'use strict';

// In-memory passwall config shared by every cursor(). nftables.uc resolves
// node addresses through this, and passwall.api opens a cursor at import, so
// a later cursor() has to see the same sections. Listed on -L ahead of
// tests/stubs, whose empty cursor stays in place for the rpcd plugin test.
let sections = {
	nodes: [
		{ ".name": "nodeip", ".type": "nodes", address: "203.0.113.10", port: "443", protocol: "vmess" },
		{ ".name": "nodedom", ".type": "nodes", address: "node.example", port: "443", protocol: "ss" }
	],
	global: [
		{ ".name": "global", ".type": "global" }
	]
};

function cursor() {
	return {
		get: function(config, section, option) {
			if (section == null)
				return null;
			for (let type, list in sections) {
				for (let s in list) {
					if (s[".name"] == section)
						return option == null ? s : (s[option] ?? null);
				}
			}
			return null;
		},
		get_all: function(config, section) {
			if (section != null) {
				for (let type, list in sections)
					for (let s in list)
						if (s[".name"] == section)
							return s;
				return null;
			}
			let all = {};
			for (let type, list in sections)
				for (let s in list)
					all[s[".name"]] = s;
			return all;
		},
		set: function() { return true; },
		add: function() { return "s"; },
		delete: function() { return true; },
		foreach: function(config, type, cb) {
			for (let s in sections[type] ?? [])
				cb(s);
			return null;
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
