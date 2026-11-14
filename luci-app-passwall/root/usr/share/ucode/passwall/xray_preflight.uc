'use strict';
import * as fs from 'fs';
import * as api from 'passwall.api';
import { apply_config } from 'passwall.xray_config';
import { check_config } from 'passwall.xray_runtime';

// Verify an edited overlay before the service manager tears down a live core.
// Baselines describe the last generated instance, not pending UCI form changes.
function check(settings, path, server) {
	if (settings.json_merge != '1') return true;
	let raw = fs.readfile(path);
	if (raw == null) {
		// First start has no running instance to preserve. Generation will validate.
		let patch = json(settings.json_config ?? '{}');
		if (type(patch) != 'object') return false;
		return true;
	}
	return check_config(apply_config(json(raw), settings, server)).code == 0;
}

export function preflight(server) {
	try {
		if (!server) {
			if (api.uci_get_c('@global[0]', 'enabled') != '1') return true;
			let node = api.uci_get_c('@global[0]', 'node');
			if (api.uci_get_c(node, 'type') != 'Xray') return true;
			return check(api.uci_get_c('@global_xray[0]') ?? {}, api.TMP_PATH + '/acl/default/global.json.base', false);
		}
		if (api.uci_get_s('@global[0]', 'enable') != '1') return true;
		let ok = true;
		api.uci_foreach_s('server', function(node) {
			if (node.enable == '1' && node.type == 'Xray') {
				if (node.custom == '1') ok = check_config(json(api.base64Decode(node.config_str ?? ''))).code == 0 && ok;
				else ok = check(node, api.S_TMP_PATH + '/' + node['.name'] + '.json.base', true) && ok;
			}
		});
		return ok;
	} catch (e) { return false; }
};
