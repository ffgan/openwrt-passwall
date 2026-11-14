'use strict';
import * as fs from 'fs';
import * as api from 'passwall.api';

export function core_env() {
	let asset = api.uci_get_c('@global_rules[0]', 'v2ray_location_asset') ?? '/usr/share/v2ray/';
	return {
		XRAY_LOCATION_ASSET: asset, V2RAY_LOCATION_ASSET: asset,
		ENABLE_DEPRECATED_GEOSITE: 'true', ENABLE_DEPRECATED_GEOIP: 'true',
		SS_SYSTEM_DNS_RESOLVER_FORCE_BUILTIN: '1'
	};
};

export function install_config(config, destination) {
	let dir = fs.mkdtemp(destination + '.XXXXXX');
	if (dir == null) return false;
	let path = dir + '/config.json';
	let file = fs.open(path, 'w', 0o600);
	let ok = false;
	if (file != null) {
		let text = sprintf('%J', config);
		ok = file.write(text) == length(text);
		ok = file.close() && ok;
		if (ok) ok = fs.rename(path, destination);
	}
	fs.unlink(path);
	fs.rmdir(dir);
	return ok;
};

// Core diagnostics can contain credentials. Keep them out of normal logs/RPC.
export function check_config(config) {
	let dir = fs.mkdtemp('/tmp/passwall-xray-XXXXXX');
	if (dir == null) return { code: 1, error: 'Cannot create private validation directory' };
	let path = dir + '/config.json';
	let result = { code: 1, error: 'Xray rejected configuration; check fields against the installed core version' };
	try {
		if (!install_config(config, path)) die('write failed');
		let executable = api.get_app_path('xray');
		if (!executable) die('Xray is not installed');
		let argv = ['timeout', '20', 'env'];
		for (let key, value in core_env()) push(argv, key + '=' + value);
		push(argv, executable, 'run', '-test', '-c', path);
		let pipe = api.command_pipe(join(' ', map(argv, api.shellquote)) + ' 2>/dev/null', 'r');
		if (pipe == null) die('Cannot execute Xray');
		while (pipe.read(4096)) {}
		let rc = pipe.close();
		if (rc == 0) result = { code: 0, valid: true };
	}
	catch (e) { /* Never return arbitrary core output or configuration values. */ }
	fs.unlink(path);
	fs.rmdir(dir);
	return result;
};
