'use strict';

import { writefile, unlink, lsdir, access, popen } from 'fs';

let command_rc, safe_dir, safe_status, main;

command_rc = function(argv) {
	if (type(global.system) == "function") {
		let rc = global.system(argv);
		return rc == null ? 255 : rc;
	}
	let ph = popen(argv, "r");
	if (ph == null)
		return 255;
	let rc = ph.close();
	return rc == null ? 255 : rc;
};

safe_dir = function(dir) {
	return type(dir) == "string" && match(dir, /^\/tmp\/passwall_luci_update\.[A-Za-z0-9_-]+$/) != null;
};

safe_status = function(status) {
	return type(status) == "string" && match(status, /^\/www\/luci-static\/resources\/passwall-update\/[A-Za-z0-9_-]+\.json$/) != null;
};

// Copied into /tmp before package install replaces the files under /usr.
main = function(argv) {
	let dir = argv[0] ?? "";
	let status = argv[1] ?? "";
	let manager = argv[2] ?? "";
	let force = argv[3] ?? "";
	if (!safe_dir(dir) || !safe_status(status))
		exit(1);

	let rc = 1;
	if (manager == "apk") {
		let argv_apk = ["apk", "add", "--allow-untrusted"];
		if (force == "1") {
			push(argv_apk, "--force-reinstall");
			push(argv_apk, "--force-overwrite");
		}
		push(argv_apk, dir + "/luci-app-passwall.apk");
		push(argv_apk, dir + "/luci-i18n-passwall-zh-cn.apk");
		rc = command_rc(argv_apk);
	} else {
		let argv_opkg = ["opkg", "install"];
		if (force == "1")
			push(argv_opkg, "--force-reinstall");
		push(argv_opkg, dir + "/luci-app-passwall.ipk");
		push(argv_opkg, dir + "/luci-i18n-passwall-zh-cn.ipk");
		rc = command_rc(argv_opkg);
	}

	command_rc(["rm", "-rf", dir]);
	if (rc == 0) {
		unlink("/tmp/etc/passwall_tmp/passwall_version");
		unlink("/tmp/luci-indexcache");
		let cached = lsdir("/tmp");
		if (cached != null) {
			for (let name in cached) {
				if (substr(name, 0, 16) == "luci-indexcache.")
					unlink("/tmp/" + name);
			}
		}
		if (access("/etc/init.d/rpcd", "x"))
			command_rc(["/etc/init.d/rpcd", "restart"]);
		if (access("/etc/init.d/uhttpd", "x"))
			command_rc(["/etc/init.d/uhttpd", "reload"]);
	}
	writefile(status, rc == 0 ? "{\"code\":0}\n" : "{\"code\":1}\n");
	command_rc(["/bin/sleep", "60"]);
	unlink(status);
	exit(rc == 0 ? 0 : 1);
};

export { main };
