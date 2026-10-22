'use strict';

import * as api from 'passwall.api';
import { command_rc, background } from 'passwall.proc';

let number_or_null, launch, run;

number_or_null = function(value) {
	value = trim(value == null ? "" : ("" + value));
	if (match(value, /^[0-9]+$/) == null)
		return null;
	return int(value);
};

launch = function(argv) {
	let parts = [];
	for (let arg in argv)
		push(parts, api.shellquote(arg));
	background(join(" ", parts) + " >/dev/null 2>&1");
};

run = function() {
	let elapsed = 0;
	while (true) {
		if (elapsed != 0) {
			let restart_week = api.uci_get_c("@global_delay[0]", "restart_week_mode") ?? "";
			let restart_every = number_or_null(api.uci_get_c("@global_delay[0]", "restart_interval_mode"));
			if (restart_week != "" && restart_week == "8" && restart_every != null) {
				let span = restart_every * 60;
				if (span > 0 && elapsed % span == 0)
					launch(["/etc/init.d/passwall", "restart", "cron"]);
			}

			let rules_week = api.uci_get_c("@global_rules[0]", "update_week_mode") ?? "";
			let rules_every = number_or_null(api.uci_get_c("@global_rules[0]", "update_interval_mode"));
			if (rules_week != "" && rules_week == "8" && rules_every != null) {
				let span = rules_every * 60;
				if (span > 0 && elapsed % span == 0)
					launch(["/usr/bin/ucode", "/usr/libexec/passwall/rule_update.uc", "log", "all", "cron"]);
			}

			let groups = {};
			api.uci.foreach("passwall", "subscribe_list", function(section) {
				let week = section.update_week_mode ?? "";
				let every = number_or_null(section.update_interval_mode);
				if (week == "8" && every != null) {
					let key = week + "_" + every;
					if (groups[key] == null)
						groups[key] = [];
					push(groups[key], section[".name"]);
				}
			});
			for (let key in groups) {
				let mark = index(key, "_");
				if (mark < 0)
					continue;
				let every = number_or_null(substr(key, mark + 1));
				if (every == null)
					continue;
				let span = every * 60;
				if (span <= 0 || elapsed % span != 0)
					continue;
				let ids = join(",", groups[key]);
				launch(["/usr/bin/ucode", "/usr/libexec/passwall/subscribe.uc", "start", ids, "cron"]);
			}
		}
		elapsed += 10;
		command_rc(["sleep", "600"]);
	}
};

export { run };
