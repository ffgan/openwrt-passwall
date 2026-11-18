#!/bin/sh
# Opt-in connectivity recovery. Never change an intentionally selected SS node.
failures=0
last_node=
while :; do
	if [ "$(uci -q get passwall.@global[0].enabled)" != 1 ] ||
	   [ "$(uci -q get passwall.@global[0].reality_auto_fallback)" != 1 ] ||
	   [ ! -f /var/lock/passwall_ready.lock ]; then
		failures=0
		last_node=
		sleep 5
		continue
	fi
	node=$(uci -q get passwall.@global[0].node)
	if [ "$(uci -q get "passwall.$node.type")" != Reality ]; then
		failures=0
		last_node=
		sleep 5
		continue
	fi
	if [ "$node" != "$last_node" ]; then
		last_node=$node
		failures=0
		sleep 10
		continue
	fi
	curl --noproxy '*' --connect-timeout 3 --max-time 5 -fsS -o /dev/null https://www.google.com/generate_204 >/dev/null 2>&1 &
	first=$!
	curl --noproxy '*' --connect-timeout 3 --max-time 5 -fsS -o /dev/null https://www.cloudflare.com/cdn-cgi/trace >/dev/null 2>&1 &
	second=$!
	healthy=0
	wait "$first" && healthy=1
	wait "$second" && healthy=1
	if [ "$healthy" = 1 ]; then
		failures=0
	else
		failures=$((failures + 1))
		logger -t reality-recovery "Both connectivity probes failed ($failures/3)."
	fi
	if [ "$failures" -ge 3 ]; then
		# Re-read selection after the probes so a manual switch wins.
		if [ "$(uci -q get passwall.@global[0].node)" = "$node" ] &&
		   [ "$(uci -q get passwall.@global[0].reality_auto_fallback)" = 1 ]; then
			fallback=$(uci -q get passwall.@global[0].reality_fallback_node)
			if [ "$(uci -q get "passwall.$fallback.type")" != SS-Rust ]; then
				# Subscription refreshes regenerate IDs. Resolve the current SS node.
				fallback=$(uci -q show passwall | sed -n "s/^passwall\.\([A-Za-z0-9_]*\)\.type='SS-Rust'$/\1/p" | head -n 1)
			fi
			if [ -n "$fallback" ]; then
				logger -t reality-recovery "Switching failed REALITY node $node to SS node $fallback."
				uci set "passwall.@global[0].node=$fallback"
				uci commit passwall
				/etc/init.d/passwall restart
			else
				logger -t reality-recovery "No SS fallback is configured; selection retained."
			fi
		fi
		failures=0
	fi
	sleep 5
done
