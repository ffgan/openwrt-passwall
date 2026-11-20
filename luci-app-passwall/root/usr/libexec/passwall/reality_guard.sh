#!/bin/sh
# Switch away from a selected node when it cannot reach the outside.
# REALITY falls back to SS. A dead SS node falls back to a REALITY node
# whose TCP port is open, so a stale SS address cannot pin the network.
failures=0
last_node=
last_refresh=0
last_switch=0

port_open() {
	[ -n "$1" ] && [ -n "$2" ] || return 1
	timeout 3 nc "$1" "$2" </dev/null >/dev/null 2>&1
}

# First REALITY node other than $1 with an open port.
open_reality() {
	skip=$1
	for id in $(uci show passwall | sed -n "s/^passwall\\.\\([A-Za-z0-9_]*\\)\\.type='Reality'$/\\1/p"); do
		[ "$id" = "$skip" ] && continue
		addr=$(uci -q get "passwall.$id.address")
		port=$(uci -q get "passwall.$id.port")
		if port_open "$addr" "$port"; then
			echo "$id"
			return 0
		fi
	done
	return 1
}

while :; do
	# Direct-DNS address refresh. Subscription updates travel through the
	# proxy, so this has to run even when the selected node is not REALITY.
	now=$(date +%s 2>/dev/null) || now=0
	if [ -x /usr/libexec/passwall/refresh_node_addresses.sh ] &&
	   [ "$((now - last_refresh))" -ge 300 ]; then
		last_refresh=$now
		/usr/libexec/passwall/refresh_node_addresses.sh >/dev/null 2>&1
	fi
	if [ "$(uci -q get passwall.@global[0].enabled)" != 1 ] ||
	   [ "$(uci -q get passwall.@global[0].reality_auto_fallback)" != 1 ] ||
	   [ ! -f /var/lock/passwall_ready.lock ]; then
		failures=0
		last_node=
		sleep 5
		continue
	fi
	node=$(uci -q get passwall.@global[0].node)
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
		# A stale address fails closed. Refresh it before giving up on REALITY.
		if [ -x /usr/libexec/passwall/refresh_node_addresses.sh ]; then
			/usr/libexec/passwall/refresh_node_addresses.sh >/dev/null 2>&1
			refreshed=$?
			last_refresh=$(date +%s 2>/dev/null) || last_refresh=$now
			if [ "$refreshed" -eq 2 ]; then
				logger -t reality-recovery "Refreshed a stale node address and restarted."
				failures=0
				sleep 5
				continue
			fi
		fi
		# Re-read selection after the probes so a manual switch wins.
		if [ "$(uci -q get passwall.@global[0].node)" = "$node" ] &&
		   [ "$(uci -q get passwall.@global[0].reality_auto_fallback)" = 1 ] &&
		   [ "$((now - last_switch))" -ge 60 ]; then
			fallback=
			if [ "$(uci -q get "passwall.$node.type")" = Reality ]; then
				fallback=$(uci -q get passwall.@global[0].reality_fallback_node)
				if [ "$(uci -q get "passwall.$fallback.type")" != SS-Rust ]; then
					# Subscription refreshes regenerate IDs. Resolve the current SS node.
					fallback=$(uci -q show passwall | sed -n "s/^passwall\\.\\([A-Za-z0-9_]*\\)\\.type='SS-Rust'$/\\1/p" | head -n 1)
				fi
				label=SS
			else
				fallback=$(open_reality "$node") || fallback=
				label=REALITY
			fi
			if [ -n "$fallback" ]; then
				logger -t reality-recovery "Switching failed node $node to $label node $fallback."
				uci set "passwall.@global[0].node=$fallback"
				uci commit passwall
				last_switch=$(date +%s 2>/dev/null) || last_switch=$now
				/etc/init.d/passwall restart
			else
				logger -t reality-recovery "No reachable backup for $node; selection retained."
			fi
		fi
		failures=0
	fi
	sleep 5
done
