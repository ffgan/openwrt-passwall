#!/bin/sh
# Refresh node addresses from the hostname embedded in remarks.
# Subscription fetches go through the proxy, so a stale address also blocks
# the update that would replace it. This uses direct DNS and only writes an
# address when the stored port is closed and the newly resolved port is open.

if [ -z "$NODE_REFRESH_LOCKED" ]; then
	export NODE_REFRESH_LOCKED=1
	exec flock -n /var/lock/passwall_node_refresh.lock "$0" "$@"
fi

resolve() {
	host=$1
	for dns in 223.5.5.5 119.29.29.29; do
		ip=$(nslookup "$host" "$dns" 2>/dev/null | awk -v dns="$dns" '
			$1 == "Address:" || $1 == "Address" {
				ip = $NF
				sub(/:.*/, "", ip)
				if (ip != dns && ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
					print ip
					exit
				}
			}
		')
		if [ -n "$ip" ]; then
			echo "$ip"
			return 0
		fi
	done
	return 1
}

port_open() {
	timeout 3 nc "$1" "$2" </dev/null >/dev/null 2>&1
}

active=$(uci -q get passwall.@global[0].node)
enabled=$(uci -q get passwall.@global[0].enabled)
gtype=$(uci -q get "passwall.$active.type")
gaddr=$(uci -q get "passwall.$active.address")
# The global node is the local HAProxy listener. A backend address change
# reloads that one SOCKS process; restarting PassWall would drop every flow.
pool=0
if [ "$gtype" = Socks ] && [ "$gaddr" = 127.0.0.1 ]; then
	pool=1
fi
changed=
restart=0

reload_one() {
	id=$1
	old=$2
	new=$3
	if [ -n "$PASSWALL_RELOAD" ]; then
		$PASSWALL_RELOAD "$id" "$old" "$new"
		return $?
	fi
	/usr/bin/ucode /usr/libexec/passwall/reload_backend.uc address "$id" "$old" "$new"
}

for id in $(uci show passwall | sed -n 's/^passwall\.\([A-Za-z0-9_]*\)=nodes$/\1/p'); do
	remarks=$(uci -q get "passwall.$id.remarks")
	address=$(uci -q get "passwall.$id.address")
	port=$(uci -q get "passwall.$id.port")
	host=$(printf '%s\n' "$remarks" | sed -n 's/.*@\([A-Za-z0-9.-][A-Za-z0-9.-]*\):[0-9][0-9]*$/\1/p')
	[ -n "$host" ] || continue
	[ -n "$port" ] || continue
	case "$address" in
		''|*[!0-9.]*) continue ;;
	esac
	new=$(resolve "$host") || continue
	[ "$new" = "$address" ] && continue
	if port_open "$address" "$port"; then
		continue
	fi
	if ! port_open "$new" "$port"; then
		logger -t node-address "$id $address:$port and $new:$port are both closed"
		continue
	fi
	uci set "passwall.$id.address=$new"
	logger -t node-address "$id address $address -> $new"
	changed=1
	if [ "$pool" = 1 ]; then
		uci commit passwall
		if ! reload_one "$id" "$address" "$new"; then
			logger -t node-address "backend reload failed for $id"
		fi
	elif [ "$id" = "$active" ]; then
		restart=1
	fi
done

if [ -n "$changed" ]; then
	uci commit passwall
fi

if [ "$restart" = 1 ] && [ "$enabled" = 1 ]; then
	logger -t node-address "Active node address changed; restarting passwall"
	if [ -n "$PASSWALL_RESTART" ]; then
		$PASSWALL_RESTART
	else
		/etc/init.d/passwall restart
	fi
	exit 2
fi
exit 0
