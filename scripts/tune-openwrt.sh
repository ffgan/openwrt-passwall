#!/bin/sh
# Run on OpenWrt after installing the matching BBR/CAKE modules and sqm-scripts.
# Speeds are the measured line rates in Mbps; reserve 5% for queue control.
set -eu
[ "$#" -eq 2 ] || { echo "Usage: $0 DOWNLOAD_Mbps UPLOAD_Mbps" >&2; exit 2; }
case "$1:$2" in *[!0-9:]*|:*|*:) echo 'Speeds must be positive integers' >&2; exit 2;; esac
[ "$1" -gt 0 ] && [ "$1" -le 10000 ] && [ "$2" -gt 0 ] && [ "$2" -le 10000 ] || exit 2
command -v tc >/dev/null
[ -x /etc/init.d/sqm ]
interface=$(ubus call network.interface.wan status | jsonfilter -e '@.l3_device')
[ -n "$interface" ] || { echo 'WAN interface is not ready' >&2; exit 1; }
umask 077
backup=$(mktemp -d /tmp/passwall-tuning.XXXXXX)
cp /etc/config/passwall "$backup/passwall"
cp /etc/config/sqm "$backup/sqm"
cp /etc/config/firewall "$backup/firewall"
# SQM must see the packets; hardware/software forwarding offload bypasses it.
uci set firewall.@defaults[0].flow_offloading=0
uci set firewall.@defaults[0].flow_offloading_hw=0
uci commit firewall
uci set sqm.passwall=queue
uci set sqm.passwall.enabled=1
uci set sqm.passwall.interface="$interface"
uci set sqm.passwall.download="$(( $1 * 950 ))"
uci set sqm.passwall.upload="$(( $2 * 950 ))"
uci set sqm.passwall.qdisc=cake
uci set sqm.passwall.script=piece_of_cake.qos
uci set sqm.passwall.linklayer=ethernet
# Conservative Ethernet/PPPoE framing allowance; adjust for a measured link.
uci set sqm.passwall.overhead=44
uci set sqm.passwall.ingress_ecn=ECN
uci set sqm.passwall.egress_ecn=ECN
uci set sqm.passwall.qdisc_advanced=1
uci set sqm.passwall.qdisc_really_really_advanced=1
uci set sqm.passwall.iqdisc_opts='nat dual-dsthost ingress'
uci set sqm.passwall.eqdisc_opts='nat dual-srchost'
uci commit sqm
node=$(uci -q get passwall.@global[0].node || true)
protocol=$(uci -q get "passwall.$node.protocol" || true)
case "$protocol" in
vless|vmess|trojan|shadowsocks|socks|http)
	uci set "passwall.$node.happy_eyeballs=1"
	uci set "passwall.$node.happy_delay_ms=250"
	uci set "passwall.$node.tcp_keepalive_idle=60"
	uci set "passwall.$node.tcp_keepalive_interval=15"
	uci set "passwall.$node.tcp_user_timeout=60000"
	if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control; then
		uci set "passwall.$node.tcp_congestion=bbr"
	fi
	uci commit passwall
	;;
esac
if /etc/init.d/firewall reload && /etc/init.d/sqm restart && /etc/init.d/passwall restart; then
	/etc/init.d/sqm enable
	printf 'Applied SQM %s/%s Kbps on %s; private backup: %s\n' "$(( $1 * 950 ))" "$(( $2 * 950 ))" "$interface" "$backup"
else
	/etc/init.d/sqm stop || true
	cp "$backup/sqm" /etc/config/sqm
	cp "$backup/passwall" /etc/config/passwall
	cp "$backup/firewall" /etc/config/firewall
	/etc/init.d/firewall reload || true
	/etc/init.d/sqm restart || true
	/etc/init.d/passwall restart || true
	echo "Tuning failed; restored configuration from $backup" >&2
	exit 1
fi
