#!/bin/bash
# Load the ucode nftables rules in a network namespace and check the path the
# settings page depends on: foreign TCP is redirected, China TCP is not, and
# the proxy node is not redirected back into itself.
#
# The fixture is hostile on purpose.
# - resolveip -6 node.example prints an IPv4 address. That used to land in
#   psw_vps6 and roll back the whole element batch.
# - direct_ip contains "not-a-cidr", which nft rejects.
# - IPT_APPEND_DNS is 256.256.256.256. That return rule used to make the
#   atomic rule batch fail, so no redirect was installed at all. Domestic
#   checks then succeeded and Google/GitHub/YouTube did not.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
UCODE=${UCODE:-/tmp/ucode/build/ucode}

if [ "$(id -u)" -ne 0 ]; then
	exec sudo -E UCODE="$UCODE" "$0" "$@"
fi

if [ ! -x "$UCODE" ]; then
	echo "ucode not found at $UCODE" >&2
	exit 1
fi

for bin in nft ip python3 unshare; do
	if ! command -v "$bin" >/dev/null 2>&1; then
		echo "missing $bin" >&2
		exit 1
	fi
done

if [ "${ROUTING_INSIDE:-}" != "1" ]; then
	work=$(mktemp -d -p /var/tmp routing.XXXXXX)
	mkdir -p "$work/tmp-etc/passwall" "$work/tmp-log" "$work/user-rules" "$work/bin" "$work/lock"
	cp "$ROOT/tests/fixtures/resolveip" "$work/bin/resolveip"
	chmod 755 "$work/bin/resolveip"
	cat > "$work/bin/uci" <<'EOF'
#!/bin/sh
exit 1
EOF
	chmod 755 "$work/bin/uci"
	printf '%s\n' 'not-a-cidr' > "$work/user-rules/direct_ip"
	printf '%s\n' 'nodedom' > "$work/tmp-etc/passwall/direct_node_list"
	cat > "$work/tmp-etc/passwall/nft.json" <<'EOF'
{
  "NODE": "nodedom",
  "ENABLED": "1",
  "ENABLED_DEFAULT_ACL": "1",
  "ENABLED_ACLS": "0",
  "CLIENT_PROXY": "1",
  "TCP_NO_REDIR_PORTS": "disable",
  "UDP_NO_REDIR_PORTS": "disable",
  "TCP_PROXY_DROP_PORTS": "disable",
  "UDP_PROXY_DROP_PORTS": "80,443",
  "TCP_REDIR_PORTS": "80,443",
  "UDP_REDIR_PORTS": "1:65535",
  "TCP_PROXY_MODE": "proxy",
  "UDP_PROXY_MODE": "proxy",
  "USE_DIRECT_LIST": "1",
  "USE_PROXY_LIST": "1",
  "USE_BLOCK_LIST": "1",
  "USE_GFW_LIST": "1",
  "CHN_LIST": "direct",
  "DNS_REDIRECT_PORT": "11400",
  "USE_FAKEDNS": "0",
  "PROXY_IPV6": "0",
  "TCP_PROXY_WAY": "redirect",
  "LOCALHOST_TCP_PROXY_MODE": "proxy",
  "LOCALHOST_UDP_PROXY_MODE": "proxy",
  "LOCALHOST_PROXY": "1",
  "REDIR_PORT": "1041",
  "TCP_PROXY_DNS": "1",
  "REMOTE_DNS": "1.1.1.1",
  "IPT_APPEND_DNS": "256.256.256.256#53",
  "DNS_REDIRECT": "1",
  "FILTER_PROXY_IPV6": "0"
}
EOF
	cleanup() {
		rmdir /usr/share/passwall/rules /etc/passwall/rules 2>/dev/null || true
		rm -rf "$work"
	}
	trap cleanup EXIT
	export ROUTING_INSIDE=1 ROUTING_WORK="$work" ROUTING_ROOT="$ROOT" UCODE="$UCODE"
	unshare --net --mount --pid --fork --mount-proc bash "$0"
	exit $?
fi

work=$ROUTING_WORK
root=$ROUTING_ROOT
export PATH="$work/bin:/usr/local/sbin:/usr/sbin:/sbin:/usr/bin:/bin"

mkdir -p /usr/share/passwall/rules /etc/passwall/rules /tmp/etc /tmp/log /run/lock
mount --bind "$root/luci-app-passwall/root/usr/share/passwall/rules" /usr/share/passwall/rules
mount --bind "$work/user-rules" /etc/passwall/rules
mount --bind "$work/tmp-etc" /tmp/etc
mount --bind "$work/tmp-log" /tmp/log
mount --bind "$work/lock" /run/lock
ip link set lo up
ip link add veth0 type veth peer name veth1
ip link set veth0 up
ip link set veth1 up
ip addr add 192.0.2.1/24 dev veth0
ip addr add 192.0.2.2/24 dev veth1
ip route add default via 192.0.2.2

python3 - <<'PY' &
import socket, threading, time
def serve(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(64)
    while True:
        conn, _ = s.accept()
        conn.close()
for port in (1041, 11400):
    threading.Thread(target=serve, args=(port,), daemon=True).start()
while True:
    time.sleep(3600)
PY
listener=$!
trap 'kill "$listener" 2>/dev/null || true' EXIT
sleep 0.2

set +e
"$UCODE" \
	-L "$root/tests/routing-stubs" \
	-L "$root/tests/stubs" \
	-L "$root/luci-app-passwall/root/usr/share/ucode" \
	-L /tmp/ucode/build \
	"$root/tests/routing-start.uc"
start_rc=$?
set -e
if [ "$start_rc" -ne 0 ]; then
	echo "FAIL nftables start exited $start_rc" >&2
	cat /tmp/log/passwall.log >&2 || true
	exit 1
fi

failed=0
note() {
	failed=$((failed + 1))
	echo "FAIL $*" >&2
}

python3 "$root/tests/routing-probe.py" || failed=$((failed + 1))

if ! ip rule show | grep -q '0x50535731'; then
	note "fwmark rule for the proxy was not installed"
fi
if ! nft get element inet passwall psw_chn_static '{ 1.2.4.1 }' >/dev/null 2>&1; then
	note "China route 1.2.4.1 is missing from psw_chn_static"
fi
if ! nft get element inet passwall psw_vps '{ 203.0.113.10 }' >/dev/null 2>&1; then
	note "literal node IP is missing from psw_vps"
fi
if ! nft get element inet passwall psw_vps '{ 198.51.100.10 }' >/dev/null 2>&1; then
	note "resolved node IP is missing from psw_vps"
fi
if nft get element inet passwall psw_vps6 '{ 198.51.100.10 }' >/dev/null 2>&1; then
	note "IPv4 node address was inserted into psw_vps6"
fi

rules=$(nft list table inet passwall)
if printf '%s\n' "$rules" | grep -q 'node\.example'; then
	note "bypass rule still matches the hostname node.example"
fi
if printf '%s\n' "$rules" | grep -q '256\.256\.256\.256'; then
	note "invalid DNS address was installed as a rule"
fi
if [ -f /tmp/log/passwall.log ] && grep -q 'psw_vps6' /tmp/log/passwall.log; then
	note "log claims an IPv6 node address was installed"
fi

if [ "$failed" -ne 0 ]; then
	echo "----- passwall.log -----" >&2
	cat /tmp/log/passwall.log >&2 || true
	echo "----- ip rule -----" >&2
	ip rule show >&2 || true
	exit 1
fi

echo "routing ok"
exit 0
