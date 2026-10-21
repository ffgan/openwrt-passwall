#!/bin/sh
# Compatibility functions for external shell callers and legacy iptables.sh.
# Native callers import passwall.utils directly.

CONFIG=passwall
DIRECT_GID=9911
APP_PATH=/usr/share/passwall
UCODE_BIN=/usr/libexec/passwall
TMP_PATH=/tmp/etc/passwall
TMP_PATH2=${TMP_PATH}_tmp
LOCK_PATH=/var/lock
LOG_FILE=/tmp/log/passwall.log
TMP_ACL_PATH=${TMP_PATH}/acl
TMP_BIN_PATH=${TMP_PATH}/bin
TMP_IFACE_PATH=${TMP_PATH}/iface
TMP_ROUTE_PATH=${TMP_PATH}/route
TMP_SCRIPT_FUNC_PATH=${TMP_PATH}/script_func
RULES_PATH=/usr/share/passwall/rules
USER_RULES_PATH=/etc/passwall/rules
IPv4_REGEX='((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
IPv6_REGEX='([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}'

_pw_utils() { /usr/bin/ucode "$UCODE_BIN/utils.uc" "$@"; }
echolog() { _pw_utils log "$*"; }
pkg_installed() { _pw_utils pkg_installed "$1"; }
clean_log() { _pw_utils clean_log; }
config_get_type() { _pw_utils config_get_type "$1" "$2"; }
config_n_get() { _pw_utils config_n_get "$1" "$2" "$3"; }
config_t_get() { _pw_utils config_t_get "$1" "$2" "$3" "$4"; }
eval_set_val() { local i; for i in "$@"; do eval "$i"; done; }
eval_unset_val() { local i; for i in "$@"; do unset "${i%%=*}"; done; }
pw_api() { /usr/bin/ucode "$UCODE_BIN/api_call.uc" "$1"; }
eval_cache_var() { [ -s "$TMP_PATH/var" ] && . "$TMP_PATH/var"; }
del_cache_var() { _pw_utils del_cache_var "$1"; }
set_cache_var() { _pw_utils set_cache_var "$1" "$2"; }
get_cache_var() { _pw_utils get_cache_var "$1"; }
first_type() { _pw_utils first_type "$1" "$2"; }
get_enabled_anonymous_secs() { uci -q show "$CONFIG" | sed -n "s/^$CONFIG\.\([^.=]*\)=${1}$/\1/p"; }
get_geoip() { _pw_utils get_geoip "$1" "$2"; }
get_host_ip() { _pw_utils get_host_ip "$1" "$2" "$3"; }
get_node_host_ip() { _pw_utils get_node_host_ip "$1"; }
get_ip_port_from() {
	local value="$1" host port
	case "$value" in
		*\#*) host=${value%#*}; port=${value##*#} ;;
		\[*\]:*) host=${value%\]:*}; host=${host#\[}; port=${value##*:} ;;
		*:*:*) host=$value ;;
		*:*) host=${value%:*}; port=${value##*:} ;;
		*) host=$value ;;
	esac
	eval "$2=\$host; $3=\$port"
}
parse_doh() {
	local value url bootstrap hp host port
	value=$(printf %s "$1" | tr -d ' \t\r\n')
	url=${value%%,*}; bootstrap=${value#*,}; [ "$bootstrap" = "$value" ] && bootstrap=
	hp=$(pw_api "get_domain_from_url(\"$url\")")
	get_ip_port_from "$hp" host port
	[ -n "$port" ] || port=443
	eval "$2=\$url; $3=\$host; $4=\$port; $5=\$bootstrap"
}
host_from_url() { _pw_utils host_from_url "$1"; }
hosts_foreach() {
	local values func default item host port rc
	eval "values=\${$1}"; func=$2; default=$3; shift 3
	for item in $(printf %s "$values" | tr ' ,' '\n'); do
		get_ip_port_from "$item" host port
		"$func" "$item" "$host" "${port:-$default}" "$@"; rc=$?
		[ "$rc" -ge "${ERROR_NO_CATCH:-1}" ] && return "$rc"
	done
}
check_host() { _pw_utils check_host "$1"; }
normalize_dns() { _pw_utils normalize_dns "$1" "$2"; }
format_dns() { _pw_utils format_dns "$1" "$2"; }
check_port_exists() { _pw_utils check_port_exists "$1" "$2"; }
get_new_port() { _pw_utils get_new_port "$1" "$2"; }
check_ver() { _pw_utils check_ver "$1" "$2"; }
has_1_65535() { _pw_utils has_1_65535 "$1"; }
add_ip2route() { _pw_utils add_ip2route "$1" "$2"; }
delete_ip2route() { _pw_utils delete_ip2route; }
shell_quote() { printf "'%s'" "$(printf %s "$1" | sed "s/'/'\\\\''/g")"; }
get_process_start_time() { _pw_utils get_process_start_time "$1"; }
ln_run() { /usr/bin/ucode "$UCODE_BIN/ln_run.uc" "$@"; }
kill_all() { kill -9 $(pidof "$@") >/dev/null 2>&1; }
gen_lanlist() { _pw_utils gen_lanlist ip4; }
gen_lanlist_6() { _pw_utils gen_lanlist ip6; }
get_wan_ips() { _pw_utils get_wan_ips "$1" | tr '\n' ' '; }
get_local_ips() { _pw_utils get_local_ips "$1"; }
