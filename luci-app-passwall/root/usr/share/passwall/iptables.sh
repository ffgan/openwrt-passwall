#!/bin/sh
# Compatibility entry point. Legacy iptables orchestration is native ucode.
exec /usr/bin/ucode /usr/libexec/passwall/iptables.uc "$@"
