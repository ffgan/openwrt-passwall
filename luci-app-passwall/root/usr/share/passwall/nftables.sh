#!/bin/sh
# Compatibility entry point for third-party callers. Firewall logic lives in
# the native ucode implementation.
exec /usr/libexec/passwall/nftables.uc "$@"
