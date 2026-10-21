#!/bin/sh
# Existing HAProxy configs name this path. The probe itself is ucode.
exec /usr/bin/ucode /usr/libexec/passwall/haproxy_check.uc "$@"
