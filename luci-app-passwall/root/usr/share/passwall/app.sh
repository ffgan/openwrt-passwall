#!/bin/sh
# Compatibility entry point. Native orchestration lives in passwall.app.
exec /usr/bin/ucode /usr/libexec/passwall/app.uc "$@"
