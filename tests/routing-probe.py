#!/usr/bin/env python3
"""See whether nft redirect delivered a TCP connect to the local listener."""

import socket
import sys

SO_MARK = 36


def reaches(ip, port, mark):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.6)
    try:
        if mark is not None:
            sock.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
        sock.connect((ip, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


# want True when the packet must be redirected onto the local listener.
CHECKS = [
    ("foreign-443-redirected", "8.8.8.8", 443, None, True),
    ("china-443-direct", "1.2.4.1", 443, None, False),
    ("node-ip-direct", "203.0.113.10", 443, None, False),
    ("node-domain-ip-direct", "198.51.100.10", 443, None, False),
    ("remote-dns-tcp-redirected", "1.1.1.1", 53, None, True),
    ("marked-foreign-direct", "8.8.8.8", 443, 255, False),
]


def main():
    failed = 0
    for name, ip, port, mark, want in CHECKS:
        got = reaches(ip, port, mark)
        if got != want:
            failed += 1
            print("FAIL %s: got %s" % (name, "redirected" if got else "direct"))
        else:
            print("ok %s" % name)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
