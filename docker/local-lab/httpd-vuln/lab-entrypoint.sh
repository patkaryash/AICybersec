#!/bin/sh
# vulnerable-httpd LAB entrypoint (docker/local-lab/httpd-vuln).
#
# Why this exists: mod_cgid creates its control socket at
# $ServerRoot/logs/cgisock.<N>. The container's writable layer survives a
# stop/start (and an abrupt kill), so a socket file from the PREVIOUS run can
# still be there when the new httpd starts. Binding it then fails with
#
#   (98)Address already in use: AH01243: Couldn't bind unix domain socket
#       /usr/local/apache2/logs/cgisock.1
#   [cgid:crit] AH01238: cgid daemon failed to initialize
#
# and from that moment every CGI request answers 503 (AH02833: ScriptSock ...
# does not exist). The host still looks perfectly healthy (root serves 200,
# nmap/httpx identify Apache 2.4.49), but CVE-2021-41773 is detected through
# the template's RCE matcher - a CGI execution - so the HIGH finding silently
# disappears and scans report "completed, 0 findings".
#
# Safety: a socket is removed only when it IS a unix socket file AND no httpd
# process is running that could own it (at entrypoint time the container has
# just started, so a leftover socket can only be stale). Nothing else under
# logs/ is touched, and httpd.conf - including the intentional CVE-2021-41773
# misconfiguration - is never modified.
set -eu

SOCKET_DIR="/usr/local/apache2/logs"

if grep -lqs '^httpd$' /proc/[0-9]*/comm 2>/dev/null; then
    echo "[lab-entrypoint] httpd is already running - leaving sockets untouched" >&2
else
    for sock in "$SOCKET_DIR"/cgisock*; do
        [ -S "$sock" ] || continue
        echo "[lab-entrypoint] removing stale mod_cgid socket $sock" >&2
        rm -f "$sock"
    done
fi

# Hand over to the image's CMD (httpd-foreground).
exec "$@"
