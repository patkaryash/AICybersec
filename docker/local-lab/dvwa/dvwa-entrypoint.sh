#!/bin/bash
# DVWA LAB entrypoint wrapper (docker/local-lab/dvwa).
#
# Why this exists: the upstream image's /main.sh runs `service apache2 start`
# exactly once, and Debian's apache2 start path refuses to start when
# /var/run/apache2/apache2.pid exists and its PID is a live process. The
# container's writable layer survives a stop/start, so the PID file of the
# previous run is still there - and because Docker restarts renumber PIDs, that
# stale number usually belongs to some OTHER process in the new namespace
# (mysqld, the entrypoint, ...). Apache then logs
# "httpd (pid N) already running" and silently does nothing: nothing ever
# listens on :80, so the whole target is unreachable for nmap/httpx/nuclei and
# the MEDIUM configuration-listing finding on /config/ never appears.
#
# Safety: the PID file is removed ONLY when it is provably stale - i.e. the PID
# is not alive, or the live process with that PID is not apache2 (/proc/<pid>/
# comm is checked, which also catches PID reuse). A running apache2 is never
# disturbed. DVWA's database and configuration are not touched at all; this
# wrapper only clears the stale runtime artifact and then hands over to the
# image's own /main.sh unchanged.
set -u

PIDFILE="/var/run/apache2/apache2.pid"
RUNDIR="/var/run/apache2"

mkdir -p "$RUNDIR"

if [ -f "$PIDFILE" ]; then
    pid="$(tr -dc '0-9' < "$PIDFILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && [ -r "/proc/$pid/comm" ] \
        && grep -qs '^apache2$' "/proc/$pid/comm" 2>/dev/null; then
        echo "[dvwa-entrypoint] apache2 is running (pid $pid) - keeping $PIDFILE"
    else
        echo "[dvwa-entrypoint] removing stale $PIDFILE (pid ${pid:-unknown} is not a running apache2)"
        rm -f "$PIDFILE"
    fi
fi

# Image behaviour (mysql + apache start, log tail keep-alive), byte-for-byte.
exec /main.sh "$@"
