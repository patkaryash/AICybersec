#!/usr/bin/env sh
# REPAIR TOOL for the LOCAL lab targets. Since the 2026-10-27 lifecycle fix the
# two startups handle this themselves (see local-lab/dvwa/dvwa-entrypoint.sh,
# local-lab/httpd-vuln/lab-entrypoint.sh and the healthchecks wired in
# docker-compose.extra-targets.yml + the httpd Dockerfile), so a normal
# stop/start no longer needs this script. Keep it for the cases startup cannot
# cover: containers created BEFORE that fix, or a target that is already
# running and degraded (it repairs in place, without recreating anything).
#
# The failure it repairs: a resumed container keeps the writable layer of its
# previous run, and two stale runtime artifacts then stop the targets from
# coming up correctly - with no error surfaced to the platform, which
# correctly reports the result as "completed, 0 findings":
#
#   vulnerable-httpd - the mod_cgid unix socket left behind by the previous
#     run makes the new httpd fail at startup with
#     "(98)Address already in use: AH01243: Couldn't bind unix domain socket
#      /usr/local/apache2/logs/cgisock.1" ->
#     "cgid:crit AH01238: cgid daemon failed to initialize".
#     Afterwards every CGI execution answers 503 (AH02833: ScriptSock ...
#     does not exist), so the CVE-2021-41773 template's RCE matcher can never
#     match although the host itself is up and reachable.
#   dvwa - the stale /var/run/apache2/apache2.pid makes the container's own
#     /main.sh "service apache2 start" believe apache is "already running",
#     so nothing ever listens on :80 and the target is unreachable for
#     nmap/httpx/nuclei.
#
# The dvwa container is repaired IN PLACE on purpose: its DVWA database lives
# in the container's own mariadb data directory (config.inc.php points at
# 127.0.0.1), so recreating the container would throw the initialized lab
# application away.
#
# Usage (repo root):  sh docker/restore-lab-targets.sh
# Exit code: 0 when both targets are back in their intended vulnerable state,
# 1 when a target stays unhealthy (nothing is faked, nothing is scanned
# outside the lab). Verification: `pytest -m lab_e2e
# tests/e2e/test_lab_target_health.py`.
set -eu

COMPOSE="docker compose -f docker/docker-compose.yml -f docker/docker-compose.extra-targets.yml --profile lab"
# CVE-2021-41773 RCE path (the request the nuclei RCE matcher sends).
RCE_PATH='/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh'

cid() {
    $COMPOSE ps -q "$1" 2>/dev/null | head -n 1
}

# Probe through the backend container: it is the network namespace the
# scanners actually run in, so a healthy probe here means the scan pipeline
# sees a working target. Prints the HTTP status, or 000 when unreachable
# (curl itself prints 000 and exits non-zero on a refused connection).
probe() {  # probe <curl-args...>
    _out=$(docker exec "$BACKEND" sh -c "curl -s -m 5 -o /dev/null -w '%{http_code}' $*" 2>/dev/null || true)
    echo "${_out:-000}"
}

probe_httpd() {
    probe "--path-as-is -X POST -d 'echo Content-Type: text/plain; echo; echo x | rev' http://vulnerable-httpd:80$RCE_PATH"
}

probe_dvwa() {
    probe "http://dvwa:80/config/"
}

wait_for() {  # wait_for <probe-fn> <expected-codes> <seconds>
    _probe="$1"; _want="$2"; _left="$3"
    while [ "$_left" -gt 0 ]; do
        _code=$($_probe)
        case " $_want " in
            *" $_code "*) echo "$_code"; return 0 ;;
        esac
        sleep 2
        _left=$((_left - 2))
    done
    $_probe
}

BACKEND=$(cid backend)
HTTPD=$(cid vulnerable-httpd)
DVWA=$(cid dvwa)

if [ -z "$BACKEND" ] || [ -z "$HTTPD" ] || [ -z "$DVWA" ]; then
    echo "lab stack is not running - start it first, e.g.:" >&2
    echo "  $COMPOSE up -d" >&2
    exit 1
fi

# --- vulnerable-httpd: stale mod_cgid socket ------------------------------
httpd_code=$(probe_httpd)
if [ "$httpd_code" != "200" ]; then
    echo "vulnerable-httpd CGI broken (probe=$httpd_code) - clearing stale cgisock and restarting"
    docker exec "$HTTPD" sh -c 'rm -f /usr/local/apache2/logs/cgisock*'
    docker restart "$HTTPD" >/dev/null
    httpd_code=$(wait_for probe_httpd "200" 30)
fi

# --- dvwa: stale apache2 pid file -----------------------------------------
dvwa_code=$(probe_dvwa)
if [ "$dvwa_code" != "200" ] && [ "$dvwa_code" != "302" ]; then
    echo "dvwa not serving (probe=$dvwa_code) - clearing stale apache2.pid and starting apache"
    docker exec "$DVWA" sh -c 'rm -f /var/run/apache2/apache2.pid && service apache2 start'
    dvwa_code=$(wait_for probe_dvwa "200 302" 30)
fi

echo "vulnerable-httpd cve-probe=$httpd_code (200 = CGI reachable, RCE matcher can match)"
echo "dvwa /config/=$dvwa_code (200/302 = target serving)"

case " $httpd_code " in *" 200 "*) ;; *) echo "FAIL: vulnerable-httpd still unhealthy" >&2; exit 1 ;; esac
case " $dvwa_code " in *" 200 "*|*" 302 "*) ;; *) echo "FAIL: dvwa still unhealthy" >&2; exit 1 ;; esac
echo "lab targets healthy"
