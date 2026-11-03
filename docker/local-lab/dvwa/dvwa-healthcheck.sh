#!/bin/bash
# DVWA LAB healthcheck (docker/local-lab/dvwa).
#
# A container is NOT healthy just because it is "Up": the upstream entrypoint
# starts Apache once, so a failed start leaves mysqld running and the container
# alive while nothing listens on :80 (that is how the silent zero-findings
# regression looked). This checks the actual HTTP service and the exact route
# the MEDIUM configuration-listing finding is recorded against (/config/ must
# answer 200 with an Apache directory listing).
#
# Dependency-free: no curl/wget in the image, so bash's /dev/tcp is used.
# Loopback only.
set -u

HOST="127.0.0.1"
PORT="80"

http_response() {  # http_response <path>
    local path="$1"
    exec 3<>"/dev/tcp/${HOST}/${PORT}" || return 1
    printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$path" "$HOST" >&3
    cat <&3
    exec 3<&-
}

response=$(http_response /config/) || { echo "unhealthy: no HTTP service on ${PORT}"; exit 1; }

case "$response" in
    *" 200 "*) ;;
    *) echo "unhealthy: GET /config/ did not return 200"; exit 1 ;;
esac
case "$response" in
    *"Index of /config"*) ;;
    *) echo "unhealthy: /config/ is not served as a directory listing"; exit 1 ;;
esac

echo "healthy: apache serving /config/ directory listing"
