# LOCAL TESTING ONLY - DO NOT COMMIT
# Apache httpd 2.4.49 configured to be genuinely exploitable for
# CVE-2021-41773 (path traversal). The stock image denies "/" by default,
# so the traversal returns 403 and detection templates correctly do not
# match. This config grants "/" and enables cgi-bin so the flaw is real.
FROM httpd:2.4.49

RUN mkdir -p /usr/local/apache2/cgi-bin && \
    printf '#!/bin/sh\necho "Content-Type: text/plain"\necho\necho ok\n' > /usr/local/apache2/cgi-bin/test && \
    chmod +x /usr/local/apache2/cgi-bin/test && \
    printf '\n<Directory />\n    Require all granted\n</Directory>\nLoadModule cgid_module modules/mod_cgid.so\nScriptAlias /cgi-bin/ "/usr/local/apache2/cgi-bin/"\n<Directory "/usr/local/apache2/cgi-bin">\n    Options +ExecCGI\n    SetHandler cgi-script\n    Require all granted\n</Directory>\n' >> /usr/local/apache2/conf/httpd.conf

# --- durable lab startup lifecycle (see local-lab/README.md) ----------------
# Regression repaired here (2026-10-27): a mod_cgid socket left over by the
# previous run made the resumed container fail to bind it
# ("AH01243: Address already in use" -> "AH01238: cgid daemon failed to
# initialize"), so every CGI request answered 503 while root still served 200.
# nuclei detects CVE-2021-41773 through its RCE matcher (a CGI execution), so
# scans reported "completed, 0 findings" on a target that was fully reachable.
#   lab-entrypoint.sh  - removes only a STALE cgisock before httpd starts.
#   lab-healthcheck.sh - reports unhealthy when HTTP or CGI is broken.
# The intentional CVE-2021-41773 misconfiguration above is untouched.
COPY lab-entrypoint.sh /usr/local/bin/lab-entrypoint.sh
COPY lab-healthcheck.sh /usr/local/bin/lab-healthcheck.sh
RUN chmod 0755 /usr/local/bin/lab-entrypoint.sh /usr/local/bin/lab-healthcheck.sh

# CMD must be repeated: setting ENTRYPOINT resets the base image's CMD to
# empty, and "exec $@" with no arguments would exit the container silently.
# The healthcheck asserts the RCE path actually executes, so a half-started
# lab target shows up as unhealthy instead of silently hiding findings.
ENTRYPOINT ["/usr/local/bin/lab-entrypoint.sh"]
CMD ["httpd-foreground"]
HEALTHCHECK --interval=15s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/lab-healthcheck.sh"]
