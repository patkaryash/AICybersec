# CyberSec AI — Demo Startup Guide

Run these from the repository root (`G:\Major project\AICybersec`) in Git Bash,
the morning of the demonstration. Nothing here needs administrator rights.

## 0. Prerequisites (only if the machine was rebooted)

Start Docker Desktop and wait until `docker info` succeeds:

```bash
docker info --format '{{.ServerVersion}}'
```

Expected: `29.9.2`. If it errors, open Docker Desktop from the Start menu and
wait for "Engine running".

## 1. Start the stack

```bash
docker compose -f docker/docker-compose.yml \
  -f docker/docker-compose.extra-targets.yml --profile lab \
  up -d postgres backend dvwa-db dvwa vulnerable-httpd
```

This is the exact command that was verified. It starts PostgreSQL, the FastAPI
backend, DVWA + its MariaDB, and the vulnerable Apache. Migrations run
automatically before the backend starts.

**Do not** add `-v`, and never run `docker compose down -v`, `docker volume
prune` or `docker system prune` — they destroy the database and the downloaded
nuclei templates.

If only the backend was stopped (PostgreSQL and the lab targets still running),
this is enough to bring it back — the existing results are untouched:

```bash
docker compose -f docker/docker-compose.yml \
  -f docker/docker-compose.extra-targets.yml --profile lab up -d backend
```

## 2. Confirm everything is healthy

```bash
docker compose -f docker/docker-compose.yml \
  -f docker/docker-compose.extra-targets.yml --profile lab ps
```

Wait until `docker-postgres-1`, `docker-dvwa-1` and `docker-vulnerable-httpd-1`
all show `(healthy)`. `db` only shows `Up` (it has no healthcheck by design).

Then check both lab targets at once:

```bash
sh docker/restore-lab-targets.sh
```

Expected final line: `lab targets healthy`.

Backend readiness:

```bash
curl -s http://127.0.0.1:8000/api/v1/health/ready
```

Expected: `{"success":true,"data":{"status":"ready"}, ...}`.

## 3. Start the frontend

```bash
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

Leave that terminal running. Open <http://127.0.0.1:5173> in the browser.

`npm ci` is **not** needed — dependencies are already installed. Only run it if
`frontend/node_modules` is ever deleted again.

## 4. Log in

- Email: `admin@gmail.com`
- Password: `admin123`

These are the demo/lab credentials from `docker/docker-compose.yml`. Demo mode
is off; the dashboard shows real scan data.

## 5. Show the demo

Existing verified results:

| Target | Profile | Finding |
| --- | --- | --- |
| `http://dvwa:80` | Full Assessment | Medium — Sensitive Configuration Files Listing (`/config/`) |
| `http://vulnerable-httpd:80` | Full Assessment | High — Apache 2.4.49 Path Traversal & RCE (CVE-2021-41773) |

To run a fresh scan: **New Pentest** → use a lab target chip
(`http://dvwa:80` or `http://vulnerable-httpd:80`) → tick the authorization box
→ profile **Full Assessment** → launch. A Full Assessment takes roughly
2 minutes (nuclei runs the full template set).

## 6. Shut down safely (afterwards)

Stop the containers but keep the PostgreSQL database, the DVWA database and the
nuclei templates:

```bash
docker compose -f docker/docker-compose.yml \
  -f docker/docker-compose.extra-targets.yml --profile lab stop
```

Starting again in the morning does not re-run the DVWA installer — the
databases live in named volumes (`docker_pgdata`, `docker_dvwa-mysqldata`,
`docker_dvwa-dbdata`).

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| A target shows `Up` but unhealthy | `sh docker/restore-lab-targets.sh` |
| DVWA loads its installer page | `docker compose ... restart dvwa` (do not recreate) |
| Scans complete with 0 findings | run the repair script, then `pytest -m lab_e2e tests/e2e/test_lab_target_health.py` |
| `nuclei` finds nothing at all | `docker exec -u appuser docker-backend-1 nuclei -update-templates` |
| Port 8000/5173/5432 already in use | stop the stray process, then restart the stack |

## Safety invariants — do not change for the demo

- `AICYBERSEC_LIVE_PROBE_ENABLED` stays disabled (unset = disabled). Live probe
  transport is not implemented; the ScanManager refuses those scans.
- Never expose ports 4280/4282 beyond localhost; they run intentionally
  vulnerable software.
- Never point scans at Internet targets — lab scope only.
