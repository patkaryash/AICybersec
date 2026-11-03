# LOCAL LAB SETUP (do not commit, do not push)

Notes for the local demo environment. Nothing in this directory is part
of the application source.

## 1. Nuclei templates (required for findings)

The backend container's nuclei ships with ZERO templates. They must be
downloaded once (needs internet) and are then persisted in the
`nuclei-home` docker volume (mounted at `/home/appuser`):

```bash
docker exec -u appuser docker-backend-1 nuclei -update-templates
# verify:
docker exec -u appuser docker-backend-1 sh -c 'find ~/nuclei-templates -name "*.yaml" | wc -l'
# expect ~13,700+
```

Templates are generated data: never commit them, never bake them into
the image. The `nuclei-home` volume in `docker/docker-compose.yml` makes
them survive container recreation (scans work offline afterwards).

## 2. Vulnerable Apache lab target (produces real findings)

`httpd-vuln/` builds `httpd:2.4.49` with CVE-2021-41773 actually
exploitable (stock image denies `/`, which patches the flaw away):

```bash
docker compose -f docker/docker-compose.yml \
  -f docker/docker-compose.extra-targets.yml --profile lab up -d --build vulnerable-httpd
```

- Serves on compose network as `vulnerable-httpd:80` (host port 4282).
- Scope for the platform project: `host: vulnerable-httpd` +
  `url: http://vulnerable-httpd:80` (explicit port required: httpx 1.6.0
  silently drops portless URLs).
- One-click demo: the New Pentest page's "Suggested Lab Targets" chips
  include `http://vulnerable-httpd:80` - clicking it, ticking the
  authorization box and launching a `web` scan auto-creates the project
  and yields the CVE-2021-41773 HIGH finding in ~60s.
- Note: each chip-launched scan creates a NEW "Target: ..." project
  (existing frontend behavior) - delete extras from the projects list
  before presenting if the list looks cluttered.
- A `web` scan finds CVE-2021-41773 (HIGH) via nuclei in ~60-90s.

## 3. Extra targets file (local only)

`docker/docker-compose.extra-targets.yml` adds DVWA (needs its DB init
via http://localhost:4280 once) and the vulnerable httpd. Keep it out of
git. Juice Shop remains the presentation target.

## 4. NEVER run pytest against the demo database

`tests/conftest.py::clean_db` TRUNCATEs the database named by
AICYBERSEC_DATABASE_URL (default = the dev/demo DB). To run the suite
safely, point it at a scratch database first:

```bash
docker exec docker-postgres-1 psql -U aicybersec -d aicybersec -c "CREATE DATABASE aicybersec_test_pr;"
AICYBERSEC_DATABASE_URL=postgresql+psycopg://aicybersec:aicybersec@localhost:5432/aicybersec_test_pr \
  .venv/Scripts/python.exe -m alembic upgrade head
AICYBERSEC_DATABASE_URL=postgresql+psycopg://aicybersec:aicybersec@localhost:5432/aicybersec_test_pr \
  .venv/Scripts/python.exe -m pytest tests/ -p no:cacheprovider -W ignore -q
docker exec docker-postgres-1 psql -U aicybersec -d aicybersec -c "DROP DATABASE aicybersec_test_pr;"
```
