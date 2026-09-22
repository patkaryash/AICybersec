# Contributing

## Team ownership boundaries

| Area | Owner | Paths |
|---|---|---|
| AI / agent architecture | agent developer | `agent_core/`, `docs/architecture.md` |
| Backend / security infra | backend developer | `backend/` |
| Frontend | frontend developer | `frontend/` |
| Shared contracts | **all three - change together** | `agent_core/schemas/`, `frontend/README.md` (API contract), event vocabulary in `agent_core/runtime/events.py` |

The schemas in `agent_core/schemas/` are consumed by all three
components. Any change there must be agreed by the team, keep
serializability (JSON round-trip tests must pass), and be accompanied by
updated tests on all sides.

## Git workflow

- `main` is **protected**. No direct pushes, no force pushes.
- Work on feature branches: `feature/<topic>` (e.g. `feature/agent-foundation`).
- Open a **pull request** for every change; at least one review from the
  owning teammate (plus the agent developer for anything touching
  `agent_core/schemas/`).
- **Tests must pass before merge**: `python -m pytest` runs fully offline.
- Keep commits small and focused; use imperative subjects, e.g.
  `feat: add nuclei tool contract tests`.

## Development rules (project-wide)

- `agent_core` stays a pure library: no FastAPI, no HTTP concerns, no
  shell tool, no network in mocks/tests.
- New tools: one file implementing `Tool` + registration in the
  composition root + a contract test. Never modify the core to add a tool.
- New model integrations implement `ModelProvider`; never call a model
  from inside tools or the runtime.
- Every decision passes the safety validator; never bypass it, even for
  "temporary" debugging.
- No secrets in code, logs, state or trajectory files (the store
  scrubs known secret keys - extend `_SECRET_KEYS` deliberately).

## Setup

```bash
python -m venv .venv
source .venv/Scripts/activate      # Windows (bash)
pip install -e ".[dev]"
python -m pytest
python -m agent_core --target demo.local
```
