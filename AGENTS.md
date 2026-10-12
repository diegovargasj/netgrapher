# Agent guide

If you are an AI coding agent or a new contributor, **read
[`docs/development-plan.md`](docs/development-plan.md) before changing anything.** It has the
current status, architecture map, known bugs, and the prioritized TODO backlog. The full spec is
[`docs/requirements-and-design.md`](docs/requirements-and-design.md).

## Non-negotiable rules
1. **Tests must never touch the real network or host.** An autouse fixture in `tests/conftest.py`
   blocks dumpcap, host-config reads, and the real probe transport. Use `tests/fake_transport.py`
   and the fake dumpcap. Extend the guard when you add network/host code.
2. **Never run `active`/`reactive` mode on a network you aren't authorized to scan.** Use
   `--dry-run` for manual checks.
3. **Never open the owner's personal capture files.** Use `tests/synthetic.py` or files explicitly
   provided.
4. **The engine never requires root;** the UI binds to 127.0.0.1 with a token; captured text is
   rendered as text, never HTML. Don't weaken these.
5. **Never reintroduce the owner's real email** into commits, the design doc, or `pyproject.toml`
   (history was rewritten to remove it; commit author is a GitHub no-reply address).

## Quality gates (all must pass before committing)
```bash
.venv/bin/pytest -q && .venv/bin/mypy && .venv/bin/ruff check . && .venv/bin/ruff format --check .
```
UI tests (`tests/ui/`) need a system Chromium and are skipped without one — run them where it exists.
