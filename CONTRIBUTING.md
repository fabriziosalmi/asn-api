# Contributing

Thanks for helping improve the ASN Risk Intelligence Platform.

## Local setup

```bash
# 1. Generate a .env with strong secrets (API key >= 32 chars, DB passwords)
make secrets            # or: cp .env.example .env && edit

# 2. Bring up the full stack
make up                 # docker compose up --build -d
make ps                 # check health
make logs               # tail logs

# 3. Install the git hooks (lint + format on commit)
pip install pre-commit && pre-commit install
```

## Dev loop

```bash
make test    # run the test suite (env is set by tests/conftest.py)
make lint    # ruff check + black --check   (exactly what CI runs)
make fmt     # ruff --fix + black           (auto-fix before committing)
make check   # lint + test
```

Tooling config lives in `pyproject.toml` (ruff + black). **black is the single
formatter**; ruff is used for linting only.

## Pull requests

- Branch off `main`; keep PRs focused.
- `make check` must pass. CI also validates `docker compose config`, the nginx
  config (`nginx -t`), and builds all images.
- Update `CHANGELOG.md` under a new version heading. Follow semver: new scoring
  signals or behavior changes are a **minor** bump, not a patch.
- Never commit `.env` or secrets (`.gitignore` and a pre-commit hook guard this).

## Verifying runtime changes

For changes that affect scoring or the API, verify end-to-end against the stack
(`make up`), not just unit tests — seed a row in ClickHouse/Postgres and confirm
the signal flows through to the API response.
