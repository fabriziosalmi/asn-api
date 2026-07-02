#!/usr/bin/env bash
# Generate a .env with strong secrets from .env.example.
# Fills every CHANGE_ME placeholder: API_SECRET_KEY gets 32 bytes of hex (64
# chars, satisfying the settings min_length=32), passwords get 24-byte secrets.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -f .env ]; then
  echo "refusing to overwrite existing .env (remove it first if you really mean to)" >&2
  exit 1
fi
if [ ! -f .env.example ]; then
  echo ".env.example not found" >&2
  exit 1
fi

gen() { openssl rand -hex "$1"; }

api_key=$(gen 32)          # 64 hex chars
pg_pass=$(gen 24)
ch_pass=$(gen 24)
grafana_pass=$(gen 24)

sed \
  -e "s|API_SECRET_KEY=.*|API_SECRET_KEY=${api_key}|" \
  -e "s|POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${pg_pass}|" \
  -e "s|CLICKHOUSE_PASSWORD=.*|CLICKHOUSE_PASSWORD=${ch_pass}|" \
  -e "s|GRAFANA_ADMIN_PASSWORD=.*|GRAFANA_ADMIN_PASSWORD=${grafana_pass}|" \
  .env.example > .env

echo "Wrote .env with freshly generated secrets."
echo "  API_SECRET_KEY : ${#api_key} chars"
echo "Review CORS_ORIGINS and hostnames before deploying."
