# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

import pytest
import sys
import os
from unittest.mock import MagicMock, patch, AsyncMock

# Set required env vars before importing app
os.environ.setdefault("API_SECRET_KEY", "test-secret-key")
os.environ.setdefault("POSTGRES_USER", "test_user")
os.environ.setdefault("POSTGRES_PASSWORD", "test_pass")
os.environ.setdefault("POSTGRES_DB", "test_db")
os.environ.setdefault("DB_META_HOST", "localhost")
os.environ.setdefault("DB_TS_HOST", "localhost")
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("LOG_FORMAT", "text")

# Add services to path
# api path MUST be first so its settings.py is found before engine's
_api_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../services/api"))
_engine_path = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../services/engine")
)
_services_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../services"))
# Remove any existing entries that might conflict
for p in [_api_path, _engine_path, _services_path]:
    if p in sys.path:
        sys.path.remove(p)
sys.path.insert(0, _api_path)
sys.path.insert(1, _engine_path)
sys.path.insert(2, _services_path)

# Mock dependencies before importing app (since it connects on import)
with patch("redis.asyncio.Redis"), patch("sqlalchemy.create_engine"), patch(
    "clickhouse_driver.Client"
):
    from api.main import app


@pytest.fixture(autouse=True)
def mock_dependencies():
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.setex = AsyncMock(return_value=True)
    mock_redis.eval = AsyncMock(return_value=1)
    mock_redis.ttl = AsyncMock(return_value=60)
    mock_redis.delete = AsyncMock(return_value=1)
    mock_redis.aclose = AsyncMock()

    mock_pg = MagicMock()
    mock_pg_conn = MagicMock()
    mock_pg.connect.return_value.__enter__ = MagicMock(return_value=mock_pg_conn)
    mock_pg.connect.return_value.__exit__ = MagicMock(return_value=False)
    mock_pg_conn.execute.return_value = MagicMock()

    mock_ch = MagicMock()
    mock_ch.execute.return_value = MagicMock()

    with patch("api.main.redis_client", mock_redis), patch(
        "api.main.pg_engine", mock_pg
    ), patch("api.main.ch_client", mock_ch):
        yield (mock_redis, mock_pg, mock_ch)


@pytest.fixture
def client():
    from starlette.testclient import TestClient

    return TestClient(app)


@pytest.fixture
def api_key():
    return "test-secret-key"
