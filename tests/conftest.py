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
    # Clear the module-level L1 in-memory cache so tests don't interfere with each other
    from api.main import l1_cache
    l1_cache.clear()

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.setex = AsyncMock(return_value=True)
    mock_redis.eval = AsyncMock(return_value=1)
    mock_redis.ttl = AsyncMock(return_value=60)
    mock_redis.delete = AsyncMock(return_value=1)
    mock_redis.aclose = AsyncMock()

    mock_pg = MagicMock()
    mock_pg_conn = AsyncMock()
    
    # Context manager setup for async with pg_engine.begin()
    class AsyncContextManagerMock:
        async def __aenter__(self):
            return mock_pg_conn
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
            
    mock_pg.begin.return_value = AsyncContextManagerMock()
    mock_pg_conn.execute = AsyncMock(return_value=MagicMock())

    mock_ch = MagicMock()
    mock_ch.execute.return_value = MagicMock()
    # _ch_execute is the async wrapper around the sync ch_client.
    # Patch it directly so tests don't spin real threads via run_in_executor.
    mock_ch_execute = AsyncMock(return_value=[])

    with patch("api.main.redis_client", mock_redis), patch(
        "api.main.pg_engine", mock_pg
    ), patch("api.main.ch_client", mock_ch), patch(
        "api.main._ch_execute", mock_ch_execute
    ):
        yield (mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute)


@pytest.fixture
def client():
    from starlette.testclient import TestClient

    return TestClient(app)


@pytest.fixture
def api_key():
    return "test-secret-key"
