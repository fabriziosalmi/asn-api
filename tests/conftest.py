# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

import pytest
from starlette.testclient import TestClient
import sys
import os

# Add services to path
sys.path.append(os.path.join(os.path.dirname(__file__), '../services'))

from api.main import app

from unittest.mock import MagicMock, patch

# Mock dependencies before importing app (since it connects on import)
with patch('redis.Redis'), patch('sqlalchemy.create_engine'), patch('clickhouse_driver.Client'):
    from api.main import app

@pytest.fixture(autouse=True)
def mock_dependencies():
    # Patch the actual instances in api.main
    with patch('api.main.redis_client') as mock_redis, \
         patch('api.main.pg_engine') as mock_pg, \
         patch('api.main.ch_client') as mock_ch:
        
        # Configure mocks to return success status for health checks
        mock_redis.ping.return_value = True
        mock_redis.incr.return_value = 1
        
        # Mock result of 'SELECT 1' for Postgres
        mock_pg_conn = MagicMock()
        mock_pg.connect.return_value.__enter__.return_value = mock_pg_conn
        mock_pg_conn.execute.return_value = MagicMock()
        
        # Mock ClickHouse execute
        mock_ch.execute.return_value = MagicMock()
        
        yield (mock_redis, mock_pg, mock_ch)

@pytest.fixture
def client():
    # Re-import to ensure mocked state? No, TestClient takes app.
    return TestClient(app)

@pytest.fixture
def api_key():
    return "dev-secret"
