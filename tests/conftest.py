import pytest
from starlette.testclient import TestClient
import sys
import os

# Add services to path
sys.path.append(os.path.join(os.path.dirname(__file__), '../services'))

from api.main import app

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def api_key():
    return "dev-secret"
