import re

with open("tests/conftest.py", "r") as f:
    text = f.read()

text = text.replace("mock_pg_conn.execute = AsyncMock()", "mock_pg_conn.execute = AsyncMock(return_value=MagicMock())")

with open("tests/conftest.py", "w") as f:
    f.write(text)

