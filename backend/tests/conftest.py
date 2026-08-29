import os
import sys
import tempfile
import pytest

# Create an isolated temporary SQLite database path specifically for test runs
TEST_TMP_DIR = tempfile.gettempdir()
TEST_DB_PATH = os.path.join(TEST_TMP_DIR, "threatsentinel_test_isolated.db").replace(os.sep, "/")
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH}"

# Ensure backend package is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models import Base, engine

@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    # Build schema in isolated test database
    Base.metadata.create_all(bind=engine)
    yield
    # Cleanup test database on session completion
    try:
        if os.path.exists(TEST_DB_PATH):
            os.remove(TEST_DB_PATH)
    except Exception:
        pass
