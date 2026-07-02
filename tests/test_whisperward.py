# tests/test_whisperward.py
import pytest
from database import DatabaseManager
from modules.utils import ensure_directories
from modules.roblox_osint import RobloxOSINT
from modules.sherlock_integration import SherlockIntegration

@pytest.fixture
def db(tmp_path):
    # Isolated per-test database. Using the default path would write a real
    # whisperward.db into the working directory every time the suite runs.
    db = DatabaseManager(db_path=str(tmp_path / "test_whisperward.db"))
    db.init()
    return db

def test_create_case(db):
    case_id = db.create_case("Test Case", "Testing Phase 4")
    assert case_id.startswith("CASE-")
    assert len(case_id) >= 12

def test_add_target(db):
    case_id = db.create_case("Test")
    db.add_target(case_id, "roblox", "TestUser123")
    targets = db.get_case_targets(case_id)
    assert len(targets) == 1
    assert targets[0]["username"] == "TestUser123"

@pytest.mark.asyncio
async def test_roblox_module():
    ensure_directories()
    module = RobloxOSINT()
    assert module.module_name == "RobloxOSINT"

@pytest.mark.asyncio
async def test_sherlock_module():
    ensure_directories()
    module = SherlockIntegration()
    assert module.module_name == "SherlockIntegration"

def test_ensure_directories():
    ensure_directories()
    assert True  # If no exception, directories are ready