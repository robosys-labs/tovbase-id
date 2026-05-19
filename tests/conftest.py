import os

import pytest
from fastapi.testclient import TestClient

os.environ["DATABASE_URL"] = "sqlite://"

from app.config import settings  # noqa: E402
from app.db import Base, engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from tests.helpers import trusted_bank_keys_json  # noqa: E402


@pytest.fixture(autouse=True)
def trusted_bank_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "trusted_bank_keys_json", trusted_bank_keys_json())


@pytest.fixture()
def client() -> TestClient:
    Base.metadata.drop_all(bind=engine)
    init_db()
    with TestClient(app) as test_client:
        yield test_client
    Base.metadata.drop_all(bind=engine)
