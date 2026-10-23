import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from backend.models.db_models import Base
from backend.app.database import get_db
from backend.app.main import app
from backend.app.config import settings
from backend.seed import seed_database
from backend.models.schema import Principal

TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture(scope="function")
def test_db():
    engine = create_engine(
        TEST_DB_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()

    seed_database(db=db, clear_existing=False)

    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(test_db):
    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def requester_headers():
    return {
        "Authorization": f"Bearer {settings.TOKEN_REQUESTER}",
        "X-Demo-Role": "requester"
    }


@pytest.fixture
def approver_headers():
    return {
        "Authorization": f"Bearer {settings.TOKEN_APPROVER}",
        "X-Demo-Role": "approver"
    }


@pytest.fixture
def admin_headers():
    return {
        "Authorization": f"Bearer {settings.TOKEN_ADMIN}",
        "X-Demo-Role": "admin"
    }
