from collections.abc import Generator
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.jwt_handler import create_access_token, create_refresh_token
from app.database import Base, get_db
from app.main import app


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db() -> Generator[Session, None, None]:
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def test_register_with_valid_data_returns_201(client: TestClient) -> None:
    response = client.post(
        "/register",
        json={
            "username": "new-user",
            "email": "new-user@example.com",
            "password": "VeryStrongPass123!",
        },
    )

    assert response.status_code == 201
    assert response.json()["username"] == "new-user"


def test_login_with_wrong_password_returns_401(client: TestClient) -> None:
    register_payload = {
        "username": "wrong-pass",
        "email": "wrong-pass@example.com",
        "password": "VeryStrongPass123!",
    }
    client.post("/register", json=register_payload)

    response = client.post(
        "/login",
        json={"username": "wrong-pass", "password": "invalid-password"},
    )

    assert response.status_code == 401


def test_refresh_with_expired_token_returns_401(client: TestClient) -> None:
    register_payload = {
        "username": "refresh-user",
        "email": "refresh-user@example.com",
        "password": "VeryStrongPass123!",
    }
    client.post("/register", json=register_payload)

    expired_refresh = create_refresh_token(
        subject="refresh-user",
        expires_delta=timedelta(seconds=-1),
    )

    response = client.post(
        "/refresh",
        headers={"Cookie": f"refresh_token={expired_refresh}"},
    )

    assert response.status_code == 401


def test_jwt_token_expiry(client: TestClient) -> None:
    register_payload = {
        "username": "token-user",
        "email": "token-user@example.com",
        "password": "VeryStrongPass123!",
    }
    client.post("/register", json=register_payload)

    expired_access = create_access_token(
        subject="token-user",
        expires_delta=timedelta(seconds=-1),
    )

    response = client.get(
        "/items",
        headers={"Authorization": f"Bearer {expired_access}"},
    )

    assert response.status_code == 401
