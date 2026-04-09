from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

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


def _cookie_from_set_cookie(set_cookie_header: str, cookie_name: str) -> str:
    token_prefix = f"{cookie_name}="
    for part in set_cookie_header.split(";"):
        section = part.strip()
        if section.startswith(token_prefix):
            return section.split("=", 1)[1]
    return ""


def _register_and_login(client: TestClient) -> str:
    payload = {
        "username": "csrf-user",
        "email": "csrf@example.com",
        "password": "VeryStrongPass123!",
    }
    register_response = client.post("/register", json=payload)
    assert register_response.status_code == 201

    login_response = client.post(
        "/login",
        json={"username": payload["username"], "password": payload["password"]},
    )
    assert login_response.status_code == 200
    return login_response.json()["access_token"]


def test_post_items_without_csrf_token_returns_403(client: TestClient) -> None:
    token = _register_and_login(client)

    response = client.post(
        "/items",
        json={"title": "No CSRF", "description": "blocked"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


def test_post_items_with_valid_csrf_token_succeeds(client: TestClient) -> None:
    token = _register_and_login(client)

    csrf_response = client.get(
        "/csrf-token",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert csrf_response.status_code == 200

    csrf_token = csrf_response.json()["csrf_token"]
    csrf_cookie = _cookie_from_set_cookie(
        csrf_response.headers.get("set-cookie", ""), "csrf_token"
    )

    response = client.post(
        "/items",
        json={"title": "With CSRF", "description": "allowed"},
        headers={
            "Authorization": f"Bearer {token}",
            "X-CSRF-Token": csrf_token,
            "Cookie": f"csrf_token={csrf_cookie}",
        },
    )

    assert response.status_code == 201
    assert response.json()["title"] == "With CSRF"
