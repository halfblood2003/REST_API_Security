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


def _register_and_login(client: TestClient, username: str, email: str) -> str:
    register_payload = {
        "username": username,
        "email": email,
        "password": "VeryStrongPass123!",
    }
    register_response = client.post("/register", json=register_payload)
    assert register_response.status_code == 201

    login_response = client.post(
        "/login",
        json={"username": username, "password": "VeryStrongPass123!"},
    )
    assert login_response.status_code == 200
    return login_response.json()["access_token"]


def _csrf_headers(client: TestClient, access_token: str) -> dict[str, str]:
    response = client.get(
        "/csrf-token",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200

    csrf_token = response.json()["csrf_token"]
    csrf_cookie = _cookie_from_set_cookie(response.headers.get("set-cookie", ""), "csrf_token")

    return {
        "Authorization": f"Bearer {access_token}",
        "X-CSRF-Token": csrf_token,
        "Cookie": f"csrf_token={csrf_cookie}",
    }


def _create_item(client: TestClient, access_token: str, title: str) -> int:
    headers = _csrf_headers(client=client, access_token=access_token)
    response = client.post(
        "/items",
        json={"title": title, "description": "desc"},
        headers=headers,
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_user_cannot_access_another_users_item(client: TestClient) -> None:
    token_a = _register_and_login(client, "alice", "alice@example.com")
    token_b = _register_and_login(client, "bob", "bob@example.com")

    item_id = _create_item(client=client, access_token=token_b, title="B item")

    response = client.get(
        f"/items/{item_id}",
        headers={"Authorization": f"Bearer {token_a}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Access denied"


def test_user_can_access_own_item(client: TestClient) -> None:
    token_a = _register_and_login(client, "owner", "owner@example.com")
    item_id = _create_item(client=client, access_token=token_a, title="A item")

    response = client.get(
        f"/items/{item_id}",
        headers={"Authorization": f"Bearer {token_a}"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == item_id


def test_unauthenticated_access_returns_401(client: TestClient) -> None:
    response = client.get("/items/1")
    assert response.status_code == 401
