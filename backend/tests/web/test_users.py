from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlmodel import Session

from app.core.config import settings
from tests.conftest import get_csrf_token, login_client
from tests.utils.user import create_random_user


def test_users_page_requires_superuser(normal_user_client: TestClient) -> None:
    response = normal_user_client.get("/users", follow_redirects=False)
    assert response.status_code == 403


def test_users_page(superuser_client: TestClient) -> None:
    response = superuser_client.get("/users")
    assert response.status_code == 200
    assert "Users" in response.text
    assert settings.FIRST_SUPERUSER in response.text


def test_create_user(superuser_client: TestClient) -> None:
    with patch("app.utils.send_email", return_value=None):
        response = superuser_client.get("/users")
        csrf_token = get_csrf_token(response.text)
        email = "created@example.com"
        response = superuser_client.post(
            "/users",
            data={
                "email": email,
                "full_name": "Created User",
                "password": "createdpass123",
                "confirm_password": "createdpass123",
                "is_active": "true",
                "csrf_token": csrf_token,
            },
            follow_redirects=False,
        )
    assert response.status_code == 303
    response = superuser_client.get("/users")
    assert email in response.text


def test_settings_page(normal_user_client: TestClient) -> None:
    response = normal_user_client.get("/settings")
    assert response.status_code == 200
    assert "Settings" in response.text


def test_update_profile(normal_user_client: TestClient) -> None:
    response = normal_user_client.get("/settings")
    csrf_token = get_csrf_token(response.text)
    response = normal_user_client.post(
        "/settings",
        data={
            "full_name": "Updated Name",
            "email": settings.EMAIL_TEST_USER,
            "csrf_token": csrf_token,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_superuser_cannot_delete_self(superuser_client: TestClient) -> None:
    response = superuser_client.get("/settings")
    csrf_token = get_csrf_token(response.text)
    response = superuser_client.post(
        "/settings/delete",
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 403


def test_delete_user(superuser_client: TestClient, db: Session) -> None:
    user = create_random_user(db)
    response = superuser_client.get("/users")
    csrf_token = get_csrf_token(response.text)
    response = superuser_client.post(
        f"/users/{user.id}/delete",
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    response = superuser_client.get("/users")
    assert user.email not in response.text


def test_normal_user_cannot_access_users_list(client: TestClient, db: Session) -> None:
    user = create_random_user(db)
    login_client(client, user.email, "testpassword123")
    response = client.get("/users")
    assert response.status_code == 403
