from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlmodel import Session

from app.core.config import settings
from app.utils import generate_password_reset_token
from tests.conftest import get_csrf_token, login_client
from tests.utils.user import create_test_user


def test_health_check(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_login_page(client: TestClient) -> None:
    response = client.get("/login")
    assert response.status_code == 200
    assert "Log in" in response.text


def test_login_success(client: TestClient) -> None:
    response = client.get("/login")
    csrf_token = get_csrf_token(response.text)
    response = client.post(
        "/login",
        data={
            "email": settings.FIRST_SUPERUSER,
            "password": settings.FIRST_SUPERUSER_PASSWORD,
            "csrf_token": csrf_token,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_login_wrong_password(client: TestClient) -> None:
    response = client.get("/login")
    csrf_token = get_csrf_token(response.text)
    response = client.post(
        "/login",
        data={
            "email": settings.FIRST_SUPERUSER,
            "password": "wrongpassword",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 400
    assert "Incorrect email or password" in response.text


def test_home_requires_login(client: TestClient) -> None:
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_home_authenticated(superuser_client: TestClient) -> None:
    response = superuser_client.get("/")
    assert response.status_code == 200
    assert settings.FIRST_SUPERUSER in response.text


def test_signup(client: TestClient) -> None:
    response = client.get("/signup")
    csrf_token = get_csrf_token(response.text)
    email = "newuser@example.com"
    response = client.post(
        "/signup",
        data={
            "email": email,
            "full_name": "New User",
            "password": "newpassword123",
            "confirm_password": "newpassword123",
            "csrf_token": csrf_token,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login"

    login_response = client.get("/login")
    csrf_token = get_csrf_token(login_response.text)
    response = client.post(
        "/login",
        data={
            "email": email,
            "password": "newpassword123",
            "csrf_token": csrf_token,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert email in response.text


def test_signup_duplicate_email(client: TestClient) -> None:
    response = client.get("/signup")
    csrf_token = get_csrf_token(response.text)
    response = client.post(
        "/signup",
        data={
            "email": settings.FIRST_SUPERUSER,
            "full_name": "Duplicate",
            "password": "newpassword123",
            "confirm_password": "newpassword123",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 400
    assert "already exists" in response.text


def test_logout(superuser_client: TestClient) -> None:
    response = superuser_client.get("/")
    csrf_token = get_csrf_token(response.text)
    response = superuser_client.post(
        "/logout",
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_recover_password(client: TestClient, db: Session) -> None:
    create_test_user(db)
    with patch("app.utils.send_email", return_value=None):
        response = client.get("/recover-password")
        csrf_token = get_csrf_token(response.text)
        response = client.post(
            "/recover-password",
            data={"email": settings.EMAIL_TEST_USER, "csrf_token": csrf_token},
            follow_redirects=False,
        )
    assert response.status_code == 303


def test_reset_password(client: TestClient, db: Session) -> None:
    create_test_user(db)
    token = generate_password_reset_token(email=settings.EMAIL_TEST_USER)
    response = client.get(f"/reset-password?token={token}")
    csrf_token = get_csrf_token(response.text)
    response = client.post(
        "/reset-password",
        data={
            "token": token,
            "password": "resetpassword123",
            "confirm_password": "resetpassword123",
            "csrf_token": csrf_token,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    login_client(client, settings.EMAIL_TEST_USER, "resetpassword123")
    response = client.get("/")
    assert response.status_code == 200
