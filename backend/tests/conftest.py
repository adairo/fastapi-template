import re
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, delete

from app.core.config import settings
from app.core.db import engine, init_db
from app.main import app
from app.models import User


def get_csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "CSRF token not found in page"
    return match.group(1)


@pytest.fixture(scope="session", autouse=True)
def db() -> Generator[Session]:
    with Session(engine) as session:
        init_db(session)
        yield session
        statement = delete(User)
        session.execute(statement)
        session.commit()


@pytest.fixture
def client() -> Generator[TestClient]:
    with TestClient(app) as c:
        yield c


def login_client(client: TestClient, email: str, password: str) -> None:
    response = client.get("/login")
    csrf_token = get_csrf_token(response.text)
    client.post(
        "/login",
        data={"email": email, "password": password, "csrf_token": csrf_token},
        follow_redirects=True,
    )


@pytest.fixture
def superuser_client(client: TestClient) -> TestClient:
    login_client(
        client,
        settings.FIRST_SUPERUSER,
        settings.FIRST_SUPERUSER_PASSWORD,
    )
    return client


@pytest.fixture
def normal_user_client(client: TestClient, db: Session) -> TestClient:
    from tests.utils.user import create_test_user

    user = create_test_user(db)
    login_client(client, user.email, "testpassword123")
    return client
