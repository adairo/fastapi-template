import secrets
import uuid
from collections.abc import Generator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlmodel import Session

from app.core.db import engine
from app.models import User


def get_db() -> Generator[Session]:
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_db)]


def get_csrf_token(request: Request) -> str:
    if "csrf_token" not in request.session:
        request.session["csrf_token"] = secrets.token_hex(32)
    return request.session["csrf_token"]


def validate_csrf(request: Request, token: str | None) -> None:
    expected = request.session.get("csrf_token")
    if not token or not expected or not secrets.compare_digest(token, expected):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid CSRF token",
        )


def get_current_user_optional(request: Request, session: SessionDep) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    user = session.get(User, uuid.UUID(user_id))
    if not user or not user.is_active:
        return None
    return user


class LoginRequired(Exception):
    pass


def get_current_user(request: Request, session: SessionDep) -> User:
    user = get_current_user_optional(request, session)
    if not user:
        raise LoginRequired()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
OptionalUser = Annotated[User | None, Depends(get_current_user_optional)]


def get_current_superuser(current_user: CurrentUser) -> User:
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user doesn't have enough privileges",
        )
    return current_user


SuperUser = Annotated[User, Depends(get_current_superuser)]


def login_user(request: Request, user: User) -> None:
    request.session["user_id"] = str(user.id)


def logout_user(request: Request) -> None:
    request.session.clear()


def set_flash(request: Request, message: str, category: str = "success") -> None:
    request.session["flash"] = {"message": message, "category": category}


def pop_flash(request: Request) -> dict[str, str] | None:
    return request.session.pop("flash", None)
