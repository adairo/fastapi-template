from sqlmodel import Session

from app import crud
from app.core.config import settings
from app.models import User, UserCreate
from tests.utils.utils import random_email


def create_random_user(db: Session, password: str = "testpassword123") -> User:
    email = random_email()
    user_in = UserCreate(email=email, password=password)
    return crud.create_user(session=db, user_create=user_in)


def create_test_user(db: Session) -> User:
    user_in = UserCreate(
        email=settings.EMAIL_TEST_USER,
        password="testpassword123",
    )
    user = crud.get_user_by_email(session=db, email=settings.EMAIL_TEST_USER)
    if user:
        return user
    return crud.create_user(session=db, user_create=user_in)
