import uuid
from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import col, select

from app import crud
from app.core.config import settings
from app.core.security import get_password_hash, verify_password
from app.core.templates import render_template
from app.models import User, UserCreate, UserUpdate, UserUpdateMe
from app.utils import generate_new_account_email, send_email
from app.web.deps import (
    CurrentUser,
    SessionDep,
    SuperUser,
    get_csrf_token,
    logout_user,
    pop_flash,
    set_flash,
    validate_csrf,
)

router = APIRouter(tags=["users"])


@router.get("/", response_class=HTMLResponse)
def home(request: Request, current_user: CurrentUser):
    return render_template(
        request,
        "home.html",
        {
            "current_user": current_user,
            "csrf_token": get_csrf_token(request),
            "flash": pop_flash(request),
        },
    )


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, current_user: CurrentUser):
    return render_template(
        request,
        "settings.html",
        {
            "current_user": current_user,
            "csrf_token": get_csrf_token(request),
            "flash": pop_flash(request),
        },
    )


@router.post("/settings")
def update_settings(
    request: Request,
    session: SessionDep,
    current_user: CurrentUser,
    full_name: Annotated[str, Form()] = "",
    email: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
):
    validate_csrf(request, csrf_token)
    errors: dict[str, str] = {}
    full_name_value = full_name.strip() or None
    if email and email != current_user.email:
        existing = crud.get_user_by_email(session=session, email=email)
        if existing and existing.id != current_user.id:
            errors["email"] = "A user with this email already exists"
    if errors:
        return render_template(
            request,
            "settings.html",
            {
                "current_user": current_user,
                "csrf_token": get_csrf_token(request),
                "errors": errors,
                "full_name": full_name,
                "email": email,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    user_in = UserUpdateMe(full_name=full_name_value, email=email or None)
    user_data = user_in.model_dump(exclude_unset=True)
    current_user.sqlmodel_update(user_data)
    session.add(current_user)
    session.commit()
    session.refresh(current_user)
    set_flash(request, "Profile updated successfully")
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/settings/password")
def update_password(
    request: Request,
    session: SessionDep,
    current_user: CurrentUser,
    current_password: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
    confirm_password: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
):
    validate_csrf(request, csrf_token)
    errors: dict[str, str] = {}
    verified, _ = verify_password(current_password, current_user.hashed_password)
    if not verified:
        errors["current_password"] = "Incorrect password"
    if len(new_password) < 8:
        errors["new_password"] = "Password must be at least 8 characters"
    if new_password != confirm_password:
        errors["confirm_password"] = "Passwords do not match"
    if current_password == new_password:
        errors["new_password"] = "New password cannot be the same as the current one"
    if errors:
        return render_template(
            request,
            "settings.html",
            {
                "current_user": current_user,
                "csrf_token": get_csrf_token(request),
                "password_errors": errors,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    current_user.hashed_password = get_password_hash(new_password)
    session.add(current_user)
    session.commit()
    set_flash(request, "Password updated successfully")
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/settings/delete")
def delete_self(
    request: Request,
    session: SessionDep,
    current_user: CurrentUser,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    validate_csrf(request, csrf_token)
    if current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super users are not allowed to delete themselves",
        )
    session.delete(current_user)
    session.commit()
    logout_user(request)
    set_flash(request, "Your account has been deleted")
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/users", response_class=HTMLResponse)
def list_users(
    request: Request,
    session: SessionDep,
    current_user: SuperUser,
):
    statement = select(User).order_by(col(User.created_at).desc())
    users = session.exec(statement).all()
    return render_template(
        request,
        "users.html",
        {
            "current_user": current_user,
            "users": users,
            "csrf_token": get_csrf_token(request),
            "flash": pop_flash(request),
        },
    )


@router.post("/users")
def create_user(
    request: Request,
    session: SessionDep,
    current_user: SuperUser,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    confirm_password: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    full_name: Annotated[str, Form()] = "",
    is_active: Annotated[bool, Form()] = False,
    is_superuser: Annotated[bool, Form()] = False,
):
    validate_csrf(request, csrf_token)
    errors: dict[str, str] = {}
    if len(password) < 8:
        errors["password"] = "Password must be at least 8 characters"
    if password != confirm_password:
        errors["confirm_password"] = "Passwords do not match"
    if crud.get_user_by_email(session=session, email=email):
        errors["email"] = "A user with this email already exists"
    if errors:
        statement = select(User).order_by(col(User.created_at).desc())
        users = session.exec(statement).all()
        return render_template(
            request,
            "users.html",
            {
                "current_user": current_user,
                "users": users,
                "csrf_token": get_csrf_token(request),
                "errors": errors,
                "form_email": email,
                "form_full_name": full_name,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    full_name_value = full_name.strip() or None
    user_in = UserCreate(
        email=email,
        password=password,
        full_name=full_name_value,
        is_active=is_active,
        is_superuser=is_superuser,
    )
    user = crud.create_user(session=session, user_create=user_in)
    if settings.emails_enabled:
        email_data = generate_new_account_email(
            email_to=user.email, username=user.email, password=password
        )
        send_email(
            email_to=user.email,
            subject=email_data.subject,
            html_content=email_data.html_content,
        )
    set_flash(request, f"User {user.email} created successfully")
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/edit")
def edit_user(
    request: Request,
    session: SessionDep,
    current_user: SuperUser,
    user_id: uuid.UUID,
    email: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    full_name: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
    confirm_password: Annotated[str, Form()] = "",
    is_active: Annotated[bool, Form()] = False,
    is_superuser: Annotated[bool, Form()] = False,
):
    validate_csrf(request, csrf_token)
    db_user = session.get(User, user_id)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    errors: dict[str, str] = {}
    if email != db_user.email:
        existing = crud.get_user_by_email(session=session, email=email)
        if existing and existing.id != user_id:
            errors["email"] = "A user with this email already exists"
    if password:
        if len(password) < 8:
            errors["password"] = "Password must be at least 8 characters"
        if password != confirm_password:
            errors["confirm_password"] = "Passwords do not match"
    if errors:
        statement = select(User).order_by(col(User.created_at).desc())
        users = session.exec(statement).all()
        return render_template(
            request,
            "users.html",
            {
                "current_user": current_user,
                "users": users,
                "csrf_token": get_csrf_token(request),
                "edit_errors": errors,
                "edit_user_id": user_id,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    user_in = UserUpdate(
        email=email,
        full_name=full_name.strip() or None,
        is_active=is_active,
        is_superuser=is_superuser,
        password=password or None,
    )
    crud.update_user(session=session, db_user=db_user, user_in=user_in)
    set_flash(request, f"User {email} updated successfully")
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/delete")
def delete_user(
    request: Request,
    session: SessionDep,
    current_user: SuperUser,
    user_id: uuid.UUID,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    validate_csrf(request, csrf_token)
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super users are not allowed to delete themselves",
        )
    session.delete(user)
    session.commit()
    set_flash(request, f"User {user.email} deleted successfully")
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)
