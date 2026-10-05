from typing import Annotated

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from app import crud
from app.core.config import settings
from app.core.templates import render_template
from app.models import UserCreate, UserRegister, UserUpdate
from app.utils import (
    generate_password_reset_token,
    generate_reset_password_email,
    send_email,
    verify_password_reset_token,
)
from app.web.deps import (
    OptionalUser,
    SessionDep,
    get_csrf_token,
    login_user,
    logout_user,
    pop_flash,
    set_flash,
    validate_csrf,
)

router = APIRouter(tags=["auth"])


def _redirect_if_logged_in(user: OptionalUser) -> RedirectResponse | None:
    if user:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return None


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, user: OptionalUser):
    redirect = _redirect_if_logged_in(user)
    if redirect:
        return redirect
    return render_template(
        request,
        "login.html",
        {"csrf_token": get_csrf_token(request), "flash": pop_flash(request)},
    )


@router.post("/login")
def login(
    request: Request,
    session: SessionDep,
    user: OptionalUser,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
):
    redirect = _redirect_if_logged_in(user)
    if redirect:
        return redirect
    validate_csrf(request, csrf_token)
    db_user = crud.authenticate(session=session, email=email, password=password)
    if not db_user:
        return render_template(
            request,
            "login.html",
            {
                "csrf_token": get_csrf_token(request),
                "error": "Incorrect email or password",
                "email": email,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    if not db_user.is_active:
        return render_template(
            request,
            "login.html",
            {
                "csrf_token": get_csrf_token(request),
                "error": "Inactive user",
                "email": email,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    login_user(request, db_user)
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/logout")
def logout(
    request: Request,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    validate_csrf(request, csrf_token)
    logout_user(request)
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request, user: OptionalUser):
    redirect = _redirect_if_logged_in(user)
    if redirect:
        return redirect
    return render_template(
        request,
        "signup.html",
        {"csrf_token": get_csrf_token(request)},
    )


@router.post("/signup")
def signup(
    request: Request,
    session: SessionDep,
    user: OptionalUser,
    email: Annotated[str, Form()],
    full_name: Annotated[str, Form()],
    password: Annotated[str, Form()],
    confirm_password: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
):
    redirect = _redirect_if_logged_in(user)
    if redirect:
        return redirect
    validate_csrf(request, csrf_token)
    errors: dict[str, str] = {}
    if len(password) < 8:
        errors["password"] = "Password must be at least 8 characters"
    if password != confirm_password:
        errors["confirm_password"] = "Passwords do not match"
    if not full_name.strip():
        errors["full_name"] = "Full name is required"
    if crud.get_user_by_email(session=session, email=email):
        errors["email"] = "A user with this email already exists"
    if errors:
        return render_template(
            request,
            "signup.html",
            {
                "csrf_token": get_csrf_token(request),
                "errors": errors,
                "email": email,
                "full_name": full_name,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    user_in = UserRegister(email=email, password=password, full_name=full_name.strip())
    user_create = UserCreate.model_validate(user_in)
    crud.create_user(session=session, user_create=user_create)
    set_flash(request, "Account created. Please log in.")
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/recover-password", response_class=HTMLResponse)
def recover_password_page(request: Request, user: OptionalUser):
    redirect = _redirect_if_logged_in(user)
    if redirect:
        return redirect
    return render_template(
        request,
        "recover_password.html",
        {"csrf_token": get_csrf_token(request)},
    )


@router.post("/recover-password")
def recover_password(
    request: Request,
    session: SessionDep,
    user: OptionalUser,
    email: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
):
    redirect = _redirect_if_logged_in(user)
    if redirect:
        return redirect
    validate_csrf(request, csrf_token)
    db_user = crud.get_user_by_email(session=session, email=email)
    if db_user and settings.emails_enabled:
        password_reset_token = generate_password_reset_token(email=email)
        email_data = generate_reset_password_email(
            email_to=db_user.email, email=email, token=password_reset_token
        )
        send_email(
            email_to=db_user.email,
            subject=email_data.subject,
            html_content=email_data.html_content,
        )
    set_flash(request, "If that email is registered, we sent a password recovery link")
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(
    request: Request,
    user: OptionalUser,
    token: str = "",
):
    redirect = _redirect_if_logged_in(user)
    if redirect:
        return redirect
    if not token or not verify_password_reset_token(token=token):
        return render_template(
            request,
            "reset_password.html",
            {
                "csrf_token": get_csrf_token(request),
                "error": "Invalid or expired token",
                "token": token,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return render_template(
        request,
        "reset_password.html",
        {"csrf_token": get_csrf_token(request), "token": token},
    )


@router.post("/reset-password")
def reset_password(
    request: Request,
    session: SessionDep,
    user: OptionalUser,
    token: Annotated[str, Form()],
    password: Annotated[str, Form()],
    confirm_password: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
):
    redirect = _redirect_if_logged_in(user)
    if redirect:
        return redirect
    validate_csrf(request, csrf_token)
    email = verify_password_reset_token(token=token)
    if not email:
        return render_template(
            request,
            "reset_password.html",
            {
                "csrf_token": get_csrf_token(request),
                "error": "Invalid or expired token",
                "token": token,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    errors: dict[str, str] = {}
    if len(password) < 8:
        errors["password"] = "Password must be at least 8 characters"
    if password != confirm_password:
        errors["confirm_password"] = "Passwords do not match"
    if errors:
        return render_template(
            request,
            "reset_password.html",
            {
                "csrf_token": get_csrf_token(request),
                "errors": errors,
                "token": token,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    db_user = crud.get_user_by_email(session=session, email=email)
    if not db_user or not db_user.is_active:
        return render_template(
            request,
            "reset_password.html",
            {
                "csrf_token": get_csrf_token(request),
                "error": "Invalid or expired token",
                "token": token,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    user_in_update = UserUpdate(password=password)
    crud.update_user(session=session, db_user=db_user, user_in=user_in_update)
    set_flash(request, "Password updated successfully")
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
