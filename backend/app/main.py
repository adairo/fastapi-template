from pathlib import Path

import sentry_sdk
from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse
from starlette.staticfiles import StaticFiles

from app.core.config import settings
from app.web.deps import LoginRequired
from app.web.router import router as web_router

STATIC_DIR = Path(__file__).parent / "static"

if settings.SENTRY_DSN and settings.FASTAPI_ENV != "development":
    sentry_sdk.init(dsn=str(settings.SENTRY_DSN), enable_tracing=True)

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=None,
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    max_age=settings.SESSION_MAX_AGE_SECONDS,
    https_only=settings.SERVER_HOST.startswith("https"),
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.include_router(web_router)


@app.exception_handler(LoginRequired)
async def login_required_handler(
    _request: Request, _exc: LoginRequired
) -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=303)
