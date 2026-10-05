from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from app.core.config import settings

templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")


def render_template(
    request: Request,
    name: str,
    context: dict[str, Any],
    status_code: int = 200,
) -> Response:
    return templates.TemplateResponse(
        request,
        name,
        {"project_name": settings.PROJECT_NAME, **context},
        status_code=status_code,
    )
