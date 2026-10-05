from fastapi import APIRouter

from app.web import auth, users

router = APIRouter()
router.include_router(auth.router)
router.include_router(users.router)


@router.get("/health")
def health_check() -> dict[str, bool]:
    return {"ok": True}
