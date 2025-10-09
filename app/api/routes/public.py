from fastapi import APIRouter

router = APIRouter(prefix="", tags=["Public"])

@router.get("/")
def home():
    return {"msg": "Welcome to FastAPI x Keycloak"}
