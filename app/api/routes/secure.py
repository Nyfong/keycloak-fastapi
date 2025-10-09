from fastapi import APIRouter, Depends
from app.auth.keycloak_verify import verify_token

router = APIRouter(prefix="/secure", tags=["Secure"])

@router.get("/")
def secure_route(payload: dict = Depends(verify_token)):
    return {"msg": "Secure route", "user": payload}