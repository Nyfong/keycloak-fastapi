from fastapi import APIRouter
from app.schemas.auth import LoginRequest, RegisterRequest
from app.services.auth_service import login, register, get_social_login_url, social_login_callback, verify_otp, reset_otp, test_email
from typing import Dict

router = APIRouter(prefix="/auth", tags=["Auth"])

@router.post("/login")
async def login_route(login_request: LoginRequest):
    return await login(login_request)

@router.post("/register")
async def register_route(user_data: RegisterRequest):
    return await register(user_data)

@router.post("/verify-otp")
async def verify_otp_route(email: str, otp: str) -> Dict:
    return await verify_otp(email, otp)

@router.post("/reset-otp")
async def reset_otp_route(email: str) -> Dict:
    return await reset_otp(email)

@router.get("/social-login")
async def social_login_route():
    return await get_social_login_url()

@router.get("/callback")
async def social_login_callback_route(code: str):
    return await social_login_callback(code)

@router.post("/test-email")
async def test_email_route(email: str) -> Dict:
    test_email(email)
    return {"msg": f"Test email sent to {email}"}