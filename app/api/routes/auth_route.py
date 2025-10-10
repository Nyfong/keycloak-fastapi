# /routes/auth.py
from fastapi import APIRouter
from app.schemas.auth import LoginRequest, RegisterRequest
from app.services.auth_service import login, register, get_social_login_url, social_login_callback

router = APIRouter(prefix="/auth", tags=["Auth"])

@router.post("/login")
async def login_route(login_request: LoginRequest):
    return await login(login_request)

@router.post("/register")
async def register_route(user_data: RegisterRequest):
    return await register(user_data)

@router.get("/social-login")
async def social_login_route():
    return await get_social_login_url()

@router.get("/callback")
async def social_login_callback_route(code: str):
    return await social_login_callback(code)