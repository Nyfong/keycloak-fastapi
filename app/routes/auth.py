# /routes/auth.py
from fastapi import APIRouter
from app.schemas.auth import LoginRequest, RegisterRequest
from app.services.auth_services import login, register

router = APIRouter(prefix="/auth", tags=["Auth"])

@router.post("/login")
async def login_route(login_request: LoginRequest):
    return await login(login_request)

@router.post("/register")
async def register_route(user_data: RegisterRequest):
    return await register(user_data)