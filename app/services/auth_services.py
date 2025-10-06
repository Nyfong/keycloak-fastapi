# /services/auth_service.py
import httpx
from fastapi import HTTPException
from app.schemas.auth import LoginRequest, RegisterRequest
import os
from dotenv import load_dotenv

load_dotenv()

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")
KEYCLOAK_ADMIN_URL = os.getenv("KEYCLOAK_ADMIN_URL")
ADMIN_USERNAME = os.getenv("KEYCLOAK_ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD")

async def get_admin_token() -> str:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{KEYCLOAK_ADMIN_URL}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": ADMIN_USERNAME,
                "password": ADMIN_PASSWORD,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if response.status_code != 200:
            raise HTTPException(status_code=401, detail="Admin authentication failed")
        return response.json()["access_token"]

async def login(login_request: LoginRequest) -> dict:
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{KEYCLOAK_URL}/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "scope": "openid email profile",
                    "username": login_request.username,
                    "password": login_request.password,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if response.status_code != 200:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid credentials"
                )
            return response.json()  # Returns access_token, refresh_token, etc.
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login error: {str(e)}")

async def register(user_data: RegisterRequest) -> dict:
    try:
        # Get admin token
        admin_token = await get_admin_token()

        # Create user
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{KEYCLOAK_ADMIN_URL}/realms/fastapi-realm/users",
                json={
                    "username": user_data.username,
                    "email": user_data.email,
                    "firstName": user_data.first_name,
                    "lastName": user_data.last_name,
                    "enabled": True,
                    "emailVerified": True,  # Set to False for email verification
                },
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/json",
                },
            )
            if response.status_code not in [201, 409]:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Registration failed: {response.text}"
                )
            if response.status_code == 409:
                raise HTTPException(status_code=400, detail="User already exists")

            # Get user ID
            users_response = await client.get(
                f"{KEYCLOAK_ADMIN_URL}/realms/fastapi-realm/users?username={user_data.username}",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            if users_response.status_code != 200 or not users_response.json():
                raise HTTPException(status_code=500, detail="Failed to retrieve created user")
            user_id = users_response.json()[0]["id"]

            # Set password
            password_response = await client.put(
                f"{KEYCLOAK_ADMIN_URL}/realms/fastapi-realm/users/{user_id}/reset-password",
                json={
                    "type": "password",
                    "value": user_data.password,
                    "temporary": False,  # Set to True for password reset on first login
                },
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/json",
                },
            )
            if password_response.status_code != 204:
                raise HTTPException(status_code=500, detail="Failed to set password")

        return {"msg": "User registered successfully", "username": user_data.username}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration error: {str(e)}")