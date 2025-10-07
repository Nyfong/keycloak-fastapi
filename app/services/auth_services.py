# /services/auth_service.py
import httpx
from fastapi import HTTPException, Depends
from app.schemas.auth import LoginRequest, RegisterRequest
from app.auth.keycloak_verify import verify_token
import os
from dotenv import load_dotenv

load_dotenv()
REALM_NAME = os.getenv("KEYCLOAK_REALM_NAME")
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")
KEYCLOAK_ADMIN_URL = os.getenv("KEYCLOAK_ADMIN_URL")
ADMIN_USERNAME = os.getenv("KEYCLOAK_ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD")
REDIRECT_URI = os.getenv("REDIRECT_URI")

#fix getadmin
async def get_admin_token() -> str:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{KEYCLOAK_URL}/protocol/openid-connect/token",  # Use KEYCLOAK_URL, which points to fastapi-realm
            data={
                "grant_type": "password",
                "client_secret": CLIENT_SECRET,  # Add this
                "client_id": CLIENT_ID,  # New admin client
                "username": ADMIN_USERNAME,  # fastapi-admin
                "password": ADMIN_PASSWORD,  # fastapi-admin-password
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        print("Admin token request URL:", f"{KEYCLOAK_URL}/protocol/openid-connect/token")
        print("Admin token response:", response.status_code, response.text)
        if response.status_code != 200:
            raise HTTPException(status_code=401, detail=f"Admin authentication failed: {response.text}")
        return response.json()["access_token"]
    
 #login   

#login
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
    
#fix register    
async def register(user_data: RegisterRequest) -> dict:
    try:
        admin_token = await get_admin_token()
        print("Admin token obtained:", admin_token[:10] + "...")

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{KEYCLOAK_ADMIN_URL}/realms/{REALM_NAME}/users",
                json={
                    "username": user_data.username,
                    "email": user_data.email,
                    "firstName": user_data.first_name,
                    "lastName": user_data.last_name,
                    "enabled": True,
                    "emailVerified": True,
                },
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/json",
                },
            )
            print("User creation URL:", f"{KEYCLOAK_ADMIN_URL}/realms/{REALM_NAME}/users")
            print("User creation response:", response.status_code, response.text)
            if response.status_code not in [201, 409]:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Registration failed: {response.text}"
                )
            if response.status_code == 409:
                raise HTTPException(status_code=400, detail="User already exists")

            users_response = await client.get(
                f"{KEYCLOAK_ADMIN_URL}/realms/{REALM_NAME}/users?username={user_data.username}",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            print("User retrieval URL:", f"{KEYCLOAK_ADMIN_URL}/realms/{REALM_NAME}/users?username={user_data.username}")
            print("User retrieval response:", users_response.status_code, users_response.json())
            if users_response.status_code != 200 or not users_response.json():
                raise HTTPException(status_code=500, detail="Failed to retrieve created user")
            user_id = users_response.json()[0]["id"]

            password_response = await client.put(
                f"{KEYCLOAK_ADMIN_URL}/realms/{REALM_NAME}/users/{user_id}/reset-password",
                json={
                    "type": "password",
                    "value": user_data.password,
                    "temporary": False,
                },
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/json",
                },
            )
            print("Password set URL:", f"{KEYCLOAK_ADMIN_URL}/realms/{REALM_NAME}/users/{user_id}/reset-password")
            print("Password set response:", password_response.status_code, password_response.text)
            if password_response.status_code != 204:
                raise HTTPException(status_code=500, detail="Failed to set password")

        return {"msg": "User registered successfully", "username": user_data.username}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration error: {str(e)}")
async def get_social_login_url() -> dict:
    auth_url = (
        f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/auth?"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"response_type=code&"
        f"scope=openid%20email%20profile"
    )
    return {"auth_url": auth_url}

async def social_login_callback(code: str) -> dict:
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if response.status_code != 200:
                raise HTTPException(
                    status_code=401,
                    detail=f"Failed to exchange code for token: {response.text}"
                )
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Social login error: {str(e)}")