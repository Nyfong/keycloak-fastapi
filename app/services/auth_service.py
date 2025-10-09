import httpx
import smtplib
from email.mime.text import MIMEText
from fastapi import HTTPException, Depends
from app.schemas.auth import LoginRequest, RegisterRequest
from app.auth.keycloak_verify import verify_token
import os
import random
import string
from dotenv import load_dotenv
from typing import Dict
from datetime import datetime, timedelta

load_dotenv()

# Environment variables
REALM_NAME = os.getenv("KEYCLOAK_REALM_NAME")
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")
KEYCLOAK_ADMIN_URL = os.getenv("KEYCLOAK_ADMIN_URL")
ADMIN_USERNAME = os.getenv("KEYCLOAK_ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD")
REDIRECT_URI = os.getenv("REDIRECT_URI")
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_USERNAME = os.getenv("EMAIL_USERNAME")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# In-memory OTP store (use Redis in production)
otp_store: Dict[str, Dict] = {}

# Generate 6-digit OTP
def generate_otp(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))

# Send OTP email
def send_otp_email(email: str, otp: str) -> None:
    print(f"Attempting to send OTP {otp} to {email}")
    print(f"SMTP Config: host={EMAIL_HOST}, port={EMAIL_PORT}, username={EMAIL_USERNAME}")
    if not all([EMAIL_HOST, EMAIL_PORT, EMAIL_USERNAME, EMAIL_PASSWORD]):
        raise HTTPException(status_code=500, detail="Missing SMTP configuration")
    
    try:
        # Initialize SMTP connection
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=10)
        server.connect(EMAIL_HOST, EMAIL_PORT)  # Explicitly connect
        server.starttls()  # Enable TLS
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)  # Login
        msg = MIMEText(f"Your OTP code is: {otp}\nIt expires in 5 minutes.")
        msg['Subject'] = 'Your OTP for Registration'
        msg['From'] = EMAIL_USERNAME
        msg['To'] = email
        server.send_message(msg)
        server.quit()  # Close connection
        print(f"OTP {otp} sent successfully to {email}")
    except smtplib.SMTPException as e:
        print(f"SMTP error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"SMTP error: {str(e)}")
    except Exception as e:
        print(f"Email sending failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Email sending failed: {str(e)}")

# Test email sending
def test_email(email: str) -> None:
    print(f"Testing email to {email}")
    try:
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=10)
        server.connect(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        msg = MIMEText("This is a test email from your FastAPI app.")
        msg['Subject'] = 'Test Email'
        msg['From'] = EMAIL_USERNAME
        msg['To'] = email
        server.send_message(msg)
        server.quit()
        print(f"Test email sent successfully to {email}")
    except Exception as e:
        print(f"Test email failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Test email failed: {str(e)}")

# Get admin token for Keycloak
async def get_admin_token() -> str:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{KEYCLOAK_URL}/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_secret": CLIENT_SECRET,
                "client_id": CLIENT_ID,
                "username": ADMIN_USERNAME,
                "password": ADMIN_PASSWORD,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        print("Admin token request URL:", f"{KEYCLOAK_URL}/protocol/openid-connect/token")
        print("Admin token response:", response.status_code, response.text)
        if response.status_code != 200:
            raise HTTPException(status_code=401, detail=f"Admin authentication failed: {response.text}")
        return response.json()["access_token"]

# Login
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
                raise HTTPException(status_code=401, detail="Invalid credentials")
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login error: {str(e)}")

# Register with OTP
async def register(user_data: RegisterRequest) -> dict:
    try:
        admin_token = await get_admin_token()
        print("Admin token obtained:", admin_token[:10] + "...")

        async with httpx.AsyncClient() as client:
            # Create user in Keycloak
            response = await client.post(
                f"{KEYCLOAK_ADMIN_URL}/realms/{REALM_NAME}/users",
                json={
                    "username": user_data.username,
                    "email": user_data.email,
                    "firstName": user_data.first_name,
                    "lastName": user_data.last_name,
                    "enabled": True,
                    "emailVerified": False,
                    "requiredActions": ["CONFIGURE_TOTP"],
                },
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/json",
                },
            )
            print("User creation URL:", f"{KEYCLOAK_ADMIN_URL}/realms/{REALM_NAME}/users")
            print("User creation response:", response.status_code, response.text)
            if response.status_code == 409:
                raise HTTPException(status_code=400, detail="User already exists")
            if response.status_code != 201:
                raise HTTPException(status_code=response.status_code, detail=f"Registration failed: {response.text}")

            # Get user ID
            users_response = await client.get(
                f"{KEYCLOAK_ADMIN_URL}/realms/{REALM_NAME}/users?username={user_data.username}",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            print("User retrieval URL:", f"{KEYCLOAK_ADMIN_URL}/realms/{REALM_NAME}/users?username={user_data.username}")
            print("User retrieval response:", users_response.status_code, users_response.json())
            if users_response.status_code != 200 or not users_response.json():
                raise HTTPException(status_code=500, detail="Failed to retrieve created user")
            user_id = users_response.json()[0]["id"]

            # Set password
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

            # Generate and send OTP
            otp = generate_otp()
            print(f"Generated OTP: {otp} for {user_data.email}")
            otp_store[user_data.email] = {
                "otp": otp,
                "expires": datetime.utcnow() + timedelta(minutes=5)
            }
            print(f"Stored OTP: {otp_store}")
            send_otp_email(user_data.email, otp)

        return {"msg": "User registered successfully, OTP sent to email", "username": user_data.username}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Registration error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Registration error: {str(e)}")

# Verify OTP
async def verify_otp(email: str, otp: str) -> Dict:
    try:
        if email not in otp_store:
            raise HTTPException(status_code=400, detail="No OTP found for this email")
        
        stored_otp = otp_store[email]
        if datetime.utcnow() > stored_otp["expires"]:
            del otp_store[email]
            raise HTTPException(status_code=400, detail="OTP expired")
        
        if otp != stored_otp["otp"]:
            raise HTTPException(status_code=400, detail="Invalid OTP")

        # Mark email as verified in Keycloak
        admin_token = await get_admin_token()
        async with httpx.AsyncClient() as client:
            users_response = await client.get(
                f"{KEYCLOAK_ADMIN_URL}/realms/{REALM_NAME}/users?email={email}",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            print("User retrieval for OTP verification:", users_response.status_code, users_response.json())
            if users_response.status_code != 200 or not users_response.json():
                raise HTTPException(status_code=500, detail="Failed to retrieve user")
            user_id = users_response.json()[0]["id"]

            update_response = await client.put(
                f"{KEYCLOAK_ADMIN_URL}/realms/{REALM_NAME}/users/{user_id}",
                json={"emailVerified": True},
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/json",
                },
            )
            print("Email verification update:", update_response.status_code, update_response.text)
            if update_response.status_code != 204:
                raise HTTPException(status_code=500, detail=f"Failed to verify email: {update_response.text}")

        del otp_store[email]
        return {"msg": "OTP verified successfully, email marked as verified"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"OTP verification error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"OTP verification error: {str(e)}")

# Reset OTP
async def reset_otp(email: str) -> Dict:
    try:
        admin_token = await get_admin_token()
        async with httpx.AsyncClient() as client:
            users_response = await client.get(
                f"{KEYCLOAK_ADMIN_URL}/realms/{REALM_NAME}/users?email={email}",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            print("User retrieval for OTP reset:", users_response.status_code, users_response.json())
            if users_response.status_code != 200 or not users_response.json():
                raise HTTPException(status_code=404, detail="User not found")

            otp = generate_otp()
            print(f"Generated new OTP: {otp} for {email}")
            otp_store[email] = {
                "otp": otp,
                "expires": datetime.utcnow() + timedelta(minutes=5)
            }
            print(f"Stored OTP: {otp_store}")
            send_otp_email(email, otp)

        return {"msg": "New OTP sent to email"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"OTP reset error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"OTP reset error: {str(e)}")

# Social login URL
async def get_social_login_url() -> dict:
    auth_url = (
        f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/auth?"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"response_type=code&"
        f"scope=openid%20email%20profile"
    )
    return {"auth_url": auth_url}

# Social login callback
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
                raise HTTPException(status_code=401, detail=f"Failed to exchange code for token: {response.text}")
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Social login error: {str(e)}")