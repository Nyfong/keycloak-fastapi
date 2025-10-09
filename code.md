import json
from typing import List
import httpx
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import jwt, jwk
from jose.exceptions import JWTError
from pydantic import BaseModel
from dotenv import load_dotenv
import os

# Load environment variables

load_dotenv()

# Configuration

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:1280")
REALM_NAME = os.getenv("REALM_NAME", "fastapi-realm")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "fastapi-client")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET") # Must be set in .env

# JWKS URL

JWKS_URL = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/certs"

# OAuth2 scheme for Authorization Code flow

oauth2_scheme = OAuth2AuthorizationCodeBearer(
authorizationUrl=f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/auth",
tokenUrl=f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/token",
auto_error=False
)

# FastAPI app

app = FastAPI()

# Models

class TokenData(BaseModel):
username: str
roles: List[str]

class Item(BaseModel):
name: str
description: str
price: float

# Token validation function

async def validate_token(token: str) -> TokenData:
if not token:
raise HTTPException(status_code=401, detail="No token provided")

    # Strip "Bearer " prefix and clean token
    token = token.replace("Bearer ", "").strip()

    # Validate token format
    try:
        parts = token.split(".")
        if len(parts) != 3:
            print(f"Invalid token format: {token[:20]}... has {len(parts)} parts")
            raise HTTPException(status_code=401, detail="Invalid token format: Must have 3 parts (header.payload.signature)")
    except Exception as e:
        print(f"Token format error: {str(e)}, token: {token[:20]}...")
        raise HTTPException(status_code=401, detail=f"Invalid token format: {str(e)}")

    try:
        # Debug: Log token
        print(f"Received token: {token[:20]}...")

        # Decode headers
        headers = jwt.get_unverified_headers(token)
        print(f"Token headers: {headers}")
        kid = headers.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Token missing 'kid' header")

        # Fetch JWKS
        async with httpx.AsyncClient() as client:
            response = await client.get(JWKS_URL)
            response.raise_for_status()
            jwks = response.json()

        # Find the correct key
        key_data = next((key for key in jwks["keys"] if key["kid"] == kid), None)
        if not key_data:
            raise HTTPException(status_code=401, detail="Matching key not found in JWKS")

        # Convert JWK to RSA public key
        public_key = jwk.construct(key_data).public_key()

        # Verify token
        payload = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            audience=[KEYCLOAK_CLIENT_ID, "account"],  # Allow multiple audiences
            options={"verify_aud": True}
        )
        print(f"Token payload: {payload}")

        # Extract username and roles
        username = payload.get("preferred_username")
        roles = payload.get("realm_access", {}).get("roles", [])
        if not username:
            raise HTTPException(status_code=401, detail="Token missing preferred_username")
        if not roles:
            print("Warning: No roles found in token")

        return TokenData(username=username, roles=roles)

    except JWTError as e:
        print(f"JWTError: {str(e)}, token: {token[:20]}...")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        print(f"General error: {str(e)}, token: {token[:20]}...")
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

# Dependency to get the current user

async def get_current_user(token: str = Depends(oauth2_scheme)):
return await validate_token(token)

# Role-Based Access Control (RBAC)

def has_role(required_role: str):
async def role_checker(token_data: TokenData = Depends(get_current_user)) -> TokenData:
if required_role not in token_data.roles:
raise HTTPException(status_code=403, detail=f"Role '{required_role}' required")
return token_data
return role_checker

# Routes

@app.get("/public")
async def public_endpoint():
return {"message": "This is a public endpoint accessible to everyone."}

@app.get("/protected")
async def protected_endpoint(current_user: TokenData = Depends(get_current_user)):
return {
"message": f"Hello {current_user.username}, you are authenticated!",
"roles": current_user.roles,
}

# In-memory database

items_db = {}

# Create an item (Admin only)

@app.post("/admin/items", dependencies=[Depends(has_role("admin"))])
async def create_item(item: Item):
if item.name in items_db:
raise HTTPException(status_code=400, detail="Item already exists")
items_db[item.name] = item
return {"message": f"Item '{item.name}' created successfully", "item": item}

# Read all items (Admin only)

@app.get("/admin/items", dependencies=[Depends(has_role("admin"))])
async def get_all_items():
return {"items": list(items_db.values())}

# Read a single item (Admin only)

@app.get("/admin/items/{item_name}", dependencies=[Depends(has_role("admin"))])
async def get_item(item_name: str):
item = items_db.get(item_name)
if not item:
raise HTTPException(status_code=404, detail="Item not found")
return item

# Update an item (Admin only)

@app.put("/admin/items/{item_name}", dependencies=[Depends(has_role("admin"))])
async def update_item(item_name: str, updated_item: Item):
if item_name not in items_db:
raise HTTPException(status_code=404, detail="Item not found")
items_db[item_name] = updated_item
return {"message": f"Item '{item_name}' updated successfully", "item": updated_item}

# Delete an item (Admin only)

@app.delete("/admin/items/{item_name}", dependencies=[Depends(has_role("admin"))])
async def delete_item(item_name: str):
if item_name not in items_db:
raise HTTPException(status_code=404, detail="Item not found")
del items_db[item_name]
return {"message": f"Item '{item_name}' deleted successfully"}

# Developer endpoint (read-only)

@app.get("/developer", dependencies=[Depends(has_role("developer"))])
async def developer_endpoint():
return {"items": list(items_db.values())}

# Password flow endpoint

@app.post("/get-token-password")
async def get_token_password(username: str, password: str):
if not KEYCLOAK_CLIENT_SECRET:
raise HTTPException(status_code=500, detail="KEYCLOAK_CLIENT_SECRET not set in .env")
async with httpx.AsyncClient() as client:
response = await client.post(
f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/token",
data={
"grant_type": "password",
"client_id": KEYCLOAK_CLIENT_ID,
"client_secret": KEYCLOAK_CLIENT_SECRET,
"username": username,
"password": password,
"scope": "openid profile",
},
headers={"Content-Type": "application/x-www-form-urlencoded"},
)
if response.status_code == 200:
return response.json()
else:
raise HTTPException(status_code=response.status_code, detail=response.json())

# Callback for Authorization Code flow

@app.get("/callback")
async def callback(code: str):
if not KEYCLOAK_CLIENT_SECRET:
raise HTTPException(status_code=500, detail="KEYCLOAK_CLIENT_SECRET not set in .env")
async with httpx.AsyncClient() as client:
response = await client.post(
f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/token",
data={
"grant_type": "authorization_code",
"client_id": KEYCLOAK_CLIENT_ID,
"client_secret": KEYCLOAK_CLIENT_SECRET,
"code": code,
"redirect_uri": "http://localhost:8000/callback",
},
headers={"Content-Type": "application/x-www-form-urlencoded"},
)
if response.status_code == 200:
return response.json()
else:
raise HTTPException(status_code=response.status_code, detail=response.json())
