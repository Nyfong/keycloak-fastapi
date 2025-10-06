from fastapi import FastAPI
from app.routes import public, secure , auth
app = FastAPI(title="FastAPI x Keycloak")

# Include routes
app.include_router(public.router)
app.include_router(secure.router)
app.include_router(auth.router)

