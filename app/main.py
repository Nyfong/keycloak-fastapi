from fastapi import FastAPI, APIRouter
from app.routes import public, secure , auth ,scan_route

# Create the main FastAPI app
app = FastAPI(title="FastAPI x Keycloak")


# Create a parent router with /api/v1 prefix
api_router = APIRouter(prefix="/api/v1")

# Include all routers in the parent router
api_router.include_router(public.router)
api_router.include_router(secure.router)
api_router.include_router(auth.router)
api_router.include_router(scan_route.router)

# Include the parent router in the app
app.include_router(api_router)