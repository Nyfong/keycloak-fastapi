from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.repositories.user_repo import UserRepository
from app.services.user_service import UserService
from app.schemas.user_schema import UserCreate, UserResponse
from typing import List

router = APIRouter(prefix="/users", tags=["Users"])

# Dependency injection
def get_user_service(db: AsyncSession = Depends(get_db)):
    repo = UserRepository(db)
    service = UserService(repo)
    return service


@router.get("/", response_model=List[UserResponse])
async def list_users(service: UserService = Depends(get_user_service)):
    return await service.get_all_users()
