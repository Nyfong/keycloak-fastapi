from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models.user_model import User
from app.schemas.user_schema import UserCreate
from typing import Optional, List

class UserRepository:
    def __init__(self, db: AsyncSession):
        self.db = db
        
    async def find_by_email(self, email: str) -> Optional[User]:
        result = await self.db.execute(select(User).where(User.email == email))
        return result.scalars().first()

    async def find_all(self) -> List[User]:
        result = await self.db.execute(select(User))
        return result.scalars().all()
