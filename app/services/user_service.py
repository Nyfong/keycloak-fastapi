from app.repositories.user_repo import UserRepository
from app.schemas.user_schema import UserCreate
from typing import List
from app.models.user_model import User

class UserService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo


    async def get_all_users(self) -> List[User]:
        return await self.user_repo.find_all()
