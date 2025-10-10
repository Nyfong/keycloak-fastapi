# app/models/user_detail_model.py
from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
import uuid
from app.core.database import Base

class UserDetail(Base):
    __tablename__ = "user_detail"

    detail_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("user.user_id"), nullable=False)
    full_name = Column(String(100), nullable=False)
    gender = Column(String(20), nullable=False)
    email = Column(String(90), nullable=False)
    profile_img_url = Column(String(500))
