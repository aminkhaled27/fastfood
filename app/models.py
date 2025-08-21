from .database import Base
from sqlalchemy import Column, Integer, String, Boolean, TIMESTAMP , text , ForeignKey 
from datetime import datetime
from .database import Base
from typing import List, Optional
 
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=text('now()'), nullable=False)
    is_validated = Column(Boolean, default=False, nullable=False)
    otp = Column(String, nullable=True)
    otp_expiration = Column(TIMESTAMP(timezone=True), nullable=True)
    