from pydantic import BaseModel, EmailStr, field_validator
from datetime import datetime
from typing import Optional
import re

class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one capital letter')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one symbol (!@#$%^&*(),.?":{}|<>)')
        
        if len(v) < 8:
            raise ValueError('Password must be at least 6 characters long')
        
        return v

class TokenData(BaseModel):
    id: int

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    created_at: datetime
    is_validated: bool

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class RefreshAccessTokenResponse(BaseModel):
    id: int
    access_token: str
    token_type: str
    refresh_token_expires_in_seconds: int

    

class EmailverificationTokenData(BaseModel):
    email: EmailStr
    token_type: str = "email_verification"

class PasswordResetRequest(BaseModel):
    email: EmailStr

class VerifyOtp(BaseModel):
    email: EmailStr
    otp: str

class ResetPassword(BaseModel):
    reset_token: str
    new_password: str
    
    @field_validator('new_password')
    @classmethod
    def validate_password(cls, v):
                
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one capital letter')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one symbol (!@#$%^&*(),.?":{}|<>)')
        
        if len(v) < 8:
            raise ValueError('Password must be at least 6 characters long')
        
        return v

class PasswordResetTokenData(BaseModel):
    email: EmailStr
    token_type: str = "password_reset"