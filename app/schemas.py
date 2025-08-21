from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional

class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserRegisterResponse(BaseModel):
    Message: str
    email: EmailStr
    Register_Token: str


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

class PasswordResetTokenData(BaseModel):
    email: EmailStr
    token_type: str = "password_reset"