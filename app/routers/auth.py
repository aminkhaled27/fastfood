import datetime
import secrets
from fastapi import APIRouter, Depends, HTTPException, status, Response, BackgroundTasks
from fastapi.security.oauth2 import OAuth2PasswordRequestForm 
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from .. import models, schemas, utils, oauth2
from .. import database
from .. import email_utils
from ..database import get_db
from ..oauth2 import bearer_scheme
from ..response_utils import (
    success_response, 
    error_response, 
    not_found_response, 
    unauthorized_response, 
    forbidden_response, 
    conflict_response
)

router=(APIRouter(
    prefix="/auth",
    tags=["Auth"]
))

@router.post("/register",status_code=status.HTTP_201_CREATED)
async def register_user(
    user: schemas.UserRegister, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(database.get_db)
):
    email_lower = user.email.lower()
    user.email = email_lower
    existing_user = db.query(models.User).filter(models.User.email == user.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=conflict_response(
                msg="Email already registered"
            )
        )
    hashed_password = utils.hash_password(user.password)
    new_user = models.User(
        name=user.name,
        email=user.email,
        password=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    verification_token = oauth2.create_email_verification_token(new_user.email)
    background_tasks.add_task(
        email_utils.send_verification_email, 
        email_to=new_user.email, 
        token=verification_token
    )
    return success_response(
        data={"email": new_user.email},
        msg="Your registration was successful! Please check your email to verify your account and complete the process.",
        status_code=201
    )

@router.get("/verify-email", status_code=status.HTTP_200_OK)
def verify_email(token: str, db: Session = Depends(database.get_db)):
    try:
        token_data = oauth2.verify_email_verification_token(token)
        email = token_data.email
        print(f"Email from token: {email}")
    except HTTPException as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_response(
                ret=400,
                msg="Invalid or expired email verification token"
            )
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_response(
                ret=400,
                msg="Token verification error"
            )
        )
    
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=not_found_response("User not found")
        )
    
    if user.is_validated:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_response(
                ret=400,
                msg="Email already verified"
            )
        )
    
    user.is_validated = True
    db.commit()
    return success_response(
        data={"email": user.email},
        msg="Email verified successfully"
    )

@router.post("/login")
def login(user_cerdentials: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.email == user_cerdentials.username.lower()).first()
    if not user or not utils.verify_password(user_cerdentials.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=unauthorized_response("Invalid credentials")
        )
    if not utils.verify_password(user_cerdentials.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=unauthorized_response("Incorrect password")
        )
    if not user.is_validated:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=forbidden_response("Email not verified. Please check your email for verification link.")
        )
    access_token = oauth2.create_access_token(data={"user_id": user.id})
    refresh_token = oauth2.create_refresh_token(data={"user_id": user.id})
    return success_response(
        data={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user_id": user.id,
            "email": user.email
        },
        msg="Login successful"
    )

@router.post("/forgot-password", status_code=status.HTTP_200_OK)
async def forgot_password(request: schemas.PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=not_found_response("User with this email not found")
        )
    
    otp = secrets.randbelow(900000) + 100000
    otp_str = str(otp)
    hashed_otp = utils.hash_password(otp_str)
    
    user.otp = hashed_otp
    user.otp_expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
    db.commit()
    
    # You would use a background task here for the actual email sending in a production environment
    await email_utils.send_otp_email(user.email, otp_str)
    
    return success_response(
        data={"email": user.email},
        msg="An OTP has been sent to your email to reset your password."
    )

@router.post("/verify-otp", status_code=status.HTTP_200_OK)
def verify_otp(request: schemas.VerifyOtp, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=not_found_response("User not found")
        )
    
    if not user.otp or not utils.verify_password(request.otp, user.otp):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_response(
                ret=400,
                msg="Invalid OTP"
            )
        )
    
    if user.otp_expiration and datetime.datetime.now(datetime.timezone.utc) > user.otp_expiration:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_response(
                ret=400,
                msg="OTP has expired. Please request a new one."
            )
        )

    # If valid, generate a short-lived password reset token
    reset_token = oauth2.create_password_reset_access_token(email=user.email)
    
    return success_response(
        data={"reset_token": reset_token},
        msg="OTP is valid."
    )

@router.post("/reset-password", status_code=status.HTTP_200_OK)
def reset_password(
    request: schemas.ResetPassword,
    db: Session = Depends(get_db)
):
    # Verify the reset token
    try:
        token_data = oauth2.verify_password_reset_token(request.reset_token)
    except HTTPException:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_response(
                ret=400,
                msg="Invalid or expired reset token"
            )
        )
    
    user = db.query(models.User).filter(models.User.email == token_data.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=not_found_response("User not found")
        )

    # Hash the new password and update it
    hashed_password = utils.hash_password(request.new_password)
    user.password = hashed_password
    
    # Clear the OTP to prevent token re-use with old OTP
    user.otp = None
    user.otp_expiration = None
    db.commit()
    
    return success_response(
        data={"email": user.email},
        msg="Password has been successfully reset."
    )

# Refresh endpoint using Bearer refresh token
bearer_scheme = HTTPBearer(auto_error=False)

@router.post("/refresh", response_model=schemas.RefreshAccessTokenResponse)
def refresh_token(
    body: schemas.RefreshTokenRequest | None = None,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(database.get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=unauthorized_response("Could not validate credentials")
    )
    # Prefer token from body if provided
    token_value = None
    if body and body.refresh_token:
        token_value = body.refresh_token
    elif credentials is not None and credentials.scheme and credentials.scheme.lower() == "bearer":
        token_value = credentials.credentials
    else:
        raise credentials_exception

    token_data, expires_at = oauth2.verify_refresh_token(token_value, credentials_exception)
    user = db.query(models.User).filter(models.User.id == token_data.id).first()
    if user is None:
        raise credentials_exception

    new_access_token = oauth2.create_access_token({"user_id": user.id})

    # Remaining lifetime of the provided refresh token in seconds
    from datetime import datetime, timezone as _tz
    now = datetime.now(_tz.utc)
    remaining_seconds = max(0, int((expires_at - now).total_seconds()))

    return success_response(
        data=schemas.RefreshAccessTokenResponse(
            id=user.id,
            access_token=new_access_token,
            token_type="bearer",
            refresh_token_expires_in_seconds=remaining_seconds
        ),
        msg="Token refreshed successfully"
    )

@router.delete("/delete-user/{id}")
async def delete_user(id: int, db: Session = Depends(get_db), current_user: models.User = Depends(oauth2.get_current_user)):
    user = db.query(models.User).filter(models.User.id == id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=not_found_response("User not found")
        )
    
    db.delete(user)
    db.commit()
    
    return success_response(
        data={"deleted_user_id": id},
        msg="User deleted successfully"
    )


@router.get("/get-all-users")
async def get_all_users(db: Session = Depends(get_db), current_user: models.User = Depends(oauth2.get_current_user)):
    all_users = db.query(models.User).all()
    if not all_users:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=not_found_response("User not found")
        )
    return success_response(
        data=all_users,
        message="",
    )