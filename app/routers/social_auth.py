from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi_sso.sso.google import GoogleSSO
from fastapi_sso.sso.facebook import FacebookSSO
from sqlalchemy.orm import Session

from .. import schemas, oauth2, models, database
from ..response_utils import success_response, conflict_response, unauthorized_response

import os
from datetime import datetime, timedelta

router = APIRouter(prefix="/auth", tags=["Social Authentication"])

# Load credentials from environment variables for security
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
FACEBOOK_CLIENT_ID = os.getenv("FACEBOOK_CLIENT_ID")
FACEBOOK_CLIENT_SECRET = os.getenv("FACEBOOK_CLIENT_SECRET")

# Replace with your actual redirect URIs

base_url = "https://fastfood-taupe.vercel.app"
localurl = "http://127.0.0.1:8000"


REDIRECT_URI = f"{base_url}/auth/google/callback"
FACEBOOK_REDIRECT_URI = f"{base_url}/auth/facebook/callback"

# Initialize SSO providers
google_sso = GoogleSSO(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    REDIRECT_URI
)

facebook_sso = FacebookSSO(
    FACEBOOK_CLIENT_ID,
    FACEBOOK_CLIENT_SECRET,
    FACEBOOK_REDIRECT_URI
)

@router.get("/google/login")
async def google_login():
    return await google_sso.get_login_url()

@router.get("/google/callback")
async def google_callback(request: Request, db: Session = Depends(database.get_db)):
    try:
        user_info = await google_sso.verify_and_process(request)
        email = user_info.email
        name = user_info.display_name

        user = db.query(models.User).filter(models.User.email == email).first()

        if not user:
            new_user = models.User(
                name=name,
                email=email,
                password="social_login_no_password", 
                is_validated=True
            )
            db.add(new_user)
            db.commit()
            db.refresh(new_user)
            user = new_user

        access_token = oauth2.create_access_token(data={"user_id": user.id})
        refresh_token = oauth2.create_refresh_token(data={"user_id": user.id})

        refresh_token_expires_in = int(timedelta(days=oauth2.REFRESH_TOKEN_EXPIRE_DAYS).total_seconds())

        return success_response(
            data={
                "access_token": access_token,
                "token_type": "bearer",
                "refresh_token": refresh_token,
                "refresh_token_expires_in_seconds": refresh_token_expires_in,
                "user": schemas.UserResponse(
                    id=user.id,
                    name=user.name,
                    email=user.email,
                    created_at=user.created_at,
                    is_validated=user.is_validated
                ).dict()
            },
            msg="User authenticated successfully via Google"
        )
    except Exception as e:
        print(f"Google SSO callback error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=unauthorized_response(
                data=[{"message": "Could not authenticate with Google"}],
                msg="Authentication failed"
            )
        )

@router.get("/facebook/login")
async def facebook_login():
    return await facebook_sso.get_login_url()

@router.get("/facebook/callback")
async def facebook_callback(request: Request, db: Session = Depends(database.get_db)):
    try:
        user_info = await facebook_sso.verify_and_process(request)
        email = user_info.email
        name = user_info.display_name

        user = db.query(models.User).filter(models.User.email == email).first()

        if not user:
            new_user = models.User(
                name=name,
                email=email,
                password="social_login_no_password",
                is_validated=True
            )
            db.add(new_user)
            db.commit()
            db.refresh(new_user)
            user = new_user

        access_token = oauth2.create_access_token(data={"user_id": user.id})
        refresh_token = oauth2.create_refresh_token(data={"user_id": user.id})
        refresh_token_expires_in = int(timedelta(days=oauth2.REFRESH_TOKEN_EXPIRE_DAYS).total_seconds())

        return success_response(
            data={
                "access_token": access_token,
                "token_type": "bearer",
                "refresh_token": refresh_token,
                "refresh_token_expires_in_seconds": refresh_token_expires_in,
                "user": schemas.UserResponse(
                    id=user.id,
                    name=user.name,
                    email=user.email,
                    created_at=user.created_at,
                    is_validated=user.is_validated
                ).dict()
            },
            msg="User authenticated successfully via Facebook"
        )
    except Exception as e:
        print(f"Facebook SSO callback error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=unauthorized_response(
                data=[{"message": "Could not authenticate with Facebook"}],
                msg="Authentication failed"
            )
        )