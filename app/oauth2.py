from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError
from datetime import datetime, timedelta, timezone

from app.response_utils import unauthorized_response
from . import schemas, models, database
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

bearer_scheme = HTTPBearer(auto_error=False)

SECRET_KEY = "version0.1ofpostsapplicationthisisthesecretkey0.1anditshouldnotbeexposedthanks0123456789"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
EMAIL_TOKEN_EXPIRE_MINUTES = 60
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = 10


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "token_type": "access"})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "token_type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_access_token(token: str, credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        raw_id = payload.get("user_id")
        token_type = payload.get("token_type")
        if raw_id is None:
            raise credentials_exception
        if token_type != "access":
            raise credentials_exception
        # Ensure the ID is an integer
        try:
            user_id = int(raw_id)
        except (TypeError, ValueError):
            raise credentials_exception
        token_data = schemas.TokenData(id=user_id)
    except JWTError:
        raise credentials_exception
    return token_data
    
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(database.get_db),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=unauthorized_response(
                data=[{"message":"Could not validate credentials"}],
                msg= "Expierd Token"
            ),
        headers={"WWW-Authenticate": "Bearer"}
    )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise credentials_exception
    token = credentials.credentials
    token_data = verify_access_token(token, credentials_exception)
    user = db.query(models.User).filter(models.User.id == token_data.id).first()
    if user is None:
        raise credentials_exception
    return user


def verify_refresh_token(token: str, credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        raw_id = payload.get("user_id")
        token_type = payload.get("token_type")
        exp_ts = payload.get("exp")
        if raw_id is None:
            raise credentials_exception
        if token_type != "refresh":
            raise credentials_exception
        if exp_ts is None:
            raise credentials_exception
        try:
            user_id = int(raw_id)
        except (TypeError, ValueError):
            raise credentials_exception
        token_data = schemas.TokenData(id=user_id)
        expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired; please log in again",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except JWTError:
        raise credentials_exception
    return token_data, expires_at
    

def create_email_verification_token(email: str):
    to_encode = {"email": email, "token_type": "email_verification"}
    expire = datetime.now(timezone.utc) + timedelta(minutes=EMAIL_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_email_verification_token(token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate email verification token",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        token_type = payload.get("token_type")
        if email is None or token_type != "email_verification":
            raise credentials_exception
        token_data = schemas.EmailverificationTokenData(email=email)
    except JWTError:
        raise credentials_exception
    return token_data


def create_password_reset_access_token(email: str):
    to_encode = {"email": email, "token_type": "password_reset"}
    expire = datetime.now(timezone.utc) + timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES) 
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_password_reset_token(token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired password reset token",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        token_type = payload.get("token_type")
        if email is None or token_type != "password_reset":
            raise credentials_exception
        return schemas.PasswordResetTokenData(email=email)
    except JWTError:
        raise credentials_exception