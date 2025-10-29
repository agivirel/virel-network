# services/service-users/app/security.py
import os
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel
from .schemas import TokenData

# --- Настройки безопасности ---
# В реальном проекте это должно быть в .env!
SECRET_KEY = "virel-super-secret-key" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # 1 день

# --- Хэширование паролей ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# --- Работа с JWT ---
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt