# services/service-users/app/schemas.py
from pydantic import BaseModel, EmailStr

# --- Схемы для пользователя ---
class UserBase(BaseModel):
    email: EmailStr
    username: str

class UserCreate(UserBase):
    password: str

class UserPublic(UserBase):
    id: int
    is_active: bool

    class Config:
        orm_mode = True # Позволяет Pydantic читать данные из ORM-моделей

# --- Схемы для токена ---
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None