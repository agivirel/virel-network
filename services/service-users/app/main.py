# services/service-users/app/main.py
import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import OperationalError
from jose import JWTError, jwt
from datetime import timedelta

# --- CORS ---
from fastapi.middleware.cors import CORSMiddleware

# --- Локальные импорты ---
from . import models, schemas, crud, security
from .models import Base
from .schemas import TokenData

# --- Настройка БД ---
DATABASE_URL = os.environ.get("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# !!! ЭТА СТРОКА СОЗДАЕТ ТАБЛИЦЫ В БД ПРИ ЗАПУСКЕ !!!
Base.metadata.create_all(bind=engine)

app = FastAPI(title="VIREL Users Service")

# --- Настройка CORS ---
# Разрешаем нашему фронтенду (localhost:3000) делать запросы
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Зависимости (Dependencies) ---

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Схема аутентификации
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def authenticate_user(db: Session, username: str, password: str):
    """Проверяет, существует ли юзер и верен ли пароль."""
    # Мы используем username для входа, но можно и email
    user = crud.get_user_by_username(db, username)
    if not user:
        return False
    if not security.verify_password(password, user.hashed_password):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Декодирует токен и возвращает пользователя."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, security.SECRET_KEY, algorithms=[security.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = crud.get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# --- Эндпоинты (API Routes) ---

@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected"}
    except OperationalError:
        raise HTTPException(status_code=503, detail="Database connection failed")

@app.post("/register", response_model=schemas.UserPublic)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Регистрация нового пользователя."""
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user_username = crud.get_user_by_username(db, username=user.username)
    if db_user_username:
        raise HTTPException(status_code=400, detail="Username already taken")
        
    return crud.create_user(db=db, user=user)

@app.post("/login", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Вход пользователя. Принимает form-data (не JSON!).
    username - это поле username, которое мы создали.
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = security.create_access_token(
        data={"sub": user.username} # "sub" (subject) - стандартное имя для ID в JWT
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=schemas.UserPublic)
async def read_users_me(current_user: schemas.UserPublic = Depends(get_current_user)):
    """Защищенный эндпоинт, возвращает "себя"."""
    return current_user