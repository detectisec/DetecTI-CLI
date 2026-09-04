from datetime import datetime, timedelta
from typing import Optional
import os

from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt

from core.database.config_db import ConfigDBManager, verify_password

# Secret key for JWT (can be stored in .env in production, using a default for simplicity if missing)
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "b33ff8f39572c0ecfc115b882650eb340e4f8d22797e887d2ef1c1d683701254")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minutos

router = APIRouter(tags=["Auth"])

class Token(BaseModel):
    access_token: str
    token_type: str

def get_config_db():
    from pathlib import Path
    project_root = Path(__file__).parent.parent.parent
    db_path = project_root / "data" / "config.sqlite"
    return ConfigDBManager(db_path)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Use a custom dependency instead of OAuth2PasswordBearer directly 
# to check the cookie if the header is not present
def get_current_user(request: Request, config_db: ConfigDBManager = Depends(get_config_db)):
    token = request.cookies.get("detecti_token")
    if not token:
        # fallback to bearer
        auth = request.headers.get("Authorization")
        if auth and auth.startswith("Bearer "):
            token = auth.split(" ")[1]
            
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
        
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = config_db.get_user(username)
    if user is None:
        raise credentials_exception
    return user

@router.post("/login", response_model=Token)
async def login_for_access_token(
    response: Response, 
    form_data: OAuth2PasswordRequestForm = Depends(),
    config_db: ConfigDBManager = Depends(get_config_db)
):
    user = config_db.get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    
    response.set_cookie(
        key="detecti_token", 
        value=access_token, 
        httponly=True, 
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax"
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("detecti_token")
    return {"message": "Successfully logged out"}
