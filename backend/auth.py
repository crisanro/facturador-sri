from datetime import datetime, timedelta
from typing import Optional
from jose import jwt
from passlib.context import CryptContext

# CONFIGURACIÓN DE SEGURIDAD
SECRET_KEY = "TU_SECRETO_SUPER_SEGURO_CAMBIALO_POR_ALGO_LARGO"
ALGORITHM = "HS256"
# Recomendación: Token de API de larga duración (7 días)
ACCESS_TOKEN_EXPIRE_MINUTES = 60 # 7 días

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    """Encripta la contraseña antes de guardarla en la BD"""
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    """Verifica si la contraseña es correcta"""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    """Genera el Token JWT"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    """Lee el token y nos dice de quién es"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except:

        return None
