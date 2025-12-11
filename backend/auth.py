# CAMBIO CRÍTICO: Aumentar la duración del token JWT
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 días (10080 minutos)

# Resto del código se mantiene igual...
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
import base64
import hashlib
import os

SECRET_KEY = os.getenv(
    "APP_SECRET_KEY", 
    "ESTA_CLAVE_DEBE_SER_REEMPLAZADA_POR_UNA_VARIABLE_DE_ENTORNO_EN_PRODUCCION" 
)
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

try:
    FERNET_KEY = base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest())
    f = Fernet(FERNET_KEY)
except Exception as e:
    print(f"ERROR: No se pudo inicializar Fernet: {e}")
    f = None

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except:
        return None

def encrypt_firma_key(plain_key: str) -> str:
    if f:
        return f.encrypt(plain_key.encode('utf-8')).decode('utf-8')
    raise Exception("El servicio de cifrado interno no está disponible.") 

def decrypt_firma_key(encrypted_key: str) -> str:
    if f:
        try:
            return f.decrypt(encrypted_key.encode('utf-8')).decode('utf-8')
        except Exception:
            raise Exception("Error al descifrar la clave de la firma.")
    raise Exception("El servicio de cifrado interno no está disponible.")
