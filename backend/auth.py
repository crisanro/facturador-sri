from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
import base64
import hashlib
import os # <-- NUEVA IMPORTACIÓN

# CONFIGURACIÓN DE SEGURIDAD
SECRET_KEY = os.getenv(
    "APP_SECRET_KEY", 
    "ESTA_CLAVE_DEBE_SER_REEMPLAZADA_POR_UNA_VARIABLE_DE_ENTORNO_EN_PRODUCCION" 
)
ALGORITHM = "HS256"
# Recomendación: Token de API de larga duración (7 días)
ACCESS_TOKEN_EXPIRE_MINUTES = 60 # 7 días

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Inicialización de Fernet para Cifrado Simétrico ---
# Se genera una clave de 32 bytes de largo, codificada en Base64 URL-safe.
try:
    FERNET_KEY = base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest())
    f = Fernet(FERNET_KEY)
except Exception as e:
    print(f"ERROR: No se pudo inicializar Fernet para cifrado reversible: {e}")
    f = None
# --------------------------------------------------------

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

# --- NUEVAS FUNCIONES DE CIFRADO REVERSIBLE PARA LA CLAVE DE LA FIRMA ---

def encrypt_firma_key(plain_key: str) -> str:
    """Cifra la clave de la firma de manera reversible para su almacenamiento."""
    if f:
        return f.encrypt(plain_key.encode('utf-8')).decode('utf-8')
    # Manejo de fallback: si Fernet falló, lanzamos un error en lugar de guardar plano
    raise Exception("El servicio de cifrado interno no está disponible.") 

def decrypt_firma_key(encrypted_key: str) -> str:
    """Descifra la clave de la firma para usarla en el proceso de firma (firmador.py)."""
    if f:
        try:
            return f.decrypt(encrypted_key.encode('utf-8')).decode('utf-8')
        except Exception:
             # Este error puede significar clave incorrecta o clave Fernet incorrecta
             raise Exception("Error al descifrar la clave de la firma. La clave es incorrecta o está dañada.")
    raise Exception("El servicio de cifrado interno no está disponible.")
