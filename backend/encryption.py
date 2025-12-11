# encryption.py

import os
from cryptography.fernet import Fernet
from fastapi import HTTPException

# Cargar la clave de encriptación desde las variables de entorno
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

if not ENCRYPTION_KEY:
    # ¡CRÍTICO! Si la clave no está, el sistema es inseguro e inoperable
    print("FATAL: La variable de entorno ENCRYPTION_KEY no está definida.")
    exit(1)

# Inicializar Fernet con la clave
try:
    f = Fernet(ENCRYPTION_KEY)
except Exception as e:
    print(f"FATAL: Error al inicializar Fernet: {e}")
    exit(1)


def encrypt_data(data: str) -> str:
    """Cifra una cadena de texto."""
    try:
        token = f.encrypt(data.encode())
        return token.decode()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al cifrar datos: {e}")

def decrypt_data(token: str) -> str:
    """Descifra un token cifrado. Lanza error si la clave es incorrecta."""
    try:
        data = f.decrypt(token.encode())
        return data.decode()
    except Exception as e:
        # Esto ocurre si el token está mal o si se usa una clave Fernet diferente
        raise HTTPException(status_code=500, detail="Error al descifrar datos (Clave de Firma Inválida o Error de Encriptación).")
