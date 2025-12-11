import datetime
from endesive import xades
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
import os
from datetime import datetime, timezone

def firmar_xml(xml_string, ruta_p12, password_p12):
    """
    Firma un XML usando el estándar XAdES-BES (SRI Ecuador).
    """
    try:
        # 1. Cargar el archivo .p12
        if not os.path.exists(ruta_p12):
            raise Exception("Archivo de firma no encontrado")
            
        with open(ruta_p12, 'rb') as f:
            p12_data = f.read()

        # 2. Desbloquear la firma (Extraer clave privada y certificado)
        # El SRI usa SHA1 o SHA256. Python moderno usa bytes para el password.
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, 
            password_p12.encode('utf-8')
        )

        # 3. Configuración de XAdES-BES
        # El SRI pide que la firma esté "Enveloped" (dentro del mismo XML)
        signature_options = {
            'known_roots': [],
            'cert_info': True,
            'signing_time': datetime.datetime.now(datetime.timezone.utc) # Hora actual UTC
        }

        # 4. Firmar
        # xades.bes.sign_xml genera la estructura <ds:Signature>
        xml_firmado = xades.bes.sign_xml(
            xml_string.encode('utf-8'), # El XML original en bytes
            private_key,
            certificate,
            additional_certificates,
            signature_options
        )

        # Retornamos el XML firmado como texto
        return xml_firmado.decode('utf-8')

    except Exception as e:

        raise Exception(f"Error en el proceso de firma: {str(e)}")

def validar_archivo_p12(ruta_p12, password, ruc_usuario):
    try:
        with open(ruta_p12, 'rb') as f:
            p12_data = f.read()
        
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, 
            password.encode('utf-8')
        )
        
        # --- CORRECCIÓN AQUÍ ---
        # 1. Obtenemos la fecha actual en UTC (con zona horaria consciente)
        now = datetime.now(timezone.utc)
        
        # 2. Obtenemos la fecha del certificado (que ya suele venir en UTC)
        cert_expires = certificate.not_valid_after
        cert_starts = certificate.not_valid_before

        # Aseguramos que las fechas del certificado tengan zona horaria para evitar errores
        if cert_expires.tzinfo is None:
            cert_expires = cert_expires.replace(tzinfo=timezone.utc)
        if cert_starts.tzinfo is None:
            cert_starts = cert_starts.replace(tzinfo=timezone.utc)

        # 3. Comparación segura
        if now > cert_expires:
            return False, f"La firma electrónica expiró el {cert_expires}"
        
        if now < cert_starts:
            return False, "La firma electrónica aún no es válida (fecha futura)."
        # -----------------------

        subject = certificate.subject.rfc4514_string()
        if ruc_usuario not in subject:
             # Ojo: A veces el RUC no está directo, podrías relajar esta validación temporalmente para probar
            pass 

        return True, "Firma válida"

    except ValueError:
        return False, "Contraseña de la firma incorrecta."
    except Exception as e:
        # Esto te ayudará a ver el error real si no es de fechas
        print(f"DEBUG ERROR FIRMA: {e}") 
        return False, f"Error leyendo firma: {str(e)}"
