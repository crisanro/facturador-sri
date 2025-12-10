import datetime
from endesive import xades
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
import os

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
    """
    Verifica:
    1. Que la contraseña abra el archivo.
    2. Que no esté expirado.
    3. Que el RUC dentro de la firma coincida con el usuario.
    """
    try:
        with open(ruta_p12, 'rb') as f:
            p12_data = f.read()
        
        # Intentamos abrir el P12
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, 
            password.encode('utf-8')
        )
        
        # 1. Validar Fechas
        now = datetime.datetime.now()
        if now > certificate.not_valid_after:
            return False, f"La firma electrónica expiró el {certificate.not_valid_after}"
        
        if now < certificate.not_valid_before:
            return False, "La firma electrónica aún no es válida (fecha futura)."

        # 2. Validar RUC (Buscamos el RUC en el 'Subject' del certificado)
        # El formato suele ser "RAZON SOCIAL ... RUC: 17XXXXXX001" o similar en el CommonName
        subject = certificate.subject.rfc4514_string() # Devuelve todo el texto del dueño
        
        if ruc_usuario not in subject:
            # A veces el RUC está en el Serial Number o CN, si no lo encuentra exacto, lanzamos advertencia o error
            # Para ser estrictos:
            return False, f"El RUC de la firma no coincide con el usuario ({ruc_usuario}). ¿Subiste la firma correcta?"

        return True, "Firma válida"

    except ValueError:
        return False, "Contraseña de la firma incorrecta."
    except Exception as e:
        return False, f"Error leyendo firma: {str(e)}"
