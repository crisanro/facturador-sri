import datetime
from endesive import xades
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
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