import datetime
from endesive import xades
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import os
from datetime import timezone

# Función auxiliar para encontrar el certificado de usuario (el vigente)
def encontrar_certificado_valido(cert_principal, certs_adicionales):
    """Busca el certificado vigente en toda la cadena."""
    
    # 1. Creamos una lista con todos los certificados
    todos_los_certs = []
    if cert_principal:
        todos_los_certs.append(cert_principal)
    todos_los_certs.extend(certs_adicionales)
    
    now = datetime.datetime.now(timezone.utc)
    
    # 2. Iteramos para encontrar el certificado vigente que NO sea el de la CA
    for cert in todos_los_certs:
        
        # Aseguramos que la fecha tenga zona horaria para comparar
        fecha_fin = cert.not_valid_after
        if fecha_fin.tzinfo is None:
            fecha_fin = fecha_fin.replace(tzinfo=timezone.utc)
            
        # Comprobamos vigencia
        if now < fecha_fin:
            # Comprobamos que no sea la Raíz (el de la Raíz suele tener una vigencia de 10 años, como el de 2029)
            # Y verificamos que contenga algo parecido a un RUC (2.5.4.5)
            subject_text = cert.subject.rfc4514_string()
            if '2.5.4.5' in subject_text: 
                # Este es el certificado de Usuario o Intermedio vigente
                return cert
                
    return None # No se encontró ningún certificado de usuario vigente


def firmar_xml(xml_string, ruta_p12, password_p12):
    """
    Firma un XML usando el estándar XAdES-BES (SRI Ecuador).
    """
    try:
        # 1. Cargar el archivo .p12 y obtener la cadena completa
        with open(ruta_p12, 'rb') as f:
            p12_data = f.read()

        private_key, certificate_principal, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, 
            password_p12.encode('utf-8')
        )
        
        # 2. Identificar el certificado de usuario VIGENTE (el de 2025)
        # Esto asegura que si el principal es viejo, usemos el correcto.
        user_certificate = encontrar_certificado_valido(certificate_principal, additional_certificates)
        
        if user_certificate is None:
             raise Exception("No se pudo identificar un certificado de usuario vigente dentro del P12.")

        # 3. Configuración de XAdES-BES
        signature_options = {
            'known_roots': [],
            'cert_info': True,
            'signing_time': datetime.datetime.now(datetime.timezone.utc)
        }

        # 4. Firmar con la clave y el certificado correcto (user_certificate)
        xml_firmado = xades.bes.sign_xml(
            xml_string.encode('utf-8'), 
            private_key,
            user_certificate, # Usamos el certificado VIGENTE que encontramos
            additional_certificates,
            signature_options
        )

        return xml_firmado.decode('utf-8')

    except Exception as e:
        # Aquí verás si hay un problema en la firma
        raise Exception(f"Error en el proceso de firma: {str(e)}")

def validar_archivo_p12(ruta_p12, password, ruc_usuario):
    """
    Verifica que la clave y el RUC sean correctos, usando la misma lógica de búsqueda.
    """
    try:
        with open(ruta_p12, 'rb') as f:
            p12_data = f.read()
        
        # Cargar todos los elementos
        private_key, certificate_principal, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, 
            password.encode('utf-8')
        )
        
        # Identificar el certificado vigente
        user_cert = encontrar_certificado_valido(certificate_principal, additional_certificates)
        
        if user_cert is None:
            return False, "No se encontró ningún certificado de usuario vigente dentro del archivo."

        # 1. Validar Fechas (usamos la del certificado vigente, que caduca en 2025)
        now = datetime.datetime.now(timezone.utc)
        
        cert_expires = user_cert.not_valid_after
        if cert_expires.tzinfo is None:
            cert_expires = cert_expires.replace(tzinfo=timezone.utc)

        if now > cert_expires:
            return False, f"La firma electrónica expiró el {cert_expires}"
        
        if now < user_cert.not_valid_before.replace(tzinfo=timezone.utc):
            return False, "La firma electrónica aún no es válida."

        # 2. Validar RUC
        subject = user_cert.subject.rfc4514_string() 
        
        if ruc_usuario not in subject:
            return False, f"El RUC de la firma no coincide con el usuario ({ruc_usuario})."

        return True, "Firma válida"

    except ValueError:
        return False, "Contraseña de la firma incorrecta."
    except Exception as e:
        return False, f"Error leyendo firma: {str(e)}"
