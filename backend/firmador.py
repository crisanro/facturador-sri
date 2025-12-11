import datetime
from endesive import xades
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import os
from datetime import timezone

# --- NO HAY CAMBIOS EN LAS FUNCIONES DE BÚSQUEDA DE CERTIFICADO Y VALIDACIÓN ---

def encontrar_certificado_valido(cert_principal, certs_adicionales):
    """Busca el certificado vigente de usuario en toda la cadena."""
    todos_los_certs = []
    if cert_principal:
        todos_los_certs.append(cert_principal)
    todos_los_certs.extend(certs_adicionales)
    
    now = datetime.datetime.now(timezone.utc)
    
    for cert in todos_los_certs:
        fecha_fin = cert.not_valid_after
        if fecha_fin.tzinfo is None:
            fecha_fin = fecha_fin.replace(tzinfo=timezone.utc)
            
        if now < fecha_fin and '2.5.4.5' in cert.subject.rfc4514_string():
            return cert
            
    return None
    
    
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
        
        # 2. Identificar el certificado de usuario VIGENTE
        user_certificate = encontrar_certificado_valido(certificate_principal, additional_certificates)
        
        if user_certificate is None:
             raise Exception("No se pudo identificar un certificado de usuario vigente dentro del P12.")

        # 3. Configuración de XAdES-BES (se mantiene)
        signature_options = {
            'known_roots': [],
            'cert_info': True,
            'signing_time': datetime.datetime.now(datetime.timezone.utc)
        }
        # Endesive espera el XML en bytes
        xml_bytes = xml_string.encode('utf-8') 
        
        # 4. CORRECCIÓN FINAL: Probar con la sintaxis más simple de xades.bes.sign
        # Si el error persiste, la librería debe ser actualizada/reinstalada.
        xml_firmado = xades.bes.sign(
            xml_bytes,
            private_key,
            user_certificate,
            additional_certificates, 
            signature_options
        )
        
        return xml_firmado.decode('utf-8')

    except Exception as e:
        raise Exception(f"Error en el proceso de firma: {str(e)}")

def validar_archivo_p12(ruta_p12, password, ruc_usuario):
    """
    VALIDACIÓN SIMPLIFICADA: Solo verifica la contraseña y la vigencia.
    """
    try:
        with open(ruta_p12, 'rb') as f:
            p12_data = f.read()
        
        # INTENTA CARGAR: Esto fallará si la contraseña es incorrecta (ValueError)
        private_key, certificate_principal, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, 
            password.encode('utf-8')
        )
        
        # 1. Verificar Vigencia
        user_cert = encontrar_certificado_valido(certificate_principal, additional_certificates)
        
        if user_cert is None:
            return False, "El archivo P12 es válido, pero todos los certificados de usuario están expirados."

        # Verificar fecha de caducidad del certificado vigente encontrado
        now = datetime.datetime.now(timezone.utc)
        cert_expires = user_cert.not_valid_after
        if cert_expires.tzinfo is None:
            cert_expires = cert_expires.replace(tzinfo=timezone.utc)
            
        if now > cert_expires:
            return False, "La firma electrónica expiró."

        # Si llegamos aquí: La clave es correcta, el archivo se abre, y hay un certificado vigente.
        return True, "Firma y Clave correctas."

    except ValueError:
        return False, "Contraseña de la firma incorrecta."
    except Exception as e:
        return False, f"Error leyendo firma: {str(e)}"
