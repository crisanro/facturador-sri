import datetime
from endesive import xades
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import os
from datetime import timezone

# ... (La función encontrar_certificado_valido no necesita cambios, aunque ya no será estrictamente necesaria para validar, sí lo es para firmar).

def encontrar_certificado_valido(cert_principal, certs_adicionales):
    """Busca el certificado vigente de usuario en toda la cadena."""
    
    # ... (Mantener la lógica para encontrar el certificado de 2025 para que FIRMAR funcione bien) ...
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
            # Devuelve el certificado de usuario que esté vigente
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
        
        # 2. Identificar el certificado de usuario VIGENTE (el de 2025)
        # Esto asegura que si el principal es viejo, usemos el correcto para firmar.
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
            user_certificate, # Usamos el certificado VIGENTE
            additional_certificates,
            signature_options
        )

        return xml_firmado.decode('utf-8')

    except Exception as e:
        raise Exception(f"Error en el proceso de firma: {str(e)}")

def validar_archivo_p12(ruta_p12, password, ruc_usuario):
    """
    VALIDACIÓN SIMPLIFICADA: Solo verifica la contraseña y la vigencia.
    Ignora el RUC.
    """
    try:
        with open(ruta_p12, 'rb') as f:
            p12_data = f.read()
        
        # INTENTA CARGAR: Esto fallará si la contraseña es incorrecta (ValueError)
        private_key, certificate_principal, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, 
            password.encode('utf-8')
        )
        
        # 1. Verificar Vigencia (Busca un certificado vigente para confirmar que el archivo sirve)
        user_cert = encontrar_certificado_valido(certificate_principal, additional_certificates)
        
        if user_cert is None:
            return False, "El archivo P12 es válido, pero todos los certificados de usuario están expirados."

        # Verificar fecha de caducidad del certificado vigente encontrado
        now = datetime.datetime.now(timezone.utc)
        cert_expires = user_cert.not_valid_after
        if cert_expires.tzinfo is None:
            cert_expires = cert_expires.replace(tzinfo=timezone.utc)
        
        if now > cert_expires:
            # Esta línea es redundante si user_cert != None, pero sirve como doble chequeo
            return False, "La firma electrónica expiró."

        # Si llegamos aquí: La clave es correcta, el archivo se abre, y hay un certificado vigente.
        return True, "Firma y Clave correctas."

    except ValueError:
        return False, "Contraseña de la firma incorrecta."
    except Exception as e:
        return False, f"Error leyendo firma: {str(e)}"
