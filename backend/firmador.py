import datetime
from datetime import timezone
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from signxml import XMLSigner, methods
from lxml import etree
import uuid


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


def validar_archivo_p12(ruta_p12, password, ruc_usuario):
    """
    VALIDACIÓN SIMPLIFICADA: Solo verifica la contraseña y la vigencia.
    """
    try:
        with open(ruta_p12, 'rb') as f:
            p12_data = f.read()
        
        private_key, certificate_principal, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, 
            password.encode('utf-8')
        )
        
        user_cert = encontrar_certificado_valido(certificate_principal, additional_certificates)
        
        if user_cert is None:
            return False, "El archivo P12 es válido, pero todos los certificados de usuario están expirados."
        
        now = datetime.datetime.now(timezone.utc)
        cert_expires = user_cert.not_valid_after
        if cert_expires.tzinfo is None:
            cert_expires = cert_expires.replace(tzinfo=timezone.utc)
            
        if now > cert_expires:
            return False, "La firma electrónica expiró."
        
        return True, "Firma y Clave correctas."
    except ValueError:
        return False, "Contraseña de la firma incorrecta."
    except Exception as e:
        return False, f"Error leyendo firma: {str(e)}"


def firmar_xml(xml_string, ruta_p12, password_p12):
    """
    Firma un XML usando XAdES-BES con signxml (compatible SRI Ecuador).
    """
    try:
        # 1. Cargar el archivo .p12
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
        
        # 3. Convertir clave privada a PEM
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # 4. Convertir certificado a PEM
        cert_pem = user_certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        )
        
        # 5. Preparar cadena de certificados (si existen)
        cert_chain = []
        if additional_certificates:
            for cert in additional_certificates:
                cert_chain.append(
                    cert.public_bytes(encoding=serialization.Encoding.PEM)
                )
        
        # 6. Parsear el XML
        try:
            root = etree.fromstring(xml_string.encode('utf-8'))
        except etree.XMLSyntaxError as e:
            raise Exception(f"XML inválido: {str(e)}")
        
        # 7. Configurar firmante XAdES-BES (compatible con SRI)
        # El SRI Ecuador requiere específicamente SHA1 y RSA
        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha1",
            digest_algorithm="sha1",
            c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        )
        
        # 8. Firmar el XML
        signed_root = signer.sign(
            root,
            key=private_key_pem,
            cert=cert_pem,
            reference_uri=""
        )
        
        # 9. Agregar información XAdES (requerido por SRI)
        agregar_propiedades_xades(signed_root, user_certificate)
        
        # 10. Convertir de vuelta a string
        xml_firmado = etree.tostring(
            signed_root,
            encoding='UTF-8',
            xml_declaration=True,
            pretty_print=False
        )
        
        return xml_firmado.decode('utf-8')
        
    except Exception as e:
        raise Exception(f"Error en el proceso de firma: {str(e)}")


def agregar_propiedades_xades(signed_root, certificate):
    """
    Agrega propiedades XAdES-BES requeridas por el SRI Ecuador.
    """
    # Namespace definitions
    ns = {
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
        'xades': 'http://uri.etsi.org/01903/v1.3.2#',
        'etsi': 'http://uri.etsi.org/01903/v1.3.2#'
    }
    
    # Buscar el nodo Signature
    signature = signed_root.find('.//ds:Signature', namespaces=ns)
    
    if signature is None:
        return
    
    # Crear el nodo Object si no existe
    obj = signature.find('.//ds:Object', namespaces=ns)
    if obj is None:
        obj = etree.SubElement(signature, '{http://www.w3.org/2000/09/xmldsig#}Object')
    
    # Crear QualifyingProperties
    qual_props = etree.SubElement(
        obj,
        '{http://uri.etsi.org/01903/v1.3.2#}QualifyingProperties',
        attrib={'Target': '#' + signature.get('Id', 'Signature')}
    )
    
    # SignedProperties
    signed_props = etree.SubElement(
        qual_props,
        '{http://uri.etsi.org/01903/v1.3.2#}SignedProperties',
        attrib={'Id': f'SignedProperties-{uuid.uuid4()}'}
    )
    
    # SignedSignatureProperties
    signed_sig_props = etree.SubElement(
        signed_props,
        '{http://uri.etsi.org/01903/v1.3.2#}SignedSignatureProperties'
    )
    
    # SigningTime
    signing_time = etree.SubElement(
        signed_sig_props,
        '{http://uri.etsi.org/01903/v1.3.2#}SigningTime'
    )
    signing_time.text = datetime.datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # SigningCertificate
    signing_cert = etree.SubElement(
        signed_sig_props,
        '{http://uri.etsi.org/01903/v1.3.2#}SigningCertificate'
    )
    
    cert_elem = etree.SubElement(
        signing_cert,
        '{http://uri.etsi.org/01903/v1.3.2#}Cert'
    )
    
    cert_digest = etree.SubElement(
        cert_elem,
        '{http://uri.etsi.org/01903/v1.3.2#}CertDigest'
    )
    
    # Agregar información del certificado
    issuer_serial = etree.SubElement(
        cert_elem,
        '{http://uri.etsi.org/01903/v1.3.2#}IssuerSerial'
    )
    
    x509_issuer = etree.SubElement(
        issuer_serial,
        '{http://www.w3.org/2000/09/xmldsig#}X509IssuerName'
    )
    x509_issuer.text = certificate.issuer.rfc4514_string()
    
    x509_serial = etree.SubElement(
        issuer_serial,
        '{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber'
    )
    x509_serial.text = str(certificate.serial_number)



