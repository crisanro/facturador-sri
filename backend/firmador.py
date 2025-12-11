import datetime
from datetime import timezone
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree
import base64
import hashlib
import uuid
from typing import List # Asegurar List está importado

# ============================================================================
# FUNCIÓN CORREGIDA: ENCONTRAR EL CERTIFICADO VIGENTE MÁS NUEVO
# ============================================================================

def encontrar_certificado_valido(cert_principal, certs_adicionales):
    """Busca el certificado vigente de usuario en toda la cadena y devuelve el más nuevo."""
    todos_los_certs = []
    if cert_principal:
        todos_los_certs.append(cert_principal)
    if certs_adicionales:
        # Los certificados adicionales pueden ser CAs o certificados intermedios/antiguos
        todos_los_certs.extend(certs_adicionales)
    
    now = datetime.datetime.now(timezone.utc)
    certificado_vigente_mas_nuevo = None
    
    for cert in todos_los_certs:
        # Aseguramos que la fecha sea UTC aware (como ya lo hiciste)
        fecha_fin = cert.not_valid_after
        if fecha_fin.tzinfo is None:
            fecha_fin = fecha_fin.replace(tzinfo=timezone.utc)
            
        # Verificar 1) Vigencia Y 2) Que sea un certificado de RUC/Cédula ('2.5.4.5')
        # La expresión '2.5.4.5' busca el identificador de Cédula/RUC en el sujeto del certificado
        if now < fecha_fin and '2.5.4.5' in cert.subject.rfc4514_string():
            
            # Si es el primer certificado válido encontrado O si expira después del actual 'más nuevo'
            if certificado_vigente_mas_nuevo is None or fecha_fin > certificado_vigente_mas_nuevo.not_valid_after.replace(tzinfo=timezone.utc):
                certificado_vigente_mas_nuevo = cert
                
    return certificado_vigente_mas_nuevo


def validar_archivo_p12(ruta_p12, password, ruc_usuario):
    """
    VALIDACIÓN SIMPLIFICADA: Solo verifica la contraseña y la vigencia.
    Ahora utiliza la lógica de selección de certificado más nuevo.
    """
    try:
        with open(ruta_p12, 'rb') as f:
            p12_data = f.read()
        
        private_key, certificate_principal, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, 
            password.encode('utf-8')
        )
        
        # Usamos la nueva lógica de selección
        user_cert = encontrar_certificado_valido(certificate_principal, additional_certificates)
        
        if user_cert is None:
            return False, "El archivo P12 es válido, pero no se encontró un certificado vigente de usuario."
        
        # Las verificaciones de expiración se hacen implícitamente en encontrar_certificado_valido,
        # pero mantenemos la verificación de la fecha del certificado seleccionado para logs.
        
        return True, "Firma y Clave correctas."
    except ValueError:
        return False, "Contraseña de la firma incorrecta."
    except Exception as e:
        return False, f"Error leyendo firma: {str(e)}"


def firmar_xml(xml_string, ruta_p12, password_p12):
    """
    Firma un XML usando XAdES-BES compatible con SRI Ecuador.
    """
    try:
        # 1. Cargar el archivo .p12
        with open(ruta_p12, 'rb') as f:
            p12_data = f.read()
        
        private_key, certificate_principal, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, 
            password_p12.encode('utf-8'),
            backend=default_backend()
        )
        
        # 2. Identificar el certificado de usuario VIGENTE Y MÁS NUEVO
        user_certificate = encontrar_certificado_valido(certificate_principal, additional_certificates)
        
        if user_certificate is None:
            raise Exception("No se pudo identificar un certificado de usuario vigente dentro del P12.")
        
        # 3. Parsear el XML
        try:
            root = etree.fromstring(xml_string.encode('utf-8'))
        except etree.XMLSyntaxError as e:
            raise Exception(f"XML inválido: {str(e)}")
            
        # 4. FIRMA MANUAL CON SHA1 
        xml_firmado = firmar_xml_manual_sha1(
            root, 
            private_key, 
            user_certificate,
            additional_certificates
        )
        
        return xml_firmado
        
    except Exception as e:
        raise Exception(f"Error en el proceso de firma: {str(e)}")


def firmar_xml_manual_sha1(root, private_key, certificate, chain_certificates):
    """
    Implementación manual de firma XAdES-BES con SHA1.
    (El resto de la función se mantiene igual a tu código original)
    """
    # Namespaces
    ns_ds = "http://www.w3.org/2000/09/xmldsig#"
    ns_xades = "http://uri.etsi.org/01903/v1.3.2#"
    
    etree.register_namespace('ds', ns_ds)
    etree.register_namespace('xades', ns_xades)
    
    # 1. Canonicalizar el XML original (C14N)
    xml_canonico = etree.tostring(root, method='c14n', exclusive=False, with_comments=False)
    
    # 2. Calcular el digest SHA1 del documento
    digest_value = hashlib.sha1(xml_canonico).digest()
    digest_value_b64 = base64.b64encode(digest_value).decode('utf-8')
    
    # 3. Crear el nodo Signature
    signature_id = f"Signature-{uuid.uuid4().hex[:8]}"
    signature = etree.SubElement(f"{{{ns_ds}}}Signature", attrib={"Id": signature_id})
    
    # 4. SignedInfo
    signed_info = etree.SubElement(signature, f"{{{ns_ds}}}SignedInfo")
    
    canonicalization_method = etree.SubElement(
        signed_info, 
        f"{{{ns_ds}}}CanonicalizationMethod",
        attrib={"Algorithm": "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"}
    )
    
    signature_method = etree.SubElement(
        signed_info,
        f"{{{ns_ds}}}SignatureMethod",
        attrib={"Algorithm": "http://www.w3.org/2000/09/xmldsig#rsa-sha1"}
    )
    
    # Reference al documento
    reference = etree.SubElement(
        signed_info,
        f"{{{ns_ds}}}Reference",
        attrib={"URI": ""}
    )
    
    transforms = etree.SubElement(reference, f"{{{ns_ds}}}Transforms")
    transform = etree.SubElement(
        transforms,
        f"{{{ns_ds}}}Transform",
        attrib={"Algorithm": "http://www.w3.org/2000/09/xmldsig#enveloped-signature"}
    )
    
    digest_method = etree.SubElement(
        reference,
        f"{{{ns_ds}}}DigestMethod",
        attrib={"Algorithm": "http://www.w3.org/2000/09/xmldsig#sha1"}
    )
    
    digest_value_elem = etree.SubElement(reference, f"{{{ns_ds}}}DigestValue")
    digest_value_elem.text = digest_value_b64
    
    # 5. Canonicalizar SignedInfo y firmarlo
    signed_info_c14n = etree.tostring(signed_info, method='c14n', exclusive=False, with_comments=False)
    
    # Firmar con SHA1 usando cryptography 
    signature_bytes = private_key.sign(
        signed_info_c14n,
        padding.PKCS1v15(),
        hashes.SHA1()  # SRI requiere SHA1
    )
    
    signature_value_b64 = base64.b64encode(signature_bytes).decode('utf-8')
    
    # 6. Agregar SignatureValue
    signature_value_elem = etree.SubElement(signature, f"{{{ns_ds}}}SignatureValue")
    signature_value_elem.text = signature_value_b64
    
    # 7. KeyInfo con el certificado
    key_info = etree.SubElement(signature, f"{{{ns_ds}}}KeyInfo")
    x509_data = etree.SubElement(key_info, f"{{{ns_ds}}}X509Data")
    x509_cert = etree.SubElement(x509_data, f"{{{ns_ds}}}X509Certificate")
    
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    x509_cert.text = base64.b64encode(cert_der).decode('utf-8')
    
    # 8. Agregar propiedades XAdES
    agregar_propiedades_xades_manual(signature, certificate, signature_id)
    
    # 9. Insertar la firma en el XML original
    root.append(signature)
    
    # 10. Convertir a string
    xml_firmado = etree.tostring(
        root,
        encoding='UTF-8',
        xml_declaration=True,
        pretty_print=False
    )
    
    return xml_firmado.decode('utf-8')


def agregar_propiedades_xades_manual(signature, certificate, signature_id):
    """
    Agrega propiedades XAdES-BES al nodo Signature.
    (La función se mantiene igual a tu código original)
    """
    ns_ds = "http://www.w3.org/2000/09/xmldsig#"
    ns_xades = "http://uri.etsi.org/01903/v1.3.2#"
    
    # Object container
    obj = etree.SubElement(signature, f"{{{ns_ds}}}Object")
    
    # QualifyingProperties
    qual_props_id = f"QualifyingProperties-{uuid.uuid4().hex[:8]}"
    qual_props = etree.SubElement(
        obj,
        f"{{{ns_xades}}}QualifyingProperties",
        attrib={
            "Target": f"#{signature_id}",
            "Id": qual_props_id
        }
    )
    
    # SignedProperties
    signed_props_id = f"SignedProperties-{uuid.uuid4().hex[:8]}"
    signed_props = etree.SubElement(
        qual_props,
        f"{{{ns_xades}}}SignedProperties",
        attrib={"Id": signed_props_id}
    )
    
    # SignedSignatureProperties
    signed_sig_props = etree.SubElement(
        signed_props,
        f"{{{ns_xades}}}SignedSignatureProperties"
    )
    
    # SigningTime
    signing_time = etree.SubElement(signed_sig_props, f"{{{ns_xades}}}SigningTime")
    signing_time.text = datetime.datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # SigningCertificate
    signing_cert = etree.SubElement(signed_sig_props, f"{{{ns_xades}}}SigningCertificate")
    cert_elem = etree.SubElement(signing_cert, f"{{{ns_xades}}}Cert")
    
    # CertDigest
    cert_digest_elem = etree.SubElement(cert_elem, f"{{{ns_xades}}}CertDigest")
    digest_method = etree.SubElement(
        cert_digest_elem,
        f"{{{ns_ds}}}DigestMethod",
        attrib={"Algorithm": "http://www.w3.org/2000/09/xmldsig#sha1"}
    )
    
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    cert_sha1 = hashlib.sha1(cert_der).digest()
    
    digest_value = etree.SubElement(cert_digest_elem, f"{{{ns_ds}}}DigestValue")
    digest_value.text = base64.b64encode(cert_sha1).decode('utf-8')
    
    # IssuerSerial
    issuer_serial = etree.SubElement(cert_elem, f"{{{ns_xades}}}IssuerSerial")
    
    x509_issuer = etree.SubElement(issuer_serial, f"{{{ns_ds}}}X509IssuerName")
    x509_issuer.text = certificate.issuer.rfc4514_string()
    
    x509_serial = etree.SubElement(issuer_serial, f"{{{ns_ds}}}X509SerialNumber")
    x509_serial.text = str(certificate.serial_number)
