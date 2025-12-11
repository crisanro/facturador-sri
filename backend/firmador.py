import datetime
from datetime import timezone
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from lxml import etree
import base64
import hashlib
import uuid
from typing import List

# ============================================================================
# FUNCIÓN CORREGIDA: ENCONTRAR EL CERTIFICADO VIGENTE VÁLIDO
# ============================================================================

def encontrar_certificado_valido(cert_principal, certs_adicionales):
    """
    Busca el certificado de usuario válido y vigente para firma electrónica.
    Prioriza certificados con keyUsage de 'digitalSignature'.
    """
    todos_los_certs = []
    if cert_principal:
        todos_los_certs.append(cert_principal)
    if certs_adicionales:
        todos_los_certs.extend(certs_adicionales)
    
    now = datetime.datetime.now(timezone.utc)
    certificado_vigente_mas_nuevo = None
    
    for cert in todos_los_certs:
        try:
            # 1. Verificar vigencia
            fecha_inicio = cert.not_valid_before_utc
            fecha_fin = cert.not_valid_after_utc
            
            if not (fecha_inicio <= now <= fecha_fin):
                print(f"[FIRMA] Certificado expirado o no válido aún: {cert.subject}")
                continue
            
            # 2. Verificar que sea un certificado de firma (no CA)
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS
                )
                if basic_constraints.value.ca:
                    print(f"[FIRMA] Certificado CA ignorado: {cert.subject}")
                    continue
            except x509.ExtensionNotFound:
                pass  # No tiene basic constraints, probablemente es end-entity
            
            # 3. Verificar Key Usage (debe tener digitalSignature)
            try:
                key_usage = cert.extensions.get_extension_for_oid(
                    ExtensionOID.KEY_USAGE
                )
                if not key_usage.value.digital_signature:
                    print(f"[FIRMA] Certificado sin digitalSignature: {cert.subject}")
                    continue
            except x509.ExtensionNotFound:
                print(f"[FIRMA] Certificado sin Key Usage extension: {cert.subject}")
                # Algunos certificados antiguos no tienen esta extensión
                # Los dejamos pasar si cumplen otras condiciones
            
            # 4. Verificar que tenga serialNumber en el Subject (persona/empresa)
            serial_number = None
            try:
                serial_number = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
            except:
                pass
            
            if not serial_number:
                print(f"[FIRMA] Certificado sin serialNumber en Subject: {cert.subject}")
                continue
            
            print(f"[FIRMA] Certificado válido encontrado: {cert.subject}")
            print(f"[FIRMA] Válido desde: {fecha_inicio} hasta: {fecha_fin}")
            
            # 5. Seleccionar el más nuevo
            if certificado_vigente_mas_nuevo is None:
                certificado_vigente_mas_nuevo = cert
            else:
                fecha_actual_mas_nueva = certificado_vigente_mas_nuevo.not_valid_after_utc
                if fecha_fin > fecha_actual_mas_nueva:
                    certificado_vigente_mas_nuevo = cert
        
        except Exception as e:
            print(f"[FIRMA] Error al procesar certificado: {e}")
            continue
    
    if certificado_vigente_mas_nuevo:
        print(f"[FIRMA] ✓ Certificado seleccionado: {certificado_vigente_mas_nuevo.subject}")
    else:
        print(f"[FIRMA] ✗ No se encontró ningún certificado válido")
    
    return certificado_vigente_mas_nuevo


def validar_archivo_p12(ruta_p12, password, ruc_usuario):
    """
    VALIDACIÓN MEJORADA: Verifica contraseña, vigencia y tipo de certificado.
    """
    try:
        with open(ruta_p12, 'rb') as f:
            p12_data = f.read()
        
        try:
            private_key, certificate_principal, additional_certificates = pkcs12.load_key_and_certificates(
                p12_data, 
                password.encode('utf-8'),
                backend=default_backend()
            )
        except ValueError as ve:
            return False, "Contraseña de la firma incorrecta."
        
        # Buscar certificado válido
        user_cert = encontrar_certificado_valido(certificate_principal, additional_certificates)
        
        if user_cert is None:
            return False, "No se encontró un certificado de firma electrónica vigente en el archivo P12."
        
        # Verificar que el RUC/CI coincida con el certificado
        try:
            serial_attrs = user_cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
            if serial_attrs:
                cert_serial = serial_attrs[0].value
                # Limpiar el serial del certificado (puede tener prefijos)
                cert_serial_clean = cert_serial.replace('-', '').replace(' ', '')
                ruc_clean = ruc_usuario.replace('-', '').replace(' ', '')
                
                if ruc_clean not in cert_serial_clean:
                    return False, f"El RUC/CI del certificado ({cert_serial}) no coincide con el RUC ingresado ({ruc_usuario})."
        except Exception as e:
            print(f"[FIRMA] Advertencia: No se pudo verificar RUC en certificado: {e}")
        
        return True, "Firma electrónica válida y vigente."
        
    except FileNotFoundError:
        return False, "Archivo de firma no encontrado."
    except Exception as e:
        return False, f"Error al validar firma: {str(e)}"


def firmar_xml(xml_string, ruta_p12, password_p12):
    """
    Firma un XML usando XAdES-BES compatible con SRI Ecuador.
    ACTUALIZADO: Usa SHA256 en lugar de SHA1.
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
        
        # 2. Identificar el certificado de usuario VIGENTE
        certificate = encontrar_certificado_valido(certificate_principal, additional_certificates)
        
        if certificate is None:
            raise Exception("No se encontró un certificado de firma electrónica vigente en el archivo P12.")
        
        # 3. Parsear el XML
        try:
            root = etree.fromstring(xml_string.encode('utf-8'))
        except etree.XMLSyntaxError as e:
            raise Exception(f"XML mal formado: {str(e)}")
        
        # 4. FIRMA CON SHA256 (REQUERIDO POR SRI)
        xml_firmado = firmar_xml_manual_sha256(
            root, 
            private_key, 
            certificate,
            additional_certificates
        )
        
        return xml_firmado
        
    except Exception as e:
        print(f"[FIRMA] Error crítico en firma: {str(e)}")
        raise Exception(f"Error en el proceso de firma: {str(e)}")


def firmar_xml_manual_sha256(root, private_key, certificate, chain_certificates):
    """
    Implementación manual de firma XAdES-BES con SHA256.
    CORRECCIÓN CRÍTICA: Usa RSA-SHA256 y canonicalización exclusiva.
    """
    # Namespaces
    ns_ds = "http://www.w3.org/2000/09/xmldsig#"
    ns_xades = "http://uri.etsi.org/01903/v1.3.2#"
    
    etree.register_namespace('ds', ns_ds)
    etree.register_namespace('xades', ns_xades)
    
    # 1. Canonicalizar el XML original (C14N EXCLUSIVO)
    xml_canonico = etree.tostring(root, method='c14n', exclusive=True, with_comments=False)
    
    # 2. Calcular el digest SHA256 del documento
    digest_value = hashlib.sha256(xml_canonico).digest()
    digest_value_b64 = base64.b64encode(digest_value).decode('utf-8')
    
    # 3. Crear el nodo Signature
    signature_id = f"Signature{uuid.uuid4().hex[:8]}"
    signature = etree.Element(f"{{{ns_ds}}}Signature", attrib={"Id": signature_id})
    
    # 4. SignedInfo
    signed_info = etree.SubElement(signature, f"{{{ns_ds}}}SignedInfo")
    
    canonicalization_method = etree.SubElement(
        signed_info, 
        f"{{{ns_ds}}}CanonicalizationMethod",
        attrib={"Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"}  # C14N EXCLUSIVO
    )
    
    signature_method = etree.SubElement(
        signed_info,
        f"{{{ns_ds}}}SignatureMethod",
        attrib={"Algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}  # SHA256
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
        attrib={"Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"}  # SHA256
    )
    
    digest_value_elem = etree.SubElement(reference, f"{{{ns_ds}}}DigestValue")
    digest_value_elem.text = digest_value_b64
    
    # 5. Canonicalizar SignedInfo y firmarlo
    signed_info_c14n = etree.tostring(signed_info, method='c14n', exclusive=True, with_comments=False)
    
    # Firmar con SHA256
    signature_bytes = private_key.sign(
        signed_info_c14n,
        padding.PKCS1v15(),
        hashes.SHA256()  # SHA256 en lugar de SHA1
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
    
    # 8. Agregar propiedades XAdES con SHA256
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
    CORRECCIÓN: Usa SHA256 en lugar de SHA1.
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
    
    # CertDigest con SHA256
    cert_digest_elem = etree.SubElement(cert_elem, f"{{{ns_xades}}}CertDigest")
    digest_method = etree.SubElement(
        cert_digest_elem,
        f"{{{ns_ds}}}DigestMethod",
        attrib={"Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"}  # SHA256
    )
    
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    cert_sha256 = hashlib.sha256(cert_der).digest()  # SHA256 en lugar de SHA1
    
    digest_value = etree.SubElement(cert_digest_elem, f"{{{ns_ds}}}DigestValue")
    digest_value.text = base64.b64encode(cert_sha256).decode('utf-8')
    
    # IssuerSerial
    issuer_serial = etree.SubElement(cert_elem, f"{{{ns_xades}}}IssuerSerial")
    
    x509_issuer = etree.SubElement(issuer_serial, f"{{{ns_ds}}}X509IssuerName")
    x509_issuer.text = certificate.issuer.rfc4514_string()
    
    x509_serial = etree.SubElement(issuer_serial, f"{{{ns_ds}}}X509SerialNumber")
    x509_serial.text = str(certificate.serial_number)


