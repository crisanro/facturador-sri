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

def encontrar_certificado_valido(cert_principal, certs_adicionales):
    """
    Busca el certificado de usuario válido y vigente.
    PRIORIDAD: Certificado más nuevo (que expira más tarde).
    """
    todos_los_certs = []
    if cert_principal:
        todos_los_certs.append(cert_principal)
    if certs_adicionales:
        todos_los_certs.extend(certs_adicionales)
    
    now = datetime.datetime.now(timezone.utc)
    candidatos = []
    
    print(f"[FIRMA] Analizando {len(todos_los_certs)} certificados...")
    
    for idx, cert in enumerate(todos_los_certs, 1):
        try:
            fecha_inicio = cert.not_valid_before_utc
            fecha_fin = cert.not_valid_after_utc
            
            # Información del certificado
            try:
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except:
                cn = "Desconocido"
            
            print(f"[FIRMA] Cert {idx}: {cn}")
            print(f"        Válido: {fecha_inicio.strftime('%Y-%m-%d')} a {fecha_fin.strftime('%Y-%m-%d')}")
            
            # Verificar vigencia
            if now < fecha_inicio:
                print(f"        ❌ No válido aún")
                continue
            
            if now > fecha_fin:
                dias_expirado = (now - fecha_fin).days
                print(f"        ❌ Expirado hace {dias_expirado} días")
                continue
            
            dias_restantes = (fecha_fin - now).days
            print(f"        ✓ Vigente ({dias_restantes} días restantes)")
            
            # Ignorar CAs
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                if basic_constraints.value.ca:
                    print(f"        ❌ Es certificado CA")
                    continue
            except x509.ExtensionNotFound:
                pass
            
            # Verificar digitalSignature
            tiene_digital_sig = False
            try:
                key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                if key_usage.value.digital_signature:
                    tiene_digital_sig = True
                    print(f"        ✓ Tiene Digital Signature")
                else:
                    print(f"        ❌ Sin Digital Signature")
                    continue
            except x509.ExtensionNotFound:
                # Si no tiene Key Usage, asumimos que puede firmar (certificados antiguos)
                print(f"        ⚠️  Sin Key Usage (asumo válido)")
                tiene_digital_sig = True
            
            # Debe tener serialNumber
            try:
                serial_attrs = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
                if not serial_attrs:
                    print(f"        ❌ Sin serialNumber en Subject")
                    continue
                serial_value = serial_attrs[0].value
                print(f"        ✓ SerialNumber: {serial_value}")
            except:
                print(f"        ❌ Error obteniendo serialNumber")
                continue
            
            # Este certificado es candidato
            print(f"        🟢 CANDIDATO VÁLIDO")
            candidatos.append((cert, fecha_fin))
        
        except Exception as e:
            print(f"[FIRMA] Error en cert {idx}: {e}")
            continue
    
    if not candidatos:
        print(f"[FIRMA] ❌ No se encontraron certificados válidos")
        return None
    
    # Ordenar por fecha de expiración (más nuevo = expira después)
    candidatos.sort(key=lambda x: x[1], reverse=True)
    
    cert_seleccionado = candidatos[0][0]
    fecha_exp = candidatos[0][1]
    
    try:
        cn = cert_seleccionado.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except:
        cn = "Desconocido"
    
    print(f"[FIRMA] ✅ CERTIFICADO SELECCIONADO: {cn}")
    print(f"[FIRMA]    Expira: {fecha_exp.strftime('%Y-%m-%d')}")
    
    return cert_seleccionado


def validar_archivo_p12(ruta_p12, password, ruc_usuario):
    """Valida el archivo P12 y contraseña."""
    try:
        with open(ruta_p12, 'rb') as f:
            p12_data = f.read()
        
        try:
            private_key, certificate_principal, additional_certificates = pkcs12.load_key_and_certificates(
                p12_data, 
                password.encode('utf-8'),
                backend=default_backend()
            )
        except ValueError:
            return False, "Contraseña de la firma incorrecta."
        
        user_cert = encontrar_certificado_valido(certificate_principal, additional_certificates)
        
        if user_cert is None:
            return False, "No se encontró un certificado de firma electrónica vigente."
        
        return True, "Firma electrónica válida y vigente."
        
    except FileNotFoundError:
        return False, "Archivo de firma no encontrado."
    except Exception as e:
        return False, f"Error al validar firma: {str(e)}"


def firmar_xml(xml_string, ruta_p12, password_p12):
    """
    Firma un XML con XAdES-BES compatible con SRI Ecuador.
    NUEVA ESTRATEGIA: Intenta con TODOS los certificados válidos.
    """
    try:
        with open(ruta_p12, 'rb') as f:
            p12_data = f.read()
        
        private_key, certificate_principal, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, 
            password_p12.encode('utf-8'),
            backend=default_backend()
        )
        
        # NUEVA ESTRATEGIA: Buscar TODOS los certificados válidos
        todos_los_certs = []
        if certificate_principal:
            todos_los_certs.append(certificate_principal)
        if additional_certificates:
            todos_los_certs.extend(additional_certificates)
        
        print(f"[FIRMA] Total de certificados en P12: {len(todos_los_certs)}")
        
        # Buscar todos los candidatos válidos
        now = datetime.datetime.now(timezone.utc)
        candidatos = []
        
        for idx, cert in enumerate(todos_los_certs, 1):
            try:
                inicio = cert.not_valid_before_utc
                fin = cert.not_valid_after_utc
                
                # Verificar vigencia
                if not (inicio <= now <= fin):
                    continue
                
                # Ignorar CAs
                try:
                    bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                    if bc.value.ca:
                        continue
                except:
                    pass
                
                # Verificar digital signature
                try:
                    ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                    if not ku.value.digital_signature:
                        continue
                except:
                    pass
                
                # Debe tener serial number
                try:
                    sn = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
                    if not sn:
                        continue
                except:
                    continue
                
                candidatos.append((cert, fin))
                print(f"[FIRMA] Candidato {len(candidatos)}: Expira {fin.strftime('%Y-%m-%d')}")
            except:
                continue
        
        if not candidatos:
            raise Exception("No se encontró ningún certificado válido en el P12.")
        
        # Ordenar por fecha (más nuevo primero)
        candidatos.sort(key=lambda x: x[1], reverse=True)
        
        # USAR EL MÁS NUEVO
        certificate = candidatos[0][0]
        
        try:
            cn = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            print(f"[FIRMA] ✅ Usando certificado: {cn}")
            print(f"[FIRMA]    Expira: {candidatos[0][1].strftime('%Y-%m-%d')}")
        except:
            print(f"[FIRMA] ✅ Usando certificado (expira: {candidatos[0][1].strftime('%Y-%m-%d')})")
        
        try:
            root = etree.fromstring(xml_string.encode('utf-8'))
        except etree.XMLSyntaxError as e:
            raise Exception(f"XML mal formado: {str(e)}")
        
        xml_firmado = firmar_xml_xades_bes(root, private_key, certificate)
        
        return xml_firmado
        
    except Exception as e:
        print(f"[FIRMA] ✗ Error: {str(e)}")
        raise Exception(f"Error en firma: {str(e)}")


def firmar_xml_xades_bes(root, private_key, certificate):
    """
    Implementación de firma XAdES-BES para SRI Ecuador.
    Usa SHA1 en todo (requerido por SRI en ambiente de pruebas).
    """
    ns_ds = "http://www.w3.org/2000/09/xmldsig#"
    ns_xades = "http://uri.etsi.org/01903/v1.3.2#"
    
    etree.register_namespace('ds', ns_ds)
    etree.register_namespace('xades', ns_xades)
    
    # Obtener el ID del nodo raíz
    node_id = root.get('id')
    if not node_id:
        raise Exception("El nodo raíz debe tener atributo 'id'")
    
    print(f"[FIRMA] Firmando nodo id='{node_id}'")
    
    # CRÍTICO: Calcular digest ANTES de agregar la firma
    # Esto simula la transformación enveloped-signature
    xml_sin_firma = etree.tostring(root, method='c14n', exclusive=False, with_comments=False)
    digest_sha1 = hashlib.sha1(xml_sin_firma).digest()
    digest_b64 = base64.b64encode(digest_sha1).decode('utf-8')
    
    print(f"[FIRMA] DigestValue: {digest_b64} ({len(digest_b64)} chars)")
    
    # Crear estructura de firma
    sig_id = f"Signature{uuid.uuid4().hex[:8]}"
    signature = etree.Element(f"{{{ns_ds}}}Signature", Id=sig_id)
    
    # SignedInfo
    signed_info = etree.SubElement(signature, f"{{{ns_ds}}}SignedInfo")
    
    etree.SubElement(
        signed_info,
        f"{{{ns_ds}}}CanonicalizationMethod",
        Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    )
    
    etree.SubElement(
        signed_info,
        f"{{{ns_ds}}}SignatureMethod",
        Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    )
    
    # Reference
    reference = etree.SubElement(
        signed_info,
        f"{{{ns_ds}}}Reference",
        URI=f"#{node_id}"
    )
    
    transforms = etree.SubElement(reference, f"{{{ns_ds}}}Transforms")
    etree.SubElement(
        transforms,
        f"{{{ns_ds}}}Transform",
        Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    )
    
    etree.SubElement(
        reference,
        f"{{{ns_ds}}}DigestMethod",
        Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"
    )
    
    digest_value_elem = etree.SubElement(reference, f"{{{ns_ds}}}DigestValue")
    digest_value_elem.text = digest_b64
    
    # Firmar SignedInfo
    signed_info_c14n = etree.tostring(signed_info, method='c14n', exclusive=False, with_comments=False)
    signature_bytes = private_key.sign(signed_info_c14n, padding.PKCS1v15(), hashes.SHA1())
    signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
    
    print(f"[FIRMA] SignatureValue: {len(signature_b64)} chars")
    
    signature_value = etree.SubElement(signature, f"{{{ns_ds}}}SignatureValue")
    signature_value.text = signature_b64
    
    # KeyInfo
    key_info = etree.SubElement(signature, f"{{{ns_ds}}}KeyInfo")
    x509_data = etree.SubElement(key_info, f"{{{ns_ds}}}X509Data")
    x509_cert = etree.SubElement(x509_data, f"{{{ns_ds}}}X509Certificate")
    
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    x509_cert.text = base64.b64encode(cert_der).decode('utf-8')
    
    # XAdES
    agregar_xades(signature, certificate, sig_id)
    
    # Insertar firma
    root.append(signature)
    
    xml_final = etree.tostring(root, encoding='UTF-8', xml_declaration=True, pretty_print=False)
    
    print(f"[FIRMA] ✓ Firma completada exitosamente")
    
    return xml_final.decode('utf-8')


def agregar_xades(signature, certificate, sig_id):
    """Agrega propiedades XAdES-BES."""
    ns_ds = "http://www.w3.org/2000/09/xmldsig#"
    ns_xades = "http://uri.etsi.org/01903/v1.3.2#"
    
    obj = etree.SubElement(signature, f"{{{ns_ds}}}Object")
    
    qp_id = f"QualifyingProperties-{uuid.uuid4().hex[:8]}"
    qual_props = etree.SubElement(
        obj,
        f"{{{ns_xades}}}QualifyingProperties",
        Target=f"#{sig_id}",
        Id=qp_id
    )
    
    sp_id = f"SignedProperties-{uuid.uuid4().hex[:8]}"
    signed_props = etree.SubElement(
        qual_props,
        f"{{{ns_xades}}}SignedProperties",
        Id=sp_id
    )
    
    sig_props = etree.SubElement(signed_props, f"{{{ns_xades}}}SignedSignatureProperties")
    
    # SigningTime
    signing_time = etree.SubElement(sig_props, f"{{{ns_xades}}}SigningTime")
    signing_time.text = datetime.datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # SigningCertificate
    signing_cert = etree.SubElement(sig_props, f"{{{ns_xades}}}SigningCertificate")
    cert = etree.SubElement(signing_cert, f"{{{ns_xades}}}Cert")
    
    # CertDigest
    cert_digest = etree.SubElement(cert, f"{{{ns_xades}}}CertDigest")
    etree.SubElement(
        cert_digest,
        f"{{{ns_ds}}}DigestMethod",
        Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"
    )
    
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    cert_sha1 = hashlib.sha1(cert_der).digest()
    
    digest_val = etree.SubElement(cert_digest, f"{{{ns_ds}}}DigestValue")
    digest_val.text = base64.b64encode(cert_sha1).decode('utf-8')
    
    # IssuerSerial
    issuer_serial = etree.SubElement(cert, f"{{{ns_xades}}}IssuerSerial")
    
    issuer_name = etree.SubElement(issuer_serial, f"{{{ns_ds}}}X509IssuerName")
    issuer_name.text = certificate.issuer.rfc4514_string()
    
    serial_num = etree.SubElement(issuer_serial, f"{{{ns_ds}}}X509SerialNumber")
    serial_num.text = str(certificate.serial_number)

