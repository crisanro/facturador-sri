import requests
import time
import xml.etree.ElementTree as ET
import base64
import os
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# --- CONFIGURACIÓN DE URLS DEL SRI ---
AMBIENTE_PRUEBAS = 1
AMBIENTE_PRODUCCION = 2

URLS = {
    AMBIENTE_PRUEBAS: {
        'recepcion': 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl',
        'autorizacion': 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl'
    },
    AMBIENTE_PRODUCCION: {
        'recepcion': 'https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl',
        'autorizacion': 'https://cel.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl'
    }
}

# --- CONFIGURACIÓN DE POLLING ---
MAX_ATTEMPTS = 5
DELAY_SECONDS = 5


def crear_sesion_con_reintentos():
    """
    Crea una sesión de requests con reintentos automáticos.
    """
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["POST"]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def validar_xml_firmado(xml_firmado: str):
    """
    Valida que el XML firmado tenga la estructura mínima requerida.
    """
    try:
        root = ET.fromstring(xml_firmado.encode('utf-8'))
        
        # Verificar que existe el nodo Signature
        ns_ds = {'ds': 'http://www.w3.org/2000/09/xmldsig#'}
        signature = root.find('.//ds:Signature', ns_ds)
        
        if signature is None:
            return False, "El XML no contiene firma digital"
        
        # Verificar clave de acceso
        clave_acceso = root.find('.//claveAcceso')
        if clave_acceso is None or not clave_acceso.text:
            return False, "El XML no contiene clave de acceso"
        
        return True, "XML válido"
        
    except ET.ParseError as e:
        return False, f"XML mal formado: {str(e)}"


def enviar_comprobante(xml_firmado: str, ambiente: int):
    """
    Envía comprobante al SRI con manejo robusto de errores.
    """
    # 1. VALIDAR XML ANTES DE ENVIAR
    es_valido, mensaje_validacion = validar_xml_firmado(xml_firmado)
    if not es_valido:
        return {
            "estado": "ERROR_VALIDACION",
            "mensaje": mensaje_validacion
        }
    
    # 2. PREPARAR URL Y DATOS
    url_recepcion = URLS[ambiente]['recepcion']
    
    try:
        xml_firmado_b64 = base64.b64encode(xml_firmado.encode('utf-8')).decode('utf-8')
    except Exception as e:
        return {
            "estado": "ERROR_ENCODING",
            "mensaje": f"Error al codificar XML: {str(e)}"
        }

    # 3. CONSTRUIR SOAP ENVELOPE CORRECTO
    # NOTA: La URL no debe tener ?wsdl al final para el POST
    url_servicio = url_recepcion.replace('?wsdl', '')
    
    soap_envelope = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                  xmlns:ec="http://ec.gob.sri.ws.recepcion">
   <soapenv:Header/>
   <soapenv:Body>
      <ec:validarComprobante>
         <xml>{xml_firmado_b64}</xml>
      </ec:validarComprobante>
   </soapenv:Body>
</soapenv:Envelope>"""
    
    headers = {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': '',
        'User-Agent': 'Python-SRI-Client/1.0'
    }

    # 4. ENVIAR CON SESIÓN Y REINTENTOS
    session = crear_sesion_con_reintentos()
    
    try:
        print(f"[SRI] Enviando a: {url_servicio}")
        print(f"[SRI] Tamaño XML: {len(xml_firmado)} bytes")
        
        response = session.post(
            url_servicio,
            data=soap_envelope.encode('utf-8'),
            headers=headers,
            timeout=60,
            verify=True  # Verificar certificado SSL
        )
        
        print(f"[SRI] Status Code: {response.status_code}")
        
        # 5. MANEJAR RESPUESTA
        if response.status_code != 200:
            # Intentar extraer mensaje de error del SOAP Fault
            try:
                root = ET.fromstring(response.content)
                fault = root.find('.//{http://schemas.xmlsoap.org/soap/envelope/}Fault')
                if fault is not None:
                    faultstring = fault.find('faultstring')
                    error_msg = faultstring.text if faultstring is not None else "Error SOAP desconocido"
                    return {
                        "estado": "ERROR_SRI",
                        "mensaje": f"SRI rechazó el comprobante: {error_msg}",
                        "codigo_http": response.status_code
                    }
            except:
                pass
            
            return {
                "estado": "ERROR_HTTP",
                "mensaje": f"Error HTTP {response.status_code}: {response.text[:500]}",
                "codigo_http": response.status_code
            }
        
        # 6. PARSEAR RESPUESTA EXITOSA
        root = ET.fromstring(response.content)
        
        namespaces = {
            'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
            'ns2': 'http://ec.gob.sri.ws.recepcion'
        }

        estado_sri_elem = root.find('.//ns2:estado', namespaces)
        estado_sri = estado_sri_elem.text if estado_sri_elem is not None else 'NO_ESTADO'
        
        print(f"[SRI] Estado recepción: {estado_sri}")
        
        if estado_sri == 'RECIBIDA':
            return {
                "estado": estado_sri,
                "mensaje": "Comprobante recibido exitosamente por el SRI."
            }
        
        # Si es DEVUELTA, extraer mensajes de error
        mensajes = root.findall('.//ns2:mensaje', namespaces)
        errores = []
        for msg in mensajes:
            identificador = msg.find('identificador')
            mensaje = msg.find('mensaje')
            info_adicional = msg.find('informacionAdicional')
            tipo = msg.find('tipo')
            
            error_detalle = {
                "identificador": identificador.text if identificador is not None else "",
                "mensaje": mensaje.text if mensaje is not None else "",
                "info_adicional": info_adicional.text if info_adicional is not None else "",
                "tipo": tipo.text if tipo is not None else ""
            }
            errores.append(error_detalle)
        
        return {
            "estado": estado_sri,
            "mensaje": "Comprobante DEVUELTO por el SRI.",
            "errores": errores
        }

    except requests.exceptions.Timeout:
        return {
            "estado": "ERROR_TIMEOUT",
            "mensaje": "Tiempo de espera agotado al conectar con el SRI (60s)"
        }
    
    except requests.exceptions.SSLError as e:
        return {
            "estado": "ERROR_SSL",
            "mensaje": f"Error de certificado SSL: {str(e)}"
        }
    
    except requests.exceptions.ConnectionError as e:
        return {
            "estado": "ERROR_CONEXION",
            "mensaje": f"No se pudo conectar con el SRI: {str(e)}"
        }
    
    except requests.exceptions.RequestException as e:
        return {
            "estado": "ERROR_REQUEST",
            "mensaje": f"Error en la petición HTTP: {str(e)}"
        }
    
    except ET.ParseError as e:
        return {
            "estado": "ERROR_PARSE_RESPUESTA",
            "mensaje": f"Error al parsear respuesta del SRI: {str(e)}",
            "respuesta_raw": response.text[:1000]
        }
    
    except Exception as e:
        return {
            "estado": "ERROR_DESCONOCIDO",
            "mensaje": f"Error inesperado: {str(e)}"
        }
    
    finally:
        session.close()


def consultar_autorizacion(clave_acceso: str, ambiente: int):
    """
    Consulta el estado de autorización de un comprobante.
    """
    url_autorizacion = URLS[ambiente]['autorizacion'].replace('?wsdl', '')

    soap_envelope = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                  xmlns:ec="http://ec.gob.sri.ws.autorizacion">
   <soapenv:Header/>
   <soapenv:Body>
      <ec:autorizacionComprobante>
         <claveAccesoComprobante>{clave_acceso}</claveAccesoComprobante>
      </ec:autorizacionComprobante>
   </soapenv:Body>
</soapenv:Envelope>"""

    headers = {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': '',
        'User-Agent': 'Python-SRI-Client/1.0'
    }

    session = crear_sesion_con_reintentos()
    
    try:
        print(f"[SRI] Consultando autorización: {clave_acceso}")
        
        response = session.post(
            url_autorizacion,
            data=soap_envelope.encode('utf-8'),
            headers=headers,
            timeout=60,
            verify=True
        )
        
        if response.status_code != 200:
            return {
                "estado": "ERROR_HTTP",
                "mensaje": f"Error HTTP {response.status_code}",
                "codigo_http": response.status_code
            }

        root = ET.fromstring(response.content)
        
        namespaces = {
            'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
            'ns2': 'http://ec.gob.sri.ws.autorizacion'
        }
        
        estado_autorizacion_elem = root.find('.//estado', namespaces)
        estado_autorizacion = estado_autorizacion_elem.text if estado_autorizacion_elem is not None else 'NO_ESTADO'
        
        print(f"[SRI] Estado autorización: {estado_autorizacion}")
        
        if estado_autorizacion == 'AUTORIZADO':
            numero_autorizacion_elem = root.find('.//numeroAutorizacion', namespaces)
            comprobante_elem = root.find('.//comprobante', namespaces)
            
            if numero_autorizacion_elem is None or comprobante_elem is None:
                return {
                    "estado": "ERROR_RESPUESTA",
                    "mensaje": "Respuesta del SRI incompleta"
                }
            
            numero_autorizacion = numero_autorizacion_elem.text
            xml_autorizacion = comprobante_elem.text
            
            try:
                xml_factura_completa = base64.b64decode(xml_autorizacion).decode('utf-8')
            except Exception as e:
                return {
                    "estado": "ERROR_DECODE",
                    "mensaje": f"Error al decodificar XML autorizado: {str(e)}"
                }
            
            return {
                "estado": 'AUTORIZADO',
                "numero_autorizacion": numero_autorizacion,
                "xml_autorizado": xml_factura_completa
            }
        
        elif estado_autorizacion == 'NO AUTORIZADO':
            mensajes = root.findall('.//mensaje', namespaces)
            errores = []
            for msg in mensajes:
                identificador = msg.find('identificador')
                mensaje = msg.find('mensaje')
                info_adicional = msg.find('informacionAdicional')
                tipo = msg.find('tipo')
                
                error_detalle = {
                    "identificador": identificador.text if identificador is not None else "",
                    "mensaje": mensaje.text if mensaje is not None else "",
                    "info_adicional": info_adicional.text if info_adicional is not None else "",
                    "tipo": tipo.text if tipo is not None else ""
                }
                errores.append(error_detalle)
            
            return {
                "estado": 'NO AUTORIZADO',
                "errores": errores
            }

        elif estado_autorizacion in ['EN PROCESO', 'RECIBIDA']:
            return {
                "estado": estado_autorizacion,
                "mensaje": "Aún en proceso de validación por el SRI."
            }
        
        return {
            "estado": estado_autorizacion,
            "mensaje": "Estado desconocido en autorización."
        }

    except Exception as e:
        return {
            "estado": "ERROR_CONSULTA",
            "mensaje": f"Error al consultar autorización: {str(e)}"
        }
    
    finally:
        session.close()


def consultar_y_actualizar_autorizacion(clave_acceso: str, ambiente: int):
    """
    Función de polling para consultar autorización y actualizar BD.
    NOTA: Necesitas importar 'database' si usas esta función.
    """
    intentos = 0
    estado_final = "FALLO_SRI"
    numero_autorizacion = None
    xml_autorizado = None

    while intentos < MAX_ATTEMPTS:
        time.sleep(DELAY_SECONDS)
        intentos += 1
        
        print(f"[POLLING SRI] Consultando {clave_acceso}, Intento {intentos}/{MAX_ATTEMPTS}")

        resultado = consultar_autorizacion(clave_acceso, ambiente)

        if resultado['estado'] == 'AUTORIZADO':
            estado_final = 'AUTORIZADO'
            numero_autorizacion = resultado.get('numero_autorizacion')
            xml_autorizado = resultado.get('xml_autorizado')
            break
        
        elif resultado['estado'] == 'NO AUTORIZADO':
            estado_final = 'NO AUTORIZADO'
            break
    
    # Actualizar base de datos (descomentar si usas database)
    """
    try:
        import database
        conn = database.get_db_connection()
        if conn:
            cursor = conn.cursor()
            try:
                sql_update = "UPDATE comprobantes SET estado = %s, numero_autorizacion = %s WHERE clave_acceso = %s"
                cursor.execute(sql_update, (estado_final, numero_autorizacion, clave_acceso))
                conn.commit()
                print(f"[DB] Actualizado {clave_acceso}: {estado_final}")
            except Exception as e:
                print(f"[DB] Error al actualizar: {e}")
            finally:
                cursor.close()
                conn.close()
    except ImportError:
        print("[DB] Módulo database no disponible")
    """
    
    return {
        "estado": estado_final,
        "numero_autorizacion": numero_autorizacion,
        "xml_autorizado": xml_autorizado
    }


# ============================================================================
# FUNCIÓN DE DIAGNÓSTICO
# ============================================================================
def diagnosticar_conexion_sri(ambiente: int = AMBIENTE_PRUEBAS):
    """
    Prueba la conectividad con los servicios del SRI.
    """
    print("=" * 60)
    print("DIAGNÓSTICO DE CONEXIÓN CON EL SRI")
    print("=" * 60)
    
    urls = URLS[ambiente]
    
    for servicio, url in urls.items():
        print(f"\n[{servicio.upper()}]")
        print(f"URL: {url}")
        
        try:
            # Intentar GET al WSDL
            response = requests.get(url, timeout=10, verify=True)
            
            if response.status_code == 200:
                print(f"✓ WSDL accesible (HTTP {response.status_code})")
                if 'wsdl' in response.text.lower():
                    print(f"✓ Contenido WSDL válido")
            else:
                print(f"✗ Error HTTP {response.status_code}")
                
        except requests.exceptions.SSLError:
            print(f"✗ Error de certificado SSL")
        except requests.exceptions.Timeout:
            print(f"✗ Timeout (>10s)")
        except requests.exceptions.ConnectionError:
            print(f"✗ No se pudo conectar")
        except Exception as e:
            print(f"✗ Error: {str(e)}")
    
    print("\n" + "=" * 60)


# Para ejecutar diagnóstico manualmente:
# if __name__ == "__main__":
#     diagnosticar_conexion_sri()
