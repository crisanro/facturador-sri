import requests
import time
import xml.etree.ElementTree as ET
import base64
import os
# --- NUEVOS IMPORTS ---
import database # Necesitas importar la BD para actualizar el estado
# ----------------------

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
MAX_ATTEMPTS = 5    # Máximo de intentos de consulta
DELAY_SECONDS = 5   # Tiempo de espera entre intentos (segundos)


def enviar_comprobante(xml_firmado: str, ambiente: int):
    # ... (código de enviar_comprobante se mantiene igual) ...
    url_recepcion = URLS[ambiente]['recepcion']
    
    xml_firmado_b64 = base64.b64encode(xml_firmado.encode('utf-8')).decode('utf-8')

    soap_envelope = f"""<?xml version='1.0' encoding='utf-8'?>
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                      xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                      xmlns:sri="http://ec.gob.sri.ws.recepcion">
       <soapenv:Header/>
       <soapenv:Body>
          <sri:validarComprobante>
             <xml>{xml_firmado_b64}</xml>
          </sri:validarComprobante>
       </soapenv:Body>
    </soapenv:Envelope>"""
    
    headers = {
        'Content-Type': 'text/xml;charset=UTF-8',
        'SOAPAction': 'validarComprobante',
    }

    try:
        response = requests.post(url_recepcion, data=soap_envelope.encode('utf-8'), headers=headers, timeout=30)
        response.raise_for_status() 
        
        root = ET.fromstring(response.content)
        
        namespaces = {
            'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
            'ns2': 'http://ec.gob.sri.ws.recepcion'
        }

        estado_sri_elem = root.find('.//ns2:estado', namespaces)
        estado_sri = estado_sri_elem.text if estado_sri_elem is not None else 'NO_ESTADO'
        
        if estado_sri == 'RECIBIDA':
            return {"estado": estado_sri, "mensaje": "Comprobante recibido exitosamente por el SRI."}
        
        # Si es DEVUELTA, extraemos los mensajes
        mensajes = root.findall('.//ns2:mensaje', namespaces)
        errores = []
        for msg in mensajes:
            mensaje = msg.find('mensaje').text
            info_adicional = msg.find('informacionAdicional')
            info_adicional_text = info_adicional.text if info_adicional is not None else ""
            errores.append(f"{mensaje}. Detalle: {info_adicional_text}")
            
        return {"estado": estado_sri, "mensaje": "La recepción fue DEVUELTA.", "errores": errores}

    except requests.exceptions.RequestException as e:
        return {"estado": "ERROR_CONEXION", "mensaje": f"Error de conexión con el SRI: {e}"}
    except Exception as e:
        return {"estado": "ERROR_PROCESAMIENTO", "mensaje": f"Error al procesar respuesta de recepción: {e}"}


def consultar_autorizacion(clave_acceso: str, ambiente: int):
    # ... (código de consultar_autorizacion se mantiene igual) ...
    url_autorizacion = URLS[ambiente]['autorizacion']

    soap_envelope = f"""<?xml version='1.0' encoding='utf-8'?>
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                      xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                      xmlns:sri="http://ec.gob.sri.ws.autorizacion">
       <soapenv:Header/>
       <soapenv:Body>
          <sri:autorizacionComprobante>
             <claveAccesoComprobante>{clave_acceso}</claveAccesoComprobante>
          </sri:autorizacionComprobante>
       </soapenv:Body>
    </soapenv:Envelope>"""

    headers = {
        'Content-Type': 'text/xml;charset=UTF-8',
        'SOAPAction': 'autorizacionComprobante',
    }

    try:
        response = requests.post(url_autorizacion, data=soap_envelope.encode('utf-8'), headers=headers, timeout=30)
        response.raise_for_status()

        root = ET.fromstring(response.content)
        
        namespaces = {
            'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
            'ns2': 'http://ec.gob.sri.ws.autorizacion'
        }
        
        estado_autorizacion_elem = root.find('.//estado', namespaces)
        estado_autorizacion = estado_autorizacion_elem.text if estado_autorizacion_elem is not None else 'NO_ESTADO'
        
        if estado_autorizacion == 'AUTORIZADO':
            numero_autorizacion = root.find('.//numeroAutorizacion', namespaces).text
            xml_autorizacion = root.find('.//comprobante', namespaces).text 
            xml_factura_completa = base64.b64decode(xml_autorizacion).decode('utf-8')
            
            return {
                "estado": 'AUTORIZADO', 
                "numero_autorizacion": numero_autorizacion,
                "xml_autorizado": xml_factura_completa
            }
        
        elif estado_autorizacion == 'NO AUTORIZADO':
            mensajes = root.findall('.//mensaje', namespaces)
            errores = []
            for msg in mensajes:
                mensaje = msg.find('mensaje').text
                info_adicional = msg.find('informacionAdicional')
                info_adicional_text = info_adicional.text if info_adicional is not None else ""
                errores.append(f"{mensaje}. Detalle: {info_adicional_text}")
                
            return {"estado": 'NO AUTORIZADO', "errores": errores}

        elif estado_autorizacion in ['EN PROCESO', 'RECIBIDA']:
            return {"estado": estado_autorizacion, "mensaje": "Aún en proceso de validación por el SRI."}
        
        return {"estado": estado_autorizacion, "mensaje": "Estado desconocido en autorización."}

    except requests.exceptions.RequestException as e:
        return {"estado": "ERROR_CONEXION", "mensaje": f"Error de conexión con el SRI: {e}"}
    except Exception as e:
        return {"estado": "ERROR_PROCESAMIENTO", "mensaje": f"Error al procesar respuesta de autorización: {e}"}


# --- NUEVA FUNCIÓN DE POLLING (TAREA ASÍNCRONA) ---
def consultar_y_actualizar_autorizacion(clave_acceso: str, ambiente: int):
    """
    Función de polling (reintento) ejecutada en segundo plano para consultar la autorización
    y actualizar la base de datos sin bloquear la API.
    """
    intentos = 0
    estado_final = "FALLO_SRI"

    while intentos < MAX_ATTEMPTS:
        time.sleep(DELAY_SECONDS) 
        intentos += 1
        
        print(f"[POLLING SRI] Consultando {clave_acceso}, Intento {intentos}/{MAX_ATTEMPTS}")

        # Llama a la función de consulta de autorización que ya existe
        resultado = consultar_autorizacion(clave_acceso, ambiente) 

        if resultado['estado'] == 'AUTORIZADO':
            estado_final = 'AUTORIZADO'
            break
        
        elif resultado['estado'] == 'NO AUTORIZADO':
            estado_final = 'NO AUTORIZADO'
            break
        
    # Fuera del bucle: Actualizar el estado final en la base de datos
    conn = database.get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            # Aquí también podrías guardar el XML autorizado si el estado es AUTORIZADO
            sql_update = "UPDATE comprobantes SET estado = %s WHERE clave_acceso = %s"
            cursor.execute(sql_update, (estado_final, clave_acceso))
            conn.commit()
            print(f"DB Actualizada. Clave {clave_acceso}: {estado_final}")
        except Exception as e:
            print(f"Error al actualizar estado final en DB: {e}")
        finally:
            cursor.close()
            conn.close()
