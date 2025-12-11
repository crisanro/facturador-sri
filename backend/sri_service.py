import requests
import time
import xml.etree.ElementTree as ET
import base64
import os

# --- CONFIGURACIÓN DE URLS DEL SRI ---
# Las URLs de PRUEBAS/PRODUCCIÓN deben ser definidas o leídas desde config
# Ambiente 1 = Pruebas, 2 = Producción
AMBIENTE_PRUEBAS = 1
AMBIENTE_PRODUCCION = 2

# Definición de URLs (Se recomienda usar variables de entorno)
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


def enviar_comprobante(xml_firmado: str, ambiente: int):
    """
    Paso 1: Envía el XML firmado al Web Service de Recepción del SRI.
    """
    url_recepcion = URLS[ambiente]['recepcion']
    
    # El XML debe ir codificado en Base64 para el SRI
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
        response.raise_for_status() # Lanza excepción para errores HTTP (4xx o 5xx)
        
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
    """
    Paso 2: Consulta el Web Service de Autorización con la Clave de Acceso.
    """
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
        # Hacemos una única consulta por simplicidad
        response = requests.post(url_autorizacion, data=soap_envelope.encode('utf-8'), headers=headers, timeout=30)
        response.raise_for_status()

        root = ET.fromstring(response.content)
        
        namespaces = {
            'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
            'ns2': 'http://ec.gob.sri.ws.autorizacion'
        }
        
        # Buscamos el estado de la Autorización
        estado_autorizacion_elem = root.find('.//estado', namespaces)
        estado_autorizacion = estado_autorizacion_elem.text if estado_autorizacion_elem is not None else 'NO_ESTADO'
        
        if estado_autorizacion == 'AUTORIZADO':
            numero_autorizacion = root.find('.//numeroAutorizacion', namespaces).text
            xml_autorizacion = root.find('.//comprobante', namespaces).text # XML de la factura dentro de la respuesta
            
            # El SRI devuelve el XML de la factura en base64 dentro de <comprobante>
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
