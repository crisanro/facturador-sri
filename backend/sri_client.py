# Nuevo archivo: sri_client.py

import requests
from zeep import Client, Settings, Transport
from zeep.exceptions import Fault
import logging
import time
from typing import Tuple

# Configuramos logging para ver errores si algo falla
logging.basicConfig()
logging.getLogger('zeep').setLevel(logging.WARNING)

# URLs de los Web Services del SRI (Ambiente de Pruebas / Certificación)
# NOTA: Usar 'celcer.sri.gob.ec' para pruebas y 'cel.sri.gob.ec' para Producción.
WSDL_RECEPCION_PRUEBAS = "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl"
WSDL_AUTORIZACION_PRUEBAS = "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl"

# Se recomienda configurar un timeout (5 segundos según la ficha técnica de RIDE)
# Se recomienda usar un User-Agent normal, aunque no se ha incluido en este ejemplo.
transport = Transport(timeout=5)

def enviar_comprobante(xml_firmado: str) -> Tuple[str, str]:
    """
    Envía el XML firmado al Web Service de Recepción del SRI.
    Retorna (estado, mensaje_error_o_info)
    """
    try:
        settings = Settings(strict=False, xml_huge_tree=True)
        client = Client(WSDL_RECEPCION_PRUEBAS, settings=settings, transport=transport)
        
        # El servicio espera el XML en formato 'byte[]' [cite: 205]
        xml_bytes = xml_firmado.encode('utf-8')
        
        # Invocamos el método validarComprobante [cite: 205]
        respuesta = client.service.validarComprobante(xml_bytes)
        
        # La respuesta tiene la estructura <RespuestaRecepcionComprobante> [cite: 207]
        estado = respuesta.estado  # 'RECIBIDA' o 'DEVUELTA' [cite: 207]
        
        if estado == 'RECIBIDA':
            return "RECIBIDA", "Comprobante recibido por el SRI, en procesamiento."
        
        elif estado == 'DEVUELTA':
            # Si es DEVUELTA, hay mensajes de error que debemos parsear
            if respuesta.comprobantes and respuesta.comprobantes[0].mensajes:
                mensajes = respuesta.comprobantes[0].mensajes
                error_msgs = [f"[{m.identificador}] {m.mensaje} ({m.tipo})" for m in mensajes if m.tipo == 'ERROR']
                info_msgs = [f"[{m.identificador}] {m.mensaje} ({m.tipo})" for m in mensajes if m.tipo == 'ADVERTENCIA']
                
                # Devolvemos el primer error encontrado
                return "DEVUELTA", f"Error(es): {'; '.join(error_msgs) if error_msgs else 'N/A'}. Advertencias: {'; '.join(info_msgs)}"
            
            return "DEVUELTA", "Comprobante devuelto sin detalles de error."
            
    except Fault as f:
        # Errores SOAP (ej: XML mal formado que no pasa el esquema)
        return "DEVUELTA_SOAP", f"Error de protocolo (SOAP Fault): {str(f.message)}"
        
    except Exception as e:
        return "ERROR_CONEXION", f"Fallo al conectar o procesar respuesta: {str(e)}"


def consultar_autorizacion(clave_acceso: str) -> Tuple[str, str, str]:
    """
    Consulta el estado de autorización del comprobante usando la clave de acceso.
    Retorna (estado, numero_autorizacion, xml_autorizado_o_mensaje)
    """
    try:
        settings = Settings(strict=False, xml_huge_tree=True)
        client = Client(WSDL_AUTORIZACION_PRUEBAS, settings=settings, transport=transport)
        
        # Invocamos el método autorizacionComprobante [cite: 221]
        respuesta = client.service.autorizacionComprobante(clave_acceso)
        
        # Respuesta es RespuestaAutorizacionComprobante [cite: 220]
        if respuesta.autorizaciones and respuesta.autorizaciones[0]:
            autorizacion = respuesta.autorizaciones[0]
            estado = autorizacion.estado  # 'AUTORIZADO', 'NO AUTORIZADO', 'RECHAZADO' [cite: 149, 235]
            
            # En el esquema offline, el número de autorización es la clave de acceso [cite: 137]
            numero_autorizacion = autorizacion.numeroAutorizacion if hasattr(autorizacion, 'numeroAutorizacion') else clave_acceso
            
            if estado == 'AUTORIZADO':
                # El SRI devuelve el XML completo (con la firma y la etiqueta de Autorización)
                return "AUTORIZADO", numero_autorizacion, autorizacion.comprobante # Contiene el CDATA del XML autorizado [cite: 233]
            
            else: # NO AUTORIZADO o RECHAZADO
                mensajes = autorizacion.mensajes
                error_msgs = [f"[{m.identificador}] {m.mensaje} ({m.tipo})" for m in mensajes if m.tipo == 'ERROR']
                
                # Se devuelve el primer error para el log del usuario
                return estado, numero_autorizacion, f"Motivo(s): {'; '.join(error_msgs)}"
                
        # Si no hay autorizaciones, puede que siga en 'EN PROCESAMIENTO' (PPR)
        return "EN PROCESAMIENTO", clave_acceso, "Esperando respuesta del SRI..."
        
    except Fault as f:
        return "ERROR_AUTORIZACION_SOAP", clave_acceso, f"Error de protocolo (SOAP Fault): {str(f.message)}"
        
    except Exception as e:
        return "ERROR_CONEXION", clave_acceso, f"Fallo al consultar autorización: {str(e)}"
