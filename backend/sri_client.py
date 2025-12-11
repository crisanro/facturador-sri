# Nuevo archivo: sri_client.py

import requests
from zeep import Client, Settings, Transport
from zeep.exceptions import Fault
import logging
import time
from typing import Tuple, Dict, Any
import database 
import ride_generator

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


        
def consultar_autorizacion(clave_acceso: str, ambiente: int) -> Dict[str, Any]: 
    """
    Consulta el estado de autorización del comprobante.
    Aseguramos que SIEMPRE devuelva un diccionario.
    """
    try:
        settings = Settings(strict=False, xml_huge_tree=True)
        client = Client(WSDL_AUTORIZACION_PRUEBAS, settings=settings, transport=transport) 
        respuesta = client.service.autorizacionComprobante(clave_acceso)
        
        # 1. Verificar si hay autorización
        if respuesta.autorizaciones and respuesta.autorizaciones[0]:
            autorizacion = respuesta.autorizaciones[0]
            estado = autorizacion.estado
            numero_autorizacion = autorizacion.numeroAutorizacion if hasattr(autorizacion, 'numeroAutorizacion') else clave_acceso

            # 2. Caso AUTORIZADO
            if estado == 'AUTORIZADO':
                # Esto es un Dict, está bien.
                return {
                    "estado": "AUTORIZADO", 
                    "numero_autorizacion": numero_autorizacion,
                    "xml_autorizado": autorizacion.comprobante
                }
    
            # 3. Caso NO AUTORIZADO o RECHAZADO
            else: 
                error_msgs = [f"[{m.identificador}] {m.mensaje} ({m.tipo})" 
                              for m in autorizacion.mensajes if m.tipo == 'ERROR']

                # Esto es un Dict, está bien.
                return {
                    "estado": estado, 
                    "numero_autorizacion": numero_autorizacion,
                    "mensaje": f"Motivo(s): {'; '.join(error_msgs)}"
                }

        # 4. Si no hay autorizaciones (sigue EN PROCESAMIENTO)
        # Esto es un Dict, está bien.
        return {"estado": "EN PROCESAMIENTO", "mensaje": "Esperando respuesta del SRI..."}
            
    except Fault as f:
        # 5. Manejo de Errores SOAP (Protocolo)
        # Esto debe devolver un Dict.
        return {"estado": "ERROR_AUTORIZACION_SOAP", "mensaje": f"Error de protocolo (SOAP Fault): {str(f.message)}"}
        
    except Exception as e:
        # 6. Manejo de Errores de Conexión/Genéricos (ÚLTIMO PUNTO DE FALLO)
        # Esto debe devolver un Dict.
        return {"estado": "ERROR_CONEXION", "mensaje": f"Fallo al consultar autorización: {str(e)}"}

MAX_ATTEMPTS = 5
DELAY_SECONDS = 5

def iniciar_polling_autorizacion(clave_acceso: str, ambiente: int):
    """
    Maneja el polling en segundo plano, actualiza la BD y genera el PDF.
    
    Asume que consultar_autorizacion SIEMPRE devuelve un diccionario 
    con la clave 'estado'.
    """
    intentos = 0
    estado_final = "EN PROCESO"
    numero_autorizacion = None
    xml_autorizado = None
    mensaje_final = None # Capturaremos el mensaje de error/rechazo aquí
    
    print(f"[POLLING] Iniciando polling para clave: {clave_acceso}")

    while intentos < MAX_ATTEMPTS:
        time.sleep(DELAY_SECONDS)
        intentos += 1
        
        # Consultar la autorización (debe devolver Dict)
        resultado = consultar_autorizacion(clave_acceso, ambiente)

        # 1. Chequeo de estados finales y errores irrecuperables
        estado_polling = resultado['estado']
        
        if estado_polling == 'AUTORIZADO':
            estado_final = 'AUTORIZADO'
            numero_autorizacion = resultado.get('numero_autorizacion')
            xml_autorizado = resultado.get('xml_autorizado')
            mensaje_final = "Autorización exitosa."
            break # Salir del bucle al autorizarse
        
        elif estado_polling in ['NO AUTORIZADO', 'ERROR_CONEXION', 'ERROR_AUTORIZACION_SOAP']:
            # NO AUTORIZADO (Rechazo final del SRI) o Error de comunicación/protocolo
            estado_final = estado_polling
            mensaje_final = resultado.get('mensaje', 'Error desconocido.')
            numero_autorizacion = resultado.get('numero_autorizacion') # Puede ser None
            break # Salir del bucle por rechazo o fallo grave
        
        # Si el estado es 'EN PROCESAMIENTO', el bucle continúa
        
        print(f"[POLLING] {clave_acceso} - Intento {intentos}/{MAX_ATTEMPTS}. Estado: {estado_polling}")

    # 1. Procesar resultado final y generar PDF si está autorizado
    pdf_path = None
    if estado_final == 'AUTORIZADO':
        # Simular la generación del PDF (RIDE)
        pdf_path = ride_generator.generar_pdf_ride(clave_acceso)

    # 2. Actualizar base de datos con el estado final
    database.actualizar_estado_factura(
        clave_acceso,
        estado_final,
        numero_autorizacion,
        xml_autorizado,
        pdf_path 
    )
    
    print(f"[POLLING] Finalizado para {clave_acceso}. Estado final: {estado_final}. Mensaje: {mensaje_final}")
