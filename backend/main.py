@app.post("/emitir-factura")
def emitir_factura(factura: FacturaCompleta, 
                   background_tasks: BackgroundTasks, 
                   user: dict = Depends(get_current_user_api_key)):
    
    # Chequeo inicial: Si el usuario tiene créditos
    if user['creditos'] <= 0:
        raise HTTPException(400, "Créditos insuficientes. Por favor, recargue su saldo.")
        
    # Chequeo inicial: Si tiene la configuración de la empresa
    if not user['ruc']: 
        raise HTTPException(400, "Falta configurar empresa.")

    try:
        # --- PREPARACIÓN DE LA FACTURA ---
        
        # 1. Obtener clave de firma descifrada
        clave_firma_descifrada = encryption.decrypt_data(user['firma_clave']).strip()
        
        # 2. Obtener secuencial y ajustar la factura
        secuencial = database.obtener_siguiente_secuencial(user['id'], factura.serie)
        factura.secuencial = secuencial
        factura.ruc = user['ruc']
        
        # 3. Generar CLAVE de Acceso
        clave = utils_sri.generar_clave_acceso(
            factura.fecha_emision, "01", factura.ruc, factura.ambiente, 
            factura.serie, factura.secuencial, "12345678"
        )
        
        # 4. Generar XML CRUDO
        xml_crudo = xml_builder.crear_xml_factura(factura, clave)
        
        # 5. Firmar XML
        xml_firmado = firmador.firmar_xml(xml_crudo, user['firma_path'], clave_firma_descifrada)
        
        # --- ENVÍO AL SRI ---
        
        # 6. Enviar el comprobante a RECEPCIÓN
        envio_resultado = sri_service.enviar_comprobante(xml_firmado, factura.ambiente)
        
        if envio_resultado['estado'] == 'RECIBIDA':
            
            # Guardar en DB con estado RECIBIDA
            database.guardar_factura_bd(user['id'], clave, "01", xml_firmado, "RECIBIDA")
            database.descontar_credito(user['id'])

            # Delegar consulta de autorización a tarea de fondo
            background_tasks.add_task(
                sri_service.consultar_y_actualizar_autorizacion, 
                clave, 
                factura.ambiente
            )
            
            return {
                "estado": "RECIBIDA", 
                "clave_acceso": clave,
                "mensaje": "Comprobante recibido por el SRI. El estado final se actualizará en 5-30 segundos."
            }
                
        elif envio_resultado['estado'] == 'DEVUELTA':
            # ============================================================
            # CORRECCIÓN: Mostrar errores detallados del SRI
            # ============================================================
            
            # Guardar en BD con estado DEVUELTA
            database.guardar_factura_bd(user['id'], clave, "01", xml_firmado, "DEVUELTA")
            
            # Construir mensaje de error detallado
            mensaje_error = "❌ El SRI DEVOLVIÓ el comprobante:\n\n"
            
            # Opción 1: Si tenemos errores_legibles (formato simple)
            if 'errores_legibles' in envio_resultado and envio_resultado['errores_legibles']:
                for i, error in enumerate(envio_resultado['errores_legibles'], 1):
                    mensaje_error += f"{i}. {error}\n"
            
            # Opción 2: Si tenemos errores estructurados (formato completo)
            elif 'errores' in envio_resultado and envio_resultado['errores']:
                for i, error in enumerate(envio_resultado['errores'], 1):
                    mensaje_error += f"\n{i}. Error #{error.get('identificador', 'N/A')}\n"
                    mensaje_error += f"   Mensaje: {error.get('mensaje', 'Sin descripción')}\n"
                    if error.get('info_adicional'):
                        mensaje_error += f"   Detalle: {error.get('info_adicional')}\n"
                    if error.get('tipo'):
                        mensaje_error += f"   Tipo: {error.get('tipo')}\n"
            
            # Si no hay errores específicos, usar mensaje genérico
            else:
                mensaje_error += envio_resultado.get('mensaje', 'Error desconocido del SRI')
            
            # Devolver como HTTPException con código 400 (error del cliente)
            raise HTTPException(
                status_code=400,
                detail=mensaje_error
            )
            
        else:
            # Otro tipo de error (conexión, timeout, etc.)
            raise HTTPException(
                status_code=500, 
                detail=f"Error al enviar al SRI: {envio_resultado.get('mensaje', 'Error desconocido')}"
            )

    except HTTPException:
        # Re-lanzar las excepciones HTTP que ya generamos
        raise
    
    except Exception as e:
        # Capturar errores inesperados (firma, cifrado, DB, etc.)
        raise HTTPException(
            status_code=500,
            detail=f"Error interno: {str(e)}"
        )


# ============================================================================
# ENDPOINT ADICIONAL: Ver detalles de una factura específica
# ============================================================================

@app.get("/factura/{clave_acceso}")
def obtener_detalle_factura(clave_acceso: str, user: dict = Depends(get_current_user)):
    """
    Obtiene los detalles de una factura específica por su clave de acceso.
    """
    factura = database.obtener_factura_por_clave(user['id'], clave_acceso)
    
    if not factura:
        raise HTTPException(status_code=404, detail="Factura no encontrada")
    
    return {
        "clave_acceso": factura['clave_acceso'],
        "estado": factura['estado'],
        "fecha_emision": factura['fecha_creacion'],
        "xml": factura.get('xml_firmado') if factura['estado'] == 'AUTORIZADO' else None,
        "numero_autorizacion": factura.get('numero_autorizacion')
    }


# ============================================================================
# ENDPOINT DE DEBUG: Ver XML de una factura
# ============================================================================

@app.get("/debug/factura/{clave_acceso}/xml")
def ver_xml_factura(clave_acceso: str, user: dict = Depends(get_current_user)):
    """
    SOLO PARA DEBUG: Muestra el XML completo de una factura.
    En producción, considera remover o proteger este endpoint.
    """
    factura = database.obtener_factura_por_clave(user['id'], clave_acceso)
    
    if not factura:
        raise HTTPException(status_code=404, detail="Factura no encontrada")
    
    return Response(
        content=factura['xml_firmado'],
        media_type="application/xml",
        headers={
            "Content-Disposition": f"attachment; filename=factura_{clave_acceso}.xml"
        }
    )


# ============================================================================
# ENDPOINT PARA RE-CONSULTAR AUTORIZACIÓN MANUAL
# ============================================================================

@app.post("/factura/{clave_acceso}/consultar-autorizacion")
def consultar_autorizacion_manual(
    clave_acceso: str,
    user: dict = Depends(get_current_user)
):
    """
    Permite al usuario consultar manualmente el estado de autorización
    de una factura que quedó en estado RECIBIDA.
    """
    factura = database.obtener_factura_por_clave(user['id'], clave_acceso)
    
    if not factura:
        raise HTTPException(status_code=404, detail="Factura no encontrada")
    
    if factura['estado'] not in ['RECIBIDA', 'EN PROCESO']:
        return {
            "mensaje": f"La factura ya tiene estado final: {factura['estado']}",
            "estado": factura['estado']
        }
    
    # Obtener ambiente de la factura (debes guardarlo en la BD)
    # Por ahora, asumimos ambiente de pruebas
    ambiente = 1  # TODO: Guardar ambiente en la BD
    
    # Consultar directamente
    resultado = sri_service.consultar_autorizacion(clave_acceso, ambiente)
    
    if resultado['estado'] == 'AUTORIZADO':
        # Actualizar en BD
        database.actualizar_estado_factura(
            clave_acceso,
            'AUTORIZADO',
            resultado.get('numero_autorizacion'),
            resultado.get('xml_autorizado')
        )
        
        return {
            "estado": "AUTORIZADO",
            "numero_autorizacion": resultado['numero_autorizacion'],
            "mensaje": "Factura autorizada exitosamente"
        }
    
    elif resultado['estado'] == 'NO AUTORIZADO':
        database.actualizar_estado_factura(clave_acceso, 'NO AUTORIZADO')
        
        mensaje_error = "Factura NO AUTORIZADA:\n\n"
        if 'errores' in resultado:
            for i, error in enumerate(resultado['errores'], 1):
                mensaje_error += f"{i}. {error.get('mensaje', 'Error desconocido')}\n"
        
        raise HTTPException(status_code=400, detail=mensaje_error)
    
    return {
        "estado": resultado['estado'],
        "mensaje": resultado.get('mensaje', 'Aún en proceso')
    }
