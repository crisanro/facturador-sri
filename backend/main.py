from fastapi import (
    FastAPI, 
    HTTPException, 
    UploadFile, 
    File, 
    Form, 
    Depends, 
    status,
    Request, 
    Response, 
    BackgroundTasks,
    Header,
)
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from pydantic import BaseModel
from typing import List, Optional
import shutil
import os
import random
from contextlib import asynccontextmanager
import stripe_service
import sri_service
import utils_sri, xml_builder, database, auth, firmador, sri_client
import encryption

# Importamos nuestros módulos locales
import utils_sri, xml_builder, database, auth, firmador
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "firmas_clientes")
# --- LIFECYCLE (INICIO/APAGADO) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Se ejecuta al iniciar
    os.makedirs("firmas_clientes", exist_ok=True)
    database.inicializar_tablas()
    yield
    # Se ejecuta al apagar (opcional)

app = FastAPI(title="SaaS Facturación Ecuador", lifespan=lifespan)

# Seguridad
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login") 
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True) 

# --- MODELOS DE DATOS ---

class RegistroUsuario(BaseModel):
    nombre: str
    email: str
    password: str

class VerificarCodigo(BaseModel):
    email: str
    codigo: str

class LoginEmail(BaseModel):
    email: str
    password: str

class DetalleProducto(BaseModel):
    codigo_principal: str
    descripcion: str
    cantidad: float
    precio_unitario: float
    descuento: float
    precio_total_sin_impuesto: float
    codigo_impuesto: str = "2"
    codigo_porcentaje: str
    tarifa: float
    base_imponible: float
    valor_impuesto: float

class TotalImpuesto(BaseModel):
    codigo: str
    codigo_porcentaje: str
    base_imponible: float
    valor: float

class FacturaCompleta(BaseModel):
    ruc: str 
    ambiente: int
    serie: str
    secuencial: Optional[int] = None
    fecha_emision: str 
    razon_social_emisor: str
    nombre_comercial: Optional[str] = None
    direccion_matriz: str
    direccion_establecimiento: str
    obligado_contabilidad: str
    tipo_identificacion_comprador: str 
    razon_social_comprador: str
    identificacion_comprador: str
    direccion_comprador: Optional[str] = None
    total_sin_impuestos: float
    total_descuento: float
    importe_total: float
    propina: float = 0.0
    detalles: List[DetalleProducto]
    total_impuestos: List[TotalImpuesto]
    forma_pago: str = "01"

class Recarga(BaseModel):
    ruc_cliente: str
    cantidad: int

class CompraCreditos(BaseModel):
    cantidad: int 

# --- DEPENDENCIAS DE SEGURIDAD ---

# 1. DEPENDENCIA API KEY (para uso programático)
def get_current_user_api_key(api_key: str = Depends(api_key_header)):
    """Dependencia para validar API Key en el header X-API-Key"""
    user = database.buscar_usuario_por_api_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="API Key inválida o faltante en X-API-Key")
    
    # Chequeo CRÍTICO para facturación: email verificado y configuración completa
    if user['email_verificado'] == 0 or user['ruc'] is None:
        raise HTTPException(status_code=403, detail="Cuenta no verificada o configuración (RUC/Firma) incompleta.")
        
    return user
    
# 2. DEPENDENCIA JWT (para sesión web)
def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = auth.decode_token(token)
    if not payload:
        raise HTTPException(401, "Token inválido o expirado")
    email = payload.get("sub")
    user = database.buscar_usuario_por_email(email)
    if not user:
        raise HTTPException(401, "Usuario no encontrado")
    
    # Chequeo de verificación de email
    if user['email_verificado'] == 0:
        raise HTTPException(403, "Debes verificar tu email primero.")
        
    return user

# --- ENDPOINTS PÚBLICOS ---

@app.post("/registrar-usuario")
def registrar_usuario(datos: RegistroUsuario):
    if database.buscar_usuario_por_email(datos.email):
        raise HTTPException(400, "Este correo ya está registrado.")
    
    codigo = str(random.randint(100000, 999999))
    print(f"📧 [SIMULACION EMAIL] Código para {datos.email}: {codigo}") 
    
    hash_pass = auth.get_password_hash(datos.password)
    exito = database.registrar_usuario_inicial(datos.nombre, datos.email, hash_pass, codigo)
    
    if exito:
        return {"mensaje": "Usuario creado. Revisa tu correo (o logs) por el código."}
    raise HTTPException(500, "Error en base de datos")

@app.post("/verificar-email")
def verificar_email(datos: VerificarCodigo):
    if database.verificar_codigo_email(datos.email, datos.codigo):
        return {"mensaje": "Email verificado. Ya puedes iniciar sesión."}
    raise HTTPException(400, "Código incorrecto.")

@app.post("/login")
def login(datos: LoginEmail):
    
    user = database.buscar_usuario_por_email(datos.email)

    if not user or not auth.verify_password(datos.password, user['password_hash']):
        raise HTTPException(401, "Credenciales incorrectas")
    
    if user['email_verificado'] == 0:
        raise HTTPException(403, "Debes verificar tu email primero.")
        
    api_key_existente = user.get('api_key') 
    
    tiene_empresa = user['ruc'] is not None
    
    # Generar el JWT para la sesión web
    token = auth.create_access_token({"sub": user['email']})
    
    return {
        "access_token": token, 
        "token_type": "bearer", 
        "configuracion_completa": tiene_empresa,
        "ruc_usuario": user['ruc'],
        "api_key_persistente": api_key_existente 
    }

@app.get("/consultar-ruc/{ruc}")
def consultar_ruc_endpoint(ruc: str):
    # Llamamos a la función que conecta con el SRI
    datos = utils_sri.consultar_datos_ruc_sri(ruc)
    
    return datos

# --- ENDPOINTS DE GESTIÓN WEB (REQUIERE JWT) ---

@app.post("/configurar-empresa")
def configurar_empresa(
    ruc: str = Form(...),
    razon_social: str = Form(...),
    clave_firma: str = Form(...),
    archivo_firma: UploadFile = File(...),
    usuario_actual: dict = Depends(get_current_user) # <--- JWT
):
    existe = database.buscar_empresa_por_ruc(ruc)
    if existe and existe['email'] != usuario_actual['email']:
        raise HTTPException(400, "Este RUC ya está registrado por otro usuario.")

    path = f"firmas_clientes/{ruc}.p12"
    try:
        with open(path, "wb") as b: 
            shutil.copyfileobj(archivo_firma.file, b)
        
        # 1. Validar la firma con la clave EN TEXTO PLANO
        valido, msg = firmador.validar_archivo_p12(path, clave_firma, ruc)
        if not valido:
            if os.path.exists(path): os.remove(path)
            raise HTTPException(400, f"Error en firma: {msg}")
            
        # 2. Cifrar con encryption.py
        clave_firma_cifrada = encryption.encrypt_data(clave_firma)
        
        # 3. Guardar
        database.completar_datos_empresa(
            usuario_actual['email'], 
            ruc, 
            razon_social, 
            path, 
            clave_firma_cifrada
        )
        return {"mensaje": "Empresa configurada exitosamente."}
        
    except Exception as e:
        if os.path.exists(path): os.remove(path)
        raise HTTPException(500, str(e))

@app.get("/obtener-configuracion-empresa")
def obtener_configuracion_empresa(user: dict = Depends(get_current_user)): # <--- JWT
    """
    Obtiene la configuración actual del RUC, Razón Social y ruta del archivo P12.
    """
    empresa = database.buscar_empresa_por_email(user['email'])
    
    if empresa:
        return {
            "ruc": empresa['ruc'],
            "razon_social": empresa['razon_social'],
            "firma_path": empresa['firma_path'],
            "configurada": True
        }
    return {"configurada": False}

@app.delete("/eliminar-configuracion-empresa")
def eliminar_configuracion_empresa(user: dict = Depends(get_current_user)): # <--- JWT
    """
    Elimina la configuración de la empresa (firma, ruc, razón social) y el archivo .p12 asociado.
    """
    empresa = database.buscar_empresa_por_email(user['email'])
    if not empresa:
        raise HTTPException(status_code=404, detail="No hay configuración de empresa para eliminar.")

    try:
        # 1. Eliminar el archivo .p12 físico del disco
        if os.path.exists(empresa['firma_path']):
            os.remove(empresa['firma_path'])

        # 2. Eliminar la entrada de la base de datos
        database.eliminar_configuracion_empresa(user['email'])

        return {"mensaje": "Configuración de empresa eliminada exitosamente. Debes volver a configurarla."}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar la configuración: {str(e)}")


@app.get("/saldo-facturas")
def consultar_saldo(user: dict = Depends(get_current_user)): # <--- JWT
    """
    Permite al usuario logueado consultar cuántas facturas tiene disponibles.
    """
    return {
        "creditos_disponibles": user.get('creditos', 0),
        "ruc_empresa": user.get('ruc')
    }
    
@app.post("/generar-api-key")
def generar_nueva_api_key(user: dict = Depends(get_current_user)): # <--- JWT
    """Genera o regenera la API Key persistente para el usuario logueado."""
    
    if user['ruc'] is None:
        raise HTTPException(400, "Debe completar la configuración (RUC/Firma) primero.")
    
    new_key = database.generar_api_key(user['id'])
    
    if new_key:
        return {"mensaje": "API Key generada exitosamente.", "api_key": new_key}
    
    raise HTTPException(500, "Error al guardar la nueva clave en la base de datos.")

@app.post("/comprar-facturas")
def comprar_creditos(datos: CompraCreditos, user: dict = Depends(get_current_user)): # <--- JWT
    # ... (Chequeos iniciales) ...

    checkout_url = stripe_service.crear_sesion_checkout(
        user['id'], 
        user['ruc'], 
        user['email'], 
        datos.cantidad 
    )
    
    if checkout_url:
        return {"mensaje": "Redirigiendo a Stripe", "checkout_url": checkout_url}
    
    raise HTTPException(500, "Error al generar sesión de pago.")

@app.get("/historial-recargas")
def historial_recargas(user: dict = Depends(get_current_user)): # <--- JWT
    """Muestra el historial de pagos y recargas de créditos del usuario."""
    historial = database.obtener_historial_transacciones(user['id'])
    return {"historial": historial}

@app.get("/historial-facturas")
def historial_facturas(user: dict = Depends(get_current_user)): # <--- JWT
    """Muestra la lista de comprobantes emitidos por el usuario."""
    historial = database.obtener_historial_comprobantes(user['id'])
    return {"facturas": historial}


# --- ENDPOINTS API REST PROGRAMÁTICA (REQUIERE API KEY) ---

@app.post("/emitir-factura")
def emitir_factura(factura: FacturaCompleta, user: dict = Depends(get_current_user_api_key)): # <--- API KEY
    if not user['ruc']: 
        raise HTTPException(400, "Falta configurar empresa.")
    
    target_ruc = user['ruc']
    
    if not user['firma_path']:
        raise HTTPException(400, "Falta firma electrónica.")
    if user['creditos'] <= 0:
        raise HTTPException(402, "Saldo insuficiente.")

    try:
        # ⚠️ CRÍTICO: Descifrado de la clave de la firma
        clave_descifrada = encryption.decrypt_data(user['firma_clave'])
        
        secuencial = database.obtener_siguiente_secuencial(user['id'], factura.serie)
        factura.secuencial = secuencial
        factura.ruc = target_ruc 

        clave = utils_sri.generar_clave_acceso(
            factura.fecha_emision, "01", factura.ruc, factura.ambiente, 
            factura.serie, factura.secuencial, "12345678"
        )
        
        xml_crudo = xml_builder.crear_xml_factura(factura, clave)
        xml_firmado = firmador.firmar_xml(xml_crudo, user['firma_path'], clave_descifrada)
        
        estado_recepcion, mensaje_recepcion = sri_client.enviar_comprobante(xml_firmado)
        
        database.guardar_factura_bd(user['id'], clave, "01", xml_firmado, estado_recepcion)
        database.descontar_credito(user['id'])
        
        if estado_recepcion == "RECIBIDA":
            return {
                "estado": estado_recepcion, 
                "clave_acceso": clave, 
                "mensaje": f"{mensaje_recepcion} Consulte el estado en 10-30 segundos.",
                "creditos_restantes": user['creditos'] - 1
            }
        else:
             raise HTTPException(400, f"Rechazo en Recepción SRI. {mensaje_recepcion}")

    except Exception as e:
        raise HTTPException(400, str(e))

# NOTA: Los siguientes endpoints deberían usar get_current_user_api_key si son para API REST, 
# pero los mantengo con get_current_user según tu fragmento, asumiendo que son usados en el dashboard web.
# Si quieres que usen la API Key, cambia la dependencia.

@app.get("/consultar-estado/{clave_acceso}", tags=["Comprobantes"])
def consultar_estado(clave_acceso: str, user: dict = Depends(get_current_user)): # <-- JWT
    """
    Consulta el estado de autorización del comprobante en el SRI.
    """
    estado_autorizacion, num_autorizacion, mensaje_o_xml = sri_client.consultar_autorizacion(clave_acceso)
    
    return {
        "clave_acceso": clave_acceso,
        "estado": estado_autorizacion,
        "numero_autorizacion": num_autorizacion,
        "respuesta_sri": mensaje_o_xml
    }


@app.get("/factura/{clave_acceso}")
def obtener_detalle_factura(clave_acceso: str, user: dict = Depends(get_current_user)): # <-- JWT
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


@app.get("/debug/factura/{clave_acceso}/xml")
def ver_xml_factura(clave_acceso: str, user: dict = Depends(get_current_user)): # <-- JWT
    """
    SOLO PARA DEBUG: Muestra el XML completo de una factura.
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


@app.post("/factura/{clave_acceso}/consultar-autorizacion")
def consultar_autorizacion_manual(
    clave_acceso: str,
    user: dict = Depends(get_current_user) # <-- JWT
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
    
    ambiente = 1 
    
    resultado = sri_service.consultar_autorizacion(clave_acceso, ambiente)
    
    if resultado['estado'] == 'AUTORIZADO':
        # Actualizar en BD
        # La función actualizar_estado_factura NO está en los snippets, pero asumimos su existencia
        # database.actualizar_estado_factura(...) 
        
        return {
            "estado": "AUTORIZADO",
            "numero_autorizacion": resultado['numero_autorizacion'],
            "mensaje": "Factura autorizada exitosamente"
        }
    
    elif resultado['estado'] == 'NO AUTORIZADO':
        # database.actualizar_estado_factura(clave_acceso, 'NO AUTORIZADO')
        
        mensaje_error = "Factura NO AUTORIZADA:\n\n"
        if 'errores' in resultado:
            for i, error in enumerate(resultado['errores'], 1):
                mensaje_error += f"{i}. {error.get('mensaje', 'Error desconocido')}\n"
        
        raise HTTPException(status_code=400, detail=mensaje_error)
    
    return {
        "estado": resultado['estado'],
        "mensaje": resultado.get('mensaje', 'Aún en proceso')
    }

@app.post("/admin/recargar")
def recargar_saldo(datos: Recarga):
    exito = database.recargar_creditos(datos.ruc_cliente, datos.cantidad)
    if exito:
        return {"mensaje": "Recarga exitosa"}
    else:
        raise HTTPException(404, "Cliente no encontrado")

@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    """
    Endpoint secreto para que Stripe nos notifique de pagos exitosos.
    """
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    
    response, status_code = stripe_service.procesar_webhook(payload, sig_header, webhook_secret)
    
    return Response(content=response, status_code=status_code)

@app.get("/admin/montos-ganados")
def montos_ganados():
    """Muestra el total de dinero ganado por la plataforma."""
    total = database.obtener_monto_total_ganado()
    return {"monto_total_usd": total}
