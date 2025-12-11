from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, status, Request, Response
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List, Optional
import shutil
import os
import random
from contextlib import asynccontextmanager
import stripe_service
import sri_service

# Importamos nuestros módulos locales
import utils_sri, xml_builder, database, auth, firmador

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

# --- DEPENDENCIA ---

def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = auth.decode_token(token)
    if not payload:
        raise HTTPException(401, "Token inválido o expirado")
    email = payload.get("sub")
    user = database.buscar_usuario_por_email(email)
    if not user:
        raise HTTPException(401, "Usuario no encontrado")
    return user

# --- ENDPOINTS ---

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
        
    token = auth.create_access_token({"sub": user['email']})
    
    # Aquí estaba el error de indentación, ahora está alineado
    tiene_empresa = user['ruc'] is not None
    
    return {
        "access_token": token, 
        "token_type": "bearer", 
        "configuracion_completa": tiene_empresa,
        "ruc_usuario": user['ruc']
    }

@app.post("/configurar-empresa")
def configurar_empresa(
    ruc: str = Form(...),
    razon_social: str = Form(...),
    clave_firma: str = Form(...),
    archivo_firma: UploadFile = File(...),
    usuario_actual: dict = Depends(get_current_user)
):
    # Validar unicidad RUC
    existe = database.buscar_empresa_por_ruc(ruc)
    if existe and existe['email'] != usuario_actual['email']:
        raise HTTPException(400, "Este RUC ya está registrado por otro usuario.")

    path = f"firmas_clientes/{ruc}.p12"
    try:
        with open(path, "wb") as b: 
            shutil.copyfileobj(archivo_firma.file, b)
        
        valido, msg = firmador.validar_archivo_p12(path, clave_firma, ruc)
        if not valido:
            if os.path.exists(path): os.remove(path)
            raise HTTPException(400, f"Error en firma: {msg}")
            
        hash_clave_firma = auth.get_password_hash(clave_firma)    
        database.completar_datos_empresa(usuario_actual['email'], ruc, razon_social, path, 
    hash_clave_firma)
        return {"mensaje": "Empresa configurada exitosamente."}
        
    except Exception as e:
        if os.path.exists(path): os.remove(path)
        raise HTTPException(500, str(e))

@app.post("/emitir-factura")
def emitir_factura(factura: FacturaCompleta, user: dict = Depends(get_current_user)):
    if not user['ruc']: 
        raise HTTPException(400, "Falta configurar empresa.")
    
    target_ruc = user['ruc']
    
    # ... (omitiendo checks de firma_path y creditos por brevedad, pero mantenlos) ...

    try:
        secuencial = database.obtener_siguiente_secuencial(user['id'], factura.serie)
        factura.secuencial = secuencial
        factura.ruc = target_ruc

        clave = utils_sri.generar_clave_acceso(
            factura.fecha_emision, "01", factura.ruc, factura.ambiente, 
            factura.serie, factura.secuencial, "12345678"
        )
        
        xml_crudo = xml_builder.crear_xml_factura(factura, clave)
        xml_firmado = firmador.firmar_xml(xml_crudo, user['firma_path'], user['firma_clave'])
        
        # --- NUEVA LÓGICA DE ENVÍO AL SRI ---
        
        # 1. Enviar el comprobante
        envio_resultado = sri_service.enviar_comprobante(xml_firmado, factura.ambiente)
        
        if envio_resultado['estado'] == 'RECIBIDA':
            
            # 2. Consultar el estado de autorización (espera breve y consulta)
            # En producción, esto se haría en una tarea asíncrona o un bucle de espera
            # Aquí, por ser una API síncrona, consultamos una vez inmediatamente:
            
            time.sleep(1) # Esperamos 1 segundo por si el SRI está lento
            autorizacion_resultado = sri_service.consultar_autorizacion(clave, factura.ambiente)

            database.guardar_factura_bd(user['id'], clave, "01", xml_firmado, autorizacion_resultado['estado'])
            database.descontar_credito(user['id'])

            if autorizacion_resultado['estado'] == 'AUTORIZADO':
                # La factura está OK y lista.
                return {
                    "estado": "AUTORIZADO", 
                    "clave_acceso": clave,
                    "numero_autorizacion": autorizacion_resultado['numero_autorizacion']
                }
            
            elif autorizacion_resultado['estado'] == 'NO AUTORIZADO':
                # El SRI la rechazó después de recibirla (ej. error en totales)
                raise HTTPException(400, f"SRI RECHAZÓ (NO AUTORIZADO): {autorizacion_resultado.get('errores', ['Error desconocido'])}")
                
            else:
                # Quedó en RECIBIDA o EN PROCESO. (Se debe consultar después)
                return {
                    "estado": autorizacion_resultado['estado'], 
                    "mensaje": "Factura enviada. Consulta el estado en unos segundos."
                }
                
        elif envio_resultado['estado'] == 'DEVUELTA':
            # Rechazo inmediato (ej. error en XML o clave de acceso)
            database.guardar_factura_bd(user['id'], clave, "01", xml_firmado, "DEVUELTA")
            raise HTTPException(400, f"SRI DEVUELTA (Error de Recepción): {envio_resultado.get('errores', ['Error desconocido'])}")
            
        else:
             # Otro error (conexión, etc.)
             raise HTTPException(500, f"Error al enviar al SRI: {envio_resultado['mensaje']}")


    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/admin/recargar")
def recargar_saldo(datos: Recarga):
    exito = database.recargar_creditos(datos.ruc_cliente, datos.cantidad)
    if exito:
        return {"mensaje": "Recarga exitosa"}
    else:
        raise HTTPException(404, "Cliente no encontrado")

# --- Agregar esto en backend/main.py ---

@app.get("/consultar-ruc/{ruc}")
def consultar_ruc_endpoint(ruc: str):
    # Llamamos a la función que conecta con el SRI
    datos = utils_sri.consultar_datos_ruc_sri(ruc)
    
    # Si devuelve error, igual respondemos 200 pero con valido=False
    # para que el frontend muestre el mensaje bonito en rojo
    return datos

@app.get("/saldo-facturas")
def consultar_saldo(user: dict = Depends(get_current_user)):
    """
    Permite al usuario logueado consultar cuántas facturas tiene disponibles.
    """
    # El diccionario 'user' ya contiene todos los datos del usuario, incluyendo 'creditos'.
    # Si quieres evitar devolver información sensible (como la firma_path o hash_pass),
    # puedes seleccionar los campos, pero para simplicidad, usamos lo que ya tenemos.
    
    return {
        "creditos_disponibles": user.get('creditos', 0),
        "ruc_empresa": user.get('ruc')
    }

class CompraCreditos(BaseModel):
    # La cantidad de facturas que quiere comprar (ej. 50, 100)
    cantidad: int 

# --- ENDPOINTS DE STRIPE ---

@app.post("/comprar-facturas")
def comprar_creditos(datos: CompraCreditos, user: dict = Depends(get_current_user)):
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

@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    """
    Endpoint secreto para que Stripe nos notifique de pagos exitosos.
    """
    # 1. Obtener los datos sin parsear
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    
    # 2. Tu secreto de Webhook (OBTENIDO DESDE TU DASHBOARD DE STRIPE)
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    
    # 3. Procesar el evento y recargar
    response, status_code = stripe_service.procesar_webhook(payload, sig_header, webhook_secret)
    
    return Response(content=response, status_code=status_code)



@app.get("/historial-recargas")
def historial_recargas(user: dict = Depends(get_current_user)):
    """Muestra el historial de pagos y recargas de créditos del usuario."""
    historial = database.obtener_historial_transacciones(user['id'])
    return {"historial": historial}

# --- Nuevo Endpoint de Admin (Montos Ganados) ---
# Nota: Esto debería tener un control de acceso estricto, aquí solo lo limitamos por API Key o credenciales de Admin
@app.get("/admin/montos-ganados")
def montos_ganados():
    """Muestra el total de dinero ganado por la plataforma."""
    # RECUERDA: Agregar autenticación de administrador aquí
    total = database.obtener_monto_total_ganado()
    return {"monto_total_usd": total}

# En main.py, agregar este endpoint:
@app.get("/historial-facturas")
def historial_facturas(user: dict = Depends(get_current_user)):
    """Muestra la lista de comprobantes emitidos por el usuario."""
    historial = database.obtener_historial_comprobantes(user['id'])
    return {"facturas": historial}

