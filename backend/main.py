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
    BackgroundTasks # <--- ¡AGREGA ESTO!
)
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader # <--- Esto es para JWT y API Key
from pydantic import BaseModel
from typing import List, Optional
import shutil
import os
import random
from contextlib import asynccontextmanager
import stripe_service
import sri_service
from fastapi.security import APIKeyHeader
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
# 1. Definir el esquema de seguridad para API Key
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True) 

# 2. Definición de la dependencia de API Key
def get_current_user_api_key(api_key: str = Depends(api_key_header)):
    """Dependencia para validar API Key en el header X-API-Key"""
    user = database.buscar_usuario_por_api_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="API Key inválida o faltante en X-API-Key")
    
    if user['email_verificado'] == 0 or user['ruc'] is None:
        raise HTTPException(status_code=403, detail="Cuenta no verificada o configuración (RUC/Firma) incompleta.")
        
    return user
    
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
        
    # --- LÓGICA CORREGIDA ---
    # 1. Ya no generamos la clave aquí.
    # 2. Asumimos que la columna 'api_key' existe y puede ser None.
    api_key_existente = user.get('api_key') 
    
    tiene_empresa = user['ruc'] is not None
    
    # Generar el JWT para la sesión web
    token = auth.create_access_token({"sub": user['email']})
    
    return {
        "access_token": token, 
        "token_type": "bearer", 
        "configuracion_completa": tiene_empresa,
        "ruc_usuario": user['ruc'],
        "api_key_persistente": api_key_existente # <-- Devolvemos lo que exista (será None si no se ha generado)
    }

@app.post("/configurar-empresa")
def configurar_empresa(
    ruc: str = Form(...),
    razon_social: str = Form(...),
    clave_firma: str = Form(...), # <-- Clave de la firma en texto plano
    archivo_firma: UploadFile = File(...),
    usuario_actual: dict = Depends(get_current_user)
):
    # Validar unicidad RUC
    existe = database.buscar_empresa_por_ruc(ruc)
    if existe and existe['email'] != usuario_actual['email']:
        raise HTTPException(400, "Este RUC ya está registrado por otro usuario.")

    # 1. Definir la ruta de destino ABSOLUTA
    nombre_archivo = f"{ruc}.p12"
    path_completo = os.path.join(UPLOAD_DIR, nombre_archivo) # <-- RUTA ABSOLUTA

    try:
        # Asegurar que el directorio exista (aunque lifespan lo haga)
        os.makedirs(UPLOAD_DIR, exist_ok=True) 
        
        # 2. Escribir el archivo en la ruta ABSOLUTA
        archivo_firma.file.seek(0)
        with open(path_completo, "wb") as f: 
            shutil.copyfileobj(archivo_firma.file, f) # Usar copyfileobj es eficiente
        
        # 3. Validar la firma usando la RUTA ABSOLUTA
        valido, msg = firmador.validar_archivo_p12(path_completo, clave_firma, ruc) 
    
        if not valido:
            if os.path.exists(path_completo): os.remove(path_completo)
            raise HTTPException(400, f"Error en firma: {msg}")
        
        # --- LÓGICA DE ENCRIPTACIÓN: Cifrar la clave ---
        # 2. Cifrar la clave de texto plano (clave_firma) usando Fernet
        clave_firma_cifrada = encryption.encrypt_data(clave_firma)
    
        # 3. Guardar la RUTA ABSOLUTA y la CLAVE CIFRADA en la base de datos
        database.completar_datos_empresa(
            usuario_actual['email'], 
            ruc, 
            razon_social, 
            path_completo, 
            clave_firma_cifrada # <-- ¡Guardar la versión CIFRADA!
        )
    
        return {"mensaje": "Empresa configurada exitosamente."}
        
    except Exception as e:
        # Limpieza de archivo en caso de error
        if os.path.exists(path_completo): os.remove(path_completo)
        # Devolvemos el error en formato string para debug
        raise HTTPException(500, f"Error crítico al configurar: {str(e)}")

@app.post("/emitir-factura")
def emitir_factura(factura: FacturaCompleta, 
                   background_tasks: BackgroundTasks, 
                   user: dict = Depends(get_current_user_api_key)):
    
    # ... (Chequeos iniciales) ...

    try:
        # 1. Obtener secuencial y ajustar la factura (OBLIGATORIO)
        secuencial = database.obtener_siguiente_secuencial(user['id'], factura.serie)
        factura.secuencial = secuencial
        factura.ruc = user['ruc'] # Usamos el RUC del usuario autenticado
        
        # 2. Generar CLAVE de Acceso (OBLIGATORIO)
        clave = utils_sri.generar_clave_acceso(
            factura.fecha_emision, "01", factura.ruc, factura.ambiente, 
            factura.serie, factura.secuencial, "12345678"
        )
        
        # 3. Generar XML CRUDO (OBLIGATORIO - ¡LA LÍNEA QUE FALTABA!)
        xml_crudo = xml_builder.crear_xml_factura(factura, clave)
        
        # 4. Firmar XML (Ahora sí usa las variables definidas)
        xml_firmado = firmador.firmar_xml(xml_crudo, user['firma_path'], user['firma_clave'])
        
        # ... (resto de la lógica de envío asíncrono al SRI) ...
        
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

def get_current_user_api_key(api_key: str = Depends(api_key_header)):
    """Dependencia para validar API Key en el header X-API-Key"""
    user = database.buscar_usuario_por_api_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="API Key inválida o faltante en X-API-Key")
    
    # Chequeo adicional si la cuenta no está verificada o configurada
    if user['email_verificado'] == 0 or user['ruc'] is None:
        raise HTTPException(status_code=403, detail="Cuenta no verificada o configuración (RUC/Firma) incompleta.")
        
    return user

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


@app.post("/generar-api-key")
def generar_nueva_api_key(user: dict = Depends(get_current_user)):
    """Genera o regenera la API Key persistente para el usuario logueado."""
    
    # 1. Requerir que la configuración esté completa antes de dar una API Key
    if user['ruc'] is None:
        raise HTTPException(400, "Debe completar la configuración (RUC/Firma) primero.")
    
    # 2. Generar la clave en la BD
    new_key = database.generar_api_key(user['id'])
    
    if new_key:
        return {"mensaje": "API Key generada exitosamente.", "api_key": new_key}
    
    raise HTTPException(500, "Error al guardar la nueva clave en la base de datos.")












