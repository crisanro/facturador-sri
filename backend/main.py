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
    Header, # <--- ¡CORRECCIÓN!
)
from fastapi.security import APIKeyHeader # Solo mantenemos APIKeyHeader
# from fastapi.security import OAuth2PasswordBearer # <--- COMENTADO/ELIMINADO
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
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login") # <-- Eliminado
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True) 

# --- MODELOS DE DATOS ---
# (Modelos omitidos por brevedad)
# ...

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
# ... (Otros modelos de datos) ...
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

# 1. Definición de la dependencia de API Key (SIN CAMBIOS)
def get_current_user_api_key(api_key: str = Depends(api_key_header)):
    """Dependencia para validar API Key en el header X-API-Key"""
    user = database.buscar_usuario_por_api_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="API Key inválida o faltante en X-API-Key")
    
    # Chequeo adicional si la cuenta no está verificada o configurada (MANTENEMOS ESTO)
    if user['email_verificado'] == 0 or user['ruc'] is None:
        raise HTTPException(status_code=403, detail="Cuenta no verificada o configuración (RUC/Firma) incompleta.")
        
    return user
    
# 2. Definición de la dependencia de JWT (MODIFICADA para leer Header)
def get_current_user(authorization: str = Header(..., alias="Authorization")):
    """
    Lee el token del header Authorization: Bearer [token] y valida.
    """
    # 1. Verifica el formato "Bearer "
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token JWT inválido o faltante en Authorization: Bearer.")
        
    # 2. Extrae solo el token
    token = authorization.split(" ")[1]
    
    # 3. Decodifica el token (usando auth.py)
    payload = auth.decode_token(token)
    if not payload:
        raise HTTPException(401, "Token JWT inválido o expirado")
        
    # 4. Busca el usuario en la BD (usando database.py)
    email = payload.get("sub")
    user = database.buscar_usuario_por_email(email)
    if not user:
        raise HTTPException(401, "Usuario no encontrado")
        
    # 5. Chequeo de verificación de email (solo para JWT/Web)
    if user['email_verificado'] == 0:
        raise HTTPException(403, "Debes verificar tu email primero.")
        
    return user

# --- ENDPOINTS ---
# (Endpoints de registro y login SIN CAMBIOS)
@app.post("/registrar-usuario")
def registrar_usuario(datos: RegistroUsuario):
    # ...
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

# --- ENDPOINTS WEB (JWT OBLIGATORIO) ---

@app.post("/configurar-empresa")
def configurar_empresa(
    ruc: str = Form(...),
    razon_social: str = Form(...),
    clave_firma: str = Form(...),
    archivo_firma: UploadFile = File(...),
    usuario_actual: dict = Depends(get_current_user) # <--- REQUIERE JWT
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

@app.get("/saldo-facturas")
def consultar_saldo(user: dict = Depends(get_current_user)): # <--- REQUIERE JWT
    """
    Permite al usuario logueado consultar cuántas facturas tiene disponibles.
    """
    return {
        "creditos_disponibles": user.get('creditos', 0),
        "ruc_empresa": user.get('ruc')
    }
    
@app.post("/generar-api-key")
def generar_nueva_api_key(user: dict = Depends(get_current_user)): # <--- REQUIERE JWT
    """Genera o regenera la API Key persistente para el usuario logueado."""
    
    # 1. Requerir que la configuración esté completa antes de dar una API Key
    if user['ruc'] is None:
        raise HTTPException(400, "Debe completar la configuración (RUC/Firma) primero.")
    
    # 2. Generar la clave en la BD
    new_key = database.generar_api_key(user['id'])
    
    if new_key:
        return {"mensaje": "API Key generada exitosamente.", "api_key": new_key}
    
    raise HTTPException(500, "Error al guardar la nueva clave en la base de datos.")

# (Otros endpoints de gestión web omitidos por brevedad: historial, configuracion-empresa, etc.)
@app.get("/consultar-estado/{clave_acceso}", tags=["Comprobantes"])
def consultar_estado(clave_acceso: str, user: dict = Depends(get_current_user)):
    # ...
    # Lógica de consulta al SRI
    # ...
    return {
        "clave_acceso": clave_acceso,
        "estado": estado_autorizacion,
        "numero_autorizacion": num_autorizacion,
        "respuesta_sri": mensaje_o_xml
    }


@app.get("/factura/{clave_acceso}")
def obtener_detalle_factura(clave_acceso: str, user: dict = Depends(get_current_user)):
    # ...
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

# --- ENDPOINTS API REST (API KEY OBLIGATORIO) ---

@app.post("/emitir-factura")
def emitir_factura(factura: FacturaCompleta, user: dict = Depends(get_current_user_api_key)): # <--- ¡REQUIERE API KEY!
    if not user['ruc']: 
        # Este chequeo es redundante pero útil si se salta el de 403 en get_current_user_api_key
        raise HTTPException(400, "Falta configurar empresa.")
    
    target_ruc = user['ruc']
    
    if not user['firma_path']:
        raise HTTPException(400, "Falta firma electrónica.")
    if user['creditos'] <= 0:
        raise HTTPException(402, "Saldo insuficiente.")

    try:
        # ⚠️ CRÍTICO: Descifrado de la clave de la firma
        clave_descifrada = encryption.decrypt_data(user['firma_clave'])
        
        # ... (Resto de la lógica de facturación) ...
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
        # Si falla el descifrado aquí, se lanza la HTTPException
        raise HTTPException(400, str(e))
        
# (El resto de endpoints no relacionados con la seguridad permanecen igual)
# ...





