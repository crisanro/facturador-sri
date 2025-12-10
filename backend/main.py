from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List, Optional
import shutil
import os
import random

import utils_sri, xml_builder, database, auth, firmador

app = FastAPI(title="SaaS Facturación Ecuador")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login") # Ojo: cambiamos a 'login'

# --- MODELOS ---
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

# (Copia aquí tus modelos de FacturaCompleta, DetalleProducto, etc. del código anterior)
# ... [ESPACIO DE MODELOS DE FACTURA] ...
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
    ruc: str # El RUC ahora viene en la factura, lo validamos contra el usuario
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

# --- DEPENDENCIA ---
def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = auth.decode_token(token)
    if not payload: raise HTTPException(401, "Token inválido")
    email = payload.get("sub")
    user = database.buscar_usuario_por_email(email)
    if not user: raise HTTPException(401, "Usuario no encontrado")
    return user

@app.on_event("startup")
def startup():
    os.makedirs("firmas_clientes", exist_ok=True)
    database.inicializar_tablas()

# --- ENDPOINTS NUEVOS ---

@app.post("/registrar-usuario")
def registrar_usuario(datos: RegistroUsuario):
    # Verificar si ya existe
    if database.buscar_usuario_por_email(datos.email):
        raise HTTPException(400, "Este correo ya está registrado.")
    
    # Generar código de seguridad de 6 dígitos
    codigo = str(random.randint(100000, 999999))
    print(f"📧 [SIMULACION EMAIL] Código para {datos.email}: {codigo}") # Ver en logs
    
    hash_pass = auth.get_password_hash(datos.password)
    exito = database.registrar_usuario_inicial(datos.nombre, datos.email, hash_pass, codigo)
    
    if exito:
        return {"mensaje": "Usuario creado. Revisa tu correo (o los logs) por el código de verificación."}
    raise HTTPException(500, "Error en base de datos")

@app.post("/verificar-email")
def verificar_email(datos: VerificarCodigo):
    if database.verificar_codigo_email(datos.email, datos.codigo):
        return {"mensaje": "Email verificado correctamente. Ya puedes iniciar sesión."}
    raise HTTPException(400, "Código incorrecto.")

@app.post("/login")
def login(datos: LoginEmail):
    user = database.buscar_usuario_por_email(datos.email)
    if not user or not auth.verify_password(datos.password, user['password_hash']):
        raise HTTPException(401, "Credenciales incorrectas")
    
    if user['email_verificado'] == 0:
        raise HTTPException(403, "Debes verificar tu email primero (revisa el código).")
        
token = auth.create_access_token({"sub": user['email']})
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
    """Este paso se hace DESPUÉS de loguearse para subir el P12 y RUC"""
    
    # Validar que el RUC no esté usado por otro (salvo que sea el mismo usuario actualizando)
    existe = database.buscar_empresa_por_ruc(ruc)
    if existe and existe['email'] != usuario_actual['email']:
        raise HTTPException(400, "Este RUC ya está registrado por otro usuario.")

    path = f"firmas_clientes/{ruc}.p12"
    try:
        with open(path, "wb") as b: shutil.copyfileobj(archivo_firma.file, b)
        
        # Validar P12
        valido, msg = firmador.validar_archivo_p12(path, clave_firma, ruc)
        if not valido:
            os.remove(path)
            raise HTTPException(400, f"Error en firma: {msg}")
            
        # Guardar datos finales
        database.completar_datos_empresa(usuario_actual['email'], ruc, razon_social, path, clave_firma)
        return {"mensaje": "Empresa configurada exitosamente."}
        
    except Exception as e:
        if os.path.exists(path): os.remove(path)
        raise HTTPException(500, str(e))

@app.post("/emitir-factura")
def emitir_factura(factura: FacturaCompleta, user: dict = Depends(get_current_user)):
    # Validaciones
    if not user['ruc']: 
        raise HTTPException(400, "Falta configurar empresa.")
    if user['ruc'] != factura.ruc:
        raise HTTPException(403, "El RUC no coincide con tu cuenta.")
    if not user['firma_path']:
        raise HTTPException(400, "Falta firma electrónica.")
    if user['creditos'] <= 0:
        raise HTTPException(402, "Saldo insuficiente.")

    try:
        secuencial = database.obtener_siguiente_secuencial(user['id'], factura.serie)
        factura.secuencial = secuencial
        
        clave = utils_sri.generar_clave_acceso(
            factura.fecha_emision, "01", factura.ruc, factura.ambiente, 
            factura.serie, factura.secuencial, "12345678"
        )
        
        xml_crudo = xml_builder.crear_xml_factura(factura, clave)
        xml_firmado = firmador.firmar_xml(xml_crudo, user['firma_path'], user['firma_clave'])
        
        database.guardar_factura_bd(user['id'], clave, "01", xml_firmado)
        database.descontar_credito(user['id'])
        
        return {
            "estado": "firmado", 
            "clave_acceso": clave, 
            "xml_firmado": xml_firmado,
            "creditos_restantes": user['creditos'] - 1
        }
    except Exception as e:
        raise HTTPException(400, str(e))

