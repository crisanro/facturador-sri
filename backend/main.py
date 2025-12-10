from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List, Optional
import shutil
import os

# --- IMPORTAMOS NUESTROS MÓDULOS ---
import utils_sri
import xml_builder
import database
import auth       # <--- Nuevo: Seguridad
import firmador   # <--- Nuevo: Firma Electrónica

app = FastAPI(title="SaaS Facturación Ecuador")

# Configuración de Seguridad (Dónde buscar el token)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- MODELOS DE DATOS ---

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
    # Datos Clave
    ruc: str
    ambiente: int
    serie: str
    secuencial: Optional[int] = None
    fecha_emision: str 
    
    # Datos Emisor y Cliente
    razon_social_emisor: str
    nombre_comercial: Optional[str] = None
    direccion_matriz: str
    direccion_establecimiento: str
    obligado_contabilidad: str
    
    tipo_identificacion_comprador: str 
    razon_social_comprador: str
    identificacion_comprador: str
    direccion_comprador: Optional[str] = None
    
    # Totales
    total_sin_impuestos: float
    total_descuento: float
    importe_total: float
    propina: float = 0.0
    
    detalles: List[DetalleProducto]
    total_impuestos: List[TotalImpuesto]
    forma_pago: str = "01"

# Modelo para Login
class LoginData(BaseModel):
    ruc: str
    password: str

# --- DEPENDENCIA DE SEGURIDAD ---
# Esta función protege los endpoints. Si no hay token válido, bloquea el acceso.
def get_current_empresa(token: str = Depends(oauth2_scheme)):
    payload = auth.decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    ruc = payload.get("sub")
    empresa = database.buscar_empresa_por_ruc(ruc)
    if not empresa:
        raise HTTPException(status_code=401, detail="Empresa no encontrada")
    return empresa

# --- INICIO ---
@app.on_event("startup")
def startup_event():
    os.makedirs("firmas_clientes", exist_ok=True)
    database.inicializar_tablas()

# --- ENDPOINTS PÚBLICOS ---

@app.post("/registrar-empresa")
def registrar_empresa(
    ruc: str = Form(...),
    razon_social: str = Form(...),
    password_login: str = Form(...),
    email: str = Form(...),    # Nuevo campo
    telefono: str = Form(...)  # Nuevo campo
):
    pass_hash = auth.get_password_hash(password_login)
    exito = database.crear_empresa(ruc, razon_social, pass_hash, email, telefono)
    if exito:
        return {"mensaje": "Cuenta creada. Por favor inicia sesión para configurar tu firma."}
    else:
        raise HTTPException(400, "Error: El RUC ya existe")

# Nuevo Endpoint: Subir Firma (Validando)
@app.post("/subir-firma")
def subir_firma_electronica(
    clave_firma: str = Form(...),
    archivo_firma: UploadFile = File(...),
    empresa_actual: dict = Depends(get_current_empresa)
):
    # 1. Guardar temporalmente para validar
    path_firma = f"firmas_clientes/{empresa_actual['ruc']}.p12"
    
    try:
        with open(path_firma, "wb") as buffer:
            shutil.copyfileobj(archivo_firma.file, buffer)
            
        # 2. VALIDAR (Llamamos a la función nueva)
        es_valida, mensaje = firmador.validar_archivo_p12(
            path_firma, 
            clave_firma, 
            empresa_actual['ruc']
        )
        
        if not es_valida:
            os.remove(path_firma) # Borramos el archivo malo
            raise HTTPException(400, detail=f"Firma Inválida: {mensaje}")
            
        # 3. Si es válida, actualizamos la BD
        database.actualizar_firma_cliente(empresa_actual['ruc'], path_firma, clave_firma)
        
        return {"mensaje": "✅ Firma electrónica validada y guardada correctamente."}
        
    except Exception as e:
        if os.path.exists(path_firma): os.remove(path_firma) # Limpieza
        raise HTTPException(500, detail=str(e))

@app.post("/token")
def login(datos: LoginData):
    """Genera un Token de acceso si el RUC y contraseña son correctos."""
    empresa = database.buscar_empresa_por_ruc(datos.ruc)
    
    if not empresa or not auth.verify_password(datos.password, empresa['password_hash']):
        raise HTTPException(status_code=401, detail="RUC o contraseña incorrectos")
        
    access_token = auth.create_access_token(data={"sub": empresa['ruc']})
    return {"access_token": access_token, "token_type": "bearer"}

# --- ENDPOINTS PROTEGIDOS (Requieren Token) ---
@app.post("/emitir-factura")
def emitir_factura(
    factura: FacturaCompleta, 
    empresa_actual: dict = Depends(get_current_empresa)
):
    # 1. Seguridad de RUC
    if factura.ruc != empresa_actual['ruc']:
        raise HTTPException(status_code=403, detail="RUC incorrecto")

    # 2. VALIDACIÓN DE SALDO (¡EL COBRO!)
    if empresa_actual['creditos'] <= 0:
        raise HTTPException(
            status_code=402, # 402 = Payment Required (Pago Requerido)
            detail="⚠️ Saldo insuficiente. Por favor recarga créditos para seguir facturando."
        )

    try:
        # 2. Calcular Secuencial Automático
        secuencial_auto = database.obtener_siguiente_secuencial(empresa_actual['id'], factura.serie)
        if not secuencial_auto:
            raise HTTPException(500, "Error generando secuencial")
            
        factura.secuencial = secuencial_auto

        # 3. Generar Clave de Acceso
        clave = utils_sri.generar_clave_acceso(
            fecha_emision=factura.fecha_emision,
            tipo_comprobante="01",
            ruc=factura.ruc,
            ambiente=factura.ambiente,
            serie=factura.serie,
            secuencial=factura.secuencial, 
            codigo_numerico="12345678"
        )
        
        # 4. Generar XML Crudo
        xml_crudo = xml_builder.crear_xml_factura(factura, clave)
        
        # 5. FIRMAR EL XML (La parte nueva)
        try:
            xml_firmado = firmador.firmar_xml(
                xml_string=xml_crudo,
                ruta_p12=empresa_actual['firma_path'],
                password_p12=empresa_actual['firma_clave']
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error firmando XML: {str(e)}")
        
        # 6. Guardar en Base de Datos (El firmado)
        database.guardar_factura_bd(empresa_actual['id'], clave, "01", xml_firmado)
        
        # 7. RESTAR EL CRÉDITO
        database.descontar_credito(empresa_actual['id'])

        # Obtener saldo restante para mostrarlo
        saldo_restante = empresa_actual['creditos'] - 1

        return {
            "estado": "firmado",
            "mensaje": "Factura generada con éxito.",
            "creditos_restantes": saldo_restante, # Le avisamos cuánto le queda
            "clave_acceso": clave,
            "xml_firmado": xml_firmado
        }

    except Exception as e:
        raise HTTPException(400, f"Error: {str(e)}")
    

class Recarga(BaseModel):
    ruc_cliente: str
    cantidad: int

@app.post("/admin/recargar")
def recargar_saldo(datos: Recarga):
    """Endpoint para que TÚ le recargues saldo a un cliente"""
    exito = database.recargar_creditos(datos.ruc_cliente, datos.cantidad)
    if exito:
        return {"mensaje": f"Se agregaron {datos.cantidad} créditos al RUC {datos.ruc_cliente}"}
    else:

        raise HTTPException(404, "Cliente no encontrado")
