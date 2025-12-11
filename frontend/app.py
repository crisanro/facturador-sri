
import streamlit as st
import requests
import os
import time
import pandas as pd
from datetime import datetime, timedelta
from extra_streamlit_components import CookieManager

# --- 1. CONFIGURACIÓN INICIAL ---
BACKEND_URL = os.getenv("API_URL", "http://facturador-backend:80") 
RUC_ADMIN = "1760013210001" 
IVA_RATE = 0.15 # Tasa de IVA actual en Ecuador
TOKEN_COOKIE_KEY = 'auth_token_jwt' # Nombre de la cookie para guardar el token
TOKEN_EXPIRY_DAYS = 7 

st.set_page_config(page_title="Facturación SaaS", page_icon="🧾", layout="wide")

# Inicializar el gestor de cookies
cookie_manager = CookieManager()

# CRÍTICO: Esperar a que las cookies se carguen
cookies = cookie_manager.get_all()

# --- 2. ESTILOS CSS PARA QUE SE VEA PROFESIONAL ---
st.markdown("""
    <style>
    .stButton>button { width: 100%; font-weight: bold; border-radius: 8px; }
    .metric-card { 
        background-color: #f0f2f6; 
        padding: 15px; 
        border-radius: 10px; 
        margin-bottom: 10px; 
        box-shadow: 2px 2px 8px rgba(0,0,0,0.1); 
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 15px; /* Espacio entre pestañas */
    }
    </style>
""", unsafe_allow_html=True)

# --- 3. GESTIÓN DE ESTADO (SESIÓN) ---
# Lógica clave: Intenta obtener el token de la cookie si no está en la sesión
# --- GESTIÓN DE ESTADO (SESIÓN) - CORREGIDA ---
# Intentar obtener el token de la cookie si no está en la sesión
if 'token' not in st.session_state or st.session_state.token is None:
    token_from_cookie = cookie_manager.get(TOKEN_COOKIE_KEY)
    if token_from_cookie and token_from_cookie != "":
        st.session_state.token = token_from_cookie
    else:
        st.session_state.token = None

# Inicializar otras variables de sesión
if 'config_completa' not in st.session_state: 
    st.session_state.config_completa = False
if 'empresa_ruc' not in st.session_state: 
    st.session_state.empresa_ruc = None
if 'api_key' not in st.session_state: 
    st.session_state.api_key = None
if 'datos_sri_temp' not in st.session_state: 
    st.session_state.datos_sri_temp = {}

# Variable para controlar la carga inicial
if 'initial_load_done' not in st.session_state:
    st.session_state.initial_load_done = False


# --- 4. FUNCIONES DE CONEXIÓN AL BACKEND (Corregidas para el token) ---

def logout_user():
    """Limpia la sesión y la cookie de forma segura."""
    st.session_state.token = None
    st.session_state.config_completa = False
    st.session_state.empresa_ruc = None
    st.session_state.api_key = None
    st.session_state.initial_load_done = False
    
    # Eliminar cookie solo si existe
    try:
        existing_cookies = cookie_manager.get_all()
        if TOKEN_COOKIE_KEY in existing_cookies:
            cookie_manager.delete(TOKEN_COOKIE_KEY)
    except Exception:
        pass  # Ignorar errores al eliminar cookies
    
    st.rerun()
    

def consultar_saldo_api(token_a_usar):
    """
    Consulta los créditos disponibles y, si el token es válido (200),
    actualiza los datos de sesión (ruc, config_completa).
    """
    headers = {"Authorization": f"Bearer {token_a_usar}"}
    try:
        res = requests.get(f"{BACKEND_URL}/saldo-facturas", headers=headers, timeout=5)
        if res.status_code == 200:
            data = res.json()
            # Actualiza los datos de la sesión (esencial para la persistencia)
            st.session_state.config_completa = data.get("ruc_usuario") is not None
            st.session_state.empresa_ruc = data.get("ruc_usuario")
            st.session_state.api_key = data.get("api_key_persistente") # <-- ASEGURAR ESTO
            return data
        return None
    except:
        return None

def load_persisted_token():
    """
    Verifica si el token cargado desde la cookie es válido.
    """
    if st.session_state.token is not None:
        valido = consultar_saldo_api(st.session_state.token)
        
        if valido:
            return True
        else:
            # Token expirado - limpiar todo
            st.session_state.token = None
            st.session_state.config_completa = False
            st.session_state.empresa_ruc = None
            st.session_state.api_key = None
            st.session_state.initial_load_done = False
            
            # Eliminar cookie de forma segura
            try:
                existing_cookies = cookie_manager.get_all()
                if TOKEN_COOKIE_KEY in existing_cookies:
                    cookie_manager.delete(TOKEN_COOKIE_KEY)
            except Exception:
                pass
            
            st.warning("⚠️ Su sesión ha expirado. Ingrese sus credenciales nuevamente.")
            return False
            
    return False


def do_login(email, password):
    """Limpia la sesión y la cookie de forma segura."""
    st.session_state.token = None
    st.session_state.config_completa = False
    st.session_state.empresa_ruc = None
    st.session_state.api_key = None
    st.session_state.initial_load_done = False
    
    # Eliminar cookie solo si existe
    try:
        existing_cookies = cookie_manager.get_all()
        if TOKEN_COOKIE_KEY in existing_cookies:
            cookie_manager.delete(TOKEN_COOKIE_KEY)
    except Exception:
        pass  # Ignorar errores al eliminar cookies
    
    st.rerun()


# ... (El resto de funciones auxiliares consultar_ruc_api, recargar_saldo_admin, emitir_factura_api,
# obtener_historial_facturas_api, obtener_historial_recargas_api, crear_sesion_compra_api se mantienen) ...

def consultar_ruc_api(ruc):
    """Consulta al backend, quien a su vez consulta al SRI"""
    try:
        res = requests.get(f"{BACKEND_URL}/consultar-ruc/{ruc}")
        if res.status_code == 200:
            return res.json()
        return None
    except:
        return None

def recargar_saldo_admin(ruc_cliente, cantidad):
    """Función secreta para el dueño del SaaS"""
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    try:
        res = requests.post(f"{BACKEND_URL}/admin/recargar", json={"ruc_cliente": ruc_cliente, "cantidad": cantidad}, headers=headers)
        if res.status_code == 200:
            st.success(f"✅ Recarga de {cantidad} créditos exitosa al RUC {ruc_cliente}")
        else:
            st.error(f"Error: {res.text}")
    except Exception as e:
        st.error(f"Error: {e}")

def emitir_factura_api(payload):
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    try:
        return requests.post(f"{BACKEND_URL}/emitir-factura", json=payload, headers=headers)
    except Exception as e:
        return None


def obtener_historial_facturas_api():
    """Consulta el historial de facturas generadas."""
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    try:
        res = requests.get(f"{BACKEND_URL}/historial-facturas", headers=headers)
        if res.status_code == 200:
            return res.json().get('facturas', [])
        return []
    except:
        return []

def obtener_historial_recargas_api():
    """Consulta el historial de pagos y recargas."""
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    try:
        res = requests.get(f"{BACKEND_URL}/historial-recargas", headers=headers)
        if res.status_code == 200:
            return res.json().get('historial', [])
        return []
    except:
        return []
        
def crear_sesion_compra_api(cantidad):
    """Llama al backend para iniciar el proceso de Stripe."""
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    try:
        res = requests.post(f"{BACKEND_URL}/comprar-facturas", json={"cantidad": cantidad}, headers=headers)
        if res.status_code == 200:
            return res.json().get("checkout_url")
        st.error(f"Error al iniciar pago: {res.json().get('detail')}")
        return None
    except Exception as e:
        st.error(f"Error de conexión: {e}")
        return None

# --- 5. MÓDULOS DE INTERFAZ (UI Functions) ---

# Función auxiliar para consultar el estado del backend
@st.cache_data(ttl=60) # Cacha la respuesta por 60 segundos
def obtener_configuracion_api():
    token = st.session_state.token
    if not token: return {"configurada": False}
    
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(f"{BACKEND_URL}/obtener-configuracion-empresa", headers=headers)
        if response.status_code == 200:
            return response.json()
    except:
        pass # Ignorar errores de conexión
    return {"configurada": False}

# Función auxiliar para eliminar la configuración
def eliminar_configuracion_api():
    token = st.session_state.token
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.delete(f"{BACKEND_URL}/eliminar-configuracion-empresa", headers=headers)
        if response.status_code == 200:
            return True, response.json().get("mensaje", "Eliminado.")
        else:
            return False, response.json().get("detail", "Error al eliminar.")
    except Exception as e:
        return False, f"Error de conexión: {e}"


def configurar_empresa_api(ruc, razon_social, clave_firma, archivo_firma):
    """Llama al backend para subir la firma y configurar la empresa."""
    
    # 1. Crear el FormData
    files = {'archivo_firma': (archivo_firma.name, archivo_firma.getvalue(), archivo_firma.type)}
    data = {
        'ruc': ruc,
        'razon_social': razon_social,
        'clave_firma': clave_firma,
    }
    
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    
    try:
        # 2. Enviar la solicitud multipart/form-data
        res = requests.post(f"{BACKEND_URL}/configurar-empresa", data=data, files=files, headers=headers)
        
        if res.status_code == 200:
            return True, res.json().get("mensaje", "Configuración guardada.")
        
        # Manejar errores de validación de firma o RUC
        detail = res.json().get("detail", res.text)
        return False, detail
        
    except Exception as e:
        return False, f"Error de conexión con el backend: {e}"


# --- NUEVA FUNCIÓN DE DESCARGA ---
def generar_opciones_descarga_ui(clave_acceso, estado):
    """Genera los botones HTML para descargar XML y RIDE (PDF)."""
    
    # URL base para el endpoint público de descarga
    base_url = f"{BACKEND_URL}/facturas/descargar/{clave_acceso}"
    
    if estado == 'AUTORIZADO':
        url_pdf = f"{base_url}?tipo=pdf"
        url_xml = f"{base_url}?tipo=xml"
        
        # Usamos HTML/CSS para alinear los botones en la tabla
        return f"""
        <div style="display: flex; gap: 5px; justify-content: center;">
            <a href="{url_pdf}" target="_blank" 
                style="background-color: #007bff; color: white; padding: 5px 10px; border-radius: 5px; text-decoration: none; font-weight: bold;">
                RIDE (PDF)
            </a>
            <a href="{url_xml}" target="_blank" 
                style="background-color: #6c757d; color: white; padding: 5px 10px; border-radius: 5px; text-decoration: none; font-weight: bold;">
                XML
            </a>
        </div>
        """
    elif estado == 'DEVUELTA' or estado == 'NO AUTORIZADO':
        return '<span style="color: red; font-weight: bold;">Rechazada</span>'
    
    return '<span style="color: orange;">En Proceso...</span>'


def show_configuracion():
    """Muestra y permite editar la configuración de firma electrónica"""
    config = obtener_configuracion_api()
    
    st.subheader("Firma Electrónica y Datos de Facturación")

    is_configurada = config.get("configurada", False)
    
    if is_configurada:
        # ===== MODO EDICIÓN =====
        st.success("✅ Configuración de empresa registrada y vigente.")
        
        # Mostrar datos actuales
        col1, col2 = st.columns(2)
        with col1:
            st.metric("RUC", config.get("ruc", "—"))
        with col2:
            st.metric("Razón Social", config.get("razon_social", "—"))
        
        firma_path = config.get("firma_path") or ''
        nombre_archivo = os.path.basename(firma_path) if firma_path else 'No configurado'
        st.caption(f"📄 Archivo .p12 actual: **{nombre_archivo}**")
        
        st.markdown("---")
        
        # OPCIÓN 1: Editar solo la firma (mantener RUC y Razón Social)
        with st.expander("🔄 Actualizar Firma Electrónica"):
            st.info("Si su firma ha expirado, puede actualizarla aquí sin cambiar los demás datos.")
            with st.form("actualizar_firma_form"):
                nueva_clave = st.text_input("Nueva Clave de Firma", type="password")
                nuevo_archivo = st.file_uploader(
                    "Subir Nueva Firma (.p12)", 
                    type=["p12"],
                    help="Tamaño máximo: 100 KB"
                )
                
                if st.form_submit_button("Actualizar Firma", type="primary"):
                    if not nueva_clave or not nuevo_archivo:
                        st.error("Complete todos los campos.")
                    elif nuevo_archivo.size > 100 * 1024:  # 100 KB en bytes
                        st.error("⚠️ El archivo supera el tamaño máximo de 100 KB.")
                    else:
                        # Reutilizar RUC y Razón Social existentes
                        success, msg = configurar_empresa_api(
                            config.get("ruc"),
                            config.get("razon_social"),
                            nueva_clave,
                            nuevo_archivo
                        )
                        if success:
                            st.success(msg)
                            obtener_configuracion_api.clear()
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error(msg)
        
        # OPCIÓN 2: Eliminar todo y reconfigurar desde cero
        st.markdown("---")
        st.warning("⚠️ **Eliminar toda la configuración** (incluye RUC, Razón Social y Firma)")
        
        if st.button("🗑️ Eliminar Configuración Completa", type="secondary"):
            st.session_state.confirm_delete = True
            
        if st.session_state.get("confirm_delete"):
            st.error("⚠️ ¿Está seguro? Esta acción eliminará **todos** los datos de configuración.")
            col_del, col_cancel = st.columns(2)
            with col_del:
                if st.button("SÍ, Eliminar Todo", key="confirm_del_btn", type="primary"):
                    success, msg = eliminar_configuracion_api()
                    if success:
                        st.session_state.confirm_delete = False
                        st.success(msg)
                        obtener_configuracion_api.clear()
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(msg)
            with col_cancel:
                if st.button("Cancelar", key="cancel_del_btn"):
                    st.session_state.confirm_delete = False
                    st.rerun()

    else:
        # ===== MODO CREACIÓN (Primera vez) =====
        st.warning("⚠️ Su empresa no está configurada. Complete el formulario para empezar a facturar.")
        
        with st.form("config_empresa_form", clear_on_submit=True):
            ruc = st.text_input("RUC (Ecuador)", max_chars=13, placeholder="1234567890001")
            razon_social = st.text_input("Razón Social / Nombre Comercial", placeholder="Mi Empresa S.A.")
            clave_firma = st.text_input("Clave de la Firma Electrónica", type="password")
            archivo_firma = st.file_uploader(
                "Subir Archivo de Firma (.p12)", 
                type=["p12"],
                help="Tamaño máximo: 100 KB"
            )
            
            submitted = st.form_submit_button("💾 Guardar Configuración", type="primary")

            if submitted:
                if not all([ruc, razon_social, clave_firma, archivo_firma]):
                    st.error("❌ Por favor, complete todos los campos.")
                elif len(ruc) != 13:
                    st.error("❌ El RUC debe tener exactamente 13 dígitos.")
                elif archivo_firma.size > 100 * 1024:  # 100 KB
                    st.error(f"⚠️ El archivo pesa {archivo_firma.size / 1024:.1f} KB. Máximo permitido: 100 KB.")
                else:
                    success, msg = configurar_empresa_api(ruc, razon_social, clave_firma, archivo_firma)
                    if success:
                        st.success(msg)
                        obtener_configuracion_api.clear()
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(msg)


def show_configuracion():
    """Muestra y permite editar la configuración de firma electrónica"""
    config = obtener_configuracion_api()
    
    st.subheader("Firma Electrónica y Datos de Facturación")

    is_configurada = config.get("configurada", False)
    
    if is_configurada:
        # ===== MODO EDICIÓN =====
        st.success("✅ Configuración de empresa registrada y vigente.")
        
        # Mostrar datos actuales
        col1, col2 = st.columns(2)
        with col1:
            st.metric("RUC", config.get("ruc", "—"))
        with col2:
            st.metric("Razón Social", config.get("razon_social", "—"))
        
        firma_path = config.get("firma_path") or ''
        nombre_archivo = os.path.basename(firma_path) if firma_path else 'No configurado'
        st.caption(f"📄 Archivo .p12 actual: **{nombre_archivo}**")
        
        st.markdown("---")
        
        # OPCIÓN 1: Editar solo la firma (mantener RUC y Razón Social)
        with st.expander("🔄 Actualizar Firma Electrónica"):
            st.info("Si su firma ha expirado, puede actualizarla aquí sin cambiar los demás datos.")
            with st.form("actualizar_firma_form"):
                nueva_clave = st.text_input("Nueva Clave de Firma", type="password")
                nuevo_archivo = st.file_uploader(
                    "Subir Nueva Firma (.p12)", 
                    type=["p12"],
                    help="Tamaño máximo: 100 KB"
                )
                
                if st.form_submit_button("Actualizar Firma", type="primary"):
                    if not nueva_clave or not nuevo_archivo:
                        st.error("Complete todos los campos.")
                    elif nuevo_archivo.size > 100 * 1024:  # 100 KB en bytes
                        st.error("⚠️ El archivo supera el tamaño máximo de 100 KB.")
                    else:
                        # Reutilizar RUC y Razón Social existentes
                        success, msg = configurar_empresa_api(
                            config.get("ruc"),
                            config.get("razon_social"),
                            nueva_clave,
                            nuevo_archivo
                        )
                        if success:
                            st.success(msg)
                            obtener_configuracion_api.clear()
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error(msg)
        
        # OPCIÓN 2: Eliminar todo y reconfigurar desde cero
        st.markdown("---")
        st.warning("⚠️ **Eliminar toda la configuración** (incluye RUC, Razón Social y Firma)")
        
        if st.button("🗑️ Eliminar Configuración Completa", type="secondary"):
            st.session_state.confirm_delete = True
            
        if st.session_state.get("confirm_delete"):
            st.error("⚠️ ¿Está seguro? Esta acción eliminará **todos** los datos de configuración.")
            col_del, col_cancel = st.columns(2)
            with col_del:
                if st.button("SÍ, Eliminar Todo", key="confirm_del_btn", type="primary"):
                    success, msg = eliminar_configuracion_api()
                    if success:
                        st.session_state.confirm_delete = False
                        st.success(msg)
                        obtener_configuracion_api.clear()
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(msg)
            with col_cancel:
                if st.button("Cancelar", key="cancel_del_btn"):
                    st.session_state.confirm_delete = False
                    st.rerun()

    else:
        # ===== MODO CREACIÓN (Primera vez) =====
        st.warning("⚠️ Su empresa no está configurada. Complete el formulario para empezar a facturar.")
        
        with st.form("config_empresa_form", clear_on_submit=True):
            ruc = st.text_input("RUC (Ecuador)", max_chars=13, placeholder="1234567890001")
            razon_social = st.text_input("Razón Social / Nombre Comercial", placeholder="Mi Empresa S.A.")
            clave_firma = st.text_input("Clave de la Firma Electrónica", type="password")
            archivo_firma = st.file_uploader(
                "Subir Archivo de Firma (.p12)", 
                type=["p12"],
                help="Tamaño máximo: 100 KB"
            )
            
            submitted = st.form_submit_button("💾 Guardar Configuración", type="primary")

            if submitted:
                if not all([ruc, razon_social, clave_firma, archivo_firma]):
                    st.error("❌ Por favor, complete todos los campos.")
                elif len(ruc) != 13:
                    st.error("❌ El RUC debe tener exactamente 13 dígitos.")
                elif archivo_firma.size > 100 * 1024:  # 100 KB
                    st.error(f"⚠️ El archivo pesa {archivo_firma.size / 1024:.1f} KB. Máximo permitido: 100 KB.")
                else:
                    success, msg = configurar_empresa_api(ruc, razon_social, clave_firma, archivo_firma)
                    if success:
                        st.success(msg)
                        obtener_configuracion_api.clear()
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(msg)

                        

def show_compras():
    st.subheader("🛒 Comprar Créditos (Recarga)")
    
    st.markdown("Selecciona el paquete de facturas que deseas recargar. Serás redirigido a la pasarela de pago segura de Stripe.")
    
    col_p1, col_p2 = st.columns(2)
    
    # Paquete 1: 50 Créditos (A $0.10 c/u)
    with col_p1:
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #ff4b4b;">'
                    f'<h4>50 Facturas</h4><h1>$5.00 USD</h1>'
                    f'<p>Ideal para negocios con baja rotación.</p></div>', 
                    unsafe_allow_html=True)
        if st.button("Comprar 50 Créditos", key="buy50_get_url", type="primary"):
            url = crear_sesion_compra_api(50)
            if url:
                st.link_button("💳 Ir a Pagar (Se abre en pestaña nueva)", url, help="Pagar con tarjeta o PSE.", type="secondary")

    # Paquete 2: 100 Créditos (A $0.05 c/u - ¡Mejor oferta!)
    with col_p2:
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #3366ff;">'
                    f'<h4>100 Facturas</h4><h1>$5.00 USD</h1>'
                    f'<p>¡Precio promocional! La mejor oferta.</p></div>', 
                    unsafe_allow_html=True)
        if st.button("Comprar 100 Créditos", key="buy100_get_url", type="primary"):
            url = crear_sesion_compra_api(100)
            if url:
                st.link_button("💳 Ir a Pagar (Se abre en pestaña nueva)", url, help="Pagar con tarjeta o PSE.", type="secondary")

    st.markdown("---")
    st.subheader("🧾 Historial de Compras")
    # ... (El resto del código de historial de compras se mantiene) ...


def generar_api_key_api():
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    try:
        res = requests.post(f"{BACKEND_URL}/generar-api-key", headers=headers)
        if res.status_code == 200:
            return res.json()
        st.error(f"Error: {res.json().get('detail')}")
        return None
    except Exception as e:
        st.error(f"Error de conexión: {e}")
        return None

# Y ahora la función de interfaz:
def show_api_key():
    """Muestra la API Key persistente del usuario"""
    st.subheader("🔑 Token de Autorización (API Key)")
    
    # Intentar obtener la API key actual (puede venir del login o del endpoint de saldo)
    api_key_actual = st.session_state.get('api_key')
    
    # Si no está en la sesión, intentar obtenerla del backend
    if not api_key_actual:
        saldo_data = consultar_saldo_api(st.session_state.token)
        if saldo_data:
            api_key_actual = saldo_data.get('api_key_persistente')
            st.session_state.api_key = api_key_actual  # Guardarla en sesión
    
    if api_key_actual:
        st.success("✅ Tu API Key está activa y lista para usar.")
        st.markdown("Esta clave **nunca expira** y puedes usarla para integrar sistemas externos.")
        st.code(api_key_actual, language="text")
        
        # Botón de copiar (usando un truco de HTML)
        st.markdown(f"""
        <button onclick="navigator.clipboard.writeText('{api_key_actual}')" 
                style="background-color: #007bff; color: white; padding: 8px 15px; 
                       border: none; border-radius: 5px; cursor: pointer; font-weight: bold;">
            📋 Copiar al Portapapeles
        </button>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        st.warning("⚠️ **Regenerar la clave anulará la anterior.** Úsalo solo si la clave fue comprometida.")
        
        if st.button("🔄 Regenerar API Key", key="regenerar_api_key_btn"):
            res = generar_api_key_api()
            if res:
                st.session_state.api_key = res['api_key']
                st.success("✅ Nueva clave generada exitosamente.")
                time.sleep(1)
                st.rerun()
    else:
        st.info("📌 Aún no tienes una API Key. Genera una para conectar sistemas externos.")
        
        if st.button("✨ Generar Mi Primera API Key", key="generar_api_key_inicial_btn", type="primary"):
            res = generar_api_key_api()
            if res:
                st.session_state.api_key = res['api_key']
                st.balloons()
                st.success("✅ ¡API Key generada! Ya puedes usarla.")
                time.sleep(1)
                st.rerun()
    
    st.markdown("---")
    
# ==========================================
#              FLUJO PRINCIPAL (Corregido)
# ==========================================

is_authenticated = False

# 1. Verificar si hay un token existente y si es válido (Persistencia)
# Esto se ejecuta en cada rerun, leyendo la cookie si es necesario.
if st.session_state.token is not None:
    is_authenticated = load_persisted_token()
    
# 2. Si no hay autenticación, mostrar la escena de Login
if not is_authenticated:
    # --- ESCENA 1: LOGIN / REGISTRO ---
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        st.title("Bienvenido 👋")
        st.markdown("##### Sistema de Facturación Electrónica SRI")
        
        tab_log, tab_reg, tab_ver = st.tabs(["🔐 Ingresar", "📝 Crear Cuenta", "✅ Verificar Email"])
        
        # --- CÓDIGO DE LOGIN / REGISTRO (Se mantiene) ---
        with tab_log:
            with st.form("login_form"):
                email = st.text_input("Email")
                pw = st.text_input("Contraseña", type="password")
                if st.form_submit_button("Iniciar Sesión", type="primary"):
                    do_login(email, pw)
        
        with tab_reg:
            with st.form("reg_form"):
                n_nom = st.text_input("Nombre Completo")
                n_em = st.text_input("Email")
                n_p1 = st.text_input("Contraseña", type="password")
                if st.form_submit_button("Registrarse"):
                    try:
                        res = requests.post(f"{BACKEND_URL}/registrar-usuario", json={"nombre":n_nom, "email":n_em, "password":n_p1})
                        if res.status_code == 200:
                            st.success("Cuenta creada. Revisa los logs de EasyPanel para ver el código.")
                        else:
                            st.error(res.text)
                    except Exception as e: st.error(f"Error: {e}")

        with tab_ver:
            st.caption("Usa el código que apareció en los logs del backend.")
            with st.form("ver_form"):
                v_em = st.text_input("Email")
                v_co = st.text_input("Código (6 dígitos)")
                if st.form_submit_button("Validar Código"):
                    try:
                        res = requests.post(f"{BACKEND_URL}/verificar-email", json={"email":v_em, "codigo":v_co})
                        if res.status_code == 200:
                            st.balloons()
                            st.success("¡Verificado! Ya puedes iniciar sesión.")
                        else: st.error("Código incorrecto")
                    except: st.error("Error conexión")

else:
    # --- ESCENA 2: DASHBOARD ---
    col_h1, col_h2 = st.columns([8, 2])
    with col_h1: st.title("🧾 Portal de Servicios API")
    with col_h2: 
        if st.button("Cerrar Sesión"):
            logout_user()
            
    # --- NAVEGACIÓN PRINCIPAL ---
    tab_dash, tab_compras, tab_config = st.tabs(["📊 Panel General", "💰 Comprar Créditos", "⚙️ Configuración"])

    with tab_dash:
        show_dashboard()
        
    with tab_compras:
        show_compras()
        
    with tab_config:
        st.subheader("🔑 Credenciales y Archivos")
        
        # PRIMERO: API Key
        st.markdown("---")
        show_api_key() 
        
        # SEGUNDO: Firma Electrónica (sin duplicar show_api_key)
        st.markdown("---")
        show_configuracion()  # Ya NO llama a show_api_key internamente
            
    # === PANEL ADMIN SECRETO (Solo visible para ti) ===
    if st.session_state.empresa_ruc == RUC_ADMIN:
        with st.sidebar:
            st.markdown("---")
            st.error("🔐 MODO SUPER ADMIN")
            # --- Montos Ganados ---
            try:
                res = requests.get(f"{BACKEND_URL}/admin/montos-ganados", headers={"Authorization": f"Bearer {st.session_state.token}"})
                monto_total = res.json().get('monto_total_usd', 0.0) if res.status_code == 200 else "N/A"
            except:
                monto_total = "Error Conexión"
                
            st.metric("Total Ganado (USD)", f"${monto_total}")
            st.markdown("---")
            
            with st.expander("Recargar Saldo a Clientes Manual"):
                a_ruc = st.text_input("RUC Cliente Destino", max_chars=13)
                a_cant = st.number_input("Cantidad a Recargar", value=100)
                if st.button("Acreditar Saldo"):
                    recargar_saldo_admin(a_ruc, a_cant)











