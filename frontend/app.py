import streamlit as st
import requests
import os
import time
import pandas as pd
from datetime import datetime, timedelta
from extra_streamlit_components import CookieManager

# --- CONFIGURACIÓN INICIAL ---
BACKEND_URL = os.getenv("API_URL", "http://facturador-backend:80") 
RUC_ADMIN = "1760013210001" 
IVA_RATE = 0.15
TOKEN_COOKIE_KEY = 'auth_token_jwt'
TOKEN_EXPIRY_DAYS = 7 

st.set_page_config(
    page_title="Facturación SaaS", 
    page_icon="🧾", 
    layout="wide"
)

# IMPORTANTE: Configurar límite de archivos subidos (100 KB = 0.1 MB)
import streamlit as st
st.set_option('server.maxUploadSize', 1)  # 1 MB máximo para todo el servidor

cookie_manager = CookieManager()
cookies = cookie_manager.get_all()

# --- ESTILOS CSS ---
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
    .stTabs [data-baseweb="tab-list"] { gap: 15px; }
    </style>
""", unsafe_allow_html=True)

# --- GESTIÓN DE ESTADO ---
if 'token' not in st.session_state or st.session_state.token is None:
    token_from_cookie = cookie_manager.get(TOKEN_COOKIE_KEY)
    if token_from_cookie and token_from_cookie != "":
        st.session_state.token = token_from_cookie
    else:
        st.session_state.token = None

if 'config_completa' not in st.session_state: 
    st.session_state.config_completa = False
if 'empresa_ruc' not in st.session_state: 
    st.session_state.empresa_ruc = None
if 'api_key' not in st.session_state: 
    st.session_state.api_key = None
if 'datos_sri_temp' not in st.session_state: 
    st.session_state.datos_sri_temp = {}
if 'initial_load_done' not in st.session_state:
    st.session_state.initial_load_done = False

# --- FUNCIONES DE AUTENTICACIÓN ---

def logout_user():
    """Limpia la sesión y la cookie."""
    st.session_state.token = None
    st.session_state.config_completa = False
    st.session_state.empresa_ruc = None
    st.session_state.api_key = None
    st.session_state.initial_load_done = False
    
    try:
        existing_cookies = cookie_manager.get_all()
        if TOKEN_COOKIE_KEY in existing_cookies:
            cookie_manager.delete(TOKEN_COOKIE_KEY)
    except Exception:
        pass
    
    st.rerun()


def consultar_saldo_api(token_a_usar):
    """Consulta créditos y actualiza datos de sesión."""
    headers = {"Authorization": f"Bearer {token_a_usar}"}
    try:
        res = requests.get(f"{BACKEND_URL}/saldo-facturas", headers=headers, timeout=5)
        if res.status_code == 200:
            data = res.json()
            st.session_state.config_completa = data.get("ruc_usuario") is not None
            st.session_state.empresa_ruc = data.get("ruc_usuario")
            st.session_state.api_key = data.get("api_key_persistente")
            return data
        return None
    except Exception:
        return None


def load_persisted_token():
    """Verifica si el token es válido."""
    if st.session_state.token is not None:
        valido = consultar_saldo_api(st.session_state.token)
        
        if valido:
            return True
        else:
            st.session_state.token = None
            st.session_state.config_completa = False
            st.session_state.empresa_ruc = None
            st.session_state.api_key = None
            st.session_state.initial_load_done = False
            
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
    """Inicia sesión y guarda el token."""
    try:
        res = requests.post(f"{BACKEND_URL}/login", json={"email": email, "password": password})
     
        if res.status_code == 200:
            data = res.json()
            new_token = data["access_token"]
            
            # Guardar en sesión
            st.session_state.token = new_token
            st.session_state.config_completa = data.get("configuracion_completa", False)
            st.session_state.empresa_ruc = data.get("ruc_usuario")
            st.session_state.api_key = data.get("api_key_persistente")
            st.session_state.initial_load_done = True  # ← Marcar como ya validado
            
            # Guardar en cookie
            expiry_date = datetime.now() + timedelta(days=TOKEN_EXPIRY_DAYS)
            cookie_manager.set(TOKEN_COOKIE_KEY, new_token, expires_at=expiry_date)
            
            st.success("✅ ¡Inicio de sesión exitoso!")
            time.sleep(1)
            st.rerun()
            
        elif res.status_code == 403:
            st.error("⚠️ Tu email no ha sido verificado.")
        else: 
            st.error(f"❌ Credenciales incorrectas.")
            
    except Exception as e:
        st.error(f"❌ Error de conexión: {e}")


# --- FUNCIONES AUXILIARES ---

def consultar_ruc_api(ruc):
    try:
        res = requests.get(f"{BACKEND_URL}/consultar-ruc/{ruc}")
        if res.status_code == 200:
            return res.json()
        return None
    except:
        return None

def recargar_saldo_admin(ruc_cliente, cantidad):
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
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    try:
        res = requests.get(f"{BACKEND_URL}/historial-facturas", headers=headers)
        if res.status_code == 200:
            return res.json().get('facturas', [])
        return []
    except:
        return []

def obtener_historial_recargas_api():
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    try:
        res = requests.get(f"{BACKEND_URL}/historial-recargas", headers=headers)
        if res.status_code == 200:
            return res.json().get('historial', [])
        return []
    except:
        return []
        
def crear_sesion_compra_api(cantidad):
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

@st.cache_data(ttl=60)
def obtener_configuracion_api():
    token = st.session_state.token
    if not token: return {"configurada": False}
    
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(f"{BACKEND_URL}/obtener-configuracion-empresa", headers=headers)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return {"configurada": False}

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
    files = {'archivo_firma': (archivo_firma.name, archivo_firma.getvalue(), archivo_firma.type)}
    data = {
        'ruc': ruc,
        'razon_social': razon_social,
        'clave_firma': clave_firma,
    }
    
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    
    try:
        res = requests.post(f"{BACKEND_URL}/configurar-empresa", data=data, files=files, headers=headers)
        
        if res.status_code == 200:
            return True, res.json().get("mensaje", "Configuración guardada.")
        
        detail = res.json().get("detail", res.text)
        return False, detail
        
    except Exception as e:
        return False, f"Error de conexión con el backend: {e}"

def generar_opciones_descarga_ui(clave_acceso, estado):
    base_url = f"{BACKEND_URL}/facturas/descargar/{clave_acceso}"
    
    if estado == 'AUTORIZADO':
        url_pdf = f"{base_url}?tipo=pdf"
        url_xml = f"{base_url}?tipo=xml"
        
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

# --- UI FUNCTIONS ---

def show_dashboard():
    st.subheader("📊 Resumen General")
    
    saldo_data = consultar_saldo_api(st.session_state.token)
    creditos_disp = saldo_data['creditos_disponibles'] if saldo_data else 0
    historial_facturas = obtener_historial_facturas_api()
    
    m1, m2, m3, m4 = st.columns(4)
    
    with m1:
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #00c087;">'
                    f'<h4>Créditos Restantes</h4><h1>{creditos_disp}</h1></div>', 
                    unsafe_allow_html=True)
    
    with m2:
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #007bff;">'
                    f'<h4>Facturas Emitidas</h4><h1>{len(historial_facturas)}</h1></div>', 
                    unsafe_allow_html=True)
                    
    with m3:
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #ffaa00;">'
                    f'<h4>Facturas en Proceso</h4><h1>{sum(1 for f in historial_facturas if f["estado"] in ["EN PROCESO", "RECIBIDA"])}</h1></div>', 
                    unsafe_allow_html=True)
                    
    with m4:
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #ff4b4b;">'
                    f'<h4>Autorizadas</h4><h1>{sum(1 for f in historial_facturas if f["estado"] == "AUTORIZADO")}</h1></div>', 
                    unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("📝 Historial de Facturas Generadas")
    
    if historial_facturas:
        df = pd.DataFrame(historial_facturas)
        df['fecha_creacion'] = pd.to_datetime(df['fecha_creacion']).dt.strftime('%Y-%m-%d %H:%M')
        
        df['Acciones'] = df.apply(
            lambda row: generar_opciones_descarga_ui(row['clave_acceso'], row['estado']),
            axis=1
        )
        
        df_display = df.rename(columns={
            'fecha_creacion': 'Fecha Emisión',
            'clave_acceso': 'Clave de Acceso',
            'tipo_comprobante': 'Tipo',
            'estado': 'Estado SRI'
        })[['Fecha Emisión', 'Clave de Acceso', 'Estado SRI', 'Acciones']]
        
        st.markdown(df_display.to_html(escape=False, index=False), unsafe_allow_html=True)
        
    else:
        st.info("Aún no has generado ninguna factura electrónica.")

def show_compras():
    st.subheader("🛒 Comprar Créditos")
    
    col_p1, col_p2 = st.columns(2)
    
    with col_p1:
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #ff4b4b;">'
                    f'<h4>50 Facturas</h4><h1>$5.00 USD</h1></div>', 
                    unsafe_allow_html=True)
        if st.button("Comprar 50 Créditos", key="buy50", type="primary"):
            url = crear_sesion_compra_api(50)
            if url:
                st.link_button("💳 Ir a Pagar", url, type="secondary")

    with col_p2:
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #3366ff;">'
                    f'<h4>100 Facturas</h4><h1>$5.00 USD</h1></div>', 
                    unsafe_allow_html=True)
        if st.button("Comprar 100 Créditos", key="buy100", type="primary"):
            url = crear_sesion_compra_api(100)
            if url:
                st.link_button("💳 Ir a Pagar", url, type="secondary")

def show_api_key():
    st.subheader("🔑 Token de Autorización (API Key)")
    
    api_key_actual = st.session_state.get('api_key')
    
    if not api_key_actual:
        saldo_data = consultar_saldo_api(st.session_state.token)
        if saldo_data:
            api_key_actual = saldo_data.get('api_key_persistente')
            st.session_state.api_key = api_key_actual
    
    if api_key_actual:
        st.success("✅ Tu API Key está activa.")
        st.code(api_key_actual, language="text")
        
        st.markdown("---")
        
        if st.button("🔄 Regenerar API Key", key="regenerar_api"):
            res = generar_api_key_api()
            if res:
                st.session_state.api_key = res['api_key']
                st.success("✅ Nueva clave generada.")
                time.sleep(1)
                st.rerun()
    else:
        st.info("📌 Aún no tienes una API Key.")
        
        if st.button("✨ Generar API Key", key="generar_api", type="primary"):
            res = generar_api_key_api()
            if res:
                st.session_state.api_key = res['api_key']
                st.success("✅ ¡API Key generada!")
                time.sleep(1)
                st.rerun()
    
    st.markdown("---")

def show_configuracion():
    config = obtener_configuracion_api()
    
    st.subheader("Firma Electrónica")

    if config.get("configurada", False):
        st.success("✅ Configuración vigente.")
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("RUC", config.get("ruc", "—"))
        with col2:
            st.metric("Razón Social", config.get("razon_social", "—"))
        
        firma_path = config.get("firma_path") or ''
        nombre_archivo = os.path.basename(firma_path) if firma_path else 'No configurado'
        st.caption(f"📄 Archivo: **{nombre_archivo}**")
        
        st.markdown("---")
        
        # OPCIÓN 1: Editar TODO (RUC, Razón Social y Firma)
        with st.expander("✏️ Editar Configuración Completa"):
            st.info("Actualiza cualquier dato de tu empresa.")
            with st.form("editar_config_completa"):
                nuevo_ruc = st.text_input("RUC", value=config.get("ruc", ""), max_chars=13)
                nueva_razon = st.text_input("Razón Social", value=config.get("razon_social", ""))
                nueva_clave = st.text_input("Clave de Firma", type="password", help="Déjala en blanco si no quieres cambiar la firma")
                nuevo_archivo = st.file_uploader(
                    "Nueva Firma (.p12) - Opcional", 
                    type=["p12"],
                    help="Solo si quieres cambiar la firma. Máximo 100 KB"
                )
                
                if st.form_submit_button("💾 Guardar Cambios", type="primary"):
                    if not nuevo_ruc or not nueva_razon:
                        st.error("❌ RUC y Razón Social son obligatorios.")
                    elif len(nuevo_ruc) != 13:
                        st.error("❌ El RUC debe tener 13 dígitos.")
                    else:
                        # Si hay nueva firma, validarla
                        if nuevo_archivo:
                            if nuevo_archivo.size > 100 * 1024:
                                st.error("⚠️ El archivo supera 100 KB.")
                            elif not nueva_clave:
                                st.error("❌ Si subes nueva firma, debes ingresar su clave.")
                            else:
                                # Actualizar con nueva firma
                                success, msg = configurar_empresa_api(
                                    nuevo_ruc,
                                    nueva_razon,
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
                        else:
                            # Solo actualizar RUC y Razón Social (sin tocar la firma)
                            # Esto requiere un nuevo endpoint en el backend
                            st.warning("⚠️ Para actualizar solo RUC/Razón Social sin cambiar la firma, contacta a soporte.")
                            # TODO: Implementar endpoint PUT /actualizar-datos-empresa
        
        # OPCIÓN 2: Solo actualizar firma (mantener RUC y Razón Social)
        with st.expander("🔄 Solo Actualizar Firma"):
            st.info("Cambia únicamente tu firma electrónica, sin modificar RUC ni Razón Social.")
            with st.form("actualizar_solo_firma"):
                nueva_clave = st.text_input("Nueva Clave de Firma", type="password")
                nuevo_archivo = st.file_uploader(
                    "Subir Nueva Firma (.p12)", 
                    type=["p12"],
                    help="Tamaño máximo: 100 KB"
                )
                
                if st.form_submit_button("🔄 Actualizar Firma", type="primary"):
                    if not nueva_clave or not nuevo_archivo:
                        st.error("❌ Complete todos los campos.")
                    elif nuevo_archivo.size > 100 * 1024:
                        st.error(f"⚠️ El archivo pesa {nuevo_archivo.size / 1024:.1f} KB. Máximo: 100 KB.")
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
        
        # OPCIÓN 3: Eliminar todo
        st.markdown("---")
        st.warning("⚠️ **Zona peligrosa:** Eliminar toda la configuración")
        
        if st.button("🗑️ Eliminar Configuración Completa", type="secondary"):
            st.session_state.confirm_delete = True
            
        if st.session_state.get("confirm_delete"):
            st.error("⚠️ ¿Está seguro? Eliminará RUC, Razón Social y Firma.")
            col_del, col_cancel = st.columns(2)
            with col_del:
                if st.button("SÍ, Eliminar", key="confirm_del", type="primary"):
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
                if st.button("Cancelar", key="cancel_del"):
                    st.session_state.confirm_delete = False
                    st.rerun()

    else:
        # ===== PRIMERA CONFIGURACIÓN =====
        st.warning("⚠️ Configure su empresa para facturar.")
        
        with st.form("config_empresa"):
            ruc = st.text_input("RUC (13 dígitos)", max_chars=13, placeholder="1234567890001")
            razon_social = st.text_input("Razón Social", placeholder="Mi Empresa S.A.")
            clave_firma = st.text_input("Clave de Firma", type="password")
            archivo_firma = st.file_uploader(
                "Firma Electrónica (.p12)", 
                type=["p12"],
                help="Tamaño máximo: 100 KB"
            )
            
            if st.form_submit_button("💾 Guardar Configuración", type="primary"):
                if not all([ruc, razon_social, clave_firma, archivo_firma]):
                    st.error("❌ Complete todos los campos.")
                elif len(ruc) != 13:
                    st.error("❌ RUC debe tener exactamente 13 dígitos.")
                elif archivo_firma.size > 100 * 1024:
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

# --- FLUJO PRINCIPAL OPTIMIZADO ---

is_authenticated = False

# Verificar si hay token y validarlo solo una vez por sesión
if st.session_state.token is not None:
    if not st.session_state.get('initial_load_done', False):
        # Primera carga: validar token con el backend
        is_authenticated = load_persisted_token()
        st.session_state.initial_load_done = True
    else:
        # Token ya validado previamente, confiar en la sesión
        is_authenticated = True
    
if not is_authenticated:
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        st.title("Bienvenido 👋")
        st.markdown("##### Sistema de Facturación Electrónica SRI")
        
        tab_log, tab_reg, tab_ver = st.tabs(["🔐 Ingresar", "📝 Crear Cuenta", "✅ Verificar Email"])
        
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
                            st.success("Cuenta creada. Revisa los logs.")
                        else:
                            st.error(res.text)
                    except Exception as e: 
                        st.error(f"Error: {e}")

        with tab_ver:
            with st.form("ver_form"):
                v_em = st.text_input("Email")
                v_co = st.text_input("Código")
                if st.form_submit_button("Validar"):
                    try:
                        res = requests.post(f"{BACKEND_URL}/verificar-email", json={"email":v_em, "codigo":v_co})
                        if res.status_code == 200:
                            st.balloons()
                            st.success("¡Verificado!")
                        else: 
                            st.error("Código incorrecto")
                    except: 
                        st.error("Error conexión")

else:
    col_h1, col_h2 = st.columns([8, 2])
    with col_h1: 
        st.title("🧾 Portal de Servicios API")
    with col_h2: 
        if st.button("Cerrar Sesión"):
            logout_user()
            
    tab_dash, tab_compras, tab_config = st.tabs(["📊 Panel", "💰 Comprar", "⚙️ Configuración"])

    with tab_dash:
        show_dashboard()
        
    with tab_compras:
        show_compras()
        
    with tab_config:
        st.subheader("🔑 Credenciales y Archivos")
        st.markdown("---")
        show_api_key() 
        st.markdown("---")
        show_configuracion()
            
    if st.session_state.empresa_ruc == RUC_ADMIN:
        with st.sidebar:
            st.markdown("---")
            st.error("🔐 MODO ADMIN")
            try:
                res = requests.get(f"{BACKEND_URL}/admin/montos-ganados", headers={"Authorization": f"Bearer {st.session_state.token}"})
                monto_total = res.json().get('monto_total_usd', 0.0) if res.status_code == 200 else "N/A"
            except:
                monto_total = "Error"
                
            st.metric("Total Ganado", f"${monto_total}")
            st.markdown("---")
            
            with st.expander("Recargar Saldo"):
                a_ruc = st.text_input("RUC Cliente", max_chars=13)
                a_cant = st.number_input("Cantidad", value=100)
                if st.button("Acreditar"):
                    recargar_saldo_admin(a_ruc, a_cant)
