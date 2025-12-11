import streamlit as st
import requests
import os
import time
import pandas as pd # <-- ¡Nuevo Import! Necesario para tablas profesionales

# --- 1. CONFIGURACIÓN INICIAL ---
BACKEND_URL = os.getenv("API_URL", "http://facturador-backend:80") 
RUC_ADMIN = "1760013210001" 
IVA_RATE = 0.15 # Tasa de IVA actual en Ecuador

st.set_page_config(page_title="Facturación SaaS", page_icon="🧾", layout="wide")

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
if 'token' not in st.session_state: st.session_state.token = None
if 'config_completa' not in st.session_state: st.session_state.config_completa = False
if 'empresa_ruc' not in st.session_state: st.session_state.empresa_ruc = None
if 'api_key' not in st.session_state: st.session_state.api_key = None # <--- ¡Nuevo Estado!
if 'datos_sri_temp' not in st.session_state: st.session_state.datos_sri_temp = {}


# --- 4. FUNCIONES DE CONEXIÓN AL BACKEND (Actualizadas) ---

# [ Mantener do_login, consultar_ruc_api, recargar_saldo_admin, emitir_factura_api ]
# ******************************************************************************

def do_login(email, password):
    """Inicia sesión y guarda el token y estado del usuario"""
    try:
        res = requests.post(f"{BACKEND_URL}/login", json={"email": email, "password": password})
        # La línea del IF (línea 48) debe estar correctamente indentada
        if res.status_code == 200: 
            data = res.json()
            st.session_state.token = data["access_token"]
            # ... (el resto del código de sesión) ...
        # ... (el resto del manejo de errores 403, 401) ...
    except Exception as e:
        st.error(f"No hay conexión con el Backend: {e}")

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
        res = requests.post(f"{BACKEND_URL}/admin/recargar", json={"ruc_cliente": ruc_cliente, "cantidad": cantidad})
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

# ******************************************************************************

# --- NUEVAS FUNCIONES DE CONEXIÓN DE DATOS ---

def consultar_saldo_api():
    """Consulta los créditos disponibles."""
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    try:
        res = requests.get(f"{BACKEND_URL}/saldo-facturas", headers=headers)
        if res.status_code == 200:
            return res.json()
        return None
    except:
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

def show_configuracion():
    """Muestra el formulario de configuración inicial de RUC y Firma."""
    st.warning("⚠️ **Perfil Incompleto:** Necesitas configurar tu RUC y Firma para empezar.")
    
    with st.expander("🚀 CONFIGURAR MI EMPRESA (Paso Único)", expanded=True):
        col_a, col_b = st.columns(2)
        
        # --- Columna A: Datos SRI ---
        with col_a:
            st.subheader("1. Datos del SRI")
            ruc_search = st.text_input("Ingresa tu RUC", max_chars=13, placeholder="17xxxxxxxx001")
            
            razon_social_val = ""
            
            if st.button("🔍 Buscar Datos en SRI"):
                if len(ruc_search) == 13:
                    with st.spinner("Conectando con SRI..."):
                        datos = consultar_ruc_api(ruc_search)
                        if datos and datos['valido']:
                            st.session_state.datos_sri_temp = datos
                            st.toast("✅ Datos encontrados", icon="🎉")
                        else:
                            st.error("❌ RUC no encontrado o inválido.")
                            st.session_state.datos_sri_temp = {}

            # Mostrar datos si existen en memoria
            if st.session_state.datos_sri_temp:
                d = st.session_state.datos_sri_temp
                razon_social_val = d.get('razon_social', '')
                st.info(f"**Nombre:** {razon_social_val}")
                if d.get('estado') != "ACTIVO":
                    st.error(f"⚠️ Estado Contribuyente: {d.get('estado')}")

            # Inputs finales
            final_razon = st.text_input("Razón Social", value=razon_social_val)
            final_dir = st.text_input("Dirección Matriz", placeholder="Ej: Av. Amazonas y ONU")

        # --- Columna B: Firma Electrónica ---
        with col_b:
            st.subheader("2. Firma Electrónica")
            uploaded_file = st.file_uploader("Archivo .p12", type="p12")
            uploaded_pass = st.text_input("Contraseña del .p12", type="password")

        st.markdown("---")
        if st.button("💾 Guardar y Activar Facturación", type="primary"):
            if ruc_search and final_razon and uploaded_file and uploaded_pass:
                files = {"archivo_firma": (uploaded_file.name, uploaded_file, "application/x-pkcs12")}
                data = {"ruc": ruc_search, "razon_social": final_razon, "clave_firma": uploaded_pass}
                headers = {"Authorization": f"Bearer {st.session_state.token}"}
                
                with st.spinner("Validando firma criptográfica..."):
                    try:
                        res = requests.post(f"{BACKEND_URL}/configurar-empresa", data=data, files=files, headers=headers)
                        if res.status_code == 200:
                            st.balloons()
                            st.success("¡Perfil Activado! El sistema se recargará...")
                            st.session_state.config_completa = True
                            st.session_state.empresa_ruc = ruc_search
                            time.sleep(2)
                            st.rerun()
                        else:
                            st.error(f"Error: {res.json().get('detail')}")
                    except Exception as e: st.error(f"Error crítico: {e}")
            else:
                st.warning("Por favor completa todos los campos obligatorios.")


def show_dashboard():
    st.subheader("📊 Resumen General")
    
    # --- 1. Obtener Datos del Backend ---
    saldo_data = consultar_saldo_api()
    creditos_disp = saldo_data['creditos_disponibles'] if saldo_data else 0
    historial_facturas = obtener_historial_facturas_api()
    
    # --- 2. Métricas Clave ---
    m1, m2, m3, m4 = st.columns(4)
    
    with m1: # Créditos restantes
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #00c087;">'
                    f'<h4>Créditos Restantes</h4><h1>{creditos_disp}</h1></div>', 
                    unsafe_allow_html=True)
    
    with m2: # Facturas Emitidas
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #007bff;">'
                    f'<h4>Facturas Emitidas</h4><h1>{len(historial_facturas)}</h1></div>', 
                    unsafe_allow_html=True)
                    
    with m3: # Estado Cuentas
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #ffaa00;">'
                    f'<h4>Facturas en Proceso</h4><h1>{sum(1 for f in historial_facturas if f["estado"] in ["EN PROCESO", "RECIBIDA"])}</h1></div>', 
                    unsafe_allow_html=True)
                    
    with m4: # Total Autorizadas
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #ff4b4b;">'
                    f'<h4>Autorizadas</h4><h1>{sum(1 for f in historial_facturas if f["estado"] == "AUTORIZADO")}</h1></div>', 
                    unsafe_allow_html=True)

    # --- 3. Historial de facturas ---
    st.markdown("---")
    st.subheader("📝 Historial de Facturas Generadas")
    
    if historial_facturas:
        df = pd.DataFrame(historial_facturas)
        df['fecha_creacion'] = pd.to_datetime(df['fecha_creacion']).dt.strftime('%Y-%m-%d %H:%M')
        
        # Renombrar columnas para el usuario final
        df_display = df.rename(columns={
            'fecha_creacion': 'Fecha Emisión',
            'clave_acceso': 'Clave de Acceso',
            'tipo_comprobante': 'Tipo',
            'estado': 'Estado SRI'
        })[['Fecha Emisión', 'Clave de Acceso', 'Tipo', 'Estado SRI']]
        
        st.dataframe(df_display, use_container_width=True, hide_index=True)
    else:
        st.info("Aún no has generado ninguna factura electrónica.")


def show_compras():
    st.subheader("🛒 Comprar Créditos (Recarga)")
    
    st.markdown("Selecciona el paquete de facturas que deseas recargar. Serás redirigido a la pasarela de pago segura de Stripe.")
    
    col_p1, col_p2 = st.columns(2)
    
    # Paquete 1: 50 Créditos
    with col_p1:
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #ff4b4b;">'
                    f'<h4>50 Facturas</h4><h1>$10.00 USD</h1>'
                    f'<p>Ideal para negocios pequeños.</p></div>', 
                    unsafe_allow_html=True)
        
        # --- MODIFICACIÓN CLAVE PARA ABRIR EN NUEVA VENTANA (Paquete 1) ---
        # Primero obtenemos la URL, luego mostramos el link_button
        if st.button("Obtener Link de Pago (50)", key="buy50_get_url", type="primary"):
            url = crear_sesion_compra_api(50)
            if url:
                st.link_button("💳 Ir a Pagar (Se abre en pestaña nueva)", url, help="Pagar con tarjeta o PSE.", type="secondary")
            # El botón de pago se muestra DESPUÉS de obtener la URL
        # --- FIN MODIFICACIÓN ---


    # Paquete 2: 100 Créditos
    with col_p2:
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #3366ff;">'
                    f'<h4>100 Facturas</h4><h1>$18.00 USD</h1>'
                    f'<p>Ahorro de $2.00. El mejor valor.</p></div>', 
                    unsafe_allow_html=True)
        
        # --- MODIFICACIÓN CLAVE PARA ABRIR EN NUEVA VENTANA (Paquete 2) ---
        if st.button("Obtener Link de Pago (100)", key="buy100_get_url", type="primary"):
            url = crear_sesion_compra_api(100)
            if url:
                st.link_button("💳 Ir a Pagar (Se abre en pestaña nueva)", url, help="Pagar con tarjeta o PSE.", type="secondary")
            # El botón de pago se muestra DESPUÉS de obtener la URL
        # --- FIN MODIFICACIÓN ---

    st.markdown("---")
    st.subheader("🧾 Historial de Compras")
    # ... (El resto del código de historial de compras se mantiene) ...


def show_api_key():
    st.subheader("🔑 Token de Autorización (API Key)")
    st.markdown("Esta es tu clave secreta de acceso persistente para sistemas externos. No expira.")
    
    # 1. Mostrar la API Key Persistente
    st.code(st.session_state.api_key, language="text")
    
    # 2. Instrucciones de Uso (¡El Header ha cambiado!)
    st.markdown("---")
    st.markdown("##### ¿Cómo usar esta Clave?")
    st.info("Debes incluirla en el encabezado (Header) de cada solicitud HTTP que envíes a nuestra API:")
    st.code('X-API-Key: [TU_CLAVE_AQUÍ]', language="text")
    
    st.markdown("##### Ejemplos de Endpoints Disponibles:")
    st.markdown("- `POST /emitir-factura`")
    st.markdown("- `GET /saldo-facturas`")
    st.markdown("- `GET /historial-facturas`")
    
    st.warning("⚠️ **Seguridad:** Mantén este Token seguro. Si sospechas que fue comprometido, cierra la sesión para generar uno nuevo.")
    

# ==========================================
#              FLUJO PRINCIPAL (Corregido)
# ==========================================

if not st.session_state.token:
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
    # --- ESCENA 2: DENTRO DEL SISTEMA (DASHBOARD) ---
    
    # --- HEADER / BARRA SUPERIOR ---
    col_h1, col_h2 = st.columns([8, 2])
    with col_h1: st.title("🧾 Portal de Servicios API")
    with col_h2: 
        if st.button("Cerrar Sesión"):
            st.session_state.token = None
            st.rerun()
            
    # --- FLUJO DE CONFIGURACIÓN / TABS PRINCIPALES ---
    
    if not st.session_state.config_completa:
        show_configuracion() 
    else:
        # Renombrado de tabs: Eliminamos 'Nueva Factura' y añadimos 'Mi API Key'
        tab_dash, tab_api, tab_compras = st.tabs(["📊 Panel General", "🔑 Mi API Key", "💰 Comprar Créditos"])

        with tab_dash:
            show_dashboard()
            
        with tab_api: # <--- ¡Nueva Pestaña! Muestra el Token de Autenticación
            show_api_key() 
            
        with tab_compras:
            show_compras()
            
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


