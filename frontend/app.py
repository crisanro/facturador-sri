import streamlit as st
import requests
import os

# --- CONFIGURACIÓN DE CONEXIÓN ---
# Si estamos en EasyPanel, busca la variable de entorno. 
# Si estamos en tu PC, usa localhost.
# "api-facturacion" es el nombre que le pondrás al servicio del backend en EasyPanel
BACKEND_URL = os.getenv("API_URL", "http://api-facturacion:80")

st.set_page_config(page_title="Facturación SaaS Ecuador", page_icon="🇪🇨", layout="centered")

# --- ESTILOS VISUALES (CSS) ---
st.markdown("""
    <style>
    .stButton>button { width: 100%; background-color: #FF4B4B; color: white; }
    .success-box { padding: 1rem; background-color: #d4edda; color: #155724; border-radius: 5px; }
    </style>
""", unsafe_allow_html=True)

# --- GESTIÓN DE SESIÓN (Cookies temporales) ---
if 'token' not in st.session_state:
    st.session_state.token = None
if 'empresa_ruc' not in st.session_state:
    st.session_state.empresa_ruc = None

# --- FUNCIONES DE CONEXIÓN AL BACKEND ---

def login(ruc, password):
    """Intenta iniciar sesión en el backend"""
    try:
        response = requests.post(f"{BACKEND_URL}/token", json={"ruc": ruc, "password": password})
        if response.status_code == 200:
            data = response.json()
            st.session_state.token = data["access_token"]
            st.session_state.empresa_ruc = ruc
            st.success("¡Bienvenido!")
            st.rerun() # Recarga la página
        else:
            st.error("❌ RUC o contraseña incorrectos")
    except Exception as e:
        st.error(f"⚠️ Error de conexión con el servidor: {e}")

def registrarse(ruc, razon, password, clave_p12, archivo):
    """Envía el archivo y datos al backend"""
    try:
        files = {"archivo_firma": (archivo.name, archivo, "application/x-pkcs12")}
        data = {
            "ruc": ruc,
            "razon_social": razon,
            "password_login": password,
            "clave_firma": clave_p12
        }
        # Nota: No usamos json=data, usamos data=data para que sea un Formulario Multipart
        response = requests.post(f"{BACKEND_URL}/registrar-empresa", data=data, files=files)
        
        if response.status_code == 200:
            st.balloons()
            st.success("✅ ¡Cuenta creada con éxito! Por favor inicia sesión.")
        else:
            st.error(f"Error al registrar: {response.text}")
    except Exception as e:
        st.error(f"⚠️ Error crítico: {e}")

def emitir_factura_api(payload):
    """Envía la factura al backend con el Token de seguridad"""
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    try:
        response = requests.post(f"{BACKEND_URL}/emitir-factura", json=payload, headers=headers)
        return response
    except Exception as e:
        return None

# ==========================================
#              INTERFAZ GRÁFICA
# ==========================================

# CASO 1: NO ESTÁ LOGUEADO (Mostrar Login/Registro)
if not st.session_state.token:
    st.title("🧾 Sistema de Facturación")
    st.info("Plataforma SaaS para facturación electrónica SRI")
    
    tab_login, tab_registro = st.tabs(["🔐 Iniciar Sesión", "📝 Crear Cuenta Nueva"])
    
    # --- PESTAÑA LOGIN ---
    with tab_login:
        with st.form("login_form"):
            ruc_login = st.text_input("RUC de la Empresa")
            pass_login = st.text_input("Contraseña de Acceso", type="password")
            btn_entrar = st.form_submit_button("Ingresar")
            
            if btn_entrar:
                if ruc_login and pass_login:
                    login(ruc_login, pass_login)
                else:
                    st.warning("Por favor llena todos los campos")

    # --- PESTAÑA REGISTRO ---
    with tab_registro:
        st.write("Sube tu firma electrónica (.p12) para empezar.")
        with st.form("register_form"):
            reg_ruc = st.text_input("RUC (13 dígitos)", max_chars=13)
            reg_razon = st.text_input("Razón Social (Nombre de la empresa)")
            reg_pass = st.text_input("Crea una contraseña para entrar aquí", type="password")
            
            st.markdown("---")
            st.write("📂 Datos de Facturación (Firma)")
            reg_file = st.file_uploader("Archivo de Firma (.p12)", type=['p12'])
            reg_clave_firma = st.text_input("Contraseña del archivo .p12", type="password")
            
            btn_registro = st.form_submit_button("Registrar mi Empresa")
            
            if btn_registro:
                if reg_ruc and reg_razon and reg_pass and reg_file and reg_clave_firma:
                    registrarse(reg_ruc, reg_razon, reg_pass, reg_clave_firma, reg_file)
                else:
                    st.error("Faltan datos obligatorios")

# CASO 2: YA ESTÁ LOGUEADO (Mostrar Panel de Facturación)
else:
    # Sidebar (Menú lateral)
    with st.sidebar:
        st.header(f"🏢 {st.session_state.empresa_ruc}")
        st.success("🟢 Conectado")
        if st.button("Cerrar Sesión"):
            st.session_state.token = None
            st.rerun()

    st.title("Nueva Factura")
    
    # --- FORMULARIO DE FACTURA ---
    with st.form("factura_form"):
        col1, col2 = st.columns(2)
        fecha_emision = col1.text_input("Fecha Emisión", value="10/12/2025")
        serie_caja = col2.text_input("Serie (Ej: 001001)", value="001001")
        
        st.markdown("### 👤 Datos del Cliente")
        c_nombre = st.text_input("Razón Social / Nombre")
        c1, c2 = st.columns(2)
        c_ident = c1.text_input("Cédula o RUC Cliente")
        c_tipo = c2.selectbox("Tipo Documento", ["05", "04", "06", "07"], format_func=lambda x: "Cédula (05)" if x=="05" else "RUC (04)" if x=="04" else "Pasaporte (06)" if x=="06" else "Consumidor Final (07)")
        c_dir = st.text_input("Dirección", value="S/N")
        
        st.markdown("### 🛒 Productos")
        # Por simplicidad, un solo producto en esta demo
        p_desc = st.text_input("Descripción del Producto", "Servicios Profesionales")
        col_cant, col_prec = st.columns(2)
        p_cant = col_cant.number_input("Cantidad", min_value=1.0, value=1.0)
        p_prec = col_prec.number_input("Precio Unitario", min_value=0.01, value=10.00)
        
        # Cálculos simples en frontend
        subtotal = p_cant * p_prec
        iva = subtotal * 0.15 # Asumiendo 15%
        total = subtotal + iva
        
        st.metric("Total a Pagar", f"${total:.2f}")
        
        submitted = st.form_submit_button("🚀 Firmar y Emitir Factura")
        
        if submitted:
            # Armamos el JSON
            payload = {
                "ruc": st.session_state.empresa_ruc, # El RUC del usuario logueado
                "ambiente": 1,
                "serie": serie_caja,
                "fecha_emision": fecha_emision,
                "razon_social_emisor": "MI EMPRESA", 
                "direccion_matriz": "Matriz",
                "direccion_establecimiento": "Sucursal",
                "obligado_contabilidad": "NO",
                
                "tipo_identificacion_comprador": c_tipo,
                "razon_social_comprador": c_nombre,
                "identificacion_comprador": c_ident,
                "direccion_comprador": c_dir,
                
                "total_sin_impuestos": subtotal,
                "total_descuento": 0,
                "importe_total": total,
                
                "detalles": [{
                    "codigo_principal": "ITEM-001",
                    "descripcion": p_desc,
                    "cantidad": p_cant,
                    "precio_unitario": p_prec,
                    "descuento": 0,
                    "precio_total_sin_impuesto": subtotal,
                    "base_imponible": subtotal,
                    "valor_impuesto": iva,
                    "codigo_impuesto": "2",
                    "codigo_porcentaje": "4", # IVA 15%
                    "tarifa": 15
                }],
                "total_impuestos": [{
                    "codigo": "2",
                    "codigo_porcentaje": "4",
                    "base_imponible": subtotal,
                    "valor": iva
                }]
            }
            
            with st.spinner("Conectando con el servidor de firma..."):
                res = emitir_factura_api(payload)
            
            if res and res.status_code == 200:
                resp_data = res.json()
                st.success(f"✅ ¡Factura Generada! ID: {resp_data.get('clave_acceso')}")
                
                # Mostrar XML
                with st.expander("Ver XML Firmado (XAdES-BES)"):
                    st.code(resp_data.get("xml_firmado"), language="xml")
                    
                # Mostrar Saldo
                if "creditos_restantes" in resp_data:
                    st.toast(f"Te quedan {resp_data['creditos_restantes']} créditos")
            
            elif res and res.status_code == 402:
                st.error("⚠️ Saldo insuficiente. Por favor recarga créditos.")
            
            elif res:
                st.error(f"Error del servidor: {res.text}")
            else:
                st.error("No se pudo conectar con la API.")