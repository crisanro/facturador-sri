import streamlit as st
import requests
import os

# --- CONFIGURACIÓN ---
# Busca la variable de entorno API_URL o usa localhost por defecto
BACKEND_URL = os.getenv("API_URL", "http://api-facturacion:80")

# ¡PON AQUÍ TU RUC REAL! (El del dueño del sistema)
RUC_ADMIN = "1760013210001" 

st.set_page_config(page_title="Facturación SaaS Ecuador", page_icon="🇪🇨", layout="centered")

# --- ESTILOS VISUALES ---
st.markdown("""
    <style>
    .stButton>button { width: 100%; background-color: #FF4B4B; color: white; }
    .success-box { padding: 1rem; background-color: #d4edda; color: #155724; border-radius: 5px; }
    .warning-box { padding: 1rem; background-color: #fff3cd; color: #856404; border-radius: 5px; border: 1px solid #ffeeba; }
    </style>
""", unsafe_allow_html=True)

# --- VARIABLES DE SESIÓN ---
if 'token' not in st.session_state:
    st.session_state.token = None
if 'empresa_ruc' not in st.session_state:
    st.session_state.empresa_ruc = None

# --- FUNCIONES DE CONEXIÓN ---

def login(ruc, password):
    try:
        res = requests.post(f"{BACKEND_URL}/token", json={"ruc": ruc, "password": password})
        if res.status_code == 200:
            data = res.json()
            st.session_state.token = data["access_token"]
            st.session_state.empresa_ruc = ruc
            st.success("¡Bienvenido!")
            st.rerun()
        else:
            st.error("❌ Credenciales incorrectas")
    except Exception as e:
        st.error(f"Error de conexión: {e}")

def registrarse(ruc, razon, password, email, telf):
    try:
        data = {
            "ruc": ruc, "razon_social": razon, "password_login": password,
            "email": email, "telefono": telf
        }
        res = requests.post(f"{BACKEND_URL}/registrar-empresa", data=data)
        
        if res.status_code == 200:
            st.balloons()
            st.success("✅ Cuenta creada con éxito. Por favor inicia sesión para configurar tu firma.")
        else:
            st.error(f"Error: {res.json().get('detail')}")
    except Exception as e:
        st.error(f"Error crítico: {e}")

def subir_firma_api(clave_firma, archivo):
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    try:
        files = {"archivo_firma": (archivo.name, archivo, "application/x-pkcs12")}
        data = {"clave_firma": clave_firma}
        res = requests.post(f"{BACKEND_URL}/subir-firma", data=data, files=files, headers=headers)
        return res
    except Exception as e:
        st.error(f"Error subiendo firma: {e}")
        return None

def recargar_saldo_admin(ruc_cliente, cantidad):
    """Función para el ADMIN (Tú)"""
    try:
        res = requests.post(f"{BACKEND_URL}/admin/recargar", json={"ruc_cliente": ruc_cliente, "cantidad": cantidad})
        if res.status_code == 200:
            st.success(f"✅ Recarga exitosa al RUC {ruc_cliente}")
        else:
            st.error(f"Error: {res.text}")
    except Exception as e:
        st.error(f"Error de conexión: {e}")

def emitir_factura_api(payload):
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    try:
        return requests.post(f"{BACKEND_URL}/emitir-factura", json=payload, headers=headers)
    except Exception as e:
        return None

# ==========================================
#              INTERFAZ GRÁFICA
# ==========================================

# --- PANTALLA 1: LOGIN / REGISTRO ---
if not st.session_state.token:
    st.title("🇪🇨 Facturación Electrónica")
    st.info("Sistema SaaS para emisión de comprobantes SRI")
    
    tab1, tab2 = st.tabs(["🔐 Ingresar", "📝 Registrarme"])
    
    with tab1:
        with st.form("login"):
            ruc = st.text_input("RUC")
            password = st.text_input("Contraseña", type="password")
            if st.form_submit_button("Iniciar Sesión"):
                login(ruc, password)
                
    with tab2:
        st.write("Crea tu cuenta gratis y recibe **10 facturas** de bienvenida.")
        with st.form("registro"):
            n_ruc = st.text_input("RUC Empresa", max_chars=13)
            n_razon = st.text_input("Razón Social")
            n_email = st.text_input("Email")
            n_telf = st.text_input("Teléfono")
            n_pass = st.text_input("Crea tu Contraseña", type="password")
            
            if st.form_submit_button("Crear Cuenta"):
                if n_ruc and n_razon and n_pass:
                    registrarse(n_ruc, n_razon, n_pass, n_email, n_telf)
                else:
                    st.warning("Llena los campos obligatorios")

# --- PANTALLA 2: DENTRO DEL SISTEMA ---
else:
    # BARRA LATERAL
    with st.sidebar:
        st.header("Mi Cuenta")
        st.write(f"🏢 **{st.session_state.empresa_ruc}**")
        
        if st.button("Cerrar Sesión"):
            st.session_state.token = None
            st.rerun()
            
        st.markdown("---")
        
        # --- PANEL SECRETO DE ADMIN ---
        if st.session_state.empresa_ruc == RUC_ADMIN:
            st.error("🔒 PANEL ADMIN")
            with st.form("admin_panel"):
                st.write("Recargar Saldo a Cliente")
                c_ruc = st.text_input("RUC Cliente")
                c_cant = st.number_input("Cantidad", value=250, step=50)
                if st.form_submit_button("💰 Recargar"):
                    recargar_saldo_admin(c_ruc, c_cant)
    
    st.title("Emitir Factura")

    # --- PESTAÑA DE CONFIGURACIÓN DE FIRMA ---
    with st.expander("⚙️ Configuración de Firma Electrónica", expanded=False):
        st.info("Si aún no has subido tu firma, hazlo aquí.")
        up_file = st.file_uploader("Archivo .p12", type="p12")
        up_pass = st.text_input("Contraseña del .p12", type="password")
        if st.button("Guardar Firma"):
            if up_file and up_pass:
                res = subir_firma_api(up_pass, up_file)
                if res and res.status_code == 200:
                    st.success("✅ Firma guardada correctamente")
                elif res:
                    st.error(f"Error: {res.json().get('detail')}")

    # --- FORMULARIO DE FACTURA ---
    with st.form("factura_form"):
        col1, col2 = st.columns(2)
        fecha_emision = col1.text_input("Fecha Emisión", value="10/12/2025")
        serie_caja = col2.text_input("Serie (Ej: 001001)", value="001001")
        
        st.markdown("### 👤 Cliente")
        c_nombre = st.text_input("Razón Social")
        c1, c2 = st.columns(2)
        c_ident = c1.text_input("Identificación")
        c_tipo = c2.selectbox("Tipo", ["05", "04", "06", "07"], format_func=lambda x: "Cédula" if x=="05" else "RUC" if x=="04" else "Pasaporte" if x=="06" else "Consumidor Final")
        c_dir = st.text_input("Dirección", value="S/N")
        
        st.markdown("### 🛒 Detalle")
        p_desc = st.text_input("Producto", "Servicios Profesionales")
        col_cant, col_prec = st.columns(2)
        p_cant = col_cant.number_input("Cantidad", min_value=1.0, value=1.0)
        p_prec = col_prec.number_input("Precio Unitario", min_value=0.01, value=10.00)
        
        subtotal = p_cant * p_prec
        iva = subtotal * 0.15
        total = subtotal + iva
        
        st.metric("Total a Pagar", f"${total:.2f}")
        
        if st.form_submit_button("🚀 Emitir Factura"):
            payload = {
                "ruc": st.session_state.empresa_ruc,
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
                    "codigo_principal": "IT-01", "descripcion": p_desc, 
                    "cantidad": p_cant, "precio_unitario": p_prec, 
                    "descuento": 0, "precio_total_sin_impuesto": subtotal,
                    "base_imponible": subtotal, "valor_impuesto": iva,
                    "codigo_impuesto": "2", "codigo_porcentaje": "4", "tarifa": 15
                }],
                "total_impuestos": [{
                    "codigo": "2", "codigo_porcentaje": "4", 
                    "base_imponible": subtotal, "valor": iva
                }]
            }
            
            with st.spinner("Firmando..."):
                res = emitir_factura_api(payload)
            
            if res and res.status_code == 200:
                data = res.json()
                st.success(f"✅ Factura Generada: {data.get('clave_acceso')}")
                if "creditos_restantes" in data:
                    st.toast(f"Te quedan {data['creditos_restantes']} créditos")
            elif res and res.status_code == 402:
                st.error("⚠️ Sin saldo. Recarga créditos.")
            elif res:
                st.error(f"Error: {res.text}")
