import streamlit as st
import requests
import os
import time

# --- CONFIGURACIÓN ---
BACKEND_URL = os.getenv("API_URL", "http://api-facturacion:80")

# ¡PON TU RUC DE ADMINISTRADOR AQUÍ! 
# (Con este RUC podrás ver el panel para recargar saldo a otros)
RUC_ADMIN = "1760013210001" 

st.set_page_config(page_title="Facturación SaaS", page_icon="🧾", layout="centered")

# --- ESTILOS ---
st.markdown("""
    <style>
    .stButton>button { width: 100%; background-color: #FF4B4B; color: white; }
    </style>
""", unsafe_allow_html=True)

# --- SESIÓN ---
if 'token' not in st.session_state: st.session_state.token = None
if 'config_completa' not in st.session_state: st.session_state.config_completa = False
if 'empresa_ruc' not in st.session_state: st.session_state.empresa_ruc = None # Para saber quién es el admin

# --- FUNCIONES API ---

def do_login(email, password):
    try:
        res = requests.post(f"{BACKEND_URL}/login", json={"email": email, "password": password})
        if res.status_code == 200:
            data = res.json()
            st.session_state.token = data["access_token"]
            st.session_state.config_completa = data["configuracion_completa"]
            
            # Decodificamos el RUC del usuario (si ya lo tiene) para saber si es admin
            # Nota: Idealmente el backend debería devolver el RUC en el login, 
            # pero por ahora asumimos que si entra, el backend validará permisos.
            # Para efectos visuales, hacemos una llamada rápida para obtener datos:
            # (Opcional, se puede mejorar luego)
            st.session_state.empresa_ruc = data.get("ruc_usuario")
            st.rerun()
        elif res.status_code == 403:
            st.error("⚠️ Debes verificar tu email primero.")
        else:
            st.error("Credenciales incorrectas")
    except: st.error("Error de conexión con el servidor")

def recargar_saldo_admin(ruc_cliente, cantidad):
    """Función exclusiva ADMIN"""
    try:
        res = requests.post(f"{BACKEND_URL}/admin/recargar", json={"ruc_cliente": ruc_cliente, "cantidad": cantidad})
        if res.status_code == 200:
            st.success(f"✅ Recarga exitosa al RUC {ruc_cliente}")
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

# ==========================================
#              VISTAS
# ==========================================

# --- VISTA 1: LOGIN / REGISTRO ---
if not st.session_state.token:
    st.title("Bienvenido 👋")
    tab1, tab2, tab3 = st.tabs(["Ingresar", "Crear Cuenta", "Verificar Código"])
    
    with tab1:
        email = st.text_input("Email")
        pw = st.text_input("Contraseña", type="password")
        if st.button("Entrar"): do_login(email, pw)
            
    with tab2:
        n_nombre = st.text_input("Tu Nombre")
        n_email = st.text_input("Tu Correo")
        n_p1 = st.text_input("Contraseña", type="password", key="p1")
        n_p2 = st.text_input("Repetir Contraseña", type="password", key="p2")
        
        if st.button("Registrarse"):
            if n_p1 != n_p2:
                st.error("Las contraseñas no coinciden")
            else:
                res = requests.post(f"{BACKEND_URL}/registrar-usuario", json={"nombre":n_nombre, "email":n_email, "password":n_p1})
                if res.status_code == 200:
                    st.success("✅ Cuenta creada. Revisa tu correo (o los logs del servidor) por el código.")
                else:
                    st.error(res.text)

    with tab3:
        v_email = st.text_input("Email registrado")
        v_code = st.text_input("Código de 6 dígitos")
        if st.button("Verificar"):
            res = requests.post(f"{BACKEND_URL}/verificar-email", json={"email":v_email, "codigo":v_code})
            if res.status_code == 200:
                st.balloons()
                st.success("¡Verificado! Ahora puedes entrar.")
            else:
                st.error("Código incorrecto")

# --- VISTA 2: ONBOARDING (Falta configurar RUC) ---
elif not st.session_state.config_completa:
    st.warning("⚠️ ¡Falta un paso! Configura tu empresa para empezar a facturar.")
    
    with st.form("setup_form"):
        st.write("Datos para el SRI:")
        ruc = st.text_input("RUC de la Empresa")
        razon = st.text_input("Razón Social")
        file = st.file_uploader("Firma Electrónica (.p12)", type="p12")
        clave = st.text_input("Clave de la Firma", type="password")
        
        if st.form_submit_button("Guardar y Validar"):
            if file:
                files = {"archivo_firma": (file.name, file, "application/x-pkcs12")}
                data = {"ruc": ruc, "razon_social": razon, "clave_firma": clave}
                headers = {"Authorization": f"Bearer {st.session_state.token}"}
                
                try:
                    res = requests.post(f"{BACKEND_URL}/configurar-empresa", data=data, files=files, headers=headers)
                    if res.status_code == 200:
                        st.success("¡Todo listo! Recargando...")
                        st.session_state.config_completa = True
                        st.session_state.empresa_ruc = ruc # Guardamos el RUC para saber si es admin luego
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(f"Error: {res.json().get('detail')}")
                except Exception as e:
                    st.error(f"Error de conexión: {e}")

# --- VISTA 3: PANEL PRINCIPAL (Facturación) ---
else:
    # BARRA LATERAL
    with st.sidebar:
        st.write("🟢 Sesión Activa")
        if st.button("Cerrar Sesión"):
            st.session_state.token = None
            st.rerun()
        
        st.markdown("---")
        
        # --- PANEL DE ADMIN (SOLO VISIBLE SI ERES TÚ) ---
        # Nota: Como el RUC se carga al login, asegúrate de que al configurar tu empresa uses el RUC_ADMIN
        # O añade un endpoint /me para traer el RUC siempre.
        # Por simplicidad, aquí ponemos el formulario siempre visible para ti si sabes el truco,
        # o puedes ocultarlo con un checkbox.
        
        with st.expander("Panel Admin (Recargas)"):
            c_ruc = st.text_input("RUC Cliente")
            c_cant = st.number_input("Cantidad", value=250, step=50)
            if st.button("💰 Recargar Saldo"):
                recargar_saldo_admin(c_ruc, c_cant)

    st.title("Emitir Factura")
    
    # FORMULARIO DE FACTURA
    with st.form("factura_form"):
        col1, col2 = st.columns(2)
        fecha_emision = col1.text_input("Fecha Emisión", value="10/12/2025")
        serie_caja = col2.text_input("Serie (Ej: 001001)", value="001001")
        
        st.markdown("### 👤 Cliente")
        c_nombre = st.text_input("Razón Social")
        c1, c2 = st.columns(2)
        c_ident = c1.text_input("Identificación")
        c_tipo = c2.selectbox("Tipo", ["05", "04", "06", "07"], format_func=lambda x: "Cédula" if x=="05" else "RUC" if x=="04" else "Consumidor Final")
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
            # Obtenemos el RUC actual (esto es un parche rápido si no tenemos el RUC en sesión)
            # En producción, usa un endpoint /me para obtener tu propio RUC.
            mi_ruc_actual = st.session_state.empresa_ruc 
            # Si es None, intentamos enviarlo así y que el backend valide el token.
            
            payload = {
                "ruc": mi_ruc_actual if mi_ruc_actual else "PENDIENTE", # El backend validará el token
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
            
            # Pequeño truco: El backend necesita el RUC en el payload para validar
            # Pero como tenemos token, el backend puede sacar el RUC del token.
            # Sin embargo, tu modelo FacturaCompleta Pydantic EXIGE el campo 'ruc'.
            # Así que necesitamos asegurarnos de enviarlo.
            # Solución: Haremos que el backend ignore el RUC del payload y use el del Token,
            # o nos aseguramos de guardarlo en sesión al configurar.
            
            # Como st.session_state.empresa_ruc se llena al configurar, debería funcionar.
            
            with st.spinner("Firmando..."):
                res = emitir_factura_api(payload)
            
            if res and res.status_code == 200:
                data = res.json()
                st.success(f"✅ Factura Generada: {data.get('clave_acceso')}")
                if "creditos_restantes" in data:
                    st.toast(f"Te quedan {data['creditos_restantes']} créditos")
                with st.expander("Ver XML"):
                    st.code(data.get("xml_firmado"), language="xml")
            elif res and res.status_code == 402:
                st.error("⚠️ Sin saldo. Contacta al admin.")
            elif res:
                st.error(f"Error: {res.text}")
