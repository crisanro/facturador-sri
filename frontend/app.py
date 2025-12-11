import streamlit as st
import requests
import os
import time

# --- 1. CONFIGURACIÓN INICIAL ---
# Ajusta el puerto si en tu backend usas 8000
BACKEND_URL = os.getenv("API_URL", "http://facturador-backend:80") 
RUC_ADMIN = "1760013210001" 

st.set_page_config(page_title="Facturación SaaS", page_icon="🧾", layout="wide")

# --- 2. ESTILOS CSS PARA QUE SE VEA PROFESIONAL ---
st.markdown("""
    <style>
    .stButton>button { width: 100%; font-weight: bold; border-radius: 8px; }
    .metric-card { background-color: #f0f2f6; padding: 15px; border-radius: 10px; margin-bottom: 10px; border-left: 5px solid #ff4b4b; }
    .auth-container { max-width: 400px; margin: auto; }
    </style>
""", unsafe_allow_html=True)

# --- 3. GESTIÓN DE ESTADO (SESIÓN) ---
if 'token' not in st.session_state: st.session_state.token = None
if 'config_completa' not in st.session_state: st.session_state.config_completa = False
if 'empresa_ruc' not in st.session_state: st.session_state.empresa_ruc = None
if 'datos_sri_temp' not in st.session_state: st.session_state.datos_sri_temp = {}

# --- 4. FUNCIONES DE CONEXIÓN CON EL BACKEND ---

def do_login(email, password):
    """Inicia sesión y guarda el token y estado del usuario"""
    try:
        res = requests.post(f"{BACKEND_URL}/login", json={"email": email, "password": password})
        if res.status_code == 200:
            data = res.json()
            st.session_state.token = data["access_token"]
            st.session_state.config_completa = data["configuracion_completa"]
            st.session_state.empresa_ruc = data.get("ruc_usuario") # Vital para saber si es admin
            st.rerun()
        elif res.status_code == 403:
            st.error("⚠️ Tu email no ha sido verificado. Revisa los logs por el código.")
        else:
            st.error("❌ Credenciales incorrectas")
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
    headers = {"Authorization": f"Bearer {st.session_state.token}"} # Opcional si proteges el endpoint
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



# ==========================================
#              INTERFAZ DE USUARIO
# ==========================================

# --- ESCENA 1: LOGIN / REGISTRO (Si no hay token) ---
if not st.session_state.token:
    c1, c2, c3 = st.columns([1, 2, 1]) # Centramos el contenido
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

# --- ESCENA 2: DENTRO DEL SISTEMA (Si hay token) ---
else:
    # --- HEADER / BARRA SUPERIOR ---
    col_h1, col_h2 = st.columns([8, 2])
    with col_h1: st.title("📊 Panel de Control")
    with col_h2: 
        if st.button("Cerrar Sesión"):
            st.session_state.token = None
            st.rerun()

    # --- BARRA DE ADVERTENCIA / ONBOARDING ---
    # Esto solo aparece si el usuario es nuevo y no ha subido su firma
    if not st.session_state.config_completa:
        st.warning("⚠️ **Perfil Incompleto:** Necesitas configurar tu RUC y Firma para empezar.")
        
        with st.expander("🚀 CONFIGURAR MI EMPRESA (Paso Único)", expanded=True):
            col_a, col_b = st.columns(2)
            
            with col_a:
                st.subheader("1. Datos del SRI")
                ruc_search = st.text_input("Ingresa tu RUC", max_chars=13, placeholder="17xxxxxxxx001")
                
                # Variables para autocompletar
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

                # Inputs finales (El usuario puede editarlos si quiere)
                final_razon = st.text_input("Razón Social", value=razon_social_val)
                # El SRI no siempre da la dirección, así que la pedimos
                final_dir = st.text_input("Dirección Matriz", placeholder="Ej: Av. Amazonas y ONU")

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
                                st.session_state.empresa_ruc = ruc_search # Actualizamos RUC
                                time.sleep(2)
                                st.rerun()
                            else:
                                st.error(f"Error: {res.json().get('detail')}")
                        except Exception as e: st.error(f"Error crítico: {e}")
                else:
                    st.warning("Por favor completa todos los campos obligatorios.")

    # --- DASHBOARD (Siempre visible) ---
    st.markdown("---")
    
    # Métricas Ficticias (Para enamorar al usuario)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Facturas Hoy", "0")
    m2.metric("Ventas Mes", "$0.00")
    m3.metric("Clientes", "0") 
    m4.metric("Créditos", "Consultando...") 
    
    # --- ÁREA DE FACTURACIÓN ---
    st.subheader("📝 Nueva Factura")
    
    # Bloqueamos el formulario si no está completo
    form_disabled = not st.session_state.config_completa
    if form_disabled:
        st.info("👆 Debes completar la configuración arriba para desbloquear este formulario.")

    with st.form("factura_form"):
        col1, col2 = st.columns(2)
        # Inputs deshabilitados si form_disabled es True
        fecha_emision = col1.text_input("Fecha Emisión", value="10/12/2025", disabled=form_disabled)
        serie_caja = col2.text_input("Serie (Ej: 001001)", value="001001", disabled=form_disabled)
        
        st.markdown("### 👤 Cliente")
        c_nombre = st.text_input("Razón Social / Nombre", disabled=form_disabled)
        c1, c2 = st.columns(2)
        c_ident = c1.text_input("Identificación", disabled=form_disabled)
        c_tipo = c2.selectbox("Tipo Documento", ["05", "04", "06", "07"], disabled=form_disabled)
        c_dir = st.text_input("Dirección", value="S/N", disabled=form_disabled)
        
        st.markdown("### 🛒 Detalle")
        p_desc = st.text_input("Descripción", "Servicios Profesionales", disabled=form_disabled)
        col_cant, col_prec = st.columns(2)
        p_cant = col_cant.number_input("Cantidad", min_value=1.0, value=1.0, disabled=form_disabled)
        p_prec = col_prec.number_input("Precio Unitario", min_value=0.01, value=10.00, disabled=form_disabled)
        
        # Cálculos en tiempo real (Frontend)
        subtotal = p_cant * p_prec
        iva = subtotal * 0.15
        total = subtotal + iva
        
        st.metric("Total a Pagar", f"${total:.2f}")
        
        enviar = st.form_submit_button("🚀 Firmar y Emitir Factura", disabled=form_disabled)
        
        if enviar and not form_disabled:
            # Payload para el backend
            mi_ruc = st.session_state.empresa_ruc
            
            payload = {
                # El backend usará el RUC del token, pero enviamos esto por validación Pydantic
                "ruc": mi_ruc if mi_ruc else "9999999999999", 
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
            
            with st.spinner("Generando XML y Firmando..."):
                res = emitir_factura_api(payload)
            
            if res and res.status_code == 200:
                data = res.json()
                st.success(f"✅ ¡Factura Exitosa! Clave: {data.get('clave_acceso')}")
                if "creditos_restantes" in data:
                    st.toast(f"Saldo restante: {data['creditos_restantes']}", icon="💰")
                with st.expander("Ver XML Firmado"):
                    st.code(data.get("xml_firmado"), language="xml")
            elif res and res.status_code == 402:
                st.error("⚠️ No tienes saldo suficiente. Contacta al administrador.")
            elif res:
                st.error(f"Error: {res.text}")

    # --- 5. MÓDULOS DE INTERFAZ (Para limpiar la vista principal) ---

def show_dashboard():
    st.subheader("📊 Resumen General")
    
    # 1. Obtener y mostrar SALDOS
    saldo_data = consultar_saldo_api()
    creditos_disp = saldo_data['creditos_disponibles'] if saldo_data else 0
    
    # Obtener el total de facturas generadas (para métrica)
    historial_facturas = obtener_historial_facturas_api()
    
    col_a, col_b, col_c = st.columns(3)
    
    with col_a:
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #00c087;">'
                    f'<h4>Créditos Restantes</h4><h1>{creditos_disp}</h1></div>', 
                    unsafe_allow_html=True)
    
    with col_b:
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #007bff;">'
                    f'<h4>Facturas Emitidas</h4><h1>{len(historial_facturas)}</h1></div>', 
                    unsafe_allow_html=True)
                    
    with col_c:
        # Se necesita un endpoint de totales de ventas en el backend para hacer esto real
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #ffaa00;">'
                    f'<h4>Ventas Estimadas (SRI)</h4><h1>$0.00</h1></div>', 
                    unsafe_allow_html=True)

    # 2. Historial de facturas
    st.markdown("---")
    st.subheader("📝 Historial de Facturas Generadas")
    
    if historial_facturas:
        # Convertir a DataFrame de Pandas para una mejor visualización en Streamlit
        import pandas as pd
        df = pd.DataFrame(historial_facturas)
        df['fecha_creacion'] = pd.to_datetime(df['fecha_creacion']).dt.strftime('%Y-%m-%d %H:%M')
        
        # Ocultamos el XML largo
        df_display = df[['fecha_creacion', 'clave_acceso', 'tipo_comprobante', 'estado']]
        
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
        if st.button("Comprar 50 Créditos", key="buy50", type="primary"):
            url = crear_sesion_compra_api(50)
            if url:
                st.info(f"Redirigiendo a Stripe... [Haz clic aquí]({url})")
                # Aquí puedes usar st.link_button en versiones recientes de Streamlit o js para redirigir
                # st.link_button("Ir a Pagar", url)

    # Paquete 2: 100 Créditos
    with col_p2:
        st.markdown(f'<div class="metric-card" style="border-left: 5px solid #3366ff;">'
                    f'<h4>100 Facturas</h4><h1>$18.00 USD</h1>'
                    f'<p>Ahorro de $2.00. El mejor valor.</p></div>', 
                    unsafe_allow_html=True)
        if st.button("Comprar 100 Créditos", key="buy100", type="primary"):
            url = crear_sesion_compra_api(100)
            if url:
                st.info(f"Redirigiendo a Stripe... [Haz clic aquí]({url})")
                # st.link_button("Ir a Pagar", url)

    st.markdown("---")
    st.subheader("🧾 Historial de Compras")
    historial_recargas = obtener_historial_recargas_api()
    if historial_recargas:
        import pandas as pd
        df_recargas = pd.DataFrame(historial_recargas)
        st.dataframe(df_recargas, use_container_width=True, hide_index=True)
    else:
        st.info("No hay recargas registradas.")


def show_facturacion_form():
    st.subheader("📝 Nueva Factura")
    # ... (MANTENER AQUÍ EL CÓDIGO DEL FORMULARIO DE FACTURACIÓN) ...
    # Copia toda la lógica del formulario de factura de tu app.py original aquí.
    # El código es extenso, asumimos que lo moverás tal cual.
    # ... (Si el usuario me envía el form completo, lo incluyo) ...

def show_configuracion():
    # ... (MANTENER AQUÍ EL CÓDIGO DE ONBOARDING/CONFIGURACIÓN) ...
    # Copia toda la lógica del `with st.expander("🚀 CONFIGURAR MI EMPRESA ...")`
    # y la lógica de búsqueda de RUC de tu app.py original aquí.
    # ...

# --- 6. FLUJO PRINCIPAL RE-ESTRUCTURADO ---

if not st.session_state.token:
    # Usar el código de Login/Registro/Verificación (ESCENA 1)
    pass # Asumo que el código de Login se mantiene intacto.
else:
    # ESCENA 2: DENTRO DEL SISTEMA
    # ... (Header y Cerrar Sesión se mantienen) ...

    # Si la configuración está incompleta, forzamos la configuración
    if not st.session_state.config_completa:
        show_configuracion() 
    else:
        # Pestañas principales para navegar
        tab_dash, tab_fact, tab_compras = st.tabs(["Panel General", "Facturación", "Comprar Créditos"])

        with tab_dash:
            show_dashboard()
            
        with tab_fact:
            show_facturacion_form()
            
        with tab_compras:
            show_compras()

    # === PANEL ADMIN SECRETO (Solo visible para ti) ===
    # Compara el RUC logueado con el RUC_ADMIN que definiste arriba
    if st.session_state.empresa_ruc == RUC_ADMIN:
        with st.sidebar:
            st.markdown("---")
            st.error("🔐 MODO SUPER ADMIN")
            with st.expander("Recargar Saldo a Clientes"):
                a_ruc = st.text_input("RUC Cliente Destino")
                a_cant = st.number_input("Cantidad a Recargar", value=100)
                if st.button("Acreditar Saldo"):
                    recargar_saldo_admin(a_ruc, a_cant)

